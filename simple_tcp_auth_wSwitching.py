from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, 
    MAIN_DISPATCHER,
    set_ev_cls
)
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib import type_desc
from ryu.lib.packet import (
    in_proto, # ipv4 layer 3 protocols
    packet,
    ethernet,
    ether_types,
    ipv4,
    ipv6,
    arp as ARP,
    tcp as TCP
)
from netaddr import IPAddress
from ryu.app.simple_hubswitch_class import SimpleHubSwitch # packet switching logic
from ryu.app.portknock_rest_server import Portknock_Server
from ryu.app.wsgi import WSGIApplication

num_port_bits = 16
def get_seq_len(key_length):
    n = 1
    while 2**n < key_length:
      n+=1
    
    if n > 15: return 0
    else: return n

class Port_Knocking(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi":WSGIApplication}
    
    def __init__(self, *args, **kwargs):
        super(Port_Knocking, self).__init__(*args,**kwargs)
        
        ## server location
        self.server_known = False                                   # declares a server has been defined, and addresses set
        self.server_ipv4_address = IPAddress('10.0.0.2')            # IPv4 address that access is restricted to (the 'server')
        self.server_ipv6_address = IPAddress('fe80::200:ff:fe00:2') # IPv6 address that access is restricted to (the 'server')
        self.server_mac_address  = '00:00:00:00:00:02'              # MAC address that access is restricted to (the 'server')
        # record of server location on each switch
        self.datapaths = {}                                         # dpid -> datapath object
        self.server_port = {}                                       # dpid -> port number on switch to reach server
        
        ## key config
        self.auth_port = 1332     # TCP port to initiate authentication key
        self.active_keys = {}     # Keys available to auth on; key_id -> key sequence (seq of decimal numbers)
        self.key_length = 4       # number of packets per key
        self.seq_size = get_seq_len( self.key_length )     # number of bits used for the sequence number (1-8 are valid)
        
        ## host records
        self.authenticated_hosts = {}     # Authorised hosts;    host_ip -> timeleft (time of expiry? time to remove access)
        self.authing_hosts = {}   # Hosts currently entering keys; host_ip -> key buffer s.t. key buffer [port0==keyID,port1,port2,port3,..]
        self.blocked_hosts = {}   # Hosts who entered incorrect key; host_ip -> timeout ## may not implement atm
        self.default_time  = 1800 # seconds till invalid (3600 == one hour)
        
        # get/register other classes
        self.switching = SimpleHubSwitch()
        wsgi = kwargs['wsgi']
        wsgi.register(Portknock_Server, {'port_knocking' : self})
        
        # testing key
        self.add_auth_key([
            {"value": 1489, "seq": 0,"port": 1489},
            {"value": 15961,"seq": 1,"port": 32345},
            {"value": 8637, "seq": 2,"port": 41405},
            {"value": 2929, "seq": 3,"port": 52081}])
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Runs when switches handshake with controller
          installs a default flow to out:CONTROLLER"""
        datapath = ev.msg.datapath
        
        self.switching.switch_features_handler(ev)
        
        self.install_server_blocking_flows(datapath)
        self.install_auth_init_flow(datapath)
        
    def set_server_address(self, server_mac, server_ipv4, server_ipv6):  # currently unused
        ''' Selects a server on the network '''
        
        self.server_mac_address  = server_mac
        self.server_ipv4_address = server_ipv4
        self.server_ipv6_address = server_ipv6
        self.server_known = True
        # flush existing flows to for server
        return
        
    def add_auth_key(self, key_list):
        ''' Keys are a given as a list of (seq, key) values, 
              each pair of letters corresponds to a port number 
              first is used as the key's ID
              return true is no key conflict, false if key_id exists  '''
        if len(key_list) != self.key_length:
            print('(AUTH-addkey) invalid key list, too long (%d!=%d)' % len(key_list),self.key_length)
            return True
            
        if len(key_list) > 2**self.seq_size:
            print('(AUTH-addkey) invalid key, longer than max sequence (%d > %d)' % (len(key_list),2**self.seq_size))
            return True # to avoid infinite loop
        
        idx = 0
        for k in key_list:
            # check they're valid and in order
            n = k['seq']
            val = k['value']
            if val > 2**(num_port_bits - self.seq_size):
                print('(AUTH-addkey) invalid value %d at key[%d] -- too large! (>%d)' % (val,n,2**(num_port_bits - self.seq_size)))
                return True
            idx+=1
            
        # check key_id doesn't exist already
        if key_list[0]['value'] in self.active_keys:
            return False
        
        auth_key = []
        auth_ports = []
        for k in key_list:
            print('%d: %d -> %d' % (k['port'], k['seq'], k['value']))
            auth_key.append(k['value'])
            auth_ports.append(k['port'])
        
        self.active_keys[auth_key[0]] = {'key': auth_key,'port': auth_ports}
        print('(AUTH-addkey) Added key %s' % auth_key)
        return True
    
    def install_server_blocking_flows(self, datapath):
        ''' Blocking IP access to the server and allowing ARP '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        action_block = [] # empty == block
        
        # install block all to server rule (mac, ipv4, ipv6)
        match_mac = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_dst=self.server_mac_address);
        match_ipv4 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=self.server_ipv4_address);
        match_ipv6 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6, ipv6_dst=self.server_ipv6_address);
        
        self.add_flow(datapath, 1, match_mac, action_block)
        self.add_flow(datapath, 1, match_ipv4, action_block)
        self.add_flow(datapath, 1, match_ipv6, action_block)
        
    def install_auth_init_flow(self, datapath):
        '''  Install rule for matching for the TCP auth init packet '''
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        action_packet_in = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        
        # send TCP on port self.auth_port to controller
        match_tcp_auth_ipv4 = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP, 
            ip_proto=in_proto.IPPROTO_TCP,
            # eth_dst= self.server_mac_address,
            ipv4_dst= IPAddress(self.server_ipv4_address),
            tcp_dst= self.auth_port)
        match_tcp_auth_ipv6 = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP, 
            ip_proto=in_proto.IPPROTO_TCP,
            # eth_dst= self.server_mac_address,
            ipv6_dst= IPAddress(self.server_ipv6_address),
            tcp_dst= self.auth_port)
        
        # add a flow for auth init packet capture
        self.add_flow(datapath, 2, match_tcp_auth_ipv4, action_packet_in)
        self.add_flow(datapath, 2, match_tcp_auth_ipv6, action_packet_in)
          
    def auth_host(self, src_ip, datapath):
        ''' Allows given host to access the server '''
        
        action_allow_to_server = [ofproto_v1_3_parser.OFPActionOutput(self.server_port[datapath.id])]
        
        # add rules for mac to access server
        match_ipv4 = ofproto_v1_3_parser.OFPMatch()
        match_ipv4.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE, ether_types.ETH_TYPE_IP)
        match_ipv4.append_field(ofproto_v1_3.OXM_OF_IPV4_SRC, int(IPAddress(src_ip)))
        match_ipv4.append_field(ofproto_v1_3.OXM_OF_IPV4_DST, int(self.server_ipv4_address))
        self.add_flow(datapath, 3, match_ipv4, action_allow_to_server)
        
        ## IPv6
        # match_ipv6 = ofproto_v1_3_parser.OFPMatch()
        # match_ipv6.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE, ether_types.ETH_TYPE_IPV6)
        # match_ipv6.append_field(ofproto_v1_3.OXM_OF_IPV6_SRC, ryu_mac)
        # match_ipv6.append_field(ofproto_v1_3.OXM_OF_IPV6_DST, self.server_ipv6_address.words)
        # self.add_flow(datapath, 3, match_ipv6, action_allow_to_server)
        
        print ('(AUTH-auth authenicated id:%s on dpid:%s' % (src_ip, datapath.id))
        
    def match_key(self, src_ip, dst_port, datapath):
        ''' Matches the sequence of knocks against buffered key '''
              
        print('dst port %d' % dst_port)
        idx     = dst_port >> (num_port_bits - self.seq_size)
        key_val = dst_port & (2**(num_port_bits - self.seq_size)) - 1
        
        if (idx > self.key_length) or (idx < 0): 
            self.invalid_key('Key sequence number out of bounds')
            return
           
        if len(self.authing_hosts[src_ip]) == 0:
            # first sequence key
            if idx != 0: return # don't accept anything until key is selected
            else: key_id = key_val
        else:
            key_id  = self.authing_hosts[src_ip][0]
        
        if key_id not in self.active_keys:
            self.invalid_key('Key id not valid %d' % (key_id))
            remove_key(src_ip)
            return 
        
        if self.active_keys[key_id]['key'][idx] != key_val: # check they match
            self.invalid_key('value %d doesn\'t match key idx %d of key %d (%d)' % (key_val, idx, key_id, self.active_keys[key_id]['key'][idx]))
            return
            
        if idx not in self.authing_hosts[src_ip]:
            print('(AUTH-ing) buffer %d = %d' % (idx, key_val))
            self.authing_hosts[src_ip][idx] = key_val
        
        if len(self.authing_hosts[src_ip]) == self.key_length:
            # key complete, authorise IP address to access server
            print('(AUTH-seq complete) ip:%s' % src_ip)
            
            # add host to authenticated hosts
            self.authenticated_hosts[src_ip] = 10000
            
            # tidy up
            del self.authing_hosts[src_ip]
            del self.active_keys[key_id]
            # self.remove_authing_flows(src_ip) # redundant, is replaced with allow flow
            
            # install flows to access server
            self.auth_host(src_ip, datapath)
        else:
            print('(AUTH-buffered) %s length: %d/%d' % (src_ip, len(self.authing_hosts[src_ip]),self.key_length))
        
    def invalid_key(self, msg=''):
        # TODO: block for a few seconds
        # TODO: release authing key from host?
        print('(AUTH-invalid key) %s' % msg)
    
    def remove_key(self, src_ip):
        ''' expired keys are disassociated from host '''
        del self.authing_hosts[src_ip]
    
    def initialise_host_auth(self, src_ip, datapath):
        print ('(AUTH-auth init) received init from %s' % src_ip)
        self.authing_hosts[src_ip] = {} # empty key buffer
        
        # install flow, fwd all tcp to controller TODO
        action_fwd_to_controller = [ofproto_v1_3_parser.OFPActionOutput(ofproto_v1_3.OFPP_CONTROLLER)]
        match_ipv4 = ofproto_v1_3_parser.OFPMatch()
        match_ipv4.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE, ether_types.ETH_TYPE_IP)
        match_ipv4.append_field(ofproto_v1_3.OXM_OF_IPV4_SRC, int(IPAddress(src_ip)))
        match_ipv4.append_field(ofproto_v1_3.OXM_OF_IPV4_DST, int(self.server_ipv4_address))
        
        self.add_flow(datapath, 3, match_ipv4, action_fwd_to_controller)
        
    def remove_authing_flows(self,src_ip):
        ''' removes the flows that capture knock sequence '''
        match_ipv4 = ofproto_v1_3_parser.OFPMatch()
        match_ipv4.append_field(ofproto_v1_3.OXM_OF_IPV4_SRC, int(IPAddress(src_ip)))
        
        for id, dp in self.datapaths:
            self.delete_flow(dp, 3, match_ipv4)
    
    def set_datapath_svr_port(self, dpid, in_port):
        if dpid in self.server_port and self.server_port[dpid] == in_port:
            # already set and no change
            return
            
        print '(AUTH-packet_in) %d\'s server_port: %d' % (dpid, in_port)
        self.server_port[dpid] = in_port
        self.server_known = True
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        '''Listen for auth packets 
            and server announcement'''
        
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        eth_type = eth.ethertype
        
        # ''' register the server (not implemented) '''
        # if (broadcast and matches server key): 
          # set_server_address()
          # set server port for this datapath
        
        # capture auth packets
        if eth_type == ether_types.ETH_TYPE_IP:
            # if TCP and dst is server
            # ipv4
            ip = pkt.get_protocols(ipv4.ipv4)[0]
            if ip.proto == in_proto.IPPROTO_TCP and ip.dst == str(self.server_ipv4_address):
                tcp = pkt.get_protocols(TCP.tcp)[0]
                
                if ip.src in self.authenticated_hosts: # likely from another switch, so needs to have flow to server installed
                    self.auth_host(ip.src, dp)
                
                if len(self.active_keys) <= 0:
                    print('no keys active')
                    return
                
                elif ip.src in self.authing_hosts:
                    self.match_key(ip.src, tcp.dst_port, dp)
                
                elif tcp.dst_port == self.auth_port:
                    # install key matching flows for host
                    self.initialise_host_auth(ip.src, dp)
                    
                return # avoid installing flow (block TCP traffic to server)
            if ip.dst == str(self.server_ipv4_address):
                # avoids controller forwarding on other IP packets while ALL TO CONTROLLER is active
                return
                
            # ipv6 version (TODO)
        if eth_type == ether_types.ETH_TYPE_IPV6:
            ip = pkt.get_protocols(ipv6.ipv6)[0]
            if ip.dst == str(self.server_ipv6_address):
                return 
        
        # if from server, get port_id of server (reply from ARP will trigger this)
        if eth.src == self.server_mac_address:
            self.set_datapath_svr_port(dp.id, msg.match['in_port'])
        
        # do regular switching
        self.switching.packet_in_handler(ev)
          
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        '''Adds this flow to the given datapath'''
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, 
                                    match=match, instructions=inst)
        self.logger.debug("(AUTH-add flow): %s %s" % (match, actions))
        datapath.send_msg(mod)
        
    def delete_flow(self, datapath, priority, match):
        ''' This method is stolen from Jarrod :P '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        command = ofproto.OFPFC_DELETE_STRICT
        mod = parser.OFPFlowMod(datapath=datapath, command=command,
                                priority=priority, match=match,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY)
        datapath.send_msg(mod)
        
    def print_object(self, obj):
        ''' Prints all the attributes of a object
            http://stackoverflow.com/a/5969930 '''
        attrs = vars(obj)
        print ', '.join("%s: %s" % item for item in attrs.items())

    def eth_type_to_str(self, eth_type):
        '''Given an eth_type hex value, return the eth_type name'''
        return {
            ether_types.ETH_TYPE_IP:        'ETH_TYPE_IP',
            ether_types.ETH_TYPE_ARP:       'ETH_TYPE_ARP',
            ether_types.ETH_TYPE_8021Q:     'ETH_TYPE_8021Q',
            ether_types.ETH_TYPE_IPV6:      'ETH_TYPE_IPV6',
            ether_types.ETH_TYPE_SLOW:      'ETH_TYPE_SLOW',
            ether_types.ETH_TYPE_MPLS:      'ETH_TYPE_MPLS',
            ether_types.ETH_TYPE_8021AD:    'ETH_TYPE_8021AD',
            ether_types.ETH_TYPE_LLDP:      'ETH_TYPE_LLDP',
            ether_types.ETH_TYPE_8021AH:    'ETH_TYPE_8021AH',
            ether_types.ETH_TYPE_IEEE802_3: 'ETH_TYPE_IEEE802_3',
            ether_types.ETH_TYPE_CFM:       'ETH_TYPE_CFM'
        }.get(eth_type,"Type %x not found" % (eth_type))
        
    def ip_proto_to_str(self, ip_proto):
        ''' Given an ip_proto number, returns the protocol name '''
        return {
            in_proto.IPPROTO_IP:        'IPPROTO_IP',
            in_proto.IPPROTO_HOPOPTS:   'IPPROTO_HOPOPTS',
            in_proto.IPPROTO_ICMP:      'IPPROTO_ICMP',
            in_proto.IPPROTO_IGMP:      'IPPROTO_IGMP',
            in_proto.IPPROTO_TCP:       'IPPROTO_TCP',
            in_proto.IPPROTO_UDP:       'IPPROTO_UDP',
            in_proto.IPPROTO_ROUTING:   'IPPROTO_ROUTING',
            in_proto.IPPROTO_FRAGMENT:  'IPPROTO_FRAGMENT',
            in_proto.IPPROTO_AH:        'IPPROTO_AH',
            in_proto.IPPROTO_ICMPV6:    'IPPROTO_ICMPV6',
            in_proto.IPPROTO_NONE:      'IPPROTO_NONE',
            in_proto.IPPROTO_DSTOPTS:   'IPPROTO_DSTOPTS',
            in_proto.IPPROTO_OSPF:      'IPPROTO_OSPF',
            in_proto.IPPROTO_VRRP:      'IPPROTO_VRRP',
            in_proto.IPPROTO_SCTP:      'IPPROTO_SCTP'
        }.get(ip_proto,"Type %x not found" % (ip_proto))

def convert_key_to_port(key, seq, seq_size):
    key_len = 16 - seq_size
    return (seq << key_len) + key
# nop
