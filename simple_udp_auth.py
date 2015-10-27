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
    udp as UDP
)
from netaddr import IPAddress


class SimpleUDPAuth(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(SimpleUDPAuth, self).__init__(*args,**kwargs)
        
        self.authd_hosts = {}                            # map host -> timeleft (time of expiry? time to remove access)
        self.server_ipv4_address = IPAddress('10.0.0.2')            # IPv4 address that access is restricted to (the 'server')
        self.server_ipv6_address = IPAddress('fe80::200:ff:fe00:2') # IPv6 address that access is restricted to (the 'server')
        self.server_mac_address  = '00:00:00:00:00:02'   # MAC address that access is restricted to (the 'server')
        self.server_known = False                         # declares a server has been defined, and addresses set
        self.auth_port = 1332                            # UDP port to authenticate on
        
        self.datapaths = {}                              # dpid -> datapath
        self.server_port = {}                            # dpid -> port number
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Runs when switches handshake with controller
          installs a default flow to out:CONTROLLER"""
        datapath = ev.msg.datapath
        # ofproto = datapath.ofproto
        # parser = datapath.ofproto_parser
        
        self.install_server_blocking(datapath)
        self.install_udp_auth(datapath)
        
    def set_server_address(self, server_mac, server_ipv4, server_ipv6):
        self.server_mac_address  = server_mac
        self.server_ipv4_address = server_ipv4
        self.server_ipv6_address = server_ipv6
        # flush existing flows to for server
        return
    
    def install_server_blocking(self, datapath):
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
        
    def install_udp_auth(self, datapath):
        '''  Install rule for matching for the UDP auth packet '''
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        action_packet_in = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        
        # send UDP on port X to controller
        match_udp_auth_ipv4 = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP, 
            ip_proto=in_proto.IPPROTO_UDP,
            # eth_dst= self.server_mac_address,
            ipv4_dst= IPAddress(self.server_ipv4_address),
            udp_dst= self.auth_port)
        match_udp_auth_ipv6 = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP, 
            ip_proto=in_proto.IPPROTO_UDP,
            # eth_dst= self.server_mac_address,
            ipv6_dst= IPAddress(self.server_ipv6_address),
            udp_dst= self.auth_port)
        
        # add a flow for UDP packet capture
        self.add_flow(datapath, 2, match_udp_auth_ipv4, action_packet_in)
        self.add_flow(datapath, 2, match_udp_auth_ipv6, action_packet_in)
          
    def auth_host(self, host_ip, host_mac, datapath):
        ''' Allows given host to access the server '''
        
        # add host to authenticated hosts
        self.authd_hosts[host_mac] = 10000
        
        ryu_mac = type_desc.MacAddr.from_user(host_mac)
        
        # add rules for mac to access server
        match_ipv4 = ofproto_v1_3_parser.OFPMatch()
        match_ipv4.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE, ether_types.ETH_TYPE_IP)
        match_ipv4.append_field(ofproto_v1_3.OXM_OF_ETH_SRC, ryu_mac)
        match_ipv4.append_field(ofproto_v1_3.OXM_OF_IPV4_DST, int(self.server_ipv4_address))
        
        match_ipv6 = ofproto_v1_3_parser.OFPMatch()
        match_ipv6.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE, ether_types.ETH_TYPE_IPV6)
        match_ipv6.append_field(ofproto_v1_3.OXM_OF_ETH_SRC, ryu_mac)
        match_ipv6.append_field(ofproto_v1_3.OXM_OF_IPV6_DST, self.server_ipv6_address.words)
        
        action_allow_to_server = [ofproto_v1_3_parser.OFPActionOutput(self.server_port[datapath.id])]
        
        self.add_flow(datapath, 3, match_ipv4, action_allow_to_server)
        self.add_flow(datapath, 3, match_ipv6, action_allow_to_server)
        print ('(AUTH-auth authenicated %s on dpid:%s' % (host_mac,datapath.id))
        
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
        
        # ''' register the server '''
        # if (broadcast and matches server key): 
          # set_server_address()
          # set server port for this datapath
        
        # capture auth packets
        if eth_type == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocols(ipv4.ipv4)[0]
            if ip.proto == in_proto.IPPROTO_UDP and ip.dst == str(self.server_ipv4_address):
                udp = pkt.get_protocols(UDP.udp)[0]
                
                if udp.dst_port == self.auth_port:
                    print ('(AUTH-auth packet received from %s' % ip.src)
                    self.auth_host(ip.src, eth.src, dp)
            return
          
        # get port_id of server
        if eth.src == self.server_mac_address:
            self.server_port[dp.id] = msg.match['in_port']
            self.server_known = True
            print '(AUTH-packet_in) %d\'s server_port: %d' % (dp.id, msg.match['in_port'])
            return
        
    
          
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        '''Adds this flow to the given datapath'''
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, 
                                    match=match, instructions=inst)
        self.logger.debug("(AUTH-add flow): %s %s" % (match, actions))
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

app_manager.require_app('ryu.app.simple_hubswitch')