from ryu.lib.packet import ether_types
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, 
    MAIN_DISPATCHER,
    set_ev_cls
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import (
    packet,
    ethernet,
    ipv4,
    ipv6,
    arp as ARP,
    udp as UDP
)
from ryu.lib.packet import in_proto
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
        print '(AUTH-packet_in) eth_type: %s' % self.eth_type_to_str(eth_type)
        # self.print_object(msg)
        
        # ''' register the server '''
        # if (broadcast and matches server key): 
          # set_server_address()
          # set server port for this datapath
        
        # capture auth packets
        if eth_type == ether_types.ETH_TYPE_IP:
            print ('(AUTH-packet_in) is IP!')
            
            ip = pkt.get_protocols(ipv4.ipv4)
            # check UDP
            # check port
            # check destination
            # add flow from src_mac 
            
            # alternatively, capture the OXM match for UDP port
            return
          
        # print '(AUTH-packet_in) eth_src: %s' % eth.src
        # print '(AUTH-packet_in) server: %s' % self.server_mac_address
        # print '(AUTH-packet_in) equal?: %s' % (eth.src == self.server_mac_address)
          
        # get port_id of server
        if eth.src == self.server_mac_address:
            self.server_port[dp.id] = msg.match['in_port']
            self.server_known = True
            print '(AUTH-packet_in) server_port: %d' % msg.match['in_port']
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

app_manager.require_app('ryu.app.simple_hubswitch')