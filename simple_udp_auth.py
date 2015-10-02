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
    ethernet
)


class SimpleUDPAuth(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(SimpleUDPAuth, self).__init__(*args,**kwargs)
        
        self.authHosts = {} # map host -> timeleft (time of expiry? time to remove access)
        self.datapaths = {}
        self.serverIPAddress = '10.0.0.2' # IP address that access is restricted to (the 'server')
        self.serverMacAddress = 'mac'     # MAC address that access is restricted to (the 'server')
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Runs when switches handshake with controller
          installs a default flow to out:CONTROLLER"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        
        
        
        # # install a table-miss flow entry
        # match = parser.OFPMatch();
        # actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        # self.add_flow(datapath, 0, match, actions)
        
        '''
            Obtain server's MAC address
        '''
        self.print_object(ev.msg)
        
        '''
            Blocking access to the server
        '''
        # install accept ARP rule, priority x
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,arp_tpa=self.serverIPAddress);
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 1, match, actions)
        
        # install block all to server rule, priority x-1
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,eth_dst=self.serverMacAddress);
        actions = [parser.OFPActionOutput()]
        self.add_flow(datapath, 1, match, actions)
    
    
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
        self.logger.debug("(AUTH) ADD FLOW: %s %s" % (match, actions))
        datapath.send_msg(mod)
    
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        '''Listen for auth packets'''
        
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        
        in_port = msg.match['in_port']
        
    def print_object(self, obj):
        ''' Prints all the attributes of a object
            http://stackoverflow.com/a/5969930 '''
        attrs = vars(obj)
        print ', '.join("%s: %s" % item for item in attrs.items())

app_manager.require_app('ryu.app.simple_hubswitch')

'''
ETH_TYPE_IP         =  0x0800
ETH_TYPE_ARP        =  0x0806
ETH_TYPE_8021Q      =  0x8100
ETH_TYPE_IPV6       =  0x86dd
ETH_TYPE_SLOW       =  0x8809
ETH_TYPE_MPLS       =  0x8847
ETH_TYPE_8021AD     =  0x88a8
ETH_TYPE_LLDP       =  0x88cc
ETH_TYPE_8021AH     =  0x88e7
ETH_TYPE_IEEE802_3  =  0x05dc
ETH_TYPE_CFM        =  0x8902
'''
