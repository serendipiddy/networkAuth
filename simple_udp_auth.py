import ryu.lib.packet.ether_types
from ryu.base import app_manager

ether_types.ETH_TYPE_ARP

class SimpleUDPAuth(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(SimpleUDPAuth, self).__init__(*args,**kwargs)
        
        
        

app_manager.require_app('ryu.app.simple_hubswitch_tasks')

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
