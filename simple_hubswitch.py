# Original copyright of the simple_switch_13.py is below.
#   The file has been modified as part of this project.

# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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

class SimpleHubSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(SimpleHubSwitch, self).__init__(*args,**kwargs)
        self.mac_to_port = {} # d[id -> {mac->port}
        self.ishub = False
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Runs when switches handshake with controller
          installs a default flow to out:CONTROLLER"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # install a table-miss flow entry
        match = parser.OFPMatch();
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 0, match, actions)
        
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
        self.logger.debug("ADD FLOW: %s %s" % (match, actions))
        datapath.send_msg(mod)
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # truncated condition?
        
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        
        in_port = msg.match['in_port']
        
        if self.ishub:
          '''For simple hub-like behaviour
            * Take the in port
            * Broadcast to all other data ports
              '''
          
          match = parser.OFPMatch(in_port=in_port)
          actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
          
          self.add_flow(dp, 1, match, actions)
          
          return
          
        '''Is a switch, so do work'''
        pkt = packet.Packet(msg.data)
        
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {}) # if not exists, create
        
        self.mac_to_port[dpid][src] = in_port # learn the src mac's port
        if dst in self.mac_to_port[dpid]:
          out_port = self.mac_to_port[dpid][dst]
        else:
          out_port = ofp.OFPP_FLOOD
          
        actions = [parser.OFPActionOutput(out_port)]
        
        # This is where a flow rule is installed
        if out_port != ofp.OFPP_FLOOD:
          match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
          
          if msg.buffer_id != ofp.OFP_NO_BUFFER:
            self.add_flow(dp, 1, match, actions, msg.buffer_id)
            return
          else:
            self.add_flow(dp, 1, match, actions)
        
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)
