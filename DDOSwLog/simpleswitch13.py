########################################################
#                                                      #
#           SLIGHTLY MODIFIED VERSION OF               # 
#               SimpleSwitch13.py from RYU             #
#           MODIFIED BY LARRY      😊😊😊😊            #
########################################################


#THIS VERSION SIMPLY ADDS A FILTER FOR EVERY IP PROTOCOL AND LAYER 4 PROTOCOL namely: TCP, UDP, ICMP

#DEFAULT IMPORTS
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

#CUSTOM IMPORTS

from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from yaml import parse


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

#SLIGHTLY MODIFIED TO ADD TIMEOUT VALUES
    def add_flow(self, datapath, priority, match, actions, buffer_id=None,idle=0,hard=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, idle_timeout=idle, hard_timeout=hard,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, idle_timeout=idle, hard_timeout=hard,
                                    match=match, instructions=inst)
        
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # CHECK IF MAC ADDRESS HAS BEEN LEARNED BEFORE
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:

            # CHECK IF IT IS AN IP PACKET
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                eth = pkt.get_protocol(ethernet.ethernet)
                src_mac = eth.src

                ip = pkt.get_protocol(ipv4.ipv4) #returns ipv4 protocol
                #EXTRACTING source and destination ip address
                src_ip = ip.src
                dst_ip = ip.dst
                protocol = ip.proto

                #IF ICMP
                if protocol == 1:
                    pkt_icmp = pkt.get_protocol(icmp.icmp)
                    # print(eth.ethertype)
                    match = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype, eth_dst=dst, ipv4_src=src_ip, ipv4_dst=dst_ip, eth_src=src_mac, ip_proto=protocol,
                    icmpv4_code=pkt_icmp.code,icmpv4_type=pkt_icmp.type)
                #IF TCP
                elif protocol == 6:
                    pkt_tcp = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype, eth_dst=dst, ipv4_src=src_ip, ipv4_dst=dst_ip, eth_src=src_mac, ip_proto=protocol,
                    tcp_src = pkt_tcp.src_port,tcp_dst=pkt_tcp.dst_port)
                #IF UDP
                elif protocol == 17:
                    pkt_udp = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype, eth_dst=dst, ipv4_src=src_ip, ipv4_dst=dst_ip, eth_src=src_mac, ip_proto=protocol,
                    udp_src = pkt_udp.src_port,udp_dst=pkt_udp.dst_port)

                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle=20, hard=100)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions, idle=20, hard=100)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        # print("Port:",in_port)
        datapath.send_msg(out)