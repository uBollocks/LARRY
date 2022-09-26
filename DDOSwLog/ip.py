from prettytable import PrettyTable  # to display output from ML model
from operator import attrgetter
from datetime import datetime
import simpleswitch13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import numpy  # for model features
import pickle  # to use ML model real-time
import pandas as pd
import numpy as np
import csv


class SimpleMonitor13(simpleswitch13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        print("Monitoring Has Began")
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.fields = {'time': '', 'datapath': '', 'in-port': '', 'eth_src': '',
                       'eth_dst': '', 'out-port': '', 'total_packets': 0, 'total_bytes': 0}
        date_time = datetime.now()
        self.ts = date_time

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(1)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def block_flow(self, data):
        IPproto = data['ip_proto']
        dp_id = data['datapath_id']
        ofproto = self.datapaths[dp_id].ofproto
        parser = self.datapaths[dp_id].ofproto_parser
        if IPproto == 1:
            # IF PROTO IS ICMP
            match = parser.OFPMatch(eth_type=data['eth_type'], eth_src=data['eth_src'], icmpv4_code=data['icmp_code'], icmpv4_type=data['icmp_type'], ipv4_dst=data['ip_dst'], ipv4_src=data['ip_src'],
                                    ip_proto=IPproto)
            victim = data['ip_dst']
        if IPproto == 6:
            # IF PROTO IS TCP
            match = parser.OFPMatch(
                eth_type=data['eth_type'], eth_src=data['eth_src'], ip_proto=IPproto, ipv4_dst=data['ip_dst'])
            victim = data['ip_dst']
        if IPproto == 17:
            # IF PROTO IS UDP
            match = parser.OFPMatch(eth_type=data['eth_type'], eth_src=data['eth_src'],
                                    ip_proto=IPproto, ipv4_dst=data['ip_dst'])
            victim = data['ip_dst']
        self.logger.info(f"victim is {victim}")
        priority = 100
        actions = []
        buffer_id = None
        for c in self.datapaths:
            datapath = self.datapaths[c]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            if buffer_id:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, idle_timeout=0, hard_timeout=0,
                                        priority=priority, match=match,
                                        instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority, idle_timeout=0, hard_timeout=0,
                                        match=match, instructions=inst)
            datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stat_reply_handler(self, ev):
        date_time = datetime.now()
        body = ev.msg.body

        # DEFINING VARIABLES TO STORE

        icmp_code = -1
        icmp_type = -1
        tp_src = 0
        tp_dst = 0
        srcIPTotal = 0
        srcPortTotal = 0
        totalFlows = 0
        totalPackets = 0
        packets_count = []
        byte_count = []
        T = 5  # interval between collection of flows
        ip_holder = []
        port_holder = []

        # FOR LOOP TO WRITE TO CSV FILE
        # return sorted list only for FLOWs with priority of 1,
        # print("THIS IS BODY",body)
        for flow in body:
            # print("THIS IS Flow", body)
            if flow.priority == 1:
                totalFlows += 1
        x = PrettyTable()
        x.field_names = ["DateTime", "SSIP", "SSP",
                         "SDFP", "SDFB", "SFE", "Status"]
        for stats in sorted([flow for flow in body if (flow.priority == 1)], key=lambda flow:  # SORT BY flows that are returned only if: they contain eth_type, ipv4 source, ipv4 destination and an IP protocol
                            (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):

            # First Print
            Perms = 0
            ip_src = stats.match['ipv4_src']
            ip_dst = stats.match['ipv4_dst']
            ip_proto = stats.match['ip_proto']
            if ip_src not in ip_holder:
                ip_holder.append(ip_src)
                srcIPTotal += 1
            if ip_proto == 6:  # IF FLOW ENTRY IS FOR TCP
                tp_src = stats.match['tcp_src']
                tp_dst = stats.match['tcp_dst']
                if tp_src not in port_holder:
                    srcPortTotal += 1
            elif ip_proto == 17:  # IF FLOW ENTRY IS FOR UDP
                tp_src = stats.match['udp_src']
                tp_dst = stats.match['udp_dst']
                if tp_src not in port_holder:
                    srcPortTotal += 1

            # 2nd Print
            self.fields['time'] = datetime.utcnow().strftime('%s')
            self.fields['datapath_id'] = ev.msg.datapath.id
            self.fields['in-port'] = stats.match['in_port']
            self.fields['eth_src'] = stats.match['eth_src']
            self.fields['eth_dst'] = stats.match['eth_dst']
            self.fields['out-port'] = stats.instructions[0].actions[0].port
            self.fields['total_packets'] = stats.packet_count
            self.fields['total_bytes'] = stats.byte_count
            ip_proto = stats.match['ip_proto']
            eth_type = stats.match['eth_type']
            with open('ip.csv', 'rt') as f:
                reader = csv.reader(f, delimiter=',')
                for row in reader:
                    print(ip_src, row)
                    if ip_src in row:
                        # print(ip_src, row)
                        Perms = 1
                        # break out of inner most for loop.
                        break
            # features = np.asarray([self.fields['datapath_id'], ip_src, tp_src, ip_dst,
            #                       tp_dst, ip_proto, icmp_code, icmp_type, eth_type, self.fields['eth_src']]).reshape(1, -1)
            file = open(
                "/home/larry/Desktop/TORONTO/trafficclassifier/csv/PredFlowStatistics.csv", "w")
            # opening with w means overwrite, w+ will append.
            # we will always read the 1 line avaliable in this file.
            file.write(
                "datapath_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,eth_type,eth_src\n")
            file.write(
                f"{self.fields['datapath_id']},{ip_src},{tp_src},{ip_dst},{tp_dst},{ip_proto},{icmp_code},{icmp_type},{eth_type},{self.fields['eth_src']}")
            totalPackets += stats.packet_count
            packets_count.append(stats.packet_count)
            byte_count.append(stats.byte_count)
        SSIP = srcIPTotal / T  # speed of source IPs per second
        SSP = srcPortTotal / T  # speed of source Ports per second
        # meanPacketsPerFlow = totalPackets / totalFlows
        SDFP = numpy.std(packets_count)
        SDFB = numpy.std(byte_count)
        SFE = totalFlows / T
        self.logger.info("_________________________________________________")
        self.logger.info("Start time: " + str(self.ts))
        self.logger.info("Current time: " + str(date_time))
        self.logger.info("Elapsed time: " + str(date_time - self.ts))
        features = np.asarray([SSIP, SSP, SDFP, SDFB, SFE]).reshape(1, -1)
        # features = pd.read_csv(
        #     '/home/larry/Desktop/TORONTO/trafficclassifier/csv/PredFlowStatistics.csv')
        infile = open(
            '/home/larry/Desktop/TORONTO/trafficclassifier/DDOS/LogisticRegression', 'rb')
        model = pickle.load(infile)
        infile.close()
        # if numpy array containing flow tables = null/ Dont print
        if (np.isnan(features).any()):
            print("No Traffic Monitored")
        else:
            if Perms == 1:
                label = model.predict(features)
                x.add_row([{date_time}, {SSIP}, {SSP}, {
                    SDFP}, {SDFB}, {SFE}, {label[0]}])
                if label[0] == 1:
                    predict_flow_data = pd.read_csv(
                        "/home/larry/Desktop/TORONTO/trafficclassifier/csv/PredFlowStatistics.csv")
                    print("Here: DDOS Stopped")
                    # print(predict_flow_data.iloc[0])
                    self.block_flow(predict_flow_data.iloc[0])
                if label[0] != None:
                    print(x)  # print output in pretty mode (i.e. formatted table)
                    print("PERGOOD", Perms)
            # Traffic Logger: for possible external users from outside our internal network
            if Perms != 1:
                print("PER", Perms)
                logfile = open(
                    r'/home/larry/Desktop/TORONTO/trafficclassifier/log.csv', 'a+', newline='')
                label = model.predict(features)
                x.add_row([{date_time}, {SSIP}, {SSP}, {
                    SDFP}, {SDFB}, {SFE}, {label[0]}])
                if label[0] == 1:
                    predict_flow_data = pd.read_csv(
                        "/home/larry/Desktop/TORONTO/trafficclassifier/csv/PredFlowStatistics.csv")
                    print("Here: DDOS Stopped")
                    # print(predict_flow_data.iloc[0])
                    self.block_flow(predict_flow_data.iloc[0])
                    # with open(
                    #     r'/home/larry/Desktop/TORONTO/trafficclassifier/log.csv', 'a+', newline='')
                    logfile.write(
                        f"Status; DDOS Observed: {ip_src} {self.fields['eth_src']}, connected to {ip_dst}, {ip_proto}, {icmp_code},{icmp_type},{eth_type},{self.fields['time']} \n")
                if label[0] != None:
                    print(x)  # print output in pretty mode (i.e. formatted table)
                    logfile.write(
                        f"Status; New Traffic Observed: {ip_src} {self.fields['eth_src']}, connected to {ip_dst}, {ip_proto}, {icmp_code},{icmp_type},{eth_type},{self.fields['time']} \n")
