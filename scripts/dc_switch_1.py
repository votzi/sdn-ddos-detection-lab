import os
from datetime import datetime
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
from ryu.app.ofctl.api import get_datapath
from ryu.lib import hub

from base_switch import BaseSwitch
from utils import Network

# ==============================
# CONSTANTES DEL LABORATORIO
# ==============================
TABLE0 = 0
MIN_PRIORITY = 0
LOW_PRIORITY = 100
IDLE_TIME = 30

class SpineLeaf1(BaseSwitch):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mac_table = {}
        self.datapaths = {}
        self.flow_stats = {}   # Diccionario para DELTAS
        self.ignore = [ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6]

        # 🔥 LIMPIAR CSV AL INICIAR
        if os.path.exists("scripts/FlowStatsfile.csv"):
            os.remove("scripts/FlowStatsfile.csv")

        self.monitor_thread = hub.spawn(self.monitor)

    # ==============================
    # MANEJO DE DATAPATHS
    # ==============================
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)

    # ==============================
    # MONITOR CADA 5 SEGUNDOS
    # ==============================
    def monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)
            hub.sleep(5)

    def request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # ==============================
    # RECOLECTOR CIENTÍFICO (15 COLS)
    # ==============================
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        active_flows = len(body)
        lines = []

        for stat in body:

            ip_src = stat.match.get('ipv4_src', '0.0.0.0')
            ip_dst = stat.match.get('ipv4_dst', '0.0.0.0')
            tp_src = stat.match.get('tcp_src', stat.match.get('udp_src', 0))
            tp_dst = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))
            ip_proto = stat.match.get('ip_proto', 0)

            # SYN detection SOLO como feature
            syn_flag = stat.match.get('tcp_flags', 0)
            is_syn = 1 if (ip_proto == 6 and (syn_flag & 0x02)) else 0

            if ip_src != '0.0.0.0' and ip_dst != '0.0.0.0':

                # 🔥 FLOW KEY CORRECTA (SIN tcp_flags)
                flow_key = (dpid, ip_src, tp_src, ip_dst, tp_dst, ip_proto)

                prev_p, prev_b = self.flow_stats.get(flow_key, (0, 0))

                delta_p = stat.packet_count - prev_p if stat.packet_count >= prev_p else stat.packet_count
                delta_b = stat.byte_count - prev_b if stat.byte_count >= prev_b else stat.byte_count

                self.flow_stats[flow_key] = (stat.packet_count, stat.byte_count)

                p_sec = delta_p / 5.0
                b_sec = delta_b / 5.0

                line = ("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                        .format(timestamp, dpid, ip_src, tp_src, ip_dst, tp_dst,
                                ip_proto, delta_p, delta_b, stat.duration_sec,
                                p_sec, b_sec, active_flows, is_syn, 0))

                lines.append(line)

        if lines:
            with open("scripts/FlowStatsfile.csv", "a+") as file0:
                file0.writelines(lines)

    # ==============================
    # CONFIGURACIÓN INICIAL SWITCH
    # ==============================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event):
        datapath = event.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        msgs = [self.del_flow(datapath)]
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        msgs += [self.add_flow(datapath, TABLE0, MIN_PRIORITY, match, inst)]

        self.send_messages(datapath, msgs)

    # ==============================
    # LÓGICA SPINE-LEAF
    # ==============================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        datapath = event.msg.datapath
        ofproto = datapath.ofproto
        in_port = event.msg.match["in_port"]

        pkt = packet.Packet(event.msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype in self.ignore:
            return

        ip_info = {"src": '0.0.0.0', "dst": '0.0.0.0', "proto": 0,
                   "tp_src": 0, "tp_dst": 0, "tcp_flags": 0}

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            ip_info.update({"src": pkt_ipv4.src,
                            "dst": pkt_ipv4.dst,
                            "proto": pkt_ipv4.proto})

            pkt_tcp = pkt.get_protocol(tcp.tcp)
            pkt_udp = pkt.get_protocol(udp.udp)

            if pkt_tcp:
                ip_info.update({"tp_src": pkt_tcp.src_port,
                                "tp_dst": pkt_tcp.dst_port,
                                "tcp_flags": pkt_tcp.bits})
            elif pkt_udp:
                ip_info.update({"tp_src": pkt_udp.src_port,
                                "tp_dst": pkt_udp.dst_port})

        dst, src = eth.dst, eth.src

        if datapath.id in net.leaves and in_port > 2:
            self.update_mac_table(src, in_port, datapath.id)

        dst_host = self.mac_table.get(dst)

        if dst_host:
            out_port = dst_host["port"]

            if dst_host["dpid"] == datapath.id:
                msgs = self.forward_packet(datapath, event.msg.data, in_port, out_port)
                msgs += self.create_match_entry(datapath, TABLE0, LOW_PRIORITY,
                                                src, dst, in_port, out_port,
                                                IDLE_TIME, eth.ethertype, ip_info)
                self.send_messages(datapath, msgs)
            else:
                spine_id = net.spines[(datapath.id + dst_host["dpid"]) % len(net.spines)]
                spine_dp = get_datapath(self, spine_id)
                dst_dp = get_datapath(self, dst_host["dpid"])
                if spine_dp is None or dst_dp is None:
                    return

                u_port = net.links[(datapath.id, spine_id)]["port"]
                msgs = self.create_match_entry(datapath, TABLE0, LOW_PRIORITY,
                                               src, dst, in_port, u_port,
                                               IDLE_TIME, eth.ethertype, ip_info)
                self.send_messages(datapath, msgs)

                s_in = net.links[(spine_id, datapath.id)]["port"]
                s_out = net.links[(spine_id, dst_host["dpid"])]["port"]

                msgs = self.create_match_entry(spine_dp, TABLE0, LOW_PRIORITY,
                                               src, dst, s_in, s_out,
                                               IDLE_TIME, eth.ethertype, ip_info)
                self.send_messages(spine_dp, msgs)

                msgs = self.forward_packet(dst_dp, event.msg.data,
                                           ofproto.OFPP_CONTROLLER,
                                           dst_host["port"])

                d_port = net.links[(dst_host["dpid"], spine_id)]["port"]

                msgs += self.create_match_entry(dst_dp, TABLE0, LOW_PRIORITY,
                                                src, dst, d_port,
                                                dst_host["port"],
                                                IDLE_TIME,
                                                eth.ethertype, ip_info)
                self.send_messages(dst_dp, msgs)
        else:
            if datapath.id in net.leaves and in_port > 2:
                for leaf_id in net.leaves:
                    dpath = get_datapath(self, leaf_id)
                    msgs = self.forward_packet(dpath, event.msg.data,
                                               ofproto.OFPP_CONTROLLER,
                                               dpath.ofproto.OFPP_ALL)
                    self.send_messages(dpath, msgs)

    def create_match_entry(self, datapath, table, priority, src, dst,
                           in_port, out_port, i_time, eth_type, ip_info):

        parser = datapath.ofproto_parser

        if eth_type == 0x0800:
            match_args = {
                "in_port": in_port,
                "eth_type": eth_type,
                "ipv4_src": ip_info["src"],
                "ipv4_dst": ip_info["dst"],
                "ip_proto": ip_info["proto"],
                "eth_src": src,
                "eth_dst": dst
            }

            if ip_info["proto"] == 6:
                match_args.update({
                    "tcp_src": ip_info["tp_src"],
                    "tcp_dst": ip_info["tp_dst"],
                    "tcp_flags": ip_info["tcp_flags"]
                })
            elif ip_info["proto"] == 17:
                match_args.update({
                    "udp_src": ip_info["tp_src"],
                    "udp_dst": ip_info["tp_dst"]
                })

            match = parser.OFPMatch(**match_args)
        else:
            match = parser.OFPMatch(in_port=in_port,
                                    eth_type=eth_type,
                                    eth_src=src,
                                    eth_dst=dst)

        inst = [parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS,
            [parser.OFPActionOutput(out_port)]
        )]

        return [self.add_flow(datapath, table, priority, match, inst, i_time=i_time)]

    def update_mac_table(self, src, port, dpid):
        self.mac_table[src] = {"port": port, "dpid": dpid}


config_file = os.environ.get("NETWORK_CONFIG_FILE", "scripts/network_config.yaml")
net = Network(config_file)