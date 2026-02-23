import os
from datetime import datetime
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4
from ryu.app.ofctl.api import get_datapath
from ryu.lib import hub

from base_switch import BaseSwitch
from utils import Network

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
        self.monitor_thread = hub.spawn(self.monitor)
        self.ignore = [ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6]

    # --- MONITOREO (RECOLECTOR) ---
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)
            hub.sleep(10)

    def request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()
        body = ev.msg.body
        # Guardar en la carpeta compartida de Docker
        file0 = open("scripts/FlowStatsfile.csv", "a+")
        
        for stat in sorted([flow for flow in body if flow.priority == LOW_PRIORITY]):
            ip_src = stat.match.get('ipv4_src', '0.0.0.0')
            ip_dst = stat.match.get('ipv4_dst', '0.0.0.0')
            p_sec = stat.packet_count/stat.duration_sec if stat.duration_sec > 0 else 0
            
            line = ("{},{},{},{},{},{},{}\n"
                    .format(timestamp, ev.msg.datapath.id, ip_src, ip_dst, 
                            stat.packet_count, stat.byte_count, p_sec))
            file0.write(line)
        file0.close()

    # --- LÓGICA DE RED (RESTAURADA) ---
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event):
        datapath = event.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msgs = [self.del_flow(datapath)]
        
        match = parser.OFPMatch()
        # Restauramos la lógica: Leaf pregunta, Spine descarta por defecto [4]
        if datapath.id in net.leaves:
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        else:
            inst = []
        
        msgs += [self.add_flow(datapath, TABLE0, MIN_PRIORITY, match, inst)]
        self.send_messages(datapath, msgs)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        datapath = event.msg.datapath
        ofproto = datapath.ofproto
        in_port = event.msg.match["in_port"]
        pkt = packet.Packet(event.msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype in self.ignore:
            return

        dst, src = eth.dst, eth.src
        self.update_mac_table(src, in_port, datapath.id)
        dst_host = self.mac_table.get(dst)

        if dst_host:
            out_port = dst_host["port"]
            if dst_host["dpid"] == datapath.id:
                # Caso: Mismo Switch Leaf [1, 5]
                msgs = self.forward_packet(datapath, event.msg.data, in_port, out_port)
                msgs += self.create_match_entry(datapath, TABLE0, LOW_PRIORITY, src, dst, in_port, out_port, IDLE_TIME, eth.ethertype)
                self.send_messages(datapath, msgs)
            else:
                # Caso: Diferentes Switches Leaf (Uso de Spines) [1, 2]
                spine_id = net.spines[(datapath.id + dst_host["dpid"]) % len(net.spines)]
                
                # Regla en Switch Origen
                upstream_port = net.links[datapath.id, spine_id]["port"]
                msgs = self.create_match_entry(datapath, TABLE0, LOW_PRIORITY, src, dst, in_port, upstream_port, IDLE_TIME, eth.ethertype)
                self.send_messages(datapath, msgs)

                # Regla en Switch Spine [6]
                spine_dp = get_datapath(self, spine_id)
                s_in_port = net.links[spine_id, datapath.id]["port"]
                s_out_port = net.links[spine_id, dst_host["dpid"]]["port"]
                msgs = self.create_match_entry(spine_dp, TABLE0, LOW_PRIORITY, src, dst, s_in_port, s_out_port, IDLE_TIME, eth.ethertype)
                self.send_messages(spine_dp, msgs)

                # Envío al Switch Destino [6, 7]
                dst_dp = get_datapath(self, dst_host["dpid"])
                remote_port = dst_host["port"]
                msgs = self.forward_packet(dst_dp, event.msg.data, ofproto.OFPP_CONTROLLER, remote_port)
                down_port = net.links[dst_host["dpid"], spine_id]["port"]
                msgs += self.create_match_entry(dst_dp, TABLE0, LOW_PRIORITY, src, dst, down_port, remote_port, IDLE_TIME, eth.ethertype)
                self.send_messages(dst_dp, msgs)
        else:
            # Flood si es desconocido [7, 8]
            for leaf in net.leaves:
                p_in = in_port if datapath.id == leaf else ofproto.OFPP_CONTROLLER
                dpath = get_datapath(self, leaf)
                msgs = self.forward_packet(dpath, event.msg.data, p_in, dpath.ofproto.OFPP_ALL)
                self.send_messages(dpath, msgs)

    def create_match_entry(self, datapath, table, priority, src, dst, in_port, out_port, i_time, eth_type):
        parser = datapath.ofproto_parser
        # CORRECCIÓN: El match debe incluir el eth_type original (sea ARP o IPv4) [9]
        match = parser.OFPMatch(in_port=in_port, eth_type=eth_type, eth_src=src, eth_dst=dst)
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        return [self.add_flow(datapath, table, priority, match, inst, i_time=i_time)]

    def update_mac_table(self, src, port, dpid):
        src_host = self.mac_table.get(src, {})
        src_host["port"], src_host["dpid"] = port, dpid
        self.mac_table[src] = src_host
        return src_host

config_file = os.environ.get("NETWORK_CONFIG_FILE", "scripts/network_config.yaml")
net = Network(config_file)