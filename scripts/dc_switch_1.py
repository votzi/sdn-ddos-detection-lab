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

# Constantes de configuración [1, 5]
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

    # --- RECOLECTOR DE ESTADÍSTICAS PARA IA (22 COLUMNAS) --- [1, 5]
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
            hub.sleep(10) # Frecuencia de recolección [6]

    def request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        
        # Abrimos el archivo dentro del volumen de Docker [7, 8]
        with open("scripts/FlowStatsfile.csv", "a+") as file0:
            for stat in body:
                # CAMBIO: Quitamos el filtro 'if priority == LOW_PRIORITY' para asegurar que grabe datos [1]
                # Capturamos IPs solo si el flujo las tiene, de lo contrario grabamos 0.0.0.0
                ip_src = stat.match['ipv4_src'] if 'ipv4_src' in stat.match else '0.0.0.0'
                ip_dst = stat.match['ipv4_dst'] if 'ipv4_dst' in stat.match else '0.0.0.0'
                ip_proto = stat.match['ip_proto'] if 'ip_proto' in stat.match else 0
                
                # Protección contra división por cero [2]
                dur_sec = stat.duration_sec if stat.duration_sec > 0 else 1
                dur_nsec = stat.duration_nsec if stat.duration_nsec > 0 else 1
                
                p_sec = stat.packet_count / dur_sec
                b_sec = stat.byte_count / dur_sec
                p_nsec = stat.packet_count / dur_nsec
                b_nsec = stat.byte_count / dur_nsec

                # Escribimos las 22 columnas para tu IA [2, 9]
                line = ("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                        .format(timestamp, dpid, "flow_id", ip_src, 0, ip_dst, 0,
                                ip_proto, -1, -1, stat.duration_sec, stat.duration_nsec,
                                stat.idle_timeout, stat.hard_timeout, stat.flags, 
                                stat.packet_count, stat.byte_count, p_sec, p_nsec, b_sec, b_nsec, 0))
                file0.write(line)

    # --- LÓGICA DE RED SPINE-LEAF --- [9]
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        datapath = event.msg.datapath
        ofproto = datapath.ofproto
        in_port = event.msg.match["in_port"]
        pkt = packet.Packet(event.msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype in self.ignore: return

        dst, src = eth.dst, eth.src
        
        # Aprendizaje de MAC seguro para evitar bucles [3, 10]
        if datapath.id in net.leaves and in_port > 2:
            self.update_mac_table(src, in_port, datapath.id)

        dst_host = self.mac_table.get(dst)
        ip_info = {"src": '0.0.0.0', "dst": '0.0.0.0', "proto": 0}
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4: 
            ip_info = {"src": pkt_ipv4.src, "dst": pkt_ipv4.dst, "proto": pkt_ipv4.proto}

        if dst_host:
            out_port = dst_host["port"]
            if dst_host["dpid"] == datapath.id:
                # Tráfico local [11]
                msgs = self.forward_packet(datapath, event.msg.data, in_port, out_port)
                msgs += self.create_match_entry(datapath, TABLE0, LOW_PRIORITY, src, dst, 
                                              in_port, out_port, IDLE_TIME, eth.ethertype, ip_info)
                self.send_messages(datapath, msgs)
            else:
                # Tráfico entre switches (Leaf-Spine-Leaf) [11, 12]
                spine_id = net.spines[(datapath.id + dst_host["dpid"]) % len(net.spines)]
                spine_dp, dst_dp = get_datapath(self, spine_id), get_datapath(self, dst_host["dpid"])
                if spine_dp is None or dst_dp is None: return

                u_port = net.links[datapath.id, spine_id]["port"]
                msgs = self.create_match_entry(datapath, TABLE0, LOW_PRIORITY, src, dst, in_port, u_port, IDLE_TIME, eth.ethertype, ip_info)
                self.send_messages(datapath, msgs)

                s_in, s_out = net.links[spine_id, datapath.id]["port"], net.links[spine_id, dst_host["dpid"]]["port"]
                msgs = self.create_match_entry(spine_dp, TABLE0, LOW_PRIORITY, src, dst, s_in, s_out, IDLE_TIME, eth.ethertype, ip_info)
                self.send_messages(spine_dp, msgs)

                msgs = self.forward_packet(dst_dp, event.msg.data, ofproto.OFPP_CONTROLLER, dst_host["port"])
                d_port = net.links[dst_host["dpid"], spine_id]["port"]
                msgs += self.create_match_entry(dst_dp, TABLE0, LOW_PRIORITY, src, dst, d_port, dst_host["port"], IDLE_TIME, eth.ethertype, ip_info)
                self.send_messages(dst_dp, msgs)
        else:
            # Flood controlado para evitar bucles infinitos [10]
            if datapath.id in net.leaves and in_port > 2:
                for leaf_id in net.leaves:
                    dpath = get_datapath(self, leaf_id)
                    msgs = self.forward_packet(dpath, event.msg.data, ofproto.OFPP_CONTROLLER, dpath.ofproto.OFPP_ALL)
                    self.send_messages(dpath, msgs)

    def create_match_entry(self, datapath, table, priority, src, dst, in_port, out_port, i_time, eth_type, ip_info):
        parser = datapath.ofproto_parser
        # Match con IPv4 para que el monitor pueda extraer los datos del CSV [4, 13]
        if eth_type == 0x0800:
            match = parser.OFPMatch(in_port=in_port, eth_type=eth_type, ipv4_src=ip_info["src"], 
                                  ipv4_dst=ip_info["dst"], ip_proto=ip_info["proto"], eth_src=src, eth_dst=dst)
        else:
            match = parser.OFPMatch(in_port=in_port, eth_type=eth_type, eth_src=src, eth_dst=dst)
        
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        return [self.add_flow(datapath, table, priority, match, inst, i_time=i_time)]

    def update_mac_table(self, src, port, dpid):
        self.mac_table[src] = {"port": port, "dpid": dpid}

config_file = os.environ.get("NETWORK_CONFIG_FILE", "scripts/network_config.yaml")
net = Network(config_file)