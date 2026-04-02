
import logging
import logging.config
import yaml

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    DEAD_DISPATCHER,
    set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp

from app.state_store import store
from config.config import (
    FORWARDING_FLOW_PRIORITY,
    DEFAULT_FLOW_PRIORITY,
    FLOW_IDLE_TIMEOUT,
    FLOW_HARD_TIMEOUT,
    LOGGING_CONFIG,
)

# ── logging setup ─────────────────────────────────────────────────────────────
with open(LOGGING_CONFIG) as f:
    logging.config.dictConfig(yaml.safe_load(f))

logger = logging.getLogger("ryu_lab.l2_switch")


class L2Switch(app_manager.RyuApp):
 
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        logger.info("L2Switch app started")

    # ------------------------------------------------------------------ #
    #  Switch connects                                                     #
    # ------------------------------------------------------------------ #

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
       
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        store.add_datapath(datapath)

        logger.info(
            "Switch connected | dpid=%016x | OF=0x%02x | n_tables=%d",
            datapath.id,
            datapath.ofproto.OFP_VERSION,
            ev.msg.n_tables,
        )

        # ── Rule 1: Table 0 default → GOTO Table 1 ───────────────────
        # Priority 0 = only matches if no higher-priority firewall rule did.
        # This is what makes normal traffic reach the L2 forwarding table.
        match0 = parser.OFPMatch()
        inst0  = [parser.OFPInstructionGotoTable(1)]
        mod0   = parser.OFPFlowMod(
            datapath=datapath,
            table_id=0,
            priority=0,
            match=match0,
            instructions=inst0,
            idle_timeout=0,   # never expire
            hard_timeout=0,
        )
        datapath.send_msg(mod0)
        logger.info(
            "Table 0 default rule installed | GOTO Table 1 | dpid=%016x",
            datapath.id,
        )

        # ── Rule 2: Table 1 table-miss → send to controller ──────────
        match1  = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER,  # send full packet, don't buffer
            )
        ]
        self._install_flow(
            datapath,
            table_id=1,
            priority=DEFAULT_FLOW_PRIORITY,
            match=match1,
            actions=actions,
            idle_timeout=0,
            hard_timeout=0,
        )
        logger.info(
            "Table 1 table-miss installed | → controller | dpid=%016x",
            datapath.id,
        )

    # ------------------------------------------------------------------ #
    #  Switch disconnects                                                  #
    # ------------------------------------------------------------------ #

    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def switch_dead_handler(self, ev):
     
        if ev.datapath:
            store.remove_datapath(ev.datapath.id)

    # ------------------------------------------------------------------ #
    #  Packet in                                                           #
    # ------------------------------------------------------------------ #

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
   
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match["in_port"]
        dpid     = datapath.id

        # ── parse Ethernet frame ──────────────────────────────────────
        pkt      = packet.Packet(msg.data)
        eth      = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return   # not Ethernet — ignore

        dst_mac  = eth.dst
        src_mac  = eth.src
        eth_type = eth.ethertype

        # LLDP is handled by topology.py — skip it here
        if eth_type == ether_types.ETH_TYPE_LLDP:
            return

        logger.debug(
            "PacketIn | dpid=%016x | port=%-3s | %s → %s | type=0x%04x",
            dpid, in_port, src_mac, dst_mac, eth_type,
        )

        # ── learn src MAC ─────────────────────────────────────────────
        store.learn_mac(dpid, src_mac, in_port)

        # ── learn src IP (populates ip→datapath for firewall) ─────────
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            store.learn_ip(ip_pkt.src, dpid)

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            store.learn_ip(arp_pkt.src_ip, dpid)

        # ── look up dst MAC ───────────────────────────────────────────
        out_port = store.lookup_mac(dpid, dst_mac)

        if out_port is None:
            # Unknown destination → flood
            out_port = ofproto.OFPP_FLOOD
            logger.debug(
                "Flooding | dpid=%016x | dst=%s → FLOOD", dpid, dst_mac,
            )
        else:
            # Known destination → install a flow rule in TABLE 1
            # Future packets with this dst MAC bypass the controller entirely.
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self._install_flow(
                datapath,
                table_id=1,
                priority=FORWARDING_FLOW_PRIORITY,
                match=match,
                actions=actions,
                idle_timeout=FLOW_IDLE_TIMEOUT,
                hard_timeout=FLOW_HARD_TIMEOUT,
            )
            logger.info(
                "Flow installed | dpid=%016x | dst=%s → port %s | "
                "table=1 | idle=%ds | hard=%ds",
                dpid, dst_mac, out_port, FLOW_IDLE_TIMEOUT, FLOW_HARD_TIMEOUT,
            )

        # ── forward this packet manually ──────────────────────────────
        # The new flow rule covers future packets.
        # This packet arrived before the rule existed — forward it now.
        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    # ------------------------------------------------------------------ #
    #  Flow removed notification                                           #
    # ------------------------------------------------------------------ #

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
      
        msg = ev.msg
        logger.debug(
            "Flow removed | dpid=%016x | table=%d | reason=%s | "
            "match=%s | packets=%d | bytes=%d",
            msg.datapath.id,
            msg.table_id,
            self._removed_reason(msg.reason),
            msg.match,
            msg.packet_count,
            msg.byte_count,
        )

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _install_flow(
        self, datapath, table_id, priority, match, actions,
        idle_timeout=0, hard_timeout=0, cookie=0,
    ):
  
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        inst = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            table_id=table_id,
            cookie=cookie,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            flags=ofproto.OFPFF_SEND_FLOW_REM,
        )
        datapath.send_msg(mod)

    def _removed_reason(self, reason):
        reasons = {
            ofproto_v1_3.OFPRR_IDLE_TIMEOUT: "idle_timeout",
            ofproto_v1_3.OFPRR_HARD_TIMEOUT: "hard_timeout",
            ofproto_v1_3.OFPRR_DELETE:        "delete",
            ofproto_v1_3.OFPRR_GROUP_DELETE:  "group_delete",
        }
        return reasons.get(reason, f"unknown({reason})")