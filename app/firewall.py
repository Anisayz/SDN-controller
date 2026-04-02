 
import logging
import time
import uuid
from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3

from app.state_store import store
from config.config import (
    FIREWALL_BLOCK_PRIORITY,
    FIREWALL_METER_PRIORITY,
    FIREWALL_DEFAULT_IDLE_TIMEOUT,
    FIREWALL_DEFAULT_HARD_TIMEOUT,
)

logger = logging.getLogger("ryu_lab.firewall")


class FirewallApp(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # meter ID counter — one per rate-limited IP
        self._next_meter_id = 1
        # rule_id → cookie (int) so we can delete by cookie
        self._rule_cookies: dict[str, int] = {}
        # cookie counter
        self._next_cookie = 1
        logger.info("FirewallApp started")

    # ------------------------------------------------------------------ #
    #  FlowRemoved — rule expired naturally on OVS                        #
    # ------------------------------------------------------------------ #

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
    
        msg = ev.msg
        cookie = msg.cookie
        # find which rule_id maps to this cookie
        rule_id = self._cookie_to_rule_id(cookie)
        if rule_id:
            store.mark_rule_inactive(rule_id)
            logger.info(
                "Firewall flow expired | rule_id=%s | cookie=%d | "
                "dpid=%016x | packets=%d | bytes=%d",
                rule_id, cookie, msg.datapath.id,
                msg.packet_count, msg.byte_count,
            )

    # ------------------------------------------------------------------ #
    #  Public API — called by ofctl_rest.py                               #
    # ------------------------------------------------------------------ #

    def block_ip(
        self,
        src_ip: str,
        dpid: int = None,
        idle_timeout: int = None,
        hard_timeout: int = None,
        source: str = "mitigation_engine",
    ) -> dict:
    
        idle_timeout = idle_timeout or FIREWALL_DEFAULT_IDLE_TIMEOUT
        hard_timeout = hard_timeout or FIREWALL_DEFAULT_HARD_TIMEOUT

        datapaths = self._resolve_datapaths(src_ip, dpid)
        if not datapaths:
            raise ValueError(f"No switch found for ip={src_ip}")

        rule_id = str(uuid.uuid4())
        cookie  = self._alloc_cookie(rule_id)

        for datapath in datapaths:
            parser   = datapath.ofproto_parser
            match    = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            actions  = []   # empty = DROP
            self._install_flow(
                datapath, table_id=0,
                priority=FIREWALL_BLOCK_PRIORITY,
                match=match, actions=actions,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
                cookie=cookie,
            )
            logger.warning(
                "BLOCK installed | rule_id=%s | src_ip=%s | dpid=%016x | "
                "idle=%ds | hard=%ds",
                rule_id, src_ip, datapath.id, idle_timeout, hard_timeout,
            )

        rule = {
            "rule_id":      rule_id,
            "action":       "block",
            "src_ip":       src_ip,
            "dst_ip":       None,
            "dpid":         datapaths[0].id,
            "priority":     FIREWALL_BLOCK_PRIORITY,
            "meter_id":     None,
            "rate_kbps":    None,
            "installed_at": time.time(),
            "idle_timeout": idle_timeout,
            "hard_timeout": hard_timeout,
            "source":       source,
            "active":       True,
            "cookie":       cookie,
        }
        store.add_firewall_rule(rule)
        return rule

    def ratelimit_ip(
        self,
        src_ip: str,
        rate_kbps: int,
        dpid: int = None,
        idle_timeout: int = None,
        hard_timeout: int = None,
        source: str = "mitigation_engine",
    ) -> dict:
       
        idle_timeout = idle_timeout or FIREWALL_DEFAULT_IDLE_TIMEOUT
        hard_timeout = hard_timeout or FIREWALL_DEFAULT_HARD_TIMEOUT

        datapaths = self._resolve_datapaths(src_ip, dpid)
        if not datapaths:
            raise ValueError(f"No switch found for ip={src_ip}")

        rule_id  = str(uuid.uuid4())
        cookie   = self._alloc_cookie(rule_id)
        meter_id = self._alloc_meter_id()

        for datapath in datapaths:
            ofproto = datapath.ofproto
            parser  = datapath.ofproto_parser

            # Step 1: create the meter
            bands = [
                parser.OFPMeterBandDrop(rate=rate_kbps, burst_size=10)
            ]
            meter_mod = parser.OFPMeterMod(
                datapath=datapath,
                command=ofproto.OFPMC_ADD,
                flags=ofproto.OFPMF_KBPS,
                meter_id=meter_id,
                bands=bands,
            )
            datapath.send_msg(meter_mod)
            logger.info(
                "MeterMod added | meter_id=%d | rate=%d kbps | dpid=%016x",
                meter_id, rate_kbps, datapath.id,
            )

            # Step 2: flow rule → apply meter, then forward normally
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            inst  = [
                parser.OFPInstructionMeter(meter_id),
                parser.OFPInstructionGotoTable(1),  # continue to L2 forwarding
            ]
            mod = parser.OFPFlowMod(
                datapath=datapath,
                table_id=0,
                priority=FIREWALL_METER_PRIORITY,
                match=match,
                instructions=inst,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
                cookie=cookie,
                flags=ofproto.OFPFF_SEND_FLOW_REM,
            )
            datapath.send_msg(mod)
            logger.warning(
                "RATELIMIT installed | rule_id=%s | src_ip=%s | rate=%d kbps | "
                "dpid=%016x | meter_id=%d",
                rule_id, src_ip, rate_kbps, datapath.id, meter_id,
            )

        rule = {
            "rule_id":      rule_id,
            "action":       "ratelimit",
            "src_ip":       src_ip,
            "dst_ip":       None,
            "dpid":         datapaths[0].id,
            "priority":     FIREWALL_METER_PRIORITY,
            "meter_id":     meter_id,
            "rate_kbps":    rate_kbps,
            "installed_at": time.time(),
            "idle_timeout": idle_timeout,
            "hard_timeout": hard_timeout,
            "source":       source,
            "active":       True,
            "cookie":       cookie,
        }
        store.add_firewall_rule(rule)
        return rule

    def isolate_host(
        self,
        host_ip: str,
        dpid: int = None,
        idle_timeout: int = None,
        hard_timeout: int = None,
        source: str = "mitigation_engine",
    ) -> dict:
        
        idle_timeout = idle_timeout or FIREWALL_DEFAULT_IDLE_TIMEOUT
        hard_timeout = hard_timeout or FIREWALL_DEFAULT_HARD_TIMEOUT

        datapaths = self._resolve_datapaths(host_ip, dpid)
        if not datapaths:
            raise ValueError(f"No switch found for ip={host_ip}")

        rule_id = str(uuid.uuid4())
        cookie  = self._alloc_cookie(rule_id)

        for datapath in datapaths:
            parser = datapath.ofproto_parser

            for direction, field in [("OUT", "ipv4_src"), ("IN", "ipv4_dst")]:
                match = parser.OFPMatch(eth_type=0x0800, **{field: host_ip})
                self._install_flow(
                    datapath, table_id=0,
                    priority=FIREWALL_BLOCK_PRIORITY,
                    match=match, actions=[],
                    idle_timeout=idle_timeout,
                    hard_timeout=hard_timeout,
                    cookie=cookie,
                )
            logger.warning(
                "ISOLATE installed | rule_id=%s | host_ip=%s | dpid=%016x",
                rule_id, host_ip, datapath.id,
            )

        rule = {
            "rule_id":      rule_id,
            "action":       "isolate",
            "src_ip":       host_ip,
            "dst_ip":       host_ip,
            "dpid":         datapaths[0].id,
            "priority":     FIREWALL_BLOCK_PRIORITY,
            "meter_id":     None,
            "rate_kbps":    None,
            "installed_at": time.time(),
            "idle_timeout": idle_timeout,
            "hard_timeout": hard_timeout,
            "source":       source,
            "active":       True,
            "cookie":       cookie,
        }
        store.add_firewall_rule(rule)
        return rule

    def delete_rule(self, rule_id: str) -> bool:
       
        rule = store.get_firewall_rule(rule_id)
        if not rule:
            logger.warning("delete_rule: rule_id=%s not found", rule_id)
            return False

        datapath = store.get_datapath(rule["dpid"])
        if not datapath:
            logger.warning(
                "delete_rule: switch dpid=%016x not connected, "
                "removing from store anyway", rule["dpid"]
            )
            store.remove_firewall_rule(rule_id)
            return True

        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        cookie  = rule.get("cookie", 0)

        # Delete all flows with this cookie on this switch
        match = parser.OFPMatch()
        mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=cookie,
            cookie_mask=0xFFFFFFFFFFFFFFFF,
            table_id=ofproto.OFPTT_ALL,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match,
        )
        datapath.send_msg(mod)
        logger.info(
            "OFPFlowMod DELETE sent | rule_id=%s | cookie=%d | dpid=%016x",
            rule_id, cookie, datapath.id,
        )

        # If ratelimit, also delete the meter
        if rule.get("meter_id"):
            meter_mod = parser.OFPMeterMod(
                datapath=datapath,
                command=ofproto.OFPMC_DELETE,
                flags=0,
                meter_id=rule["meter_id"],
            )
            datapath.send_msg(meter_mod)
            logger.info(
                "MeterMod DELETE sent | meter_id=%d | dpid=%016x",
                rule["meter_id"], datapath.id,
            )

        store.remove_firewall_rule(rule_id)
        return True

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
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

    def _resolve_datapaths(self, ip: str, dpid: int = None):
       
        if dpid:
            dp = store.get_datapath(dpid)
            return [dp] if dp else []

        dp = store.get_datapath_for_ip(ip)
        if dp:
            return [dp]

        # IP not seen yet — install on all switches
        logger.warning(
            "IP %s not seen in state_store — installing rule on ALL switches", ip
        )
        return store.get_all_datapaths()

    def _alloc_cookie(self, rule_id: str) -> int:
        cookie = self._next_cookie
        self._next_cookie += 1
        self._rule_cookies[cookie] = rule_id
        return cookie

    def _alloc_meter_id(self) -> int:
        mid = self._next_meter_id
        self._next_meter_id += 1
        return mid

    def _cookie_to_rule_id(self, cookie: int):
        return self._rule_cookies.get(cookie)


# Global singleton — ofctl_rest.py imports this
firewall_app: FirewallApp = None


def get_firewall_app() -> FirewallApp:
    return firewall_app


def set_firewall_app(app: FirewallApp):
    global firewall_app
    firewall_app = app
