
import logging
import threading
from collections import defaultdict

logger = logging.getLogger("ryu_lab.state_store")


class StateStore:

    def __init__(self):
        self._lock = threading.Lock()
        self._mac_table    = defaultdict(dict)
        self._datapaths    = {}
        self._ip_to_dpid   = {}
        self._topology     = defaultdict(dict)
        self._firewall_rules = {}
        logger.info("StateStore initialised")

    # ------------------------------------------------------------------ #
    #  Datapaths                                                           #
    # ------------------------------------------------------------------ #

    def add_datapath(self, datapath):
        with self._lock:
            self._datapaths[datapath.id] = datapath
            logger.info("Switch registered | dpid=%016x | address=%s",
                        datapath.id, datapath.address)

    def remove_datapath(self, dpid):
        with self._lock:
            if dpid in self._datapaths:
                del self._datapaths[dpid]
                logger.info("Switch removed | dpid=%016x", dpid)

    def get_datapath(self, dpid):
        with self._lock:
            return self._datapaths.get(dpid)

    def get_all_datapaths(self):
        with self._lock:
            return list(self._datapaths.values())

    # ------------------------------------------------------------------ #
    #  MAC table                                                           #
    # ------------------------------------------------------------------ #

    def learn_mac(self, dpid, mac, port):
        with self._lock:
            existing = self._mac_table[dpid].get(mac)
            self._mac_table[dpid][mac] = port
            if existing is None:
                logger.debug("MAC learned | dpid=%016x | mac=%s | port=%s", dpid, mac, port)
                return True
            elif existing != port:
                logger.debug("MAC moved   | dpid=%016x | mac=%s | port %s→%s", dpid, mac, existing, port)
                return True
            return False

    def lookup_mac(self, dpid, mac):
        with self._lock:
            port = self._mac_table[dpid].get(mac)
            if port is not None:
                logger.debug("MAC hit  | dpid=%016x | mac=%s → port=%s", dpid, mac, port)
            else:
                logger.debug("MAC miss | dpid=%016x | mac=%s → flood", dpid, mac)
            return port

    def get_mac_table(self, dpid=None):
        with self._lock:
            if dpid:
                return dict(self._mac_table.get(dpid, {}))
            return {k: dict(v) for k, v in self._mac_table.items()}

    # ------------------------------------------------------------------ #
    #  IP → datapath                                                       #
    # ------------------------------------------------------------------ #

    def learn_ip(self, ip, dpid):
        with self._lock:
            self._ip_to_dpid[ip] = dpid
            logger.debug("IP learned | ip=%s | dpid=%016x", ip, dpid)

    def get_datapath_for_ip(self, ip):
        with self._lock:
            dpid = self._ip_to_dpid.get(ip)
            if dpid:
                return self._datapaths.get(dpid)
            logger.warning("No datapath found for ip=%s", ip)
            return None

    # ------------------------------------------------------------------ #
    #  Topology                                                            #
    # ------------------------------------------------------------------ #

    def update_topology(self, links):
        with self._lock:
            self._topology.clear()
            for link in links:
                self._topology[link.src.dpid][link.dst.dpid] = (
                    link.src.port_no, link.dst.port_no
                )
            logger.info("Topology updated | %d links", len(links))

    def get_topology(self):
        with self._lock:
            return {k: dict(v) for k, v in self._topology.items()}

    # ------------------------------------------------------------------ #
    #  Firewall rule store                                                 #
    # ------------------------------------------------------------------ #
  
    # Rule dict:
    # {
    #   "rule_id":      str (uuid4),
    #   "action":       "block" | "ratelimit" | "isolate",
    #   "src_ip":       str,
    #   "dst_ip":       str | None,
    #   "dpid":         int,
    #   "priority":     int,
    #   "meter_id":     int | None,
    #   "rate_kbps":    int | None,
    #   "installed_at": float (unix timestamp),
    #   "idle_timeout": int,
    #   "hard_timeout": int,
    #   "source":       "mitigation_engine" | "manual",
    #   "active":       bool,
    # }

    def add_firewall_rule(self, rule: dict):
        with self._lock:
            rid = rule["rule_id"]
            self._firewall_rules[rid] = rule
            logger.info(
                "Rule ADDED   | id=%s | action=%-10s | ip=%-15s | dpid=%016x | src=%s",
                rid, rule["action"], rule.get("src_ip", "N/A"),
                rule["dpid"], rule.get("source", "?"),
            )

    def get_firewall_rules(self):
        """All rules — active and expired — for the dashboard history view."""
        with self._lock:
            return list(self._firewall_rules.values())

    def get_active_firewall_rules(self):
        """Only currently enforced rules."""
        with self._lock:
            return [r for r in self._firewall_rules.values() if r.get("active")]

    def get_firewall_rule(self, rule_id):
        with self._lock:
            return self._firewall_rules.get(rule_id)

    def mark_rule_inactive(self, rule_id):
       
        with self._lock:
            if rule_id in self._firewall_rules:
                self._firewall_rules[rule_id]["active"] = False
                logger.info("Rule EXPIRED | id=%s", rule_id)
                return True
            return False

    def remove_firewall_rule(self, rule_id):
      
        with self._lock:
            if rule_id in self._firewall_rules:
                rule = self._firewall_rules.pop(rule_id)
                logger.info(
                    "Rule DELETED | id=%s | action=%s | ip=%s",
                    rule_id, rule["action"], rule.get("src_ip", "N/A"),
                )
                return True
            return False

    def get_rules_for_dpid(self, dpid):
        with self._lock:
            return [
                r for r in self._firewall_rules.values()
                if r.get("dpid") == dpid and r.get("active")
            ]

    # ------------------------------------------------------------------ #
    #  Debug dump                                                          #
    # ------------------------------------------------------------------ #

    def dump(self):
        with self._lock:
            logger.info("=== STATE DUMP ===")
            logger.info("Switches: %d", len(self._datapaths))
            for dpid in self._datapaths:
                logger.info("  dpid=%016x", dpid)
            logger.info("MAC table:")
            for dpid, table in self._mac_table.items():
                for mac, port in table.items():
                    logger.info("  dpid=%016x | %s → port %s", dpid, mac, port)
            logger.info("Firewall rules (%d):", len(self._firewall_rules))
            for rid, r in self._firewall_rules.items():
                logger.info("  id=%s | action=%-10s | ip=%-15s | active=%s",
                            rid, r["action"], r.get("src_ip", "N/A"), r["active"])
            logger.info("=== END DUMP ===")


# Single global instance — imported by all app modules
store = StateStore()