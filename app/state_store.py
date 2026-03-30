
import logging
import threading
from collections import defaultdict

logger = logging.getLogger("ryu_lab.state_store")


class StateStore:
  

    def __init__(self):
        self._lock = threading.Lock()

        # dpid (int) -> { mac_str -> port_no }
        self._mac_table = defaultdict(dict)

        # dpid (int) -> datapath object
        self._datapaths = {}

        # ip string -> dpid int  (used by firewall later)
        self._ip_to_dpid = {}

        # dpid -> { neighbor_dpid -> (local_port, remote_port) }
        self._topology = defaultdict(dict)

        logger.info("StateStore initialised")

    # ------------------------------------------------------------------ #
    #  Datapaths                                                           #
    # ------------------------------------------------------------------ #

    def add_datapath(self, datapath):
        with self._lock:
            self._datapaths[datapath.id] = datapath
            logger.info(
                "Switch registered | dpid=%016x | address=%s",
                datapath.id,
                datapath.address,
            )

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
            existing_port = self._mac_table[dpid].get(mac)
            self._mac_table[dpid][mac] = port

            if existing_port is None:
                logger.debug(
                    "MAC learned  | dpid=%016x | mac=%s | port=%s",
                    dpid, mac, port,
                )
                return True
            elif existing_port != port:
                logger.debug(
                    "MAC moved    | dpid=%016x | mac=%s | port %s→%s",
                    dpid, mac, existing_port, port,
                )
                return True
            return False

    def lookup_mac(self, dpid, mac):
      
        with self._lock:
            port = self._mac_table[dpid].get(mac)
            if port is not None:
                logger.debug(
                    "MAC hit      | dpid=%016x | mac=%s → port=%s",
                    dpid, mac, port,
                )
            else:
                logger.debug(
                    "MAC miss     | dpid=%016x | mac=%s → flood",
                    dpid, mac,
                )
            return port

    def get_mac_table(self, dpid=None):
        with self._lock:
            if dpid:
                return dict(self._mac_table.get(dpid, {}))
            return {k: dict(v) for k, v in self._mac_table.items()}

    # ------------------------------------------------------------------ #
    #  IP → datapath mapping (used by firewall later)                      #
    # ------------------------------------------------------------------ #

    def learn_ip(self, ip, dpid):
        with self._lock:
            self._ip_to_dpid[ip] = dpid
            logger.debug("IP learned   | ip=%s | dpid=%016x", ip, dpid)

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
                src_dpid = link.src.dpid
                dst_dpid = link.dst.dpid
                src_port = link.src.port_no
                dst_port = link.dst.port_no
                self._topology[src_dpid][dst_dpid] = (src_port, dst_port)

            logger.info(
                "Topology updated | %d switches | %d links",
                len(self._topology),
                len(links),
            )

    def get_topology(self):
        with self._lock:
            return {k: dict(v) for k, v in self._topology.items()}

    # ------------------------------------------------------------------ #
    #  Debug dump                                                          #
    # ------------------------------------------------------------------ #

    def dump(self):
      
        with self._lock:
            logger.info("=== STATE DUMP ===")
            logger.info("Switches online: %d", len(self._datapaths))
            for dpid in self._datapaths:
                logger.info("  dpid=%016x", dpid)

            logger.info("MAC table:")
            for dpid, table in self._mac_table.items():
                for mac, port in table.items():
                    logger.info("  dpid=%016x | %s → port %s", dpid, mac, port)

            logger.info("Topology:")
            for src, neighbors in self._topology.items():
                for dst, ports in neighbors.items():
                    logger.info(
                        "  %016x -[port %s]-> %016x -[port %s]->",
                        src, ports[0], dst, ports[1],
                    )
            logger.info("=== END DUMP ===")


# Single global instance — imported by all app modules
store = StateStore()