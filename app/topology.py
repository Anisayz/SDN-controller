
import logging

from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event as topo_event
from ryu.topology.api import get_switch, get_link

from app.state_store import store

logger = logging.getLogger("ryu_lab.topology")


class TopologyDiscovery(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Tell Ryu this app depends on the built-in topology watcher.
    # Ryu will start that module automatically alongside this app.
    _CONTEXTS = {"switches": __import__(
        "ryu.topology.switches", fromlist=["Switches"]
    ).Switches}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        logger.info("TopologyDiscovery app started")

    # ------------------------------------------------------------------ #
    #  Switch events                                                       #
    # ------------------------------------------------------------------ #

    @set_ev_cls(topo_event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
      
        switch = ev.switch
        dpid = switch.dp.id
        ports = switch.ports

        logger.info(
            "Switch ENTER | dpid=%016x | ports=%d",
            dpid, len(ports),
        )
        for port in ports:
            logger.info(
                "  port_no=%-4d | hw_addr=%s | name=%s",
                port.port_no,
                port.hw_addr,
                port.name.decode() if isinstance(port.name, bytes) else port.name,
            )

        self._refresh_topology()

    @set_ev_cls(topo_event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        dpid = ev.switch.dp.id
        logger.warning("Switch LEAVE | dpid=%016x", dpid)
        self._refresh_topology()

    # ------------------------------------------------------------------ #
    #  Link events                                                         #
    # ------------------------------------------------------------------ #

    @set_ev_cls(topo_event.EventLinkAdd)
    def link_add_handler(self, ev):
        """
        LLDP confirmed a new link between two switches.
        This is how Ryu builds the topology graph.
        """
        link = ev.link
        logger.info(
            "Link ADD  | dpid=%016x port=%-4d  <-->  dpid=%016x port=%-4d",
            link.src.dpid, link.src.port_no,
            link.dst.dpid, link.dst.port_no,
        )
        self._refresh_topology()

    @set_ev_cls(topo_event.EventLinkDelete)
    def link_delete_handler(self, ev):
        link = ev.link
        logger.warning(
            "Link DEL  | dpid=%016x port=%-4d  <-->  dpid=%016x port=%-4d",
            link.src.dpid, link.src.port_no,
            link.dst.dpid, link.dst.port_no,
        )
        self._refresh_topology()

    # ------------------------------------------------------------------ #
    #  Port events                                                         #
    # ------------------------------------------------------------------ #

    @set_ev_cls(topo_event.EventPortAdd)
    def port_add_handler(self, ev):
        port = ev.port
        logger.info(
            "Port ADD  | dpid=%016x | port_no=%d | hw_addr=%s",
            port.dpid, port.port_no, port.hw_addr,
        )

    @set_ev_cls(topo_event.EventPortDelete)
    def port_delete_handler(self, ev):
        port = ev.port
        logger.warning(
            "Port DEL  | dpid=%016x | port_no=%d",
            port.dpid, port.port_no,
        )

    @set_ev_cls(topo_event.EventPortModify)
    def port_modify_handler(self, ev):
        port = ev.port
        logger.info(
            "Port MOD  | dpid=%016x | port_no=%d | hw_addr=%s",
            port.dpid, port.port_no, port.hw_addr,
        )

    # ------------------------------------------------------------------ #
    #  Internal                                                            #
    # ------------------------------------------------------------------ #

    def _refresh_topology(self):
       
        links = get_link(self, None)   # None = all switches
        store.update_topology(links)

        # print a human-readable map to the log
        self._log_topology_map(links)

    def _log_topology_map(self, links):
       
        if not links:
            logger.info("Topology map: (no inter-switch links yet)")
            return

        logger.info("Topology map (%d links):", len(links))
        seen = set()
        for link in links:
            key = tuple(sorted([
                (link.src.dpid, link.src.port_no),
                (link.dst.dpid, link.dst.port_no),
            ]))
            if key in seen:
                continue
            seen.add(key)
            logger.info(
                "  [%016x] --(port %d)--> [%016x] --(port %d)-->",
                link.src.dpid, link.src.port_no,
                link.dst.dpid, link.dst.port_no,
            )