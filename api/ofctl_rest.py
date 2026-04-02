 
import json
import logging
import time

from ryu.app.wsgi import (
    ControllerBase,
    WSGIApplication,
    route,
    Response,
)
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3

from app.state_store import store
from app.firewall import FirewallApp, set_firewall_app
from config.config import FIREWALL_API_KEY

logger = logging.getLogger("ryu_lab.rest")

# name used to share the FirewallApp instance with the REST controller
FIREWALL_APP_KEY = "firewall_app"


class RestAPI(app_manager.RyuApp):
 

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        wsgi = kwargs["wsgi"]

        # We need to pass the FirewallApp instance to the REST controller
        # because REST controllers are plain classes (not Ryu apps) and
        # can't access other apps directly.
        # We do this via the wsgi.register() data dict.

        # NOTE: FirewallApp must be instantiated before RestAPI.
        # main.py imports FirewallApp first, so app_manager starts it first.
        # We retrieve it here via set_firewall_app / get_firewall_app.
        wsgi.register(
            FirewallRestController,
            {FIREWALL_APP_KEY: self},   # passed as kwargs to controller __init__
        )
        logger.info("REST API registered | port=8080")


class FirewallRestController(ControllerBase):
 

    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        # data dict injected by wsgi.register()
        self._ryu_app = data[FIREWALL_APP_KEY]

    # ------------------------------------------------------------------ #
    #  Auth helper                                                         #
    # ------------------------------------------------------------------ #

    def _check_auth(self, req) -> bool:
        """Validate X-API-Key header."""
        if not FIREWALL_API_KEY:
            return True   # no key configured → open access (lab only)
        return req.headers.get("X-API-Key") == FIREWALL_API_KEY

    def _unauthorized(self):
        return Response(
            status=401,
            content_type="application/json",
            body=json.dumps({"error": "unauthorized"}),
        )

    def _ok(self, data):
        return Response(
            content_type="application/json",
            body=json.dumps(data, default=str),
        )

    def _bad(self, msg, status=400):
        return Response(
            status=status,
            content_type="application/json",
            body=json.dumps({"error": msg}),
        )

    # ------------------------------------------------------------------ #
    #  Firewall rules — Mitigation Engine endpoints                        #
    # ------------------------------------------------------------------ #

    @route("firewall", "/firewall/rules", methods=["POST"])
    def create_rule(self, req, **kwargs):
        """
        Install a new firewall rule.

        Called by the Mitigation Engine when it decides to act on an alert.

        Request body (JSON):
        {
            "action":       "block" | "ratelimit" | "isolate",
            "src_ip":       "10.0.0.5",
            "rate_kbps":    1000,          // required for ratelimit only
            "dpid":         1,             // optional — omit to auto-detect
            "idle_timeout": 60,            // optional
            "hard_timeout": 300,           // optional
            "source":       "mitigation_engine"
        }

        Response (201):
        {
            "rule_id": "550e8400-...",
            "action":  "block",
            "src_ip":  "10.0.0.5",
            ...
        }
        """
        if not self._check_auth(req):
            return self._unauthorized()

        try:
            body = json.loads(req.body)
        except Exception:
            return self._bad("invalid JSON body")

        action  = body.get("action")
        src_ip  = body.get("src_ip")
        source  = body.get("source", "mitigation_engine")
        dpid    = body.get("dpid")
        idle    = body.get("idle_timeout")
        hard    = body.get("hard_timeout")

        if action not in ("block", "ratelimit", "isolate"):
            return self._bad("action must be block | ratelimit | isolate")
        if not src_ip:
            return self._bad("src_ip is required")

        # retrieve the FirewallApp singleton
        fw = _get_fw()
        if fw is None:
            return self._bad("FirewallApp not ready", status=503)

        try:
            if action == "block":
                rule = fw.block_ip(src_ip, dpid=dpid,
                                   idle_timeout=idle, hard_timeout=hard,
                                   source=source)

            elif action == "ratelimit":
                rate = body.get("rate_kbps")
                if not rate:
                    return self._bad("rate_kbps is required for ratelimit")
                rule = fw.ratelimit_ip(src_ip, int(rate), dpid=dpid,
                                       idle_timeout=idle, hard_timeout=hard,
                                       source=source)

            elif action == "isolate":
                rule = fw.isolate_host(src_ip, dpid=dpid,
                                       idle_timeout=idle, hard_timeout=hard,
                                       source=source)

        except ValueError as e:
            return self._bad(str(e), status=404)
        except Exception as e:
            logger.exception("Error installing rule")
            return self._bad(f"internal error: {e}", status=500)

        logger.info(
            "REST POST /firewall/rules | action=%s | src_ip=%s | rule_id=%s",
            action, src_ip, rule["rule_id"],
        )
        return Response(
            status=201,
            content_type="application/json",
            body=json.dumps(rule, default=str),
        )

    # ------------------------------------------------------------------ #
    #  Firewall rules — Dashboard endpoints                                #
    # ------------------------------------------------------------------ #

    @route("firewall", "/firewall/rules", methods=["GET"])
    def list_rules(self, req, **kwargs):
   
        if not self._check_auth(req):
            return self._unauthorized()

        active_only = req.GET.get("active", "").lower() == "true"

        if active_only:
            rules = store.get_active_firewall_rules()
        else:
            rules = store.get_firewall_rules()

        logger.debug("REST GET /firewall/rules | count=%d | active_only=%s",
                     len(rules), active_only)
        return self._ok({"count": len(rules), "rules": rules})

    @route("firewall", "/firewall/rules/{rule_id}", methods=["GET"])
    def get_rule(self, req, **kwargs):
    
        if not self._check_auth(req):
            return self._unauthorized()

        rule_id = kwargs.get("rule_id")
        rule    = store.get_firewall_rule(rule_id)

        if not rule:
            return self._bad(f"rule {rule_id} not found", status=404)

        return self._ok(rule)

    @route("firewall", "/firewall/rules/{rule_id}", methods=["DELETE"])
    def delete_rule(self, req, **kwargs):
   
        if not self._check_auth(req):
            return self._unauthorized()

        rule_id = kwargs.get("rule_id")

        fw = _get_fw()
        if fw is None:
            return self._bad("FirewallApp not ready", status=503)

        success = fw.delete_rule(rule_id)

        if not success:
            return self._bad(f"rule {rule_id} not found", status=404)

        logger.info("REST DELETE /firewall/rules/%s | success=True", rule_id)
        return self._ok({"deleted": True, "rule_id": rule_id})

    # ------------------------------------------------------------------ #
    #  Topology — Dashboard                                                #
    # ------------------------------------------------------------------ #

    @route("topology", "/topology", methods=["GET"])
    def get_topology(self, req, **kwargs):
      
        if not self._check_auth(req):
            return self._unauthorized()

        topo = store.get_topology()

        switches = []
        for dp in store.get_all_datapaths():
            switches.append({
                "dpid":    format(dp.id, "016x"),
                "address": str(dp.address),
            })

        links = []
        for src_dpid, neighbors in topo.items():
            for dst_dpid, (src_port, dst_port) in neighbors.items():
                links.append({
                    "src_dpid": format(src_dpid, "016x"),
                    "src_port": src_port,
                    "dst_dpid": format(dst_dpid, "016x"),
                    "dst_port": dst_port,
                })

        return self._ok({"switches": switches, "links": links})

    # ------------------------------------------------------------------ #
    #  Switches & MAC table — Dashboard                                    #
    # ------------------------------------------------------------------ #

    @route("switches", "/switches", methods=["GET"])
    def get_switches(self, req, **kwargs):
        """List all connected switches and their active firewall rules."""
        if not self._check_auth(req):
            return self._unauthorized()

        result = []
        for dp in store.get_all_datapaths():
            dpid = dp.id
            rules = store.get_rules_for_dpid(dpid)
            result.append({
                "dpid":         format(dpid, "016x"),
                "address":      str(dp.address),
                "active_rules": len(rules),
            })
        return self._ok({"switches": result})

    @route("mactable", "/mactable", methods=["GET"])
    def get_mac_table(self, req, **kwargs):
     
        if not self._check_auth(req):
            return self._unauthorized()

        raw   = store.get_mac_table()
        table = []
        for dpid_int, entries in raw.items():
            for mac, port in entries.items():
                table.append({
                    "dpid": format(dpid_int, "016x"),
                    "mac":  mac,
                    "port": port,
                })
        return self._ok({"count": len(table), "entries": table})

    # ------------------------------------------------------------------ #
    #  Debug                                                               #
    # ------------------------------------------------------------------ #

    @route("dump", "/dump", methods=["GET"])
    def dump_state(self, req, **kwargs):
        """Trigger a full state dump to the log file. Useful in the lab."""
        if not self._check_auth(req):
            return self._unauthorized()
        store.dump()
        return self._ok({"message": "state dumped to log"})

    @route("health", "/health", methods=["GET"])
    def health(self, req, **kwargs):
        """Health check — no auth required. Used by Docker healthcheck."""
        return self._ok({
            "status":   "ok",
            "switches": len(store.get_all_datapaths()),
            "rules":    len(store.get_active_firewall_rules()),
            "time":     time.time(),
        })


# ------------------------------------------------------------------ #
#  Helper to get the FirewallApp singleton                            #
# ------------------------------------------------------------------ #

def _get_fw() -> FirewallApp:
    """
    Retrieve the global FirewallApp singleton.
    We use Ryu's app_manager to look it up by name.
    """
    from ryu.base.app_manager import lookup_service_brick
    return lookup_service_brick("FirewallApp")
