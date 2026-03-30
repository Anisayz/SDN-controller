
OF_VERSION        = 0x04        # OpenFlow 1.3
CONTROLLER_PORT   = 6633        # port OVS connects to

 
MAC_TABLE_TIMEOUT = 300         # seconds before a MAC entry expires
FLOOD_UNKNOWN     = True        # flood if destination MAC unknown

 
LLDP_INTERVAL     = 5           # seconds between LLDP probes
 
STATS_INTERVAL    = 10          # seconds between flow stat polls



DEFAULT_FLOW_PRIORITY   = 1     # table-miss (send to controller)
FORWARDING_FLOW_PRIORITY = 10   # learned forwarding rules
FLOW_IDLE_TIMEOUT       = 30    # seconds of inactivity before rule removed
FLOW_HARD_TIMEOUT       = 120   # max lifetime of a rule regardless



LOGGING_CONFIG = "config/logging.yaml"