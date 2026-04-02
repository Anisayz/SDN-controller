
OF_VERSION        = 0x04   # OpenFlow 1.3
CONTROLLER_PORT   = 6633

 
MAC_TABLE_TIMEOUT    = 300   # seconds before a MAC entry expires
FLOOD_UNKNOWN        = True  # flood if destination MAC unknown

 
DEFAULT_FLOW_PRIORITY    = 1    # table-miss → send to controller
FORWARDING_FLOW_PRIORITY = 10   # learned forwarding rules
FLOW_IDLE_TIMEOUT        = 30   # seconds of inactivity → remove rule
FLOW_HARD_TIMEOUT        = 120  # max lifetime regardless of traffic

 
FIREWALL_BLOCK_PRIORITY       = 200
FIREWALL_METER_PRIORITY       = 150
FIREWALL_DEFAULT_IDLE_TIMEOUT = 60    # 1 minute default for firewall rules
FIREWALL_DEFAULT_HARD_TIMEOUT = 300   # 5 minutes max


REST_PORT = 8080
 
FIREWALL_API_KEY = "sdn-lab-secret-2025"
 
LLDP_INTERVAL = 5   # seconds between LLDP probes

 
STATS_INTERVAL = 10  # seconds between flow stat polls


LOGGING_CONFIG = "config/logging.yaml"