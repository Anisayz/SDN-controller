# SDN-controller

> **FlowGuard** — Ryu-based SDN controller with integrated firewall and topology discovery for cloud network security.

Part of the [FlowGuard](https://github.com/FlowGuard-platform) intelligent network security platform built on Software Defined Networking (SDN). This module acts as the **brain of the data plane**: it programs Open vSwitch via OpenFlow 1.3, enforces security rules delivered by the mitigation engine, and exposes a REST API consumed by the dashboard.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Controller](#running-the-controller)
- [REST API Reference](#rest-api-reference)
- [OpenFlow Pipeline](#openflow-pipeline)
- [Testing](#testing)
- [CI/CD & Security](#cicd--security)
 

---

## Overview

The SDN controller is a **Ryu** application written in Python 3.11. It loads three cooperating apps in the same process:

| App | Role |
|---|---|
| `L2Switch` | Learns MAC→port mappings and installs unicast forwarding rules in table 1 |
| `FirewallApp` | Exposes `block_ip`, `ratelimit_ip`, `isolate_ip` primitives; installs rules in table 0 at higher priority |
| `Topology` | Maintains a live view of connected switches, inter-switch links, and hosts; serves it to the dashboard |

A shared `state_store` singleton keeps all three apps in sync without message passing overhead.

---

## Architecture

```
         ┌─────────────────────────────────┐
         │          FlowGuard Platform      │
         │                                 │
         │  ML Module  ──►  Mitigating      │
         │                   Engine  ──────►│
         │                                 │
         │         SDN Controller (Ryu)    │  ◄─── Dashboard
         │         REST :8080              │
         └──────────────┬──────────────────┘
                        │ OpenFlow 1.3 (:6653)
                        ▼
               ┌─────────────────┐
               │  Open vSwitch   │
               │      br0        │
               └────────┬────────┘
                  veth   │  veth
              ┌──────────┴──────────┐
         Container A            Container B
         10.0.0.2               10.0.0.3
```

**Two-table OpenFlow pipeline:**

- **Table 0** — security rules (priority 200 = block, 150 = rate-limit). Unmatched packets fall through to table 1.
- **Table 1** — standard L2 forwarding.

This separation makes security policies independent of forwarding logic: adding or removing a firewall rule never disrupts legitimate traffic.

---

## Project Structure

```
SDN-controller/
├── .github/
│   └── workflows/
│       ├── python-ci.yml     # flake8 + pytest on every push/PR
│       └── codeql.yml        # GitHub CodeQL SAST (weekly + on push)
├── api/
│   └── ofctl_rest.py         # HTTP server (port 8080) — REST routes
├── app/
│   ├── l2_switch.py          # L2 forwarding application
│   ├── firewall.py           # FirewallApp — block / ratelimit / isolate
│   └── topology.py           # Topology discovery (LLDP + Packet-In)
├── config/
│   └── settings.py           # Timeouts, priorities, defaults
├── tests/
│   ├── test.py               # pytest unit tests (cookies, state_store, Flow-Mod)
│   └── test_rest.sh          # Functional tests against a live controller instance
├── main.py                   # Entry point — loads all three apps
└── requirements.txt
```

---

## Prerequisites

- Python **3.11**
- [Ryu SDN Framework](https://ryu-sdn.org/) (`pip install ryu`)
- [Open vSwitch](https://www.openvswitch.org/) installed on the host
- Linux host (the controller communicates with OVS over a TCP socket)

---

## Installation

```bash
# Clone the repository
git clone https://github.com/Anisayz/SDN-controller.git
cd SDN-controller

# Create and activate a virtual environment (recommended)
python3.11 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Configuration

All tunable parameters live in `config/settings.py` and can be overridden via environment variables:

| Variable | Default | Description |
|---|---|---|
| `FIREWALL_API_KEY` | *(none)* | When set, all mutable requests must include `X-API-Key: <value>` |
| `OFP_TCP_LISTEN_PORT` | `6653` | Port on which Ryu listens for OpenFlow connections |
| `FIREWALL_DEFAULT_IDLE_TIMEOUT` | `300` | Seconds before an inactive firewall rule is removed |
| `FIREWALL_DEFAULT_HARD_TIMEOUT` | `3600` | Maximum lifetime of a firewall rule regardless of activity |

Create a `.env` file or export variables before launching:

```bash
export FIREWALL_API_KEY=my-secret-key
```

---

## Running the Controller

### 1. Start Open vSwitch and create the bridge

```bash
sudo ovs-vsctl add-br br0
sudo ovs-vsctl set bridge br0 protocols=OpenFlow13
sudo ovs-vsctl set-controller br0 tcp:127.0.0.1:6653
sudo ovs-vsctl set bridge br0 fail_mode=secure
```

> `fail_mode=secure` ensures the switch drops all traffic if the controller becomes unreachable — safer than autonomous L2 bridging.

### 2. Launch the Ryu controller

```bash
ryu-manager main.py \
  app/l2_switch.py \
  app/topology.py \
  app/firewall.py \
  api/ofctl_rest.py \
  --observe-links \
  --verbose
```

The `--observe-links` flag enables LLDP-based topology discovery. The REST API is available at `http://127.0.0.1:8080` immediately after startup.

---

## REST API Reference

All mutable routes require the `X-API-Key` header when `FIREWALL_API_KEY` is set. Responses are JSON.

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/firewall/rules` | Install a rule (`block` / `ratelimit` / `isolate`) |
| `DELETE` | `/firewall/rules/{id}` | Remove an existing rule by its UUID |
| `GET` | `/topology` | List of switches, inter-switch links, and known hosts |
| `GET` | `/switches` | Detailed state of each connected switch |
| `GET` | `/mactable` | MAC→port learning table |
| `GET` | `/health` | Controller uptime and number of active rules |
| `GET` | `/dump` | Raw `state_store` dump (diagnostic) |

### POST `/firewall/rules` — payload examples

**Block an IP:**
```json
{
  "action": "block",
  "src_ip": "10.0.0.1",
  "idle_timeout": 300,
  "hard_timeout": 3600
}
```

**Rate-limit an IP:**
```json
{
  "action": "ratelimit",
  "src_ip": "10.0.0.1",
  "rate_kbps": 512
}
```

**Isolate a host (bidirectional block):**
```json
{
  "action": "isolate",
  "src_ip": "10.0.0.1"
}
```

**Response:**
```json
{
  "rule_id": "a3f1c2d4-...",
  "action": "block",
  "src_ip": "10.0.0.1"
}
```

---

## OpenFlow Pipeline

```
Packet in ──► Table 0 (Firewall)
               │
               ├── priority 200: block  → DROP (empty action list)
               ├── priority 150: ratelimit → apply meter → goto table 1
               └── priority   1: default  → goto table 1
                                              │
                                         Table 1 (L2 Switch)
                                              │
                                         unicast / flood
```

Rules are tagged with a unique OF **cookie** so the controller can identify them on expiration events and clean up the `state_store` accordingly.

---

## Testing

### Unit tests

```bash
pytest tests/test.py -v
```

Covers: cookie allocation/release, `state_store` CRUD, Flow-Mod message construction.

### Functional tests (requires a running controller)

```bash
bash tests/test_rest.sh
```

Validates HTTP status codes, JSON response shapes, and API key enforcement against a live Ryu instance.

---

## CI/CD & Security

| Check | Tool | Trigger |
|---|---|---|
| Linting | `flake8` | Every push / PR |
| Unit tests | `pytest` | Every push / PR |
| Static analysis (SAST) | GitHub CodeQL | Every push + weekly cron |
| Dependency audit (SCA) | GitHub Dependabot | Continuous + auto-merge |
| AI code review | CodeRabbit | Every PR |

Dependabot auto-merges dependency updates when all CI checks pass.

---

 
