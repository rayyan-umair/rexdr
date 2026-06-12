<div align="center">

# REXDR
### Real-time Extended Detection & Response

**A unified commercial-grade XDR platform.**  
Eight intelligence engines running in complete harmony - Windows events, network flows, DNS, Active Directory, SIEM correlation, incident response, asset discovery, and vulnerability intelligence - all sharing a single entity model, cross-correlating in real time, and surfacing everything through one investigation interface.

---

![Status](https://img.shields.io/badge/Status-In%20Development-FFB800?style=for-the-badge)
![License](https://img.shields.io/badge/License-Proprietary-FF4444?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.11+-00FFD1?style=for-the-badge&logo=python&logoColor=white)
![Go](https://img.shields.io/badge/Go-1.21+-00FFD1?style=for-the-badge&logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-00FFD1?style=for-the-badge&logo=docker&logoColor=white)

</div>

---

## What REXDR Is

REXDR is not eight tools running in Docker.

It is a unified intelligence platform where the output is categorically greater than the sum of its parts. A brute force event in Windows logs, beaconing traffic in network flows, and a high-entropy DNS query to the same IP - three low-severity
events in isolation - become a confirmed C2 intrusion chain in REXDR.

That correlation is only possible because all eight engines share a single entity model, communicate through a universal schema, and cross-correlate each other's data in real time.

---

## The Eight Engines

| Engine | Intelligence Layer | Port |
|:---|:---|:---:|
| Windows Event | Log harvesting, normalization, behavioral detection across all Windows machines | 8000 |
| Network Flow | Deep packet inspection, flow analysis, beaconing and exfiltration detection | 8001 |
| SIEM | Sigma rule correlation, cross-engine attack chain detection, 5W+H narrative generation | 8002 |
| DNS | Behavioral DNS analysis, entropy scoring, DGA and tunneling detection | 8003 |
| Active Directory | Identity intelligence, group membership drift, Kerberos abuse detection | 8004 |
| Incident Response | Playbook-driven automated containment, forensic case file generation | 8005 |
| Asset Discovery | Continuous network mapping, new device detection, asset inventory | 8006 |
| Vulnerability | CVE correlation against live assets, vulnerability posture reporting | 8007 |

---

## What Makes REXDR Different

**Unified Entity Model**  
One identity across all eight engines. One risk score that reflects everything
REXDR knows about an entity — not eight separate records in eight separate tools.

**Cross-Engine Attack Chains**  
Temporal correlation across engines. Events separated by hours or days, linked
into campaigns. Attack sequences no individual tool could see.

**Coordinated Automated Response**  
A single playbook can lock an AD account, block a network path, and generate a
signed forensic case file in one execution — triggered automatically by a
cross-engine chain detection.

**Investigation Experience**  
Every detection arrives with a full 5W+H narrative — Who, What, When, Where,
Why, and How. Built for analysts who need answers, not more alerts.

**AI-Assisted Investigation**  
Configurable AI provider (Groq recommended). Every AI response is grounded in
real detection data — not hardcoded examples.

---

## Architecture

                    ┌─────────────────────────────┐
                    │      REXDR Frontend          │
                    │   React · Port 3000          │
                    └──────────────┬──────────────┘
                                   │ REST + WebSocket
                           ┌───────┴───────┐
                           │     Nginx      │
                           │  Port 80/443   │
                           └───────┬───────┘
      ┌─────────────────────────────────────────────────────┐
      │                   Engine APIs                        │
      │  8000  8001  8002  8003  8004  8005  8006  8007      │
      └──────────────────────┬──────────────────────────────┘
                             │
      ┌──────────────────────┼──────────────────────┐
      │                      │                       │
      ┌──────┴──────┐      ┌────────┴───────┐     ┌────────┴───────┐
      │  ZeroMQ PUB │      │  DuckDB ATTACH │     │  Entity Store  │
      │  5555/57/58 │      │  Cross-engine  │     │  Unified Risk  │
      └─────────────┘      │  SQL joins     │     │  Scoring       │
      └────────────────┘              └────────────────┘

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/rayyan-umair/rexdr.git
cd rexdr

# 2. Copy and configure environment
cp .env.example .env
# Edit .env with your credentials and settings

# 3. Configure your targets
cp config/targets.yaml.example config/targets.yaml
# Edit targets.yaml with your Windows machine IPs and credentials

# 4. Configure network zones
cp config/zones.yaml.example config/zones.yaml
# Edit zones.yaml with your network segment definitions

# 5. Launch REXDR
python launcher/rexdr_launcher.py

# Or directly via Docker Compose
docker compose up -d
```

Open `http://localhost` in your browser once all engines are healthy.

---

## Requirements

**REXDR Host Machine**

| Component | Minimum | Recommended |
|:---|:---|:---|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16-32 GB |
| Storage | 100 GB SSD | 500 GB+ SSD |
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 or 24.04 LTS |
| Network | 1 Gbps | 1 Gbps with VLAN access |

**Software**
- Docker Desktop / Docker Engine with Compose v2
- Python 3.11+
- Go 1.21+
- Node 20 LTS (frontend build)

**Monitored Environment**
- Windows machines with WinRM enabled
- Domain Controller accessible from the REXDR host
- Network interface or span port for packet capture

---

## Project Structure

rexdr/
├── core-shared/          rexdr_core wheel - the foundation everything depends on
├── engines/              eight intelligence engines
│   ├── windows_event/
│   ├── network_flow/
│   ├── siem/
│   ├── dns/
│   ├── identity/
│   ├── response/
│   ├── asset_discovery/
│   └── vulnerability/
├── frontend/             React SPA
├── launcher/             Tkinter launcher
├── nginx/                reverse proxy config
├── config/               targets, zones, playbooks, sigma rules
├── dist/                 built rexdr_core wheel
├── docker-compose.yml
├── .env.example
└── README.md

---

## Status

REXDR is currently in active development.

| Component | Status |
|:---|:---:|
| core-shared | Complete |
| docker-compose.yml | Complete |
| Windows Event Engine | In Progress |
| Network Flow Engine | Pending |
| SIEM Engine | Pending |
| DNS Engine | Pending |
| Active Directory Engine | Pending |
| Incident Response Engine | Pending |
| Asset Discovery Engine | Pending |
| Vulnerability Engine | Pending |
| React Frontend | Pending |
| Tkinter Launcher | Pending |

---

## Author

**Rayyan Umair**  
IT Support · Cybersecurity · Building toward Security Architecture

[rayyanxumair@gmail.com](mailto:rayyanxumair@gmail.com) ·
[linkedin.com/in/rayyanumair](https://www.linkedin.com/in/rayyanumair/) ·
[rayyan-umair.github.io](https://rayyan-umair.github.io/)

---

<div align="center">
<sub>
REXDR is proprietary software. All rights reserved. © 2026 Rayyan Umair
<br/>
"Technology evolves quickly. Responsibility does not."
</sub>
</div>