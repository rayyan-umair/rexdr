<div align="center">

# REXDR
### Real-time Extended Detection & Response

**A unified commercial-grade XDR platform.**
Eight intelligence engines running in complete harmony — Windows events, network flows,
DNS, Active Directory, SIEM correlation, incident response, asset discovery, and
vulnerability intelligence — all sharing a single entity model, cross-correlating
in real time, and surfacing everything through one investigation interface.

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

It is a unified intelligence platform where the output is categorically greater
than the sum of its parts. A brute force event in Windows logs, beaconing traffic
in network flows, and a high-entropy DNS query to the same IP — three low-severity
events in isolation — become a confirmed C2 intrusion chain in REXDR.

That correlation is only possible because all eight engines share a single entity
model, communicate through a universal schema, and cross-correlate each other's
data in real time through DuckDB ATTACH queries and a shared entity store.

REXDR is built for real enterprise environments — schools, hospitals, municipalities,
mid-market businesses — not a lab. The same codebase scales from a single dedicated
host to a SPAN-mirrored or TAP-fed deployment without any code changes; only sensor
placement changes what the platform can see.

---

## Who This Is For

- **IT administrators** at organizations that need serious detection capability without
  a dedicated security team operating it daily
- **Security analysts** who want cross-engine attack chain detection instead of eight
  separate alert feeds
- **Anyone deploying REXDR** for the first time — this README is written for a general
  technical user who is comfortable with a terminal but is not necessarily a security
  specialist

---

## Where Everything Lives

rexdr/

├── core-shared/          rexdr_core wheel - the foundation every engine depends on

├── engines/               eight intelligence engines

│   ├── windows_event/     Windows Event Log harvesting and detection

│   ├── network_flow/      Network flow capture and detection

│   ├── siem/               Cross-engine correlation and attack chain building

│   ├── dns/                DNS behavioral analysis (sniffer/ + brain/)

│   ├── identity/           Active Directory intelligence (collector/ + Python brain)

│   ├── response/           Playbook-driven incident response orchestration

│   ├── asset_discovery/    Network scanning and asset inventory

│   └── vulnerability/      CVE correlation against discovered assets

├── frontend/               React investigation UI

├── launcher/               Tkinter desktop launcher - the entry point for every user

├── nginx/                  Reverse proxy gateway - single entry point for the platform

├── config/                 targets.yaml, zones.yaml, sigma_rules/, playbooks/

├── scripts/                build helper scripts (prepare_build.ps1)

├── dist/                   built rexdr_core wheel lands here

├── docker-compose.yml      full platform orchestration

├── .env.example            environment configuration template

└── LICENSE

---

## How to Set This Up

### Requirements

**On the REXDR host machine**

| Component | Minimum | Recommended |
|:---|:---|:---|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16–32 GB |
| Storage | 100 GB SSD | 500 GB+ SSD |
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 or 24.04 LTS |
| Network | 1 Gbps | 1 Gbps with VLAN/SPAN access |

> REXDR's packet capture engines (`network_flow`, `dns`) use `network_mode: host` for
> raw socket access. This requires native Docker on Linux. **Docker Desktop on Windows
> does not support this correctly** — it runs containers inside a WSL2 VM, which has
> its own isolated network namespace and cannot see real LAN traffic. Use a Linux host
> or VM with a **bridged** network adapter for any deployment that needs live capture.

**Software needed before you start**

- Docker Engine + Docker Compose v2 (native install on Linux, not Docker Desktop, for production)
- Python 3.11+
- Go 1.21+ (only needed if rebuilding the Go harvester/sniffer/collector binaries)
- Node 20 LTS (only needed if rebuilding the frontend outside Docker)

### Step 1 — Clone the repository

```bash
git clone https://github.com/rayyan-umair/rexdr.git
cd rexdr
```

### Step 2 — Build the core-shared wheel

Every engine depends on `rexdr_core`. Build it first:

```bash
cd core-shared
pip install build
python -m build
cp dist/rexdr_core-1.0.0-py3-none-any.whl ../dist/
cd ..
```

### Step 3 — Distribute the wheel to every engine's build context

Docker build contexts cannot see files outside themselves, so the wheel must be
copied into each engine folder before building. **Run this before every
`docker compose build`**, and again any time `core-shared` changes:

```bash
# Linux / macOS
bash scripts/prepare_build.sh

# Windows (PowerShell)
.\scripts\prepare_build.ps1
```

### Step 4 — Configure the platform

The recommended way to configure REXDR is through the launcher (Step 6), which
writes these files for you. To configure manually instead:

```bash
cp .env.example .env
# Edit .env with your AD credentials, AI provider, and platform settings

cp config/targets.yaml.example config/targets.yaml
# Edit targets.yaml with your domain controllers and Windows machines

cp config/zones.yaml.example config/zones.yaml
# Edit zones.yaml with your network segment CIDR ranges
```

### Step 5 — Build and start

```bash
docker compose build
docker compose up -d
```

### Step 6 — Or use the launcher instead of Steps 4–5

The launcher gives you a configuration wizard, a live build/start monitor, and a
per-engine status dashboard in one window:

```bash
cd launcher
pip install -r requirements.txt
python rexdr_launcher.py
```

### Step 7 — Open REXDR

Once all engines report healthy, open:

http://localhost

in your browser. Nginx is the single entry point — you never need to open
individual engine ports directly.

---

## Verifying REXDR Is Running Correctly

```bash
# Check every container is up and healthy
docker compose ps

# Check the gateway is responding
curl http://localhost/health

# Check an individual engine directly (bypassing the gateway)
curl http://localhost/api/siem/health
```

A healthy platform shows all ten services (`windows-event`, `network-flow`, `siem`,
`dns`, `identity`, `response`, `asset-discovery`, `vulnerability`, `frontend`, `nginx`)
as `running` with `healthy` status in `docker compose ps`.

---

## When Things Don't Work

| Symptom | Likely Cause | Fix |
|:---|:---|:---|
| Build fails on wheel install | `prepare_build` script wasn't run, or wasn't re-run after a `core-shared` change | Re-run Step 3 |
| `network-flow` / `dns` containers unhealthy, zero events | Running on Docker Desktop/Windows, or VM is NAT-networked instead of bridged | Move to a native Linux host, or switch the VM's network adapter to bridged |
| `siem` never becomes healthy | It depends on `windows-event`, `dns`, and `identity` being healthy first — one of those three is failing | Check `docker compose logs <service>` for the actual failing engine |
| WinRM/LDAP engines healthy but collecting nothing | Credentials in `.env` are wrong, or `targets.yaml` has no `enabled: true` targets | Verify credentials and target config through the launcher |
| Frontend loads but shows no data | Nginx isn't routing correctly, or the engines it proxies to aren't healthy yet | Check `docker compose ps`, confirm nginx started after all engines |
| AI panel shows "not configured" | No `AI_PROVIDER` / `AI_API_KEY` set | Set both in `.env` or the launcher wizard — Groq is the recommended free default |

Full technical notes — DuckDB lock recovery, Sigma multi-document YAML quirks, WinRM
concurrency limits at scale, and more — are documented inline in each engine's source.

---

## Project Status

| Component | Status |
|:---|:---:|
| core-shared | Complete |
| Windows Event Engine | Complete |
| Network Flow Engine | Complete |
| SIEM Correlation Engine | Complete |
| DNS Behavioral Engine | Complete |
| Active Directory Engine | Complete |
| Incident Response Engine | Complete |
| Network Discovery Engine | Complete |
| Vulnerability Engine | Complete |
| React Frontend | Complete |
| Nginx Gateway | Complete |
| Tkinter Launcher | Complete |
| Live VM validation | Pending |

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