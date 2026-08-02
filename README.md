<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&amp;color=gradient&amp;customColorList=2,12,20&amp;height=160&amp;section=header&amp;text=REXDR&amp;fontSize=64&amp;fontColor=ffffff&amp;fontAlignY=62&amp;desc=Real-time%20Extended%20Detection%20and%20Response&amp;descSize=16&amp;descAlignY=84&amp;animation=fadeIn" width="100%"/>

<br/>

[![Status](https://img.shields.io/badge/Status-Working-22c55e?style=for-the-badge)](/)
[![Python](https://img.shields.io/badge/Python-3.11-4a9eff?style=for-the-badge&logo=python&logoColor=white)](/)
[![Go](https://img.shields.io/badge/Go-1.21-00d4aa?style=for-the-badge&logo=go&logoColor=white)](/)
[![Docker](https://img.shields.io/badge/Docker-Compose-7b8cde?style=for-the-badge&logo=docker&logoColor=white)](/)
[![React](https://img.shields.io/badge/React-Vite-4a9eff?style=for-the-badge&logo=react&logoColor=white)](/)
[![DuckDB](https://img.shields.io/badge/DuckDB-Embedded-ffd23f?style=for-the-badge)](/)

**Eight detection engines. One entity model. One investigation.**

</div>

---

## Overview

Most detection tooling gives you more of the problem it was meant to solve: several consoles, several alert queues, and an analyst left to work out whether any of them are describing the same incident.

REXDR takes the opposite approach. Every engine writes into a shared entity model, and a correlation layer continuously asks one question — *is more than one engine describing the same thing?* When the answer is yes, the platform stops producing alerts and starts producing an investigation.

It runs entirely on infrastructure you control. No SaaS backend, no telemetry leaving the network, no per-endpoint licensing.

---

## What it does

**Watches from several angles at once.** Windows security logs over WinRM. Live network traffic. Passive DNS. Active Directory events and group membership. Scheduled network scans. A local CVE cache checked against whatever those scans find.

**Scores entities, not events.** An IP address, a hostname, and a user account are all entities. Every engine contributes risk to the entities it observes, so an account flagged by Active Directory and an address flagged by network traffic converge into one profile rather than two unrelated alerts.

**Correlates across engines.** A DNS query with an unusual subdomain is weak signal. Regular outbound connections on a fixed interval are weak signal. A service running a version with a published CVE is weak signal. Individually, all three are reasonable to ignore. When they land on the same entity inside the correlation window, REXDR builds an **attack chain** — one record holding every contributing detection, the engines that produced them, the MITRE tactics and techniques involved, and a written narrative covering who, what, when, where, why, and how.

**Escalates on breadth, not only severity.** A chain spanning three engines is treated more seriously than one spanning two, because coverage across the kill chain is itself a signal. Three low-severity findings on one entity are not three small problems.

**Responds without being asked.** Every confirmed chain is picked up by the response engine, matched against YAML playbooks, and turned into a case file. Where a playbook matches and containment is enabled, actions execute automatically — disabling a compromised account, revoking its Kerberos tickets, alerting an administrator. Where no playbook matches, the case is still written and flagged for manual review. Nothing is silently dropped.

**Preserves evidence properly.** Case files are immutable Markdown written to disk with a SHA-256 hash over the chain data and each piece of evidence. They are written once and never modified.

**Lets an analyst disagree with it.** Any detection can be marked benign. The record stays for audit, but every open count, alert badge, and risk score stops including it. Real networks generate benign patterns indistinguishable from attacks — a Linux host polling its update server on a fixed schedule looks exactly like C2 beaconing until a human says otherwise.

---

## Engines

| Engine | Built with | Responsibility |
|:---|:---|:---|
| **windows_event** | Go harvester + Python | Collects Windows Security logs over WinRM, normalises them, detects authentication abuse and persistence |
| **network_flow** | Python + Scapy | Captures packets, aggregates them into flow records, detects scanning, beaconing, and exfiltration |
| **dns** | Go sniffer + Python | Passive DNS capture, entropy and frequency analysis, tunnelling and DGA indicators |
| **identity** | Go collector + Python + LDAP | Active Directory events, group membership snapshots and diffing, domain computer inventory |
| **siem** | Python | Cross-engine correlation — builds attack chains and their narratives |
| **response** | Python | Playbook matching, automated containment, immutable case file generation |
| **asset_discovery** | Python + nmap | Network scanning, host and service inventory, OS fingerprinting |
| **vulnerability** | Python + NVD API | CVE cache, service-to-CPE mapping, version-range matching against discovered services |

Two supporting services complete the stack: **entity-store**, holding the shared entity model behind its own API, and **nginx**, the single gateway the browser talks to. Eleven containers in total.

---

## Detection coverage

Twenty-one detections across five engines, each mapped to a MITRE ATT&amp;CK technique.

### Windows events

| Detection | Technique |
|:---|:---|
| Brute Force Attack | T1110 |
| Pass-the-Hash | T1550.002 |
| Lateral Movement | T1021 |
| Privilege Escalation | T1078 |
| Suspicious Service Installation | T1543.003 |

### Network flow

| Detection | Technique |
|:---|:---|
| Port Scan | T1046 |
| Beaconing | T1071 |
| High Outbound Transfer | T1041 |
| Internal Pivot | T1021 |
| Known-Bad Destination Contacted | T1071 |

### DNS

| Detection | Technique |
|:---|:---|
| High Entropy Subdomain | T1568.002 |
| DNS Record Type Frequency Spike | T1071.004 |
| DNS Beaconing | T1071.004 |
| NXDOMAIN Storm | T1568.002 |
| Rare TLD Anomaly | T1583.001 |

### Active Directory

| Detection | Technique |
|:---|:---|
| Kerberoasting | T1558.003 |
| AS-REP Roasting | T1558.004 |
| Group Membership Drift | T1098 |
| Anomalous Authentication | T1078 |
| ACL Abuse | T1484.001 |

### Vulnerability

| Detection | Technique |
|:---|:---|
| Critical Vulnerability Exposure | T1190 |

---

## The investigation interface

A React frontend served through nginx, built around one idea: every click should pull together everything the platform knows about what was clicked.

**Dashboard** — engine health, open detections, critical count, active chains. A live alert feed alongside an entity risk board ranking the entities carrying the most risk across the most engines.

**Engine views** — each engine surfaces its own domain rather than a generic alert list. Asset discovery shows the host inventory with open ports and detected services. Active Directory shows tracked accounts with group membership and authentication history, plus every domain-joined computer with its operating system and delegation flags. SIEM shows active chains. Incident response shows case files with the ability to close them.

**Investigation blade** — slides in on any selection. Shows what happened, the entity involved, contributing engines, MITRE mapping, and the full narrative. Detections can be marked benign here or inline from any list.

**AI assistant** — an optional panel that sends the selected chain or detection to a configured provider (Groq, OpenAI, Anthropic, Gemini, or a local Ollama instance) and asks for a plain-language explanation. It is always grounded in the record currently selected, never a generic example. Entirely optional; the platform runs unchanged without it.

**Desktop launcher** — a Tkinter application handling first-run configuration, build and start, per-engine status, and log inspection, for deployments where a terminal is not the preferred interface.

---

## How it works

**Cross-engine correlation over HTTP.** The SIEM engine polls every other engine's detections API rather than reading their databases. This began as a workaround and became the right design: DuckDB enforces a single writer per file and offers no safe multi-process read path, so direct cross-container database access was never viable. Each engine now owns its storage completely and exposes it through an API — a proper service boundary rather than a shared-file compromise. The entity store exists as its own service for the same reason.

**Chain lifecycle.** A chain stays active while it is being investigated, and an entity with an active chain will not form another. Closing the case file resolves the chain and releases the entity, so new activity can form a new chain. Without that lifecycle, an entity's first chain would suppress every subsequent one indefinitely.

**Version-aware CVE matching.** Rather than flagging any host running a product with a known CVE, the vulnerability engine parses NVD's published version ranges and compares them against the version detected in the service banner. Matches are reported as **confirmed** when the installed version falls inside the affected range, and **unconfirmed** when NVD published no version constraint — the difference between "this host is affected" and "this product has a CVE somewhere."

**Deduplication.** Ongoing behaviour produces one persistent alert rather than a new detection every cycle. Beaconing to the same destination, a repeated DNS pattern, an unchanged CVE match — each is reported once and stays open, instead of generating an identical alert every time the engine runs.

---

## Tech stack

| Layer | Technology |
|:---|:---|
| Detection engines | Python 3.11, FastAPI, Pydantic |
| Collectors | Go 1.21 — WinRM harvester, DNS sniffer, AD collector |
| Packet capture | Scapy, libpcap |
| Storage | DuckDB, embedded, one database per engine |
| Messaging | ZeroMQ pub/sub, HTTP between services |
| Directory integration | LDAP3, WinRM |
| Threat intelligence | NVD CVE API |
| Frontend | React, Vite |
| Gateway | nginx |
| Orchestration | Docker Compose |
| Launcher | Tkinter |

---

## Repository layout

```
rexdr/
├── core-shared/        rexdr_core - shared schemas, base classes, entity store client
├── engines/            the eight detection engines
├── frontend/           React investigation interface
├── launcher/           Tkinter desktop launcher
├── nginx/              reverse proxy gateway
├── config/             targets.yaml, zones.yaml, playbooks/
├── scripts/            build helpers
└── docker-compose.yml
```

---

## Requirements

| | Minimum | Recommended |
|:---|:---|:---|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Storage | 100 GB SSD | 500 GB SSD |
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 / 24.04 LTS |

Also required: **Docker Engine with Compose v2**, **Python 3.11+**, and **Go 1.21+** only if rebuilding the Go collectors.

The packet capture engines use `network_mode: host` for raw socket access, which requires native Docker on Linux. Docker Desktop on Windows runs containers inside a WSL2 VM with its own network namespace and cannot see real LAN traffic. Use a Linux host, or a VM with a bridged adapter.

---

## Setup

**1. Clone and build the shared core**

```bash
git clone https://github.com/rayyan-umair/rexdr.git
cd rexdr
docker compose build rexdr-base
```

`rexdr-base` compiles the shared library from source, and every engine builds on top of it. Build it first — Compose cannot infer that dependency, because it is expressed only through `FROM`.

**2. Configure**

```bash
cp .env.example .env
cp config/targets.yaml.example config/targets.yaml
cp config/zones.yaml.example config/zones.yaml
```

Set domain credentials and the LDAP base DN in `.env`, list the Windows machines to collect from in `targets.yaml`, and define network segments in `zones.yaml`.

The LDAP base DN must match the domain exactly — `DC=example,DC=local` for a domain named `example.local`. A mismatch returns the same error code as a wrong password, which makes it an unpleasant thing to debug.

**3. Build and start**

```bash
docker compose build
docker compose up -d
```

**4. Open the interface**

```
http://localhost
```

nginx is the only entry point. Individual engine ports never need to be exposed.

**Alternatively**, the launcher handles configuration, build, and monitoring in one window:

```bash
cd launcher
pip install -r requirements.txt
python rexdr_launcher.py
```

---

## Verifying it works

```bash
docker compose ps                              # all eleven services healthy
curl http://localhost/api/siem/stats           # chain counts
curl http://localhost/api/identity/entities    # tracked accounts
curl http://localhost/api/response/playbooks   # loaded playbooks
```

---

## When things go wrong

| Symptom | Cause | Fix |
|:---|:---|:---|
| Containers fail with an `await` type error | Stale shared library | `docker compose build rexdr-base`, then rebuild all |
| Packet capture engines healthy but no events | Docker Desktop, or a NAT-networked VM | Native Linux Docker with a bridged adapter |
| LDAP binds fail with `invalidCredentials` | Wrong base DN, wrong UPN suffix, or genuinely wrong password | Check the domain controller's `defaultNamingContext` against `LDAP_BASE_DN` before assuming the password is wrong |
| An engine reports zero of everything | A config file it silently depends on is missing | Check that engine's startup logs for a load warning |
| Correlation never produces chains | Entities are keyed differently across engines | Confirm usernames are normalised consistently |
| No playbook ever matches | `config/playbooks/` is empty | Playbooks are not shipped by default; add YAML definitions |

---

## Notes on the build

Engine images build on a shared base that compiles the core library from source. An earlier arrangement committed a pre-built wheel to the repository and copied it into each engine's build context — which allowed the binary to drift from the source it was built from, silently downgrading a shared dependency across all eight engines while every build reported success. Building from source in the base image makes that class of failure impossible.

Database reads name their columns explicitly rather than using `SELECT *`. `ALTER TABLE` appends new columns at the end while `CREATE TABLE` places them mid-list, so a positional column mapping silently misaligns after a migration — every value shifts one field over, and the failure surfaces somewhere unrelated to its cause.

---

## Status

Working and validated. All eight engines run against live activity, produce detections, correlate into cross-engine attack chains, and generate case files with automated playbook matching.

---

<div align="center">

## Author

**Rayyan Umair** — IT Support · Cybersecurity · Building toward Security Architecture

[![Portfolio](https://img.shields.io/badge/Portfolio-rayyan--umair.github.io-4a9eff?style=for-the-badge)](https://rayyan-umair.github.io/)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0a66c2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/rayyanumair/)
[![Email](https://img.shields.io/badge/Email-rayyanxumair%40gmail.com-00d4aa?style=for-the-badge)](mailto:rayyanxumair@gmail.com)

<br/>

REXDR is proprietary software. All rights reserved. © 2026 Rayyan Umair

*"Technology evolves quickly. Responsibility does not."*

<img src="https://capsule-render.vercel.app/api?type=waving&amp;color=gradient&amp;customColorList=2,12,20&amp;height=90&amp;section=footer" width="100%"/>

</div>
