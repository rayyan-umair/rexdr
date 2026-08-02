# REXDR

**Real-time Extended Detection & Response**

A self-hosted XDR platform. Eight detection engines share one entity model and correlate each other's findings in real time, so activity that looks harmless in isolation surfaces as a single attack chain with a written narrative, MITRE mapping, and an auto-generated case file.

![Status](https://img.shields.io/badge/status-working-22c55e?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.11-4a9eff?style=flat-square)
![Go](https://img.shields.io/badge/Go-1.21-00d4aa?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Compose-7b8cde?style=flat-square)

---

## What it does

A DNS query with an unusual subdomain is low signal. Regular outbound connections on a fixed interval are low signal. A service running a version with a known CVE is low signal. Any one of them, on its own, is noise you would reasonably ignore.

REXDR correlates them. When two or more engines flag the same entity inside a time window, it builds an **attack chain** — a single record carrying every contributing detection, the engines that produced them, the MITRE tactics and techniques involved, and a plain-language narrative covering who, what, when, where, why and how. The response engine then picks up that chain, matches it against a playbook, and writes an immutable case file with a SHA-256 hash chain over the evidence.

That is the whole point of the design: the output is not eight alert feeds, it is one investigation.

---

## Engines

| Engine | Source | What it does |
|:---|:---|:---|
| **windows_event** | Go harvester + Python | Pulls Windows Security logs over WinRM, normalises them, runs authentication and persistence detections |
| **network_flow** | Python + Scapy | Captures traffic, aggregates it into flow records, detects scanning, beaconing and exfiltration patterns |
| **dns** | Go sniffer + Python | Passive DNS capture, entropy and frequency analysis, tunnelling and DGA indicators |
| **identity** | Go collector + Python + LDAP | Active Directory events, group membership snapshots and diffing, domain computer inventory |
| **siem** | Python | Cross-engine correlation — builds attack chains and their narratives |
| **response** | Python | Playbook matching, automated containment, immutable case file generation |
| **asset_discovery** | Python + nmap | Network scanning, host and service inventory, OS fingerprinting |
| **vulnerability** | Python + NVD API | CVE cache, service-to-CPE mapping, version-range matching against discovered services |

Two supporting services sit alongside them: **entity-store**, a standalone service holding the shared entity model, and **nginx**, the single gateway the browser talks to. Eleven containers in total.

---

## Detection coverage

Twenty-one detections across five engines, each mapped to a MITRE ATT&CK technique. Detections marked **✓** have fired against live activity in the validation lab.

### Windows events

| Detection | Technique | Fired |
|:---|:---|:---:|
| Brute Force Attack | T1110 | |
| Pass-the-Hash | T1550.002 | |
| Lateral Movement | T1021 | |
| Privilege Escalation | T1078 | |
| Suspicious Service Installation | T1543.003 | ✓ |

### Network flow

| Detection | Technique | Fired |
|:---|:---|:---:|
| Port Scan | T1046 | |
| Beaconing | T1071 | ✓ |
| High Outbound Transfer | T1041 | |
| Internal Pivot | T1021 | |
| Known-Bad Destination Contacted | T1071 | |

### DNS

| Detection | Technique | Fired |
|:---|:---|:---:|
| High Entropy Subdomain | T1568.002 | ✓ |
| DNS Record Type Frequency Spike | T1071.004 | ✓ |
| DNS Beaconing | T1071.004 | |
| NXDOMAIN Storm | T1568.002 | ✓ |
| Rare TLD Anomaly | T1583.001 | |

### Active Directory

| Detection | Technique | Fired |
|:---|:---|:---:|
| Kerberoasting | T1558.003 | |
| AS-REP Roasting | T1558.004 | |
| Group Membership Drift | T1098 | ✓ |
| Anomalous Authentication | T1078 | |
| ACL Abuse | T1484.001 | |

### Vulnerability

| Detection | Technique | Fired |
|:---|:---|:---:|
| Critical Vulnerability Exposure | T1190 | ✓ |

Detections that have not fired are implemented and waiting on the conditions that trigger them — the validation lab simply has not produced that activity yet.

---

## How it works

**Shared entity model.** Every engine reports observations about entities — an IP, a hostname, a user account — into a single store. Risk contributions stack across engines, so an account flagged by Active Directory and an address flagged by network flow are the same investigation if they belong to the same entity.

**Cross-engine correlation over HTTP.** The SIEM engine polls every other engine's detections API rather than reading their databases. This started as a workaround and became the right design: DuckDB enforces a single writer per file and offers no safe multi-process read path, so direct database access across containers was never viable. Each engine now owns its storage completely and exposes it through an API — a proper service boundary rather than a shared-file compromise.

**Chain lifecycle.** A chain stays active while it is being investigated. Closing its case file resolves the chain, which releases the entity to form new chains as fresh activity arrives. Without that, one entity's first chain would suppress every subsequent one indefinitely.

**Version-aware CVE matching.** Rather than flagging any host running a product with a known CVE, the vulnerability engine parses NVD's version ranges and compares them against the version detected in the service banner. Matches are reported as **confirmed** when the installed version falls inside the affected range, and **unconfirmed** when NVD published no version constraint — the distinction between "this host is affected" and "this product has a CVE somewhere."

**Analyst triage.** Any detection can be marked benign from the interface. The record stays for audit, but every open count, alert badge and risk score stops including it. Real environments generate benign patterns that look identical to attacks — a Linux host checking for updates on a fixed schedule is indistinguishable from C2 beaconing until someone says otherwise.

**Immutable case files.** Each case is written to disk as Markdown with a SHA-256 hash over the chain data and each piece of evidence. Case files are never modified after creation.

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

Also needed: **Docker Engine + Compose v2**, **Python 3.11+**, and **Go 1.21+** only if rebuilding the Go collectors.

The packet capture engines use `network_mode: host` for raw socket access. This needs native Docker on Linux — Docker Desktop on Windows runs containers inside a WSL2 VM with its own network namespace and cannot see real LAN traffic. Use a Linux host, or a VM with a bridged adapter.

---

## Setup

**1. Clone and build the shared core**

```bash
git clone https://github.com/rayyan-umair/rexdr.git
cd rexdr
docker compose build rexdr-base
```

`rexdr-base` compiles the shared library from source and every engine builds on top of it. Build it first — Compose cannot infer that dependency, since it is expressed only through `FROM`.

**2. Configure**

```bash
cp .env.example .env
cp config/targets.yaml.example config/targets.yaml
cp config/zones.yaml.example config/zones.yaml
```

Set your domain credentials and LDAP base DN in `.env`, list the Windows machines to collect from in `targets.yaml`, and define your network segments in `zones.yaml`.

The LDAP base DN must match the domain exactly — `DC=example,DC=local` for a domain named `example.local`. A mismatch returns the same error code as a wrong password, which makes it a genuinely unpleasant thing to debug.

**3. Build and start**

```bash
docker compose build
docker compose up -d
```

**4. Open the interface**

```
http://localhost
```

Nginx is the only entry point. Individual engine ports never need to be exposed.

**Alternatively**, the launcher handles configuration, build and monitoring in one window:

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
```

---

## When things go wrong

| Symptom | Cause | Fix |
|:---|:---|:---|
| Containers fail with an `await` type error | Stale shared library | `docker compose build rexdr-base` then rebuild all |
| Packet capture engines healthy but no events | Docker Desktop, or a NAT-networked VM | Native Linux Docker, bridged adapter |
| LDAP binds fail with `invalidCredentials` | Wrong base DN, wrong UPN suffix, or genuinely wrong password | Check the DC's `defaultNamingContext` against `LDAP_BASE_DN` before assuming the password is wrong |
| An engine reports zero of everything | A config file it silently depends on is missing | Check that engine's startup logs for a load warning |
| Correlation never produces chains | Entities are keyed differently across engines | Confirm usernames are normalised consistently |

---

## Notes on the build

Engine images build on a shared base that compiles the core library from source. An earlier arrangement committed a pre-built wheel to the repository and copied it into each engine's build context — which allowed the binary to drift from the source it was built from, silently downgrading a shared dependency across all eight engines while every build reported success. Building from source in the base image makes that class of failure impossible.

Database reads name their columns explicitly rather than using `SELECT *`. `ALTER TABLE` appends new columns at the end while `CREATE TABLE` places them mid-list, so a positional column mapping silently misaligns after a migration — every value shifts one field over, and the failure surfaces somewhere unrelated to the cause.

---

## Status

Working and validated. All eight engines run against live activity, produce detections, correlate into cross-engine chains, and generate case files with automated playbook matching.

---

## Author

**Rayyan Umair** — IT Support · Cybersecurity · Building toward Security Architecture

[rayyanxumair@gmail.com](mailto:rayyanxumair@gmail.com) · [linkedin.com/in/rayyanumair](https://www.linkedin.com/in/rayyanumair/) · [rayyan-umair.github.io](https://rayyan-umair.github.io/)

---

REXDR is proprietary software. All rights reserved. © 2026 Rayyan Umair

*"Technology evolves quickly. Responsibility does not."*
