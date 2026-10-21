# LABS Lab 01: Wazuh SIEM Home Lab

**Attack from Kali. Detect with Wazuh. Investigate like a SOC analyst.**

A hands-on SOC home lab built on VirtualBox. Controlled attacks are generated from **Kali Linux** against an **Ubuntu** endpoint. The resulting logs are collected, decoded, alerted on and investigated in **Wazuh**, an open-source SIEM and XDR platform.

> **Authorized use only.** Every test in this repository runs against systems I own, on an isolated lab network. Never use these techniques against systems you do not own or do not have written permission to test.

---

## Table of Contents

- [1. What Is Wazuh?](#1-what-is-wazuh)
- [2. SIEM vs EDR vs XDR](#2-siem-vs-edr-vs-xdr)
- [3. Project Overview](#3-project-overview)
- [4. Lab Architecture](#4-lab-architecture)
- [5. Requirements](#5-requirements)
- [6. Understanding Wazuh](#6-understanding-wazuh)
- [7. Dashboard Navigation Guide](#7-dashboard-navigation-guide)
- [8. Step 1: Install the Wazuh Server](#8-step-1-install-the-wazuh-server)
- [9. Step 2: Build the Lab Network](#9-step-2-build-the-lab-network)
- [10. Step 3: Connect the Ubuntu Endpoint](#10-step-3-connect-the-ubuntu-endpoint)
- [11. Step 4: Health Check](#11-step-4-health-check)
- [12. Step 5: Simulate Attacks from Kali](#12-step-5-simulate-attacks-from-kali)
- [13. Step 6: Investigate in the Dashboard](#13-step-6-investigate-in-the-dashboard)
- [14. Events vs Alerts](#14-events-vs-alerts)
- [15. Step 7: Write a Custom Detection Rule](#15-step-7-write-a-custom-detection-rule)
- [16. Step 8: File Integrity Monitoring](#16-step-8-file-integrity-monitoring)
- [17. Wazuh Feature Overview](#17-wazuh-feature-overview)
- [18. Troubleshooting](#18-troubleshooting)
- [19. From Home Lab to Enterprise](#19-from-home-lab-to-enterprise)
- [20. Roadmap](#20-roadmap)
- [21. Analyst Quick Reference](#21-analyst-quick-reference)
- [22. References](#22-references)

---

## 1. What Is Wazuh?

Wazuh is a free, open-source security platform that combines **SIEM** capabilities (log collection, correlation and alerting) with **XDR-style endpoint protection** (file integrity monitoring, vulnerability detection, configuration assessment and active response). It started in 2015 as a fork of the OSSEC host-based intrusion detection system and has grown into a complete platform with its own indexer, dashboard and API. There are no license fees.

**In plain words:** Wazuh watches your machines, reads their logs, compares what it sees against thousands of detection rules, tells you when something looks wrong, and can respond automatically.

```text
┌─ WHAT WAZUH WATCHES ─────┐       ┌─ WAZUH ───────┐       ┌─ WHAT YOU GET ────────┐
│ Linux and Windows hosts  │       │    collect    │       │ Security alerts       │
│ Servers and applications │       │     decode    │       │ File change tracking  │
│ Cloud and containers     │ ────▶ │   correlate   │ ────▶ │ Vulnerability reports │
│ Network devices (syslog) │       │     alert     │       │ Compliance evidence   │
└──────────────────────────┘       └───────────────┘       │ Automated response    │
                                                           └───────────────────────┘
```

| Capability | What it means for a SOC analyst |
|---|---|
| Log analysis | Turns raw logs into searchable, rated alerts |
| File integrity monitoring | Tells you when important files are added, changed or removed |
| Vulnerability detection | Lists known vulnerabilities in software installed on endpoints |
| Configuration assessment | Checks endpoints against hardening benchmarks |
| Active Response | Runs an action, such as blocking an IP, when a rule fires |
| MITRE ATT&CK mapping | Labels alerts with attacker tactics and techniques |
| Compliance reporting | Maps alerts to PCI DSS, GDPR, HIPAA, NIST 800-53 and more |

---

## 2. SIEM vs EDR vs XDR

These three terms are often confused. They describe different scopes of visibility and different jobs.

**An analogy:** a SIEM is the CCTV control room for the whole building, collecting feeds from everywhere. An EDR is a security guard inside each room who inspects everything closely and can lock the door. XDR joins the two so the control room and the guards work from one picture.

```text
┌─ SIEM: broad visibility ─────────┐      ┌─ EDR: deep visibility ───────────┐
│ - logs from many sources         │      │ - agent on each endpoint         │
│ - correlates across systems      │      │ - process, file, behavior        │
│ - alerts, search, compliance     │      │ - isolate host, kill process     │
└──────────────────────────────────┘      └──────────────────────────────────┘
                  │                                         │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
                ┌─ XDR: unified ─────────────────────────────┐
                │ endpoints + network + cloud + identity     │
                │ one correlated view, one response          │
                └────────────────────────────────────────────┘
```

| | SIEM | EDR | XDR |
|---|---|---|---|
| Full name | Security Information and Event Management | Endpoint Detection and Response | Extended Detection and Response |
| Main focus | Collect, correlate and store logs from everywhere | Watch and defend individual endpoints | Detect and respond across many layers |
| Typical data | Logs from servers, firewalls, apps, cloud, identity | Process, file, registry and network activity on the endpoint | Endpoint, network, cloud and identity telemetry |
| Depth | Wide, shallower per source | Narrow, very deep per endpoint | Wide and deep |
| Response | Mostly alerting and investigation | Isolate a host, kill a process, quarantine files | Coordinated response across layers |
| Compliance and retention | Strong | Limited | Varies |
| Typical question answered | "What happened across the environment?" | "What exactly did this process do on this machine?" | "How did the attack move across systems?" |

### Where Wazuh fits

Wazuh is first and foremost a **SIEM with strong endpoint capabilities**. It covers part of the EDR job, and it positions itself as an open-source XDR and SIEM platform.

```text
┌─ SIEM STRENGTHS ─────┐     ┌─────────────┐     ┌─ ENDPOINT CAPABILITIES ───┐
│ log analysis         │     │             │     │ file integrity monitoring │
│ correlation          │─────│    WAZUH    │─────│ vulnerability detection   │
│ compliance           │     │ open source │     │ configuration assessment  │
│ search and retention │     │             │     │ Active Response           │
└──────────────────────┘     └─────────────┘     └───────────────────────────┘
```

| Capability | Wazuh | Note |
|---|---|---|
| Log collection and correlation | Strong | Core strength |
| Compliance reporting | Strong | PCI DSS, GDPR, HIPAA, NIST 800-53 |
| File integrity monitoring | Strong | Built in |
| Vulnerability detection | Strong | Built in |
| Scripted response | Yes | Active Response |
| Deep process and behavior monitoring | Partial | Improves when paired with Sysmon or Linux auditd |
| Kernel-level prevention and memory protection | Not a focus | Commercial EDR products specialise here |

**Takeaway:** Wazuh gives a SOC team the SIEM foundation and a solid set of endpoint controls for free. Many organisations run it alongside a commercial EDR, or add Sysmon and auditd telemetry to deepen endpoint visibility.

---

## 3. Project Overview

### Goals

- Build a working SIEM pipeline: endpoint, collection, analysis, storage, dashboard.
- Understand what each Wazuh component does and how they connect.
- Generate controlled attacks and learn what is, and is not, detected by default.
- Write, test and deploy a custom detection rule.
- Practise the analyst workflow: search, filter, triage and document.

### Skills demonstrated

| Area | Evidence in this lab |
|---|---|
| SIEM deployment | Wazuh server, indexer, dashboard and agent connected end to end |
| Network design | Isolated attacker, endpoint and SIEM network |
| Adversary simulation | Controlled SSH and scanning activity from Kali |
| Detection engineering | Custom rule written, tested and validated |
| SOC investigation | Search, filter, triage and document in the dashboard |
| Endpoint monitoring | File integrity monitoring on a test directory |

### The idea in one picture

```text
┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐
│   Attack  │  │    Log    │  │  Collect  │  │  Analyze  │  │   Store   │  │Investigate│
│    Kali   │─▶│   Ubuntu  │─▶│   agent   │─▶│  manager  │─▶│  indexer  │─▶│ dashboard │
└───────────┘  └───────────┘  └───────────┘  └───────────┘  └───────────┘  └───────────┘
```

---

## 4. Lab Architecture

```text
┌────────────────────────────────────────────────────────────────────┐
│ KALI LINUX (attacker)                     IP: <KALI_IP>            │
│ > ssh login failures, nmap port scans                              │
└────────────────────────────────────────────────────────────────────┘
                                   │  ATTACK: ssh, nmap
                                   ▼
┌────────────────────────────────────────────────────────────────────┐
│ UBUNTU (monitored endpoint)              IP: <UBUNTU_IP>           │
│ > wazuh-agent, sshd + auth.log, FIM test folder                    │
└────────────────────────────────────────────────────────────────────┘
                                   │  EVENTS: 1514/tcp, encrypted
                                   ▼
┌─ WAZUH SERVER (OVA)           IP: <WAZUH_IP> ──────────────────────┐
│  ┌──────────────┐        ┌──────────────┐        ┌──────────────┐  │
│  │   MANAGER    │filebeat│   INDEXER    │        │  DASHBOARD   │  │
│  │rules, alerts │───────▶│store, search │───────▶│ web UI :443  │  │
│  └──────────────┘        └──────────────┘        └──────────────┘  │
└────────────────────────────────────────────────────────────────────┘
                                                           ▲
                                                           │ HTTPS :443
                                         ┌──────────────────────────────────┐
                                         │ ANALYST: browser on Ubuntu host  │
                                         └──────────────────────────────────┘
```

| Role | Machine | Purpose |
|---|---|---|
| Attacker | Kali Linux (VirtualBox VM) | Generates scans and failed logins |
| Monitored endpoint | Ubuntu | Runs the Wazuh agent, SSH and authentication logs |
| SIEM | Wazuh OVA (VirtualBox VM) | Manager, Indexer and Dashboard in one appliance |
| Analyst workstation | Browser on the Ubuntu host | Opens `https://<WAZUH_IP>` |

Placeholders used throughout this document:

| Placeholder | Meaning |
|---|---|
| `<WAZUH_IP>` | IP address of the Wazuh server VM |
| `<UBUNTU_IP>` | IP address of the Ubuntu endpoint |
| `<KALI_IP>` | IP address of the Kali VM |
| `<UBUNTU_USERNAME>` | A user account on the Ubuntu endpoint |

---

## 5. Requirements

| Item | Details |
|---|---|
| Host OS | Ubuntu with VirtualBox 7.x |
| Wazuh VM | About 4 GB RAM and 2 or more vCPUs (follow the OVA documentation) |
| Kali VM | About 2 GB RAM |
| Disk | Around 50 GB free |
| Downloads | Wazuh OVA, Kali Linux VirtualBox image or ISO |

Tip: RAM is the usual bottleneck. Close heavy applications on the host while the lab runs.

---

## 6. Understanding Wazuh

Wazuh has four main components. Together they form a pipeline from the endpoint to the analyst.

```text
┌──────────────────────────────────────┐
│             WAZUH AGENT              │
│    logs, file changes, inventory     │
└──────────────────────────────────────┘
                    │  1514/tcp, encrypted
                    ▼
┌──────────────────────────────────────┐
│            WAZUH MANAGER             │
│  decode, match rules, raise alerts   │
└──────────────────────────────────────┘
                    │  Filebeat ships alerts
                    ▼
┌──────────────────────────────────────┐
│            WAZUH INDEXER             │
│       store and search alerts        │
└──────────────────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────┐
│           WAZUH DASHBOARD            │
│      web interface for analysts      │
└──────────────────────────────────────┘

Dashboard also calls the Manager API on 55000/tcp.
```

### 4.1 Wazuh Agent
Runs on each monitored endpoint. It reads log files, watches files for changes, inventories installed software, and sends everything to the manager over an encrypted connection.

### 4.2 Wazuh Manager
The brain of the system. It receives events from agents, decodes them, matches them against rules and generates alerts. It also exposes a REST API.

| Daemon | Role |
|---|---|
| `wazuh-remoted` | Receives events from agents |
| `wazuh-authd` | Enrolls and authenticates new agents |
| `wazuh-analysisd` | Decodes events, matches rules, creates alerts |
| `wazuh-syscheckd` | File integrity monitoring |
| `wazuh-modulesd` | Vulnerability detection, configuration assessment, cloud modules |
| `wazuh-execd` | Runs Active Response actions |
| `wazuh-apid` | REST API used by the dashboard |

### 4.3 Wazuh Indexer
A search and analytics engine based on OpenSearch. It stores alerts so they can be searched quickly. It is memory hungry, which is why RAM matters in a small lab.

### 4.4 Wazuh Dashboard
The web interface. Analysts use it to search alerts, check agents, view file integrity events, vulnerabilities, MITRE ATT&CK mappings and compliance reports.

### 4.5 Ports at a glance

| Port | Component | Purpose |
|---|---|---|
| 1514 | Manager | Agent event channel |
| 1515 | Manager | Agent enrollment |
| 55000 | Manager API | Used by the dashboard |
| 9200 | Indexer | Search and storage |
| 443 | Dashboard | Web interface |

### 4.6 Key vocabulary

| Term | Meaning |
|---|---|
| Decoder | Extracts fields (user, source IP, program) from a raw log line |
| Rule | Matches decoded fields and assigns an ID, a level and groups |
| Alert | An event that matched a rule at or above the alert threshold |
| Rule level | Severity from 0 (ignored) to 15 (critical) |

---

## 7. Dashboard Navigation Guide

Open the main menu (the hamburger icon at the top left) to reach every area of the Wazuh dashboard. Names and positions vary slightly between 4.x versions, but the structure below holds.

```text
Wazuh Dashboard
├── Overview
├── Explore
│   ├── Discover
│   ├── Dashboards
│   ├── Visualize
│   └── Reporting
├── Endpoint security
│   ├── Configuration Assessment
│   ├── Malware Detection
│   └── File Integrity Monitoring
├── Threat intelligence
│   ├── Threat Hunting
│   ├── Vulnerability Detection
│   └── MITRE ATT&CK
├── Security operations
│   └── PCI DSS, GDPR, HIPAA, NIST 800-53
├── Cloud security
│   └── Docker, AWS, Google Cloud, GitHub
├── Server management
│   ├── Endpoints Summary
│   ├── Rules, Decoders, CDB Lists, Groups
│   └── Status, Cluster, Statistics, Logs, Settings
├── Dashboard management
│   └── App Settings, Security
└── Indexer management
    └── Index Management, Dev Tools
```

### Tab-by-tab guide

| Menu area | Tab | What it is for | When you use it |
|---|---|---|---|
| Home | Overview | Summary of agents, alert volume and top modules | First look every day |
| Explore | **Discover** | Free-form search across all indexed alerts | Investigating a specific IP, user, rule or time window |
| Explore | **Dashboards** | Saved dashboards and visualizations | Building and viewing custom views |
| Explore | Visualize | Create charts from alert data | Custom reporting |
| Explore | Reporting | Export dashboards as reports | Sharing results |
| Endpoint security | Configuration Assessment | Hardening checks per endpoint | Spotting misconfigurations |
| Endpoint security | Malware Detection | Rootkit and anomaly findings | Checking for suspicious hidden artefacts |
| Endpoint security | **File Integrity Monitoring** | Added, modified and deleted files | Detecting unauthorised changes |
| Threat intelligence | **Threat Hunting** | Alert dashboard and event list per agent or overall | Daily triage and hunting |
| Threat intelligence | Vulnerability Detection | Known vulnerabilities in installed software | Patch prioritisation |
| Threat intelligence | MITRE ATT&CK | Alerts grouped by tactic and technique | Mapping detections to attacker behavior |
| Security operations | PCI DSS, GDPR, HIPAA, NIST 800-53 | Alerts mapped to compliance controls | Audit evidence |
| Cloud security | Docker, AWS, Google Cloud, GitHub | Cloud and container activity | Cloud monitoring |
| Server management | Endpoints Summary | List of agents, status, OS and version | Checking agent health |
| Server management | Rules | Browse built-in and custom rules | Reading what a rule matches |
| Server management | Decoders | Browse log parsing definitions | Understanding how fields are extracted |
| Server management | CDB Lists | Lookup lists used by rules | Allow lists and block lists |
| Server management | Groups | Agent groups and shared configuration | Applying settings to sets of agents |
| Server management | Status, Cluster, Statistics, Logs, Settings | Health, performance and configuration of the manager | Troubleshooting the server |
| Dashboard management | App Settings, Security | Dashboard configuration and API connection, users and roles | Fixing API errors, managing access |
| Indexer management | Index Management, Dev Tools | Index lifecycle and direct queries to the indexer | Advanced administration |

### The Discover tab in detail

Discover is where analysts spend most of their time.

```
┌──────────────────────────────────────────────────────────────┐
│ Index pattern: wazuh-alerts-*          Time range: Last 1 hr │
├──────────────────────────────────────────────────────────────┤
│ Search bar:  rule.groups: sshd and data.srcip: "<KALI_IP>"   │
├───────────────┬──────────────────────────────────────────────┤
│ Fields list   │  Histogram: alerts over time                 │
│ (left side)   ├──────────────────────────────────────────────┤
│ agent.name    │  Document table                              │
│ rule.id       │  time | agent.name | rule.id | description   │
│ rule.level    │  click a row to expand the full event        │
│ data.srcip    │                                              │
└───────────────┴──────────────────────────────────────────────┘
```

| Element | Use |
|---|---|
| Index pattern | `wazuh-alerts-*` holds alerts. `wazuh-archives-*` holds all events, only if archiving is enabled |
| Time picker | Always set this first. A wrong time range is the top reason for "missing" alerts |
| Search bar | Filter by field and value |
| Fields list | Click a field to see its top values, then add it as a column or filter |
| Document table | Click an event to expand it and read every field, including `full_log` |

### The Threat Hunting tab in detail

| Sub-tab | Shows |
|---|---|
| Dashboard | Charts of alert volume, top rules, top agents, MITRE tactics |
| Events | The alert list with filters, similar to Discover but with Wazuh-aware columns |

You can scope it to all agents or select one agent to see only that endpoint.

### Inside a single agent

Select an agent from **Endpoints Summary** to open its own view. Typical tabs are Inventory data (hardware, OS, packages, processes, ports), Configuration Assessment, File Integrity Monitoring, Vulnerability Detection and Threat Hunting, all filtered to that one machine. This is the closest Wazuh gets to an EDR-style single-host view.

---

## 8. Step 1: Install the Wazuh Server

The Wazuh server is delivered as a ready-made virtual appliance (OVA), so no manual installation of the components is required.

```text
┌──────────────────────────────────────┐
│ 1. Download the OVA (Wazuh docs)     │
├───────────────────▼──────────────────┤
│ 2. Import into VirtualBox            │
├───────────────────▼──────────────────┤
│ 3. Set RAM, CPU and network          │
├───────────────────▼──────────────────┤
│ 4. Start the VM and log in           │
├───────────────────▼──────────────────┤
│ 5. Note the VM IP address            │
├───────────────────▼──────────────────┤
│ 6. Open the dashboard in a browser   │
└──────────────────────────────────────┘
```

1. Download the Wazuh OVA from the official documentation: <https://documentation.wazuh.com/current/deployment-options/virtual-machine/virtual-machine.html>
2. In VirtualBox choose **File, Import Appliance**, select the `.ova` file and import.
3. Before first boot, open the VM settings and set RAM, CPU and the network adapter (see Step 2).
4. Start the VM and log in at the console. Default credentials vary by version, so use the ones in the official documentation and change them straight away.
5. Find the VM address:

```bash
ip a
```

6. On the Ubuntu host open `https://<WAZUH_IP>` in a browser and accept the self-signed certificate warning.

---

## 9. Step 2: Build the Lab Network

The goal is a private network where Kali, Ubuntu and Wazuh can reach each other and nothing else is exposed.

```text
┌─ Ubuntu host running VirtualBox ─────────────────────────────────────────┐
│                                                                          │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐               │
│   │   Kali VM    │    │  Ubuntu VM   │    │   Wazuh VM   │               │
│   └──────────────┘    └──────────────┘    └──────────────┘               │
│           │                   │                   │                      │
│           └───────────────────┼───────────────────┘                      │
│                               │                                          │
│   Host-only network (private): all three machines can reach each other   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘

Optional: a NAT adapter on Kali and Wazuh, for updates only
```

Steps (all in the VirtualBox graphical interface):

1. Open **File, Tools, Network Manager, Host-only Networks** and create a network if none exists.
2. For each VM open **Settings, Network** and set **Adapter 1** to **Host-only Adapter**.
3. If a VM needs internet access for updates, enable **Adapter 2** as **NAT**. Switch it off when not needed.
4. Start the VMs and confirm they can reach each other. From Kali:

```bash
ping -c 4 <UBUNTU_IP>
ping -c 4 <WAZUH_IP>
```

Four replies from each address means the network is ready.

---

## 10. Step 3: Connect the Ubuntu Endpoint

The Ubuntu machine needs the Wazuh agent so its logs reach the server.

```text
┌───────────────────────────────────────────────┐
│ Dashboard: Agents > Deploy new agent          │
├───────────────────────▼───────────────────────┤
│ Choose Linux, DEB. Enter server IP and name   │
├───────────────────────▼───────────────────────┤
│ Copy the generated command                    │
├───────────────────────▼───────────────────────┤
│ Paste it into the Ubuntu terminal             │
├───────────────────────▼───────────────────────┤
│ Start the agent service                       │
├───────────────────────▼───────────────────────┤
│ Agent shows Active in the dashboard           │
└───────────────────────────────────────────────┘
```

1. In the dashboard open **Agents, Deploy new agent**.
2. Choose **Linux** and **DEB**, enter `<WAZUH_IP>` as the server address and give the agent a name such as `ubuntu-lab`.
3. Copy the command the wizard generates and run it in a terminal on the Ubuntu endpoint.
4. Start the agent:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
```

5. Back in the dashboard open **Agents**. The status should read **Active**.

---

## 11. Step 4: Health Check

Confirm everything works before running any attack.

```text
┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐
│  Services  │──▶│   Agent    │──▶│    API     │──▶│   Events   │──▶│   Ready    │
└────────────┘   └────────────┘   └────────────┘   └────────────┘   └────────────┘
```

On the Wazuh server:

```bash
sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard
```

Each line should print `active`.

In the dashboard:

| Check | Where | Expected |
|---|---|---|
| Services | Server management, Status | All running |
| API connection | Dashboard settings, API configuration | Online |
| Agent | Agents | Active |
| Events | Discover | New events appear |

---

## 12. Step 5: Simulate Attacks from Kali

Two simple, safe simulations show the difference between activity that Wazuh detects out of the box and activity that needs extra telemetry.

```text
    Kali                 Ubuntu                 Wazuh                Analyst
      │                     │                     │                     │
      │ failed SSH logins   │                     │                     │
      ├────────────────────▶│                     │                     │
      │                     │                     │                     │
      │                     │ writes to auth.log  │                     │
      │                     │                     │                     │
      │                     │ agent forwards logs │                     │
      │                     ├────────────────────▶│                     │
      │                     │                     │                     │
      │                     │                     │ decode, match, alert│
      │                     │                     │                     │
      │                     │                     │ search alerts       │
      │                     │                     │◀────────────────────┤
      │                     │                     │                     │
      │                     │                     │ rule ID, level, IP  │
      │                     │                     ├────────────────────▶│
      │                     │                     │                     │
```

### 12.1 SSH authentication failures

**Objective:** generate failed logins and see them in Wazuh.

**Prerequisite:** the SSH server is installed and running on Ubuntu.

```bash
sudo apt install openssh-server -y
sudo systemctl enable --now ssh
```

From **Kali**, try to log in with a wrong password a few times, then with a user that does not exist:

```bash
ssh <UBUNTU_USERNAME>@<UBUNTU_IP>
ssh nosuchuser@<UBUNTU_IP>
```

On **Ubuntu**, confirm the log lines were written:

```bash
sudo grep -i "failed password\|invalid user" /var/log/auth.log | tail
```

Then continue to Step 6 to find the matching alerts in Wazuh.

### 12.2 Nmap port scan

**Objective:** run a basic scan against your own endpoint.

From **Kali**:

```bash
nmap <UBUNTU_IP>
nmap -sV <UBUNTU_IP>
```

The second command also identifies service versions.

**What to expect:** a default agent does not raise a port-scan alert, because a scan leaves very little in the endpoint's own logs. To detect scans you need extra telemetry, such as firewall logs or a network IDS like Suricata. That is a planned improvement (see the roadmap).

```text
Port scan
   │
   ▼
Is the traffic logged anywhere?
   │
   ├── No  (default setup) ───────▶ Nothing for Wazuh to analyze
   │
   └── Yes (firewall or IDS logs) ▶ Wazuh collects the logs
                                          │
                                          ▼
                                   Rule matches, alert raised
```

---

## 13. Step 6: Investigate in the Dashboard

### Where to look

| Goal | Dashboard location |
|---|---|
| Check agent status | Agents |
| Search events and alerts | Discover (or Threat Hunting, depending on version) |
| MITRE ATT&CK view | MITRE ATT&CK module |
| File changes | File Integrity Monitoring |
| Vulnerabilities | Vulnerability Detection |

### Fields worth knowing

| Field | Meaning |
|---|---|
| `agent.name` | Endpoint that produced the event |
| `rule.id` | Rule that matched |
| `rule.level` | Severity from 0 to 15 |
| `rule.description` | Plain-language name of the detection |
| `rule.groups` | Categories such as `sshd` or `authentication_failed` |
| `data.srcip` | Source IP address, when decoded |
| `full_log` | The original log line |

### Example searches

```
agent.name: "ubuntu-lab"
rule.groups: sshd
data.srcip: "<KALI_IP>"
rule.level >= 10
```

Field names can differ slightly between versions, so check them against a real event first.

### Investigation workflow

```text
┌──────────────────────────────────────────────────────┐
│ 1. Set the time range                                │
├───────────────────────────▼──────────────────────────┤
│ 2. Identify the affected endpoint                    │
├───────────────────────────▼──────────────────────────┤
│ 3. Filter by source IP and rule group                │
├───────────────────────────▼──────────────────────────┤
│ 4. Open an event: rule ID, level, raw log            │
├───────────────────────────▼──────────────────────────┤
│ 5. Check before and after: success after failures?   │
├───────────────────────────▼──────────────────────────┤
│ 6. Decide: false positive or real incident           │
├───────────────────────────▼──────────────────────────┤
│ 7. Document findings and next steps                  │
└──────────────────────────────────────────────────────┘
```

---

## 14. Events vs Alerts

A log line is not automatically an alert. Wazuh decides in stages.

```text
┌────────────────────────────────────────┐
│      Raw log line on the endpoint      │
└────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────┐
│           Agent forwards it            │
└────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────┐
│     Manager decodes it into fields     │
└────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────┐
│           Does a rule match?           │  ── No ──▶ Not alerted
└────────────────────────────────────────┘
                     │ Yes
                     ▼
┌────────────────────────────────────────┐
│   Level at or above alert threshold?   │  ── No ──▶ Not alerted
└────────────────────────────────────────┘
                     │ Yes
                     ▼
┌────────────────────────────────────────┐
│    Alert written, indexed, visible     │
└────────────────────────────────────────┘
```

| Term | Meaning |
|---|---|
| Raw log | A line written by a program on the endpoint |
| Event | The log line after the manager receives and decodes it |
| Alert | An event that matched a rule at or above the alert threshold |

---

## 15. Step 7: Write a Custom Detection Rule

Built-in rules cover common cases. Custom rules let you tune severity and add detections for your own environment.

```text
┌─────────────────────────────────────────┐
│ 1. Back up local_rules.xml              │
├────────────────────▼────────────────────┤
│ 2. Write the rule                       │
├────────────────────▼────────────────────┤
│ 3. Test with wazuh-logtest              │
├────────────────────▼────────────────────┤
│ 4. Validate: wazuh-analysisd -t         │
├────────────────────▼────────────────────┤
│ 5. Restart the manager                  │
├────────────────────▼────────────────────┤
│ 6. Trigger a live event                 │
├────────────────────▼────────────────────┤
│ 7. Confirm the alert in the dashboard   │
└─────────────────────────────────────────┘
```

Custom rules go in `/var/ossec/etc/rules/local_rules.xml` on the Wazuh server. Use rule IDs between 100000 and 120000.

**1. Back up the file**

```bash
sudo cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak
```

**2. Add a rule.** This example raises the severity when someone tries to log in with a non-existent user. It builds on the built-in rule 5710. Confirm that rule exists in your version first.

```xml
<group name="local,sshd,">
  <rule id="100100" level="10">
    <if_sid>5710</if_sid>
    <description>Custom: SSH login attempt using a non-existent user</description>
  </rule>
</group>
```

**3. Test it with a sample log line**

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste a real log line from the endpoint. The output shows which decoder and rule matched.

**4. Validate and apply**

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

**5. Trigger a fresh event** from Kali (`ssh nosuchuser@<UBUNTU_IP>`) and search for `rule.id: 100100` in the dashboard.

### Why three checks?

| Check | What it proves |
|---|---|
| `wazuh-logtest` matches | The rule logic works on a sample line |
| `wazuh-analysisd -t` passes | The rule files are valid |
| A live alert appears | The rule works end to end |

---

## 16. Step 8: File Integrity Monitoring

File Integrity Monitoring (FIM) reports when files are created, changed or deleted. Monitor specific directories rather than the whole filesystem to keep noise down.

```text
┌─────────────────────────────────────────┐
│ 1. Choose a folder to watch             │
├────────────────────▼────────────────────┤
│ 2. Add it to the agent configuration    │
├────────────────────▼────────────────────┤
│ 3. Restart the agent                    │
├────────────────────▼────────────────────┤
│ 4. Create, edit and delete a file       │
├────────────────────▼────────────────────┤
│ 5. FIM events appear in the dashboard   │
└─────────────────────────────────────────┘
```

On the Ubuntu endpoint, open `/var/ossec/etc/ossec.conf` and add this line inside the `<syscheck>` section:

```xml
<directories check_all="yes" realtime="yes">/home/<UBUNTU_USERNAME>/fim-test</directories>
```

Create the folder, restart the agent and make some changes:

```bash
mkdir ~/fim-test
sudo systemctl restart wazuh-agent
touch ~/fim-test/a.txt
echo "change" >> ~/fim-test/a.txt
rm ~/fim-test/a.txt
```

In the dashboard open the **File Integrity Monitoring** module. You should see the file added, modified and deleted.

---

## 17. Wazuh Feature Overview

```text
Wazuh
├── Detection
│   ├── Log analysis
│   ├── File integrity monitoring
│   ├── Rootkit and anomaly detection
│   └── Vulnerability detection
├── Posture
│   ├── Configuration assessment
│   ├── Regulatory compliance
│   └── Asset inventory
├── Response
│   ├── Active Response
│   └── REST API
└── Visibility
    ├── MITRE ATT&CK mapping
    ├── Cloud and container monitoring
    └── Dashboards
```

| Capability | Description |
|---|---|
| Log data analysis | Decoders and rules applied to system, application and security logs |
| File integrity monitoring | Detects creation, change and deletion of files |
| Vulnerability detection | Matches installed software against known vulnerabilities |
| Security configuration assessment | Checks endpoints against hardening benchmarks |
| Rootkit and anomaly detection | Looks for hidden files, processes and suspicious changes |
| Active Response | Runs scripted actions, such as blocking an IP, when a rule fires |
| MITRE ATT&CK mapping | Tags alerts with tactics and techniques |
| Regulatory compliance | Maps alerts to PCI DSS, GDPR, HIPAA, NIST 800-53 and others |
| Cloud and container monitoring | Collects logs from cloud platforms and container hosts |
| REST API | Manage agents, rules and configuration programmatically |

---

## 18. Troubleshooting

### When no alert appears

```text
No alert after a test
   │
   ▼
┌──────────────────────────────────────────┐
│     Is the log line on the endpoint?     │  ── No ──▶ Fix the test, check the service
└──────────────────────────────────────────┘
                      │ Yes
                      ▼
┌──────────────────────────────────────────┐
│  Is the agent Active, reading that log?  │  ── No ──▶ Fix agent or log source
└──────────────────────────────────────────┘
                      │ Yes
                      ▼
┌──────────────────────────────────────────┐
│     Does wazuh-logtest match a rule?     │  ── No ──▶ Add a decoder or a rule
└──────────────────────────────────────────┘
                      │ Yes
                      ▼
┌──────────────────────────────────────────┐
│    Level at or above alert threshold?    │  ── No ──▶ Raise the rule level
└──────────────────────────────────────────┘
                      │ Yes
                      ▼
┌──────────────────────────────────────────┐
│   Check time range, index and filters    │
└──────────────────────────────────────────┘
```

### Common issues

| Symptom | What to check |
|---|---|
| Dashboard rejects the default login | Credentials differ by version and OVA build. Check the official documentation for your version and the credentials file on the server |
| Indexer inactive or failed | Check its status and restart it. Low RAM is a common cause |
| Dashboard shows an API connection error | Confirm the manager is running, then check the API connection settings in the dashboard |
| Agent not Active | Confirm the agent service is running and the server IP is reachable |
| No new events | Check the dashboard time range and that the agent is connected |

Helpful commands on the Wazuh server:

```bash
sudo systemctl status wazuh-indexer
sudo systemctl restart wazuh-indexer
sudo tail -f /var/ossec/logs/ossec.log
```

---

## 19. From Home Lab to Enterprise

Everything in this lab maps directly to a production SOC. Production adds scale, process and governance.

```text
┌────────────────┐ ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
│ Linux servers  │ │ Windows hosts  │ │  Identity/SSO  │ │ Cloud and apps │
└────────────────┘ └────────────────┘ └────────────────┘ └────────────────┘
         │                  │                  │                  │
         └──────────────────┴────────┬─────────┴──────────────────┘
                                     │
                                     ▼
                 ┌──────────────────────────────────────┐
                 │ Wazuh agents and integrations        │
                 ├───────────────────▼──────────────────┤
                 │ Wazuh server cluster                 │
                 ├───────────────────▼──────────────────┤
                 │ Indexer cluster                      │
                 ├───────────────────▼──────────────────┤
                 │ Dashboard                            │
                 ├───────────────────▼──────────────────┤
                 │ SOC analysts: triage and escalate    │
                 ├───────────────────▼──────────────────┤
                 │ Incident response and documentation  │
                 └──────────────────────────────────────┘
```

| Area | Production practice |
|---|---|
| Agent management | Automated deployment, grouped configuration, health monitoring |
| Asset criticality | Tag servers, domain controllers and other critical systems so alerts are prioritized |
| Windows and identity | Windows Event Logs, Sysmon, directory and SSO logs |
| Cloud and applications | Cloud audit logs, web servers, databases |
| Tuning | Suppress known-good behavior, adjust levels, reduce false positives |
| Triage | Severity and confidence scoring, ticketing, escalation paths |
| Architecture | Clustered manager and indexer, retention policies, backups |
| SIEM security | Role-based access, TLS, audit logging, credential rotation |
| Active Response | Enable only after testing, with allow-lists, to avoid self-inflicted outages |
| Documentation | Every detection records its log source, logic, expected evidence, false positives and test method |

---

## 20. Roadmap

```text
┌──────────────────────────────────────────────────────┐
│ Phase 1  Lab build, agent, SSH detection             │
├───────────────────────────▼──────────────────────────┤
│ Phase 2  Custom rules, FIM                           │
├───────────────────────────▼──────────────────────────┤
│ Phase 3  Sudo, user creation, services, tasks        │
├───────────────────────────▼──────────────────────────┤
│ Phase 4  Port scan detection, web attack lab         │
├───────────────────────────▼──────────────────────────┤
│ Phase 5  Windows endpoint, Active Response, report   │
└──────────────────────────────────────────────────────┘
```

- [ ] Confirm all agents Active and the API connection stable
- [ ] Custom rules for repeated SSH failures and success after failures
- [ ] Sudo and privilege escalation detections
- [ ] User and group creation detection
- [ ] New service and scheduled task detection
- [ ] Port scan detection using firewall logs or Suricata
- [ ] Web attack simulation against a lab application such as DVWA
- [ ] Windows endpoint added to the lab
- [ ] Active Response test with a safety allow-list
- [ ] Full incident investigation write-up

---

## 21. Analyst Quick Reference

### Important files and folders

| Path | What it is |
|---|---|
| `/var/ossec/etc/ossec.conf` | Main configuration (manager or agent) |
| `/var/ossec/etc/rules/local_rules.xml` | Your custom rules |
| `/var/ossec/etc/decoders/local_decoder.xml` | Your custom decoders |
| `/var/ossec/ruleset/` | Built-in rules and decoders (do not edit) |
| `/var/ossec/logs/alerts/alerts.json` | Every alert, in JSON |
| `/var/ossec/logs/ossec.log` | Wazuh's own log, the first place to look when something breaks |

### Rule levels

| Level | Meaning |
|---|---|
| 0 | Ignored, no alert |
| 2 to 4 | Low priority notifications and errors |
| 5 to 7 | User errors, low relevance attacks |
| 8 to 10 | First-time events, invalid sources, repeated errors |
| 11 to 12 | Integrity warnings and high-importance events |
| 13 to 14 | Unusual errors and high-importance security events |
| 15 | Severe attack, act immediately |

By default, events at level 3 and above are written as alerts.

### Everyday commands

```bash
sudo /var/ossec/bin/wazuh-control status
sudo /var/ossec/bin/agent_control -l
sudo /var/ossec/bin/wazuh-logtest
sudo /var/ossec/bin/wazuh-analysisd -t
```

| Command | Purpose |
|---|---|
| `wazuh-control status` | Shows which Wazuh daemons are running |
| `agent_control -l` | Lists agents and their status |
| `wazuh-logtest` | Tests how a log line is decoded and which rule matches |
| `wazuh-analysisd -t` | Validates rules and configuration |

### Useful rule groups to search

| Group | Covers |
|---|---|
| `authentication_failed` | Failed logins |
| `sshd` | SSH activity |
| `syscheck` | File integrity monitoring events |
| `web` | Web server activity |
| `attack` | Rules flagged as attack patterns |

---

## 22. References

- Wazuh documentation: <https://documentation.wazuh.com>
- Wazuh ruleset and custom rules: <https://documentation.wazuh.com/current/user-manual/ruleset/index.html>
- MITRE ATT&CK: <https://attack.mitre.org>

---

**Author:** tas, [github.com/theatu1sin9h](https://github.com/theatu1sin9h)

Licensed for educational use. Provided as-is, without warranty.
