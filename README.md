<div align="center">

```
████████╗██████╗  █████╗  ██████╗███████╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
   ██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
   ██║   ██████╔╝███████║██║     █████╗  █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
   ██║   ██║  ██║██║  ██║╚██████╗███████╗██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

**Digital Forensics & Incident Response Toolkit — v2.0.0**

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Ubuntu%2022.04-orange?style=flat-square&logo=ubuntu)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-36%20Passing-success?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Supported-blue?style=flat-square&logo=docker)

*A modular DFIR toolkit built for students learning incident response and professionals conducting real investigations.*

</div>

---

## The Story Behind TraceForge

<<<<<<< HEAD
During real-world incident response, analysts are forced to use 4 to 5 separate tools just to gather and analyze evidence from a single investigation. One tool for memory forensics. Another for disk images. A third for log correlation. A fourth for PCAP analysis. None of them talk to each other. None of them share a common evidence format. And none of them enforce proper chain-of-custody tracking.
=======
TraceForge v2 is an open-source Digital Forensics and Incident Response toolkit that unifies memory forensics, disk analysis, log correlation, and network packet analysis under one roof with a proper chain-of-custody evidence ledger, a cross-module correlation engine, and a web dashboard for case management.
>>>>>>> 281627f65bca1e40379bb6c6d101b7e854584afb

TraceForge v2 was built to fix that.

The idea started in 7th semester as a research project — a DFIR toolkit that could serve both students learning incident response fundamentals and professionals who need a reliable, unified framework for real investigations. A demo skeleton was built at the time but never shipped beyond a proof of concept.

v2 is the complete rebuild. Every module is functional. Every artifact is hashed before analysis. Every finding is stored in a standardized format that the correlation engine can reason across. The entire pipeline from evidence ingestion to PDF report generation works end to end.

---

## What TraceForge v2 Actually Does

When a security incident happens — a server gets compromised, malware executes on a workstation, an attacker brute forces SSH — an investigator needs to answer several questions fast: What processes were running? Were there outbound connections to suspicious IPs? Were there failed login attempts followed by a successful one? Were any files deleted? What happened and in what order?

TraceForge v2 answers all of these questions from a single toolkit:

**1. Evidence is ingested with integrity.** Before any module touches an evidence file, TraceForge computes a SHA-256 hash of the raw file and records it in an append-only SQLite ledger along with the analyst name, timestamp, case ID, and file path. This hash cannot be modified after it is written. This is chain of custody — if the file is tampered with after ingestion, the hash will no longer match and the integrity violation is immediately detectable.

**2. Four modules analyze different evidence sources.** The memory module uses Volatility3's Python API directly — not a subprocess call — to run forensic plugins against memory dumps and extract running processes, active network connections, and command line arguments. The disk module uses dfVFS to traverse disk images and extract file timelines, metadata, and deleted file markers. The log module parses Linux authentication logs and detects suspicious patterns including brute force attacks. The network module uses Scapy to parse PCAP captures and reconstruct DNS queries, HTTP requests, and TCP flows, flagging connections to known suspicious ports.

**3. All findings are stored in a standardized format.** Every module returns Artifact objects — a common dataclass with fields for timestamp, source module, host identifier, artifact type, and data. This standardization is what makes cross-module correlation possible.

**4. The correlation engine links evidence across sources.** Once all modules have run, the correlation engine queries all artifacts and finds connections. A process seen in memory forensics that opened a socket matching a connection seen in PCAP analysis. A brute force source IP appearing in both log analysis and network analysis. A successful login in auth.log followed 10 seconds later by a suspicious outbound connection in the network capture. These connections are what incident response is actually about — TraceForge finds them automatically.

**5. A unified IOC timeline is built.** All artifacts from all modules are merged and sorted chronologically into a single timeline. Each event is tagged with its source module and a severity level — critical, high, medium, low, or informational. Correlation links are annotated inline. This timeline is the primary deliverable of any investigation.

**6. Reports are generated in three formats.** The report generator produces JSON for machine consumption and integration with other tools, HTML with a professional dark-themed layout for investigators, and PDF via WeasyPrint for formal case documentation — all from a single command.

**7. A web dashboard visualizes everything.** The Flask dashboard reads directly from the same SQLite database that the CLI writes to. Cases appear automatically. The timeline view is filterable by module and severity. The correlations page shows all cross-module links with confidence scores. Reports can be exported with a single button click.

---

## Features

- **Memory Forensics** — Volatility3 Python API integration running PsList, NetStat, and CmdLine plugins directly against .raw, .mem, .lime, and .vmem memory images without subprocess overhead
- **Disk Analysis** — dfVFS-powered disk image traversal supporting .dd, .E01, .vmdk, and .vhd formats. Extracts file timelines with created/modified/accessed timestamps and flags deleted files. Filesystem fallback mode for accessible directories
- **Log Correlation** — Multi-format log parser supporting auth.log, syslog, and structured log files. Extracts failed logins, successful logins, sudo commands, and service events. Automatic brute force detection flags any IP generating 5 or more failed login attempts
- **Network Analysis** — Scapy-based PCAP parsing with DNS query extraction, HTTP request reconstruction (method, host, URI), TCP flow tracking (src/dst IP, ports, bytes transferred), and automatic flagging of connections to suspicious ports including 4444, 1337, 31337, and known Tor relay ports
- **Chain of Custody** — SHA-256 evidence hashing before any analysis begins. Append-only SQLite ledger records analyst ID, timestamp, case ID, file path, hash, and file size. A verify function re-hashes files at any point to detect tampering
- **Cross-Module Correlation** — Confidence-scored correlation results using two strategies: timestamp proximity links artifacts from different modules that occurred within a configurable window (default 30 seconds), and IP/host matching links artifacts that share the same IP address or host identifier across evidence sources
- **IOC Timeline** — Unified chronological timeline across all evidence sources. Severity classification maps artifact types to critical/high/medium/low/info. Correlation links annotated inline on each event
- **Report Generation** — JSON, HTML, and PDF reports from a single function call. HTML reports include evidence ledger with full SHA-256 hashes, artifact counts by module, correlation findings with confidence scores, and the complete IOC timeline
- **Web Dashboard** — Flask dashboard with case list, case overview, filterable timeline, correlation findings view, and one-click report export in all three formats. Reads directly from SQLite — no sync required
- **Interactive Launcher** — Full-screen terminal launcher with ASCII banner, live database stats (total cases, total artifacts, today's date), recent cases table, and colour-coded numbered menu covering all workflows
- **Full Pipeline Mode** — Single guided workflow that walks from case creation through evidence analysis, correlation, and report generation without switching between commands
- **Docker Support** — Dockerfile and docker-compose.yml for portable deployment. The CLI and dashboard run as separate containers sharing a volume-mounted SQLite database

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Evidence Input Layer                     │
│   .raw/.mem/.lime    .dd/.E01/.vmdk    auth.log    .pcap     │
└────────────┬──────────────┬───────────────┬─────────┬───────┘
             │              │               │         │
             ↓              ↓               ↓         ↓
┌────────────────────────────────────────────────────────────┐
│                  Evidence Ledger (SQLite)                   │
│   SHA-256 hash recorded BEFORE analysis · append-only      │
│   case_id · analyst · file_path · hash · timestamp         │
└─────────────────────────┬──────────────────────────────────┘
                          │
             ┌────────────┼────────────┐
             ↓            ↓            ↓            ↓
      ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
      │  Memory  │ │   Disk   │ │   Logs   │ │ Network  │
      │Volatility│ │  dfVFS   │ │  Regex   │ │  Scapy   │
      │    3     │ │          │ │  Parser  │ │          │
      └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘
           │            │            │             │
           └────────────┴────────────┴─────────────┘
                                │
                         Artifact Objects
                  (timestamp · module · host · data)
                                │
                                ↓
              ┌─────────────────────────────────┐
              │   Cross-Module Correlation       │
              │   Timestamp proximity (30s)      │
              │   IP / Host matching             │
              └──────────────┬──────────────────┘
                             │
                             ↓
              ┌─────────────────────────────────┐
              │       IOC Timeline               │
              │   Chronological · Severity-tagged│
              │   Correlation links annotated    │
              └──────────────┬──────────────────┘
                             │
               ┌─────────────┼─────────────┐
               ↓             ↓             ↓
            JSON           HTML           PDF
                             │
                             ↓
              ┌─────────────────────────────────┐
              │       Flask Dashboard            │
              │   Cases · Timeline · Report      │
              └─────────────────────────────────┘
```

---

## Stack

| Component | Technology |
|---|---|
| Language | Python 3.11 |
| Memory Forensics | Volatility3 (Python API) |
| Disk Analysis | dfVFS |
| Network Analysis | Scapy |
| Web Dashboard | Flask + Jinja2 |
| Database | SQLite (append-only ledger) |
| CLI | Click + Rich |
| Reporting | WeasyPrint + Jinja2 |
| Logging | Loguru |
| Testing | pytest — 36 tests |
| Deployment | Docker + docker-compose |
| Target OS | Ubuntu 22.04 LTS |

---

## Installation

### Requirements

- Ubuntu 22.04 LTS (bare metal, VM, or WSL2)
- Python 3.11
- Git

### Step by step

```bash
# 1. Clone the repository
git clone https://github.com/theconsoler/TRACEFORGE-V2.git
cd TRACEFORGE-V2

# 2. Install system-level dependencies
sudo apt install -y \
  build-essential python3.11 python3.11-venv python3.11-dev \
  git tshark sleuthkit libewf-dev libvhdi-dev libvmdk-dev \
  libbde-dev libsmdev-dev libffi-dev libssl-dev pkg-config \
  libpango-1.0-0 libpangoft2-1.0-0

# 3. Add yourself to the wireshark group for packet capture
sudo usermod -aG wireshark $USER && newgrp wireshark

# 4. Create and activate virtual environment
python3.11 -m venv venv
source venv/bin/activate

# 5. Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 6. Verify all imports
python -c "import volatility3, scapy, flask, click, rich, loguru, jinja2, weasyprint, pytest; print('ALL OK')"
```

### Docker

```bash
docker build -t traceforge:v2 .

# Run CLI
docker run --rm \
  -v ~/evidence:/traceforge/samples \
  -v ~/reports:/traceforge/reports \
  traceforge:v2 --help

# Run dashboard
docker-compose up traceforge-dashboard
# Open: http://127.0.0.1:5000
```

---

## Usage

### Interactive Launcher

The recommended way to use TraceForge. Gives you live stats, recent cases, and a guided menu.

```bash
source venv/bin/activate
python -m traceforge
```

### CLI — Full Investigation Workflow

```bash
source venv/bin/activate

# Step 1 — Create a case
python -m traceforge.cli case new \
  --id CASE-2026-001 \
  --name "Server Compromise Investigation" \
  --analyst theconsoler

# Step 2 — Analyze evidence (run any combination of modules)
python -m traceforge.cli analyze \
  --case CASE-2026-001 --module logs \
  --file /path/to/auth.log --analyst theconsoler --host server-01

python -m traceforge.cli analyze \
  --case CASE-2026-001 --module network \
  --file /path/to/capture.pcap --analyst theconsoler --host 192.168.1.10

python -m traceforge.cli analyze \
  --case CASE-2026-001 --module disk \
  --file /path/to/disk.dd --analyst theconsoler --host workstation-01

python -m traceforge.cli analyze \
  --case CASE-2026-001 --module memory \
  --file /path/to/memory.raw --analyst theconsoler --host workstation-01

# Step 3 — Run cross-module correlation
python -m traceforge.cli correlate --case CASE-2026-001

# Step 4 — Generate report
python -m traceforge.cli report --case CASE-2026-001 --format all

# Step 5 — View in browser
python -m dashboard.app
# Open: http://127.0.0.1:5000
```

### Case Management

```bash
python -m traceforge.cli case list
python -m traceforge.cli case info CASE-2026-001
```

---

## Project Structure

```
TRACEFORGE-V2/
├── traceforge/
│   ├── __init__.py
│   ├── __main__.py             # python -m traceforge entry point
│   ├── cli.py                  # Click CLI — all subcommands
│   ├── launcher.py             # Interactive ASCII launcher
│   └── core/
│   │   ├── ledger.py           # Append-only SQLite evidence ledger
│   │   ├── hasher.py           # SHA-256 pre-analysis hashing
│   │   ├── artifact.py         # Standardised artifact dataclass
│   │   ├── store.py            # Artifact persistence layer
│   │   ├── correlator.py       # Cross-module correlation engine
│   │   ├── timeline.py         # IOC timeline generator
│   │   └── report.py           # JSON / HTML / PDF report generator
│   └── modules/
│       ├── memory.py           # Volatility3 memory forensics
│       ├── disk.py             # dfVFS disk image analysis
│       ├── logs.py             # Log correlation + brute force detection
│       └── network.py          # Scapy PCAP analysis
├── dashboard/
│   ├── app.py                  # Flask web application
│   ├── __init__.py
│   └── templates/
│       ├── base.html           # Base layout with nav
│       ├── index.html          # Case list home page
│       ├── case.html           # Case overview
│       ├── timeline.html       # Filterable IOC timeline
│       └── correlations.html   # Correlation findings
├── tests/
│   ├── test_phase1.py          # 13 tests — ledger, hasher, artifact schema
│   ├── test_phase2.py          # 9 tests  — all four analysis modules
│   └── test_phase3.py          # 14 tests — store, correlator, timeline, reports
├── data/                       # SQLite database (gitignored)
├── reports/                    # Generated case reports (gitignored)
├── samples/                    # Evidence samples for testing (gitignored)
├── docs/
│   ├── TRACEFORGE_V2_PHASE0.md
│   ├── TRACEFORGE_V2_PHASE1.md
│   ├── TRACEFORGE_V2_PHASE2.md
│   ├── TRACEFORGE_V2_PHASE3.md
│   └── TRACEFORGE_V2_PHASE4.md
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Supported Evidence Formats

| Module | Supported Formats | What It Extracts |
|---|---|---|
| Memory | .raw .mem .lime .vmem | Running processes, network connections, command lines |
| Disk | .dd .E01 .vmdk .vhd | File timelines, deleted files, MFT/inode metadata |
| Logs | auth.log syslog .log | Failed logins, successful logins, sudo commands, brute force |
| Network | .pcap .pcapng | DNS queries, HTTP requests, TCP flows, suspicious connections |

---

## Running Tests

```bash
source venv/bin/activate
python -m pytest tests/ -v
```

```
tests/test_phase1.py  — 13 passed   ledger, hasher, artifact schema
tests/test_phase2.py  —  9 passed   logs, network, disk, memory modules
tests/test_phase3.py  — 14 passed   store, correlator, timeline, reports

36 passed
```

---

## Correlation Engine — How It Works

The correlation engine is what makes TraceForge more than a collection of separate scripts. After all modules have run, it loads all artifacts for a case from the database and finds cross-module connections using two strategies:

**Timestamp Proximity** — Finds artifacts from different modules that occurred within a configurable time window of each other (default 30 seconds). A failed login in auth.log at 10:00:00 and a suspicious outbound connection in PCAP at 10:00:05 are linked with a confidence score based on how close in time they occurred.

**IP and Host Matching** — Finds artifacts from different modules that reference the same IP address or host identifier. A brute force source IP appearing in both log analysis and network PCAP analysis confirms the attacker's identity across two independent evidence sources.

Each correlation result has a confidence score from 0.0 to 1.0, a link type, and a human-readable description. Results are deduplicated and sorted by confidence descending.

---

## Chain of Custody — How It Works

Forensic integrity is not optional. TraceForge enforces it at the code level:

1. When an evidence file is ingested via `traceforge analyze` or `traceforge ingest`, the SHA-256 hash is computed on the raw file using chunked 64KB reads before any module runs
2. The hash, analyst name, timestamp, case ID, file path, and file size are written to the `evidence_log` table in SQLite
3. The `evidence_log` table has no UPDATE or DELETE operations in the codebase — it is append-only by design
4. At any point after ingestion, `verify_hash()` can re-hash the file and compare against the stored value to detect tampering
5. Every report includes the full evidence ledger with SHA-256 hashes for formal documentation

---

## Build History

TraceForge v2 was built across four phases, each gate-checked before the next began:

| Phase | What Was Built | Tests |
|---|---|---|
| Phase 0 | Environment, dependencies, project scaffold | — |
| Phase 1 | Evidence ledger, SHA-256 hasher, artifact schema, CLI skeleton | 13 |
| Phase 2 | Memory, disk, log, and network analysis modules | 22 |
| Phase 3 | Artifact store, correlation engine, IOC timeline, report generator | 36 |
| Phase 4 | Flask dashboard, Docker deployment, interactive launcher | 36 |

---

## Who This Is For

**Students** learning digital forensics can use TraceForge to understand how real IR investigations work end to end — from evidence hashing through artifact analysis, correlation, and reporting — using a single unified tool with readable Python code throughout.

**Professionals** doing incident response work can use TraceForge as a lightweight investigation framework that enforces chain of custody, produces properly formatted reports, and correlates findings across evidence sources automatically.

**Researchers** studying detection engineering or forensic tooling can extend TraceForge by adding new modules — the artifact schema and store layer make it straightforward to plug in new evidence sources while keeping correlation and reporting working automatically.

---

## Built By

**theconsoler** — Final year B.Tech Cybersecurity student at Sri Sri University.

Specialising in threat detection engineering, DFIR toolkit development, ML-based network intrusion detection, and SIEM/log monitoring. Led development of IntrusionIQ (AI-powered network intrusion detection system using Random Forest at 98.84% accuracy) and TraceForge v2 as capstone research projects.

- GitHub: [github.com/theconsoler](https://github.com/theconsoler)
- IntrusionIQ: [github.com/theconsoler/IntrusionIQ](https://github.com/theconsoler/IntrusionIQ)

---

## Disclaimer

TraceForge v2 is intended for legitimate digital forensics, incident response work, security research, and educational purposes only. Always ensure you have proper legal authorization before collecting or analyzing any evidence. The author is not responsible for misuse of this tool.

---

<div align="center">
<i>Stay sharp. Stay forensic.</i>
<br><br>
<b>github.com/theconsoler/TRACEFORGE-V2</b>
</div>
