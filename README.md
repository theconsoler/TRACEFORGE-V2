<div align="center">

```
████████╗██████╗  █████╗  ██████╗███████╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
   ██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
   ██║   ██████╔╝███████║██║     █████╗  █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
   ██║   ██║  ██║██║  ██║╚██████╗███████╗██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

**Digital Forensics & Incident Response Toolkit**

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Ubuntu%2022.04-orange?style=flat-square&logo=ubuntu)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-36%20Passing-success?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Supported-blue?style=flat-square&logo=docker)

*A modular DFIR toolkit built for students learning incident response and professionals conducting real investigations.*

</div>

---

## What is TraceForge v2?

TraceForge v2 is an open-source Digital Forensics and Incident Response toolkit that unifies memory forensics, disk analysis, log correlation, and network packet analysis under one roof — with a proper chain-of-custody evidence ledger, a cross-module correlation engine, and a web dashboard for case management.

Built from scratch as a research project during B.Tech Cybersecurity studies at Sri Sri University. The v1 skeleton was built in 7th semester and never shipped. v2 is the real thing.

---

## Features

- **Memory Forensics** — Volatility3 Python API integration. Runs PsList, NetStat, and CmdLine plugins directly against memory dumps without subprocess calls
- **Disk Analysis** — dfVFS-powered disk image traversal with file timeline extraction and deleted file detection. Filesystem fallback for accessible directories
- **Log Correlation** — Multi-format log parser for auth.log, syslog, and EVTX. Automatic brute force detection with configurable threshold
- **Network Analysis** — Scapy-based PCAP parsing. Extracts DNS queries, HTTP requests, TCP flow reconstruction, and flags suspicious ports (4444, 1337, 31337 etc.)
- **Chain of Custody** — SHA-256 evidence hashing before analysis begins. Append-only SQLite ledger with analyst ID, timestamp, and file metadata
- **Cross-Module Correlation** — Links artifacts across all four modules by timestamp proximity and IP/host matching. Confidence-scored results
- **IOC Timeline** — Unified chronological timeline across all evidence sources with severity classification (critical/high/medium/low/info)
- **Report Generation** — JSON, HTML, and PDF reports from a single command. Dark-themed HTML reports with evidence ledger, correlation findings, and full timeline
- **Web Dashboard** — Flask dashboard for case management, filterable timeline view, correlation graph, and one-click report export
- **Interactive Launcher** — ASCII banner with live database stats and a numbered quick-start menu
- **Docker Support** — Dockerfile and docker-compose for portable deployment

---

## Stack

| Component | Technology |
|---|---|
| Language | Python 3.11 |
| Memory Forensics | Volatility3 |
| Disk Analysis | dfVFS |
| Network Analysis | Scapy |
| Web Dashboard | Flask + Jinja2 |
| Database | SQLite |
| CLI | Click + Rich |
| Reporting | WeasyPrint + Jinja2 |
| Logging | Loguru |
| Testing | pytest (36 tests) |
| Deployment | Docker + docker-compose |
| OS | Ubuntu 22.04 LTS |

---

## Installation

### Requirements

- Ubuntu 22.04 LTS
- Python 3.11
- Git

### Setup

```bash
# Clone the repository
git clone https://github.com/theconsoler/TRACEFORGE-V2.git
cd TRACEFORGE-V2

# Install system dependencies
sudo apt install -y \
  build-essential python3.11 python3.11-venv python3.11-dev \
  git tshark sleuthkit libewf-dev libvhdi-dev libvmdk-dev \
  libbde-dev libsmdev-dev libffi-dev libssl-dev pkg-config

# Add yourself to wireshark group for packet capture
sudo usermod -aG wireshark $USER && newgrp docker

# Create and activate virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Verify installation
python -c "import volatility3, scapy, flask, click, rich; print('ALL OK')"
```

### Docker (alternative)

```bash
docker build -t traceforge:v2 .
docker run --rm -v ~/evidence:/traceforge/samples traceforge:v2 --help
```

---

## Usage

### Interactive Launcher (recommended)

```bash
source venv/bin/activate
python -m traceforge
```

The launcher shows live case stats, recent cases, and a numbered menu for all workflows.

### CLI

```bash
source venv/bin/activate

# Create a new case
python -m traceforge.cli case new \
  --id CASE-2026-001 \
  --name "Server Compromise Investigation" \
  --analyst theconsoler

# Analyze evidence
python -m traceforge.cli analyze --case CASE-2026-001 --module logs    --file /path/to/auth.log     --analyst theconsoler
python -m traceforge.cli analyze --case CASE-2026-001 --module network --file /path/to/capture.pcap --analyst theconsoler
python -m traceforge.cli analyze --case CASE-2026-001 --module disk    --file /path/to/disk.dd      --analyst theconsoler
python -m traceforge.cli analyze --case CASE-2026-001 --module memory  --file /path/to/memory.raw   --analyst theconsoler

# Run cross-module correlation
python -m traceforge.cli correlate --case CASE-2026-001

# Generate report (JSON + HTML + PDF)
python -m traceforge.cli report --case CASE-2026-001 --format all
```

### Web Dashboard

```bash
# Terminal 1 — run investigations
python -m traceforge

# Terminal 2 — view results in browser
python -m dashboard.app
# Open: http://127.0.0.1:5000
```

---

## Project Structure

```
traceforge/
├── traceforge/
│   ├── cli.py                  # Click CLI entry point
│   ├── launcher.py             # Interactive launcher
│   ├── core/
│   │   ├── ledger.py           # SQLite evidence ledger
│   │   ├── hasher.py           # SHA-256 pre-analysis hashing
│   │   ├── artifact.py         # Standardised artifact schema
│   │   ├── store.py            # Artifact persistence
│   │   ├── correlator.py       # Cross-module correlation engine
│   │   ├── timeline.py         # IOC timeline generator
│   │   └── report.py           # JSON/HTML/PDF report generator
│   └── modules/
│       ├── memory.py           # Volatility3 memory forensics
│       ├── disk.py             # dfVFS disk image analysis
│       ├── logs.py             # Log correlation
│       └── network.py          # Scapy network analysis
├── dashboard/
│   ├── app.py                  # Flask dashboard
│   └── templates/              # Jinja2 HTML templates
├── tests/
│   ├── test_phase1.py          # 13 tests — ledger, hasher, schema
│   ├── test_phase2.py          # 9 tests  — analysis modules
│   └── test_phase3.py          # 14 tests — store, correlator, timeline, reports
├── reports/                    # Generated case reports
├── samples/                    # Evidence samples for testing
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Running Tests

```bash
source venv/bin/activate
python -m pytest tests/ -v
```

Expected: **36 tests passing** across all three test files.

---

## How It Works

```
Evidence File (memory dump / disk image / log / PCAP)
        ↓
SHA-256 Hash recorded in evidence ledger BEFORE analysis
        ↓
Analysis module runs and returns standardised Artifact objects
        ↓
Artifacts stored in SQLite database
        ↓
Correlation engine links artifacts across modules
by timestamp proximity and IP/host matching
        ↓
IOC Timeline built from all artifacts sorted chronologically
        ↓
Report generated: JSON + HTML + PDF
        ↓
Dashboard displays cases, timeline, correlations, export buttons
```

---

## Supported Evidence Formats

| Module | Formats |
|---|---|
| Memory | .raw, .mem, .lime, .vmem |
| Disk | .dd, .E01, .vmdk, .vhd (via dfVFS) |
| Logs | auth.log, syslog, .log, EVTX |
| Network | .pcap, .pcapng |

---

## Built By

**theconsoler** — Final year B.Tech Cybersecurity student at Sri Sri University.
Specialising in threat detection engineering, DFIR toolkit development, ML-based intrusion detection, and SIEM/log monitoring.

- GitHub: [github.com/theconsoler](https://github.com/theconsoler)
- Project: [TRACEFORGE-V2](https://github.com/theconsoler/TRACEFORGE-V2)

---

## Disclaimer

TraceForge v2 is built for legitimate digital forensics and incident response work, security research, and educational purposes. Always ensure you have proper authorization before analyzing any evidence. The author is not responsible for misuse.

---

<div align="center">
<i>Stay sharp. Stay forensic.</i>
</div>
