# TraceForge v2

> Digital Forensics & Incident Response Toolkit

A modular, open-source DFIR toolkit built for students learning 
incident response and professionals conducting real investigations.

## What it does

- Memory forensics via Volatility3 Python API
- Disk image analysis via dfVFS
- Log correlation across syslog, auth.log and Windows EVTX
- Network PCAP analysis via Scapy
- Cross-module correlation engine linking artifacts by timestamp and host
- Append-only SQLite evidence ledger with SHA-256 pre-analysis hashing
- Flask web dashboard for case management and timeline visualization
- JSON, HTML and PDF report export

## Stack

Python 3.11 · Volatility3 · dfVFS · Scapy · Flask · SQLite · Docker

## Status

🔨 Active development — Phase 0 complete, building Phase 1

## BUILDING ON OS

Ubuntu 22.04 LTS

## Coming soon

Full installation guide, Docker support, and sample evidence files 
for testing each module.
