"""
TraceForge v2 — Network Packet Analysis Module
Parses PCAP and PCAPng files using Scapy.
Extracts DNS queries, HTTP requests, TCP flows, and suspicious connections.
"""

from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional
from loguru import logger

from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw
from scapy.layers import http

from traceforge.core.artifact import Artifact
from traceforge.core.hasher import compute_sha256
from traceforge.core.ledger import init_db, log_evidence


# Ports commonly associated with suspicious activity
SUSPICIOUS_PORTS = {
    4444, 4445, 1337, 31337, 8080, 8888,
    6666, 6667, 6668, 6669,  # IRC
    9001, 9030,               # Tor
    1080,                     # SOCKS proxy
}


def _ts_from_packet(pkt) -> str:
    """Extract ISO 8601 timestamp from a Scapy packet."""
    try:
        return datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def analyze(
    case_id: str,
    pcap_path: str,
    analyst: str,
    host_id: Optional[str] = None
) -> list[Artifact]:
    """
    Analyze a PCAP file and return a list of Artifact objects.

    Args:
        case_id   : The investigation case ID
        pcap_path : Path to the PCAP or PCAPng file
        analyst   : Analyst name or ID
        host_id   : Optional identifier for the captured host

    Returns:
        List of Artifact objects
    """
    init_db()
    path = Path(pcap_path)

    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    # Hash before analysis — chain of custody
    sha256, size = compute_sha256(path)
    log_evidence(case_id, analyst, str(path), sha256, size, "network")

    logger.info(f"Analyzing PCAP: {path.name} | Case: {case_id}")

    packets = rdpcap(str(path))
    logger.info(f"Loaded {len(packets)} packets")

    artifacts = []
    tcp_flows: dict[tuple, dict] = defaultdict(lambda: {"bytes": 0, "packets": 0, "start": None})
    host = host_id or "unknown"

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ts = _ts_from_packet(pkt)

        # DNS queries
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            dns = pkt[DNS]
            if dns.qr == 0:  # Query
                query_name = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                artifacts.append(Artifact(
                    case_id=case_id,
                    source_module="network",
                    artifact_type="dns_query",
                    host_id=host or src_ip,
                    timestamp=ts,
                    data={
                        "query": query_name,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "query_type": "A"
                    }
                ))

            elif dns.qr == 1 and dns.ancount > 0:  # Response
                try:
                    query_name = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                    answer = pkt[DNSRR].rdata if pkt.haslayer(DNSRR) else "unknown"
                    artifacts.append(Artifact(
                        case_id=case_id,
                        source_module="network",
                        artifact_type="dns_query",
                        host_id=host or src_ip,
                        timestamp=ts,
                        data={
                            "query": query_name,
                            "response": str(answer),
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "type": "response"
                        }
                    ))
                except Exception:
                    pass

        # HTTP requests
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            raw = pkt[Raw].load
            try:
                decoded = raw.decode("utf-8", errors="replace")
                if decoded.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                    lines = decoded.split("\r\n")
                    method_path = lines[0].split(" ")
                    method = method_path[0] if len(method_path) > 0 else "UNKNOWN"
                    uri = method_path[1] if len(method_path) > 1 else "/"
                    host_header = next(
                        (l.split(": ", 1)[1] for l in lines if l.lower().startswith("host:")),
                        dst_ip
                    )
                    artifacts.append(Artifact(
                        case_id=case_id,
                        source_module="network",
                        artifact_type="http_request",
                        host_id=host or src_ip,
                        timestamp=ts,
                        data={
                            "method": method,
                            "uri": uri,
                            "host": host_header,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": pkt[TCP].dport
                        }
                    ))
            except Exception:
                pass

        # TCP flow tracking
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            flow_key = (src_ip, dst_ip, sport, dport)
            flow = tcp_flows[flow_key]
            flow["bytes"] += len(pkt)
            flow["packets"] += 1
            if flow["start"] is None:
                flow["start"] = ts
            flow["last"] = ts
            flow["src_ip"] = src_ip
            flow["dst_ip"] = dst_ip
            flow["sport"] = sport
            flow["dport"] = dport

    # Convert TCP flows to artifacts
    for flow_key, flow in tcp_flows.items():
        src_ip, dst_ip, sport, dport = flow_key
        is_suspicious = dport in SUSPICIOUS_PORTS or sport in SUSPICIOUS_PORTS

        artifacts.append(Artifact(
            case_id=case_id,
            source_module="network",
            artifact_type="suspicious_connection" if is_suspicious else "tcp_flow",
            host_id=host or src_ip,
            timestamp=flow.get("start", ""),
            data={
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": sport,
                "dst_port": dport,
                "total_bytes": flow["bytes"],
                "total_packets": flow["packets"],
                "first_seen": flow.get("start", ""),
                "last_seen": flow.get("last", ""),
                "suspicious": is_suspicious
            }
        ))

        if is_suspicious:
            logger.warning(
                f"Suspicious connection: {src_ip}:{sport} -> {dst_ip}:{dport}"
            )

    logger.info(f"Network analysis complete: {len(artifacts)} artifacts found")
    return artifacts
