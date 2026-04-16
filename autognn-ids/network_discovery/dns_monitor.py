"""
DNS Monitor
Parses DNS query logs from BIND9, dnsmasq, Unbound, or sample data.
Can also passively sniff DNS traffic on port 53 using Scapy.
Detects DGA domains, DNS tunneling, C2 beaconing, and recon sweeps.
"""
import json
import re
import math
import logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Optional

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import LOG_PATHS, DISCOVERY_CONFIG

logger = logging.getLogger("autognn.dns")


# Regex patterns for common DNS server log formats
DNS_LOG_PATTERNS = {
    # BIND9: client 192.168.1.10#49152 (google.com): query: google.com IN A +
    "bind9": re.compile(
        r"client\s+([\d.]+)#\d+\s+\(([^)]+)\):\s+query:\s+(\S+)\s+IN\s+(\S+)"
    ),
    # dnsmasq: query[A] google.com from 192.168.1.10
    "dnsmasq": re.compile(
        r"query\[(\w+)\]\s+(\S+)\s+from\s+([\d.]+)"
    ),
    # dnsmasq reply: reply google.com is 142.250.190.46
    "dnsmasq_reply": re.compile(
        r"reply\s+(\S+)\s+is\s+([\d.]+)"
    ),
    # Unbound: [1234:0] info: 192.168.1.10 google.com. A IN
    "unbound": re.compile(
        r"info:\s+([\d.]+)\s+(\S+)\.\s+(\w+)\s+IN"
    ),
}


class DNSMonitor:
    """Monitor DNS queries for threat detection."""

    def __init__(self):
        self.queries: list[dict] = []
        self.per_client: dict[str, list] = defaultdict(list)
        self.domain_counts: dict[str, int] = defaultdict(int)
        self.threat_indicators: list[dict] = []
        self._file_position: int = 0

    # ─── Data Sources ────────────────────────────────────────

    def parse_log_file(self, filepath: Optional[str] = None,
                       max_lines: int = 5000) -> list[dict]:
        """
        Parse DNS query log file (BIND9, dnsmasq, or Unbound).
        Tails from last-read position for continuous monitoring.
        """
        path = None
        if filepath:
            path = Path(filepath)
        else:
            for key in ["dns_query_log", "dns_dnsmasq_log", "dns_unbound_log"]:
                p = Path(LOG_PATHS.get(key, ""))
                if p.exists():
                    path = p
                    break

        if not path or not path.exists():
            logger.warning("No DNS query log found")
            return []

        queries = []
        try:
            with open(path) as f:
                f.seek(self._file_position)
                lines_read = 0

                for line in f:
                    if lines_read >= max_lines:
                        break

                    query = self._parse_dns_log_line(line.strip())
                    if query:
                        queries.append(query)
                    lines_read += 1

                self._file_position = f.tell()

        except PermissionError:
            logger.error(f"Permission denied reading {path}")
            return []
        except IOError as e:
            logger.error(f"Error reading DNS log: {e}")
            return []

        if queries:
            self.queries.extend(queries)
            logger.info(f"Parsed {len(queries)} DNS queries from {path}")
            self._process_queries()

        return queries

    def _parse_dns_log_line(self, line: str) -> Optional[dict]:
        """Parse a single DNS log line into structured query."""
        if not line:
            return None

        timestamp = datetime.utcnow().isoformat() + "Z"

        # Try BIND9 format
        m = DNS_LOG_PATTERNS["bind9"].search(line)
        if m:
            return {
                "timestamp": timestamp,
                "client_ip": m.group(1),
                "query": m.group(3),
                "query_type": m.group(4),
                "response_ip": "",
                "response_code": "",
                "ttl": 0,
            }

        # Try dnsmasq format
        m = DNS_LOG_PATTERNS["dnsmasq"].search(line)
        if m:
            return {
                "timestamp": timestamp,
                "client_ip": m.group(3),
                "query": m.group(2),
                "query_type": m.group(1),
                "response_ip": "",
                "response_code": "",
                "ttl": 0,
            }

        # Try Unbound format
        m = DNS_LOG_PATTERNS["unbound"].search(line)
        if m:
            return {
                "timestamp": timestamp,
                "client_ip": m.group(1),
                "query": m.group(2).rstrip("."),
                "query_type": m.group(3),
                "response_ip": "",
                "response_code": "",
                "ttl": 0,
            }

        return None

    def sniff_dns(self, interface: str = "any", count: int = 100,
                  timeout: int = 30) -> list[dict]:
        """
        Passively sniff DNS packets on port 53 using Scapy.
        Requires root or CAP_NET_RAW.
        """
        try:
            from scapy.all import sniff as scapy_sniff, DNS, DNSQR, DNSRR, IP
        except ImportError:
            logger.error("Scapy not installed. Cannot sniff DNS.")
            return []

        queries = []

        def process_packet(pkt):
            if not pkt.haslayer(DNS):
                return
            dns = pkt[DNS]
            ip_layer = pkt[IP] if pkt.haslayer(IP) else None

            if dns.qr == 0 and dns.haslayer(DNSQR):
                # DNS query
                query = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "client_ip": ip_layer.src if ip_layer else "",
                    "query": dns[DNSQR].qname.decode().rstrip("."),
                    "query_type": self._qtype_to_str(dns[DNSQR].qtype),
                    "response_ip": "",
                    "response_code": "",
                    "ttl": 0,
                }
                queries.append(query)

            elif dns.qr == 1 and dns.haslayer(DNSRR):
                # DNS response — extract response IP
                response_ip = ""
                if dns.ancount > 0 and dns.haslayer(DNSRR):
                    rr = dns[DNSRR]
                    if rr.type == 1:  # A record
                        response_ip = rr.rdata
                query = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "client_ip": ip_layer.dst if ip_layer else "",
                    "query": dns[DNSQR].qname.decode().rstrip(".") if dns.haslayer(DNSQR) else "",
                    "query_type": self._qtype_to_str(dns[DNSQR].qtype) if dns.haslayer(DNSQR) else "",
                    "response_ip": str(response_ip),
                    "response_code": self._rcode_to_str(dns.rcode),
                    "ttl": dns[DNSRR].ttl if dns.haslayer(DNSRR) else 0,
                }
                queries.append(query)

        try:
            scapy_sniff(
                filter="udp port 53",
                iface=interface if interface != "any" else None,
                prn=process_packet,
                count=count,
                timeout=timeout,
                store=False,
            )
        except PermissionError:
            logger.error("DNS sniffing requires root privileges")
            return []
        except Exception as e:
            logger.error(f"DNS sniff error: {e}")
            return []

        if queries:
            self.queries.extend(queries)
            logger.info(f"Sniffed {len(queries)} DNS packets")
            self._process_queries()

        return queries

    # ─── Analysis ────────────────────────────────────────────

    def _process_queries(self):
        """Analyze DNS queries for threat indicators."""
        self.per_client.clear()
        self.domain_counts.clear()
        self.threat_indicators.clear()

        for q in self.queries:
            client = q.get("client_ip", "")
            domain = q.get("query", "")
            if client:
                self.per_client[client].append(q)
            if domain:
                self.domain_counts[domain] += 1

        # Run threat detection per client
        for client_ip, client_queries in self.per_client.items():
            self._detect_dga(client_ip, client_queries)
            self._detect_dns_tunneling(client_ip, client_queries)
            self._detect_beaconing(client_ip, client_queries)
            self._detect_recon_sweep(client_ip, client_queries)
            self._detect_nxdomain_flood(client_ip, client_queries)

    def _detect_dga(self, client_ip: str, queries: list):
        """
        Detect Domain Generation Algorithm patterns.
        DGA domains have high entropy, random-looking subdomains under the
        same parent domain.
        """
        domain_groups: dict[str, list] = defaultdict(list)
        for q in queries:
            domain = q.get("query", "")
            parts = domain.split(".")
            if len(parts) >= 3:
                parent = ".".join(parts[-2:])
                subdomain = ".".join(parts[:-2])
                domain_groups[parent].append(subdomain)

        for parent, subdomains in domain_groups.items():
            if len(subdomains) < 3:
                continue

            # Calculate average entropy of subdomains
            avg_entropy = sum(
                self._shannon_entropy(s) for s in subdomains
            ) / len(subdomains)

            # High entropy + many unique subdomains = likely DGA
            if avg_entropy > 3.0 and len(set(subdomains)) >= 3:
                self.threat_indicators.append({
                    "type": "dga_detected",
                    "client_ip": client_ip,
                    "parent_domain": parent,
                    "unique_subdomains": len(set(subdomains)),
                    "avg_entropy": round(avg_entropy, 2),
                    "risk_score": min(0.9, 0.5 + (avg_entropy - 3.0) * 0.2),
                    "severity": "critical",
                    "description": (
                        f"DGA pattern detected: {len(set(subdomains))} random "
                        f"subdomains under {parent} (entropy={avg_entropy:.1f})"
                    ),
                })

    def _detect_dns_tunneling(self, client_ip: str, queries: list):
        """
        Detect DNS tunneling: data exfiltration via TXT/NULL records
        or unusually long subdomain labels.
        """
        txt_queries = [q for q in queries if q.get("query_type") in ("TXT", "NULL", "CNAME")]
        long_queries = [
            q for q in queries
            if len(q.get("query", "")) > 60
        ]

        # Many TXT queries to the same domain
        txt_domains: dict[str, int] = defaultdict(int)
        for q in txt_queries:
            parts = q.get("query", "").split(".")
            if len(parts) >= 2:
                parent = ".".join(parts[-2:])
                txt_domains[parent] += 1

        for domain, count in txt_domains.items():
            if count >= 3:
                self.threat_indicators.append({
                    "type": "dns_tunneling",
                    "client_ip": client_ip,
                    "domain": domain,
                    "txt_query_count": count,
                    "risk_score": min(0.95, 0.6 + count * 0.05),
                    "severity": "critical",
                    "description": (
                        f"DNS tunneling suspected: {count} TXT queries to "
                        f"{domain} from {client_ip}"
                    ),
                })

        # Unusually long queries (data encoded in subdomain)
        if len(long_queries) >= 3:
            avg_len = sum(len(q["query"]) for q in long_queries) / len(long_queries)
            self.threat_indicators.append({
                "type": "dns_tunneling_long",
                "client_ip": client_ip,
                "long_query_count": len(long_queries),
                "avg_query_length": round(avg_len, 1),
                "risk_score": 0.7,
                "severity": "warning",
                "description": (
                    f"Unusually long DNS queries ({len(long_queries)} queries, "
                    f"avg length {avg_len:.0f} chars) from {client_ip}"
                ),
            })

    def _detect_beaconing(self, client_ip: str, queries: list):
        """
        Detect C2 beaconing: repeated queries to the same domain
        at regular intervals.
        """
        domain_times: dict[str, list] = defaultdict(list)
        for q in queries:
            domain = q.get("query", "")
            ts = q.get("timestamp", "")
            if domain and ts:
                try:
                    dt = datetime.fromisoformat(ts.rstrip("Z"))
                    domain_times[domain].append(dt)
                except ValueError:
                    pass

        for domain, times in domain_times.items():
            if len(times) < 3:
                continue

            times.sort()
            intervals = [
                (times[i + 1] - times[i]).total_seconds()
                for i in range(len(times) - 1)
            ]

            if not intervals:
                continue

            avg_interval = sum(intervals) / len(intervals)
            if avg_interval == 0:
                continue

            # Low variance in intervals = beaconing
            variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
            std_dev = variance ** 0.5
            cv = std_dev / avg_interval if avg_interval > 0 else float("inf")

            # Coefficient of variation < 0.3 = highly regular
            if cv < 0.3 and len(times) >= 3 and avg_interval < 300:
                self.threat_indicators.append({
                    "type": "dns_beaconing",
                    "client_ip": client_ip,
                    "domain": domain,
                    "query_count": len(times),
                    "avg_interval": round(avg_interval, 1),
                    "interval_cv": round(cv, 3),
                    "risk_score": min(0.9, 0.6 + (0.3 - cv)),
                    "severity": "critical",
                    "description": (
                        f"DNS beaconing: {domain} queried {len(times)} times "
                        f"at ~{avg_interval:.0f}s intervals (CV={cv:.2f})"
                    ),
                })

    def _detect_recon_sweep(self, client_ip: str, queries: list):
        """Detect reverse DNS (PTR) sweeps indicating network reconnaissance."""
        ptr_queries = [
            q for q in queries
            if q.get("query_type") == "PTR"
            or q.get("query", "").endswith(".in-addr.arpa")
        ]

        if len(ptr_queries) >= 3:
            self.threat_indicators.append({
                "type": "dns_recon_sweep",
                "client_ip": client_ip,
                "ptr_query_count": len(ptr_queries),
                "risk_score": min(0.7, 0.3 + len(ptr_queries) * 0.05),
                "severity": "warning",
                "description": (
                    f"DNS recon sweep: {len(ptr_queries)} PTR lookups "
                    f"from {client_ip}"
                ),
            })

    def _detect_nxdomain_flood(self, client_ip: str, queries: list):
        """Detect high NXDOMAIN rates (failed lookups)."""
        nxdomains = [
            q for q in queries
            if q.get("response_code") == "NXDOMAIN"
        ]

        total = len(queries)
        if total == 0:
            return

        nx_ratio = len(nxdomains) / total

        if len(nxdomains) >= 3 and nx_ratio > 0.3:
            self.threat_indicators.append({
                "type": "nxdomain_flood",
                "client_ip": client_ip,
                "nxdomain_count": len(nxdomains),
                "total_queries": total,
                "ratio": round(nx_ratio, 2),
                "risk_score": min(0.8, 0.4 + nx_ratio * 0.5),
                "severity": "warning",
                "description": (
                    f"High NXDOMAIN rate: {len(nxdomains)}/{total} queries "
                    f"({nx_ratio:.0%}) from {client_ip} failed"
                ),
            })

    # ─── Helpers ─────────────────────────────────────────────

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        freq: dict[str, int] = defaultdict(int)
        for c in s:
            freq[c] += 1
        length = len(s)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    @staticmethod
    def _qtype_to_str(qtype: int) -> str:
        """Convert DNS query type integer to string."""
        types = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX",
                 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
        return types.get(qtype, str(qtype))

    @staticmethod
    def _rcode_to_str(rcode: int) -> str:
        """Convert DNS response code to string."""
        codes = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
                 4: "NOTIMP", 5: "REFUSED"}
        return codes.get(rcode, str(rcode))

    # ─── Public API ──────────────────────────────────────────

    def get_queries(self) -> list:
        return self.queries

    def get_client_queries(self, client_ip: str) -> list:
        return self.per_client.get(client_ip, [])

    def get_threat_indicators(self) -> list:
        return self.threat_indicators

    def get_suspicious_clients(self) -> dict:
        """Get clients with DNS-based threat indicators, sorted by risk."""
        client_risk: dict[str, float] = defaultdict(float)
        client_threats: dict[str, list] = defaultdict(list)

        for indicator in self.threat_indicators:
            ip = indicator.get("client_ip", "")
            if ip:
                client_risk[ip] = max(
                    client_risk[ip], indicator.get("risk_score", 0)
                )
                client_threats[ip].append(indicator["type"])

        return {
            ip: {"risk_score": score, "threat_types": client_threats[ip]}
            for ip, score in sorted(
                client_risk.items(), key=lambda x: x[1], reverse=True
            )
        }

    def get_dns_stats(self) -> dict:
        """Get per-client DNS statistics for GNN features."""
        stats = {}
        for client_ip, queries in self.per_client.items():
            unique_domains = set(q.get("query", "") for q in queries)
            query_types = defaultdict(int)
            nxdomains = 0

            for q in queries:
                query_types[q.get("query_type", "")] += 1
                if q.get("response_code") == "NXDOMAIN":
                    nxdomains += 1

            stats[client_ip] = {
                "total_queries": len(queries),
                "unique_domains": len(unique_domains),
                "nxdomain_count": nxdomains,
                "query_types": dict(query_types),
                "avg_query_length": (
                    sum(len(q.get("query", "")) for q in queries) / len(queries)
                    if queries else 0
                ),
            }
        return stats

    def discover(self) -> tuple[list, dict]:
        """Run discovery: returns (threat_indicators, suspicious_clients)."""
        # Try log file first, then fall back to sniffing
        log_found = False
        for key in ["dns_query_log", "dns_dnsmasq_log", "dns_unbound_log"]:
            if Path(LOG_PATHS.get(key, "")).exists():
                self.parse_log_file()
                log_found = True
                break

        if not log_found:
            logger.warning(
                "No DNS log file found. Attempting passive sniff "
                "(requires root)..."
            )
            self.sniff_dns(timeout=DISCOVERY_CONFIG.get("dns_sniff_timeout", 10))

        return self.threat_indicators, self.get_suspicious_clients()
