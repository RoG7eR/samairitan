"""Offline demo dataset (RFC 2606 / RFC 5737 reserved names and IPs - nothing real)."""
from __future__ import annotations

from .local_scanner import GATEWAY_ID
from .graph_store import AssetGraph
from .models import Asset, Relationship
from .parser import parse_intelligence_log


def build_demo_graph() -> AssetGraph:
    g = AssetGraph()
    target = "example.org"
    subs = {
        "www.example.org": "203.0.113.10", "api.example.org": "203.0.113.10",
        "cdn.example.org": "203.0.113.10", "mail.example.org": "198.51.100.25",
        "vpn.example.org": "198.51.100.77", "admin.example.org": "198.51.100.77",
        "dev.example.org": "192.0.2.44", "status.example.org": "192.0.2.90",
    }
    ents = [Asset(target, "Primary Target", "Elevated")]
    rels = []
    for host, ip in subs.items():
        ents += [Asset(host, "Subdomain", "Unknown"), Asset(ip, "Infrastructure", "Unknown")]
        rels += [Relationship(target, host, "OWNS"), Relationship(host, ip, "RESOLVES_TO")]
    g.ingest(ents, rels)
    g.ingest(*parse_intelligence_log(
        "Asset discovered: admin-portal.example.org resolving to IP 192.0.2.50"))
    g.add_local_devices(GATEWAY_ID, [Asset(f"192.168.1.{i}", "Local Infrastructure", "Normal")
                                     for i in (1, 12, 23, 40)])
    return g
