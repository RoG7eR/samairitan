"""Turn a raw free-text intelligence log line into entities + relationships."""
from __future__ import annotations

import re
from typing import List, Tuple

from .models import Asset, Relationship

IP_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
DOMAIN_RE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]",
    re.IGNORECASE,
)


def parse_intelligence_log(raw_log: str) -> Tuple[List[Asset], List[Relationship]]:
    """Extract one (domain -> IP) pair from a log line.

    Example: "Asset discovered: admin-portal.target.com resolving to IP 192.168.1.50"
    """
    ip_match = IP_RE.search(raw_log)
    # A dotted IP also fits the domain pattern, so skip any match that is an IP.
    domain = next(
        (m.group(0) for m in DOMAIN_RE.finditer(raw_log) if not IP_RE.fullmatch(m.group(0))),
        None,
    )
    if not (ip_match and domain):
        return [], []

    ip = ip_match.group(0)
    entities = [
        Asset(domain, "Domain", "Elevated"),
        Asset(ip, "Infrastructure", "Unknown"),
    ]
    relationships = [Relationship(domain, ip, "RESOLVES_TO")]
    return entities, relationships
