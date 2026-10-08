"""Passive OSINT: Certificate Transparency (crt.sh) + DNS resolution.

Both network operations are injectable so the module can be unit-tested offline.
Only run against domains you are authorised to assess (e.g. bug-bounty scope).
"""
from __future__ import annotations

import socket
from typing import Callable, List, Optional, Tuple

import requests

from .models import Asset, Relationship

CRT_URL = "https://crt.sh/"


def fetch_ct_records(domain: str, timeout: int = 30) -> list:
    """Query crt.sh for every certificate issued to *.domain."""
    resp = requests.get(CRT_URL, params={"q": f"%.{domain}", "output": "json"}, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def extract_subdomains(records: list) -> List[str]:
    """Unique, lower-cased, wildcard-free names, in first-seen order.

    crt.sh packs several SANs into one `name_value` separated by newlines,
    so each field is split before de-duplication.
    """
    seen = {}
    for rec in records:
        for name in str(rec.get("name_value", "")).splitlines():
            name = name.strip().lower()
            if name and "*" not in name:
                seen.setdefault(name, None)
    return list(seen)


def resolve_host(hostname: str) -> str:
    """First address returned by the OS resolver (raises socket.gaierror on failure)."""
    return socket.getaddrinfo(hostname, None)[0][4][0]


def conduct_reconnaissance(
    target: str,
    limit: int = 10,
    fetcher: Callable[[str], list] = fetch_ct_records,
    resolver: Callable[[str], str] = resolve_host,
    log: Callable[[str], None] = print,
) -> Tuple[List[Asset], List[Relationship]]:
    """Run the full sweep. Returns ([], []) when the CT lookup fails."""
    log(f"[+] Initiating OSINT sweep for target: {target}")
    try:
        log("[~] Querying Certificate Transparency logs...")
        subdomains = extract_subdomains(fetcher(target))
    except (requests.RequestException, ValueError) as exc:
        log(f"[-] Reconnaissance failed: {exc}")
        return [], []
    log(f"[+] Discovered {len(subdomains)} unique subdomains.")

    entities: dict[str, Asset] = {target: Asset(target, "Primary Target", "Elevated")}
    relationships: List[Relationship] = []

    for sub in subdomains[:limit]:
        entities.setdefault(sub, Asset(sub, "Subdomain", "Unknown"))
        relationships.append(Relationship(target, sub, "OWNS"))
        try:
            ip = resolver(sub)
        except OSError:
            log(f"  -> Unresolved: {sub} (Offline/Hidden)")
            continue
        entities.setdefault(ip, Asset(ip, "Infrastructure", "Unknown"))
        relationships.append(Relationship(sub, ip, "RESOLVES_TO"))
        log(f"  -> Resolved: {sub} [{ip}]")

    return list(entities.values()), relationships
