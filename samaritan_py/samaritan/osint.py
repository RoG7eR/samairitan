"""Passive OSINT: Certificate Transparency (crt.sh) + DNS resolution.

Both network operations are injectable so the module can be unit-tested offline.
Only run against domains you are authorised to assess (e.g. bug-bounty scope).
"""
from __future__ import annotations

import socket
import time
from typing import Callable, List, Optional, Tuple

import requests

from .models import Asset, Relationship

CRT_URL = "https://crt.sh/"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
RETRY_STATUSES = {429, 500, 502, 503, 504}


def _get_json(url: str, params: dict, timeout: int, retries: int, log: Callable[[str], None]):
    """GET with exponential back-off on timeouts / 5xx (crt.sh is frequently overloaded)."""
    last: Exception = RuntimeError("no attempt made")
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, params=params, timeout=timeout,
                                headers={"User-Agent": "samaritan-asset-index/2.0"})
            if resp.status_code in RETRY_STATUSES:
                raise requests.HTTPError(f"{resp.status_code} from {resp.url}", response=resp)
            resp.raise_for_status()
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            last = exc
            if attempt < retries:
                wait = 2 ** attempt
                log(f"  [!] attempt {attempt}/{retries} failed ({exc.__class__.__name__}); retrying in {wait}s")
                time.sleep(wait)
    raise last


def fetch_crtsh(domain: str, timeout: int = 60, retries: int = 3, log=print) -> list:
    """crt.sh, asking only for unexpired + de-duplicated certs to keep the query small."""
    params = {"q": f"%.{domain}", "output": "json", "exclude": "expired", "deduplicate": "Y"}
    return _get_json(CRT_URL, params, timeout, retries, log)


def fetch_certspotter(domain: str, timeout: int = 60, retries: int = 2, log=print) -> list:
    """Fallback CT source (unauthenticated, rate-limited). Normalised to crt.sh's record shape."""
    params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
    data = _get_json(CERTSPOTTER_URL, params, timeout, retries, log)
    return [{"name_value": "\n".join(item.get("dns_names", []))} for item in data]


def fetch_ct_records(domain: str, log: Callable[[str], None] = print) -> list:
    """Try crt.sh first, then fall back to Cert Spotter."""
    try:
        return fetch_crtsh(domain, log=log)
    except (requests.RequestException, ValueError) as exc:
        log(f"[!] crt.sh unavailable ({exc}). Falling back to Cert Spotter...")
        return fetch_certspotter(domain, log=log)


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