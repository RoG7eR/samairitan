"""Proximity scan: read the OS ARP cache (`arp -a`) for neighbouring hosts."""
from __future__ import annotations

import ipaddress
import re
import subprocess
from typing import List

from .models import Asset

IPV4_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
GATEWAY_ID = "127.0.0.1 (Local Host)"


def parse_arp_output(text: str) -> List[Asset]:
    """Pure parser (testable without a shell). Works for Windows, Linux and macOS output."""
    devices, seen = [], set()
    for line in text.splitlines():
        m = IPV4_RE.search(line)
        if not m:
            continue
        ip = m.group(1)
        try:
            ipaddress.IPv4Address(ip)           # rejects e.g. 999.1.1.1
        except ValueError:
            continue
        if ip.startswith(("224.", "255.")) or ip.endswith(".255") or ip in seen:
            continue                              # multicast / broadcast / duplicate
        seen.add(ip)
        devices.append(Asset(ip, "Local Infrastructure", "Normal"))
    return devices


def scan_local_network(timeout: int = 15) -> List[Asset]:
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                             timeout=timeout, check=True).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"Unable to execute local network scan: {exc}") from exc
    devices = parse_arp_output(out)
    print(f"[+] Discovered {len(devices)} active local network nodes.")
    return devices
