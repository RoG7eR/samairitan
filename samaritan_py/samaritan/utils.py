"""Small input-validation helpers shared by the CLI and the GUI."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

_TLD = r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})"
_DOMAIN_RE = re.compile(rf"^(?=.{{1,253}}$)(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+{_TLD}$")


def normalize_target(text: str) -> str:
    """Turn whatever the user typed into a bare registrable-style domain.

    'https://www.Example.com:8443/path?q=1'  ->  'example.com'
    Raises ValueError with a user-friendly message when it cannot be a domain.
    """
    raw = (text or "").strip().lower()
    if not raw:
        raise ValueError("Enter a domain or URL.")
    if any(ch.isspace() for ch in raw):
        raise ValueError("A domain cannot contain spaces.")
    if "://" not in raw:
        raw = "//" + raw                      # make urlsplit treat it as a network location
    try:
        host = urlsplit(raw).hostname
    except ValueError:
        host = None
    if not host:
        raise ValueError("Could not find a host name in that input.")
    host = host.rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not supported here - enter a domain name.")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError(f"'{host}' is not a valid domain name.") from None
    if not _DOMAIN_RE.match(host):
        raise ValueError(f"'{host}' is not a valid domain name.")
    return host
