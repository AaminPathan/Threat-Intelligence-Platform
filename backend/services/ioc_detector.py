"""
Detects and validates the type of an Indicator of Compromise (IOC).

Supported types: ipv4, ipv6, domain, url, md5, sha1, sha256.
"""

import re
import ipaddress
from urllib.parse import urlparse

MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

# Reasonably strict RFC-1035-ish domain pattern.
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def _is_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def _ip_version(value: str):
    try:
        ip = ipaddress.ip_address(value)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        return None


def detect_ioc_type(value: str) -> dict:
    """
    Returns:
        {"value": <normalized value>, "type": <ioc type or None>, "valid": bool, "error"?: str}
    """
    if value is None:
        return {"value": value, "type": None, "valid": False, "error": "No value provided"}

    cleaned = value.strip()

    if not cleaned:
        return {"value": cleaned, "type": None, "valid": False, "error": "Empty input"}

    # Hashes first — fixed-length hex strings are unambiguous.
    if MD5_RE.match(cleaned):
        return {"value": cleaned.lower(), "type": "md5", "valid": True}
    if SHA1_RE.match(cleaned):
        return {"value": cleaned.lower(), "type": "sha1", "valid": True}
    if SHA256_RE.match(cleaned):
        return {"value": cleaned.lower(), "type": "sha256", "valid": True}

    # IP addresses
    ip_version = _ip_version(cleaned)
    if ip_version:
        return {"value": cleaned, "type": ip_version, "valid": True}

    # URL (must include a scheme, otherwise it's ambiguous with a domain)
    if "://" in cleaned and _is_url(cleaned):
        return {"value": cleaned, "type": "url", "valid": True}

    # Domain
    if "." in cleaned and DOMAIN_RE.match(cleaned):
        return {"value": cleaned.lower(), "type": "domain", "valid": True}

    return {
        "value": cleaned,
        "type": None,
        "valid": False,
        "error": (
            "Could not identify a valid IOC type. Supported types are "
            "IPv4, IPv6, domain, URL, MD5, SHA1, and SHA256."
        ),
    }