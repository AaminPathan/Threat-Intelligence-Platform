"""
VirusTotal v3 integration for IPs, domains, URLs, and file hashes.
Docs: https://docs.virustotal.com/reference/overview
"""

import os
import base64
import httpx

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def _url_id(url: str) -> str:
    """VirusTotal requires the URL identifier to be base64 (url-safe, no padding)."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


async def _get(endpoint: str) -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"status": "not_configured", "error": "VirusTotal API key not configured"}

    headers = {"x-apikey": api_key}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(f"{VT_BASE_URL}{endpoint}", headers=headers)
    except httpx.TimeoutException:
        return {"status": "timeout", "error": "VirusTotal request timed out"}
    except httpx.RequestError as exc:
        return {"status": "error", "error": f"VirusTotal network error: {exc}"}

    if response.status_code == 401:
        return {"status": "error", "error": "Invalid VirusTotal API key"}
    if response.status_code == 404:
        return {"status": "not_found", "error": "No VirusTotal data found for this indicator"}
    if response.status_code == 429:
        return {"status": "rate_limited", "error": "VirusTotal rate limit exceeded"}
    if response.status_code != 200:
        return {"status": "error", "error": f"VirusTotal returned status {response.status_code}"}

    data = response.json().get("data", {})
    attributes = data.get("attributes", {})
    stats = attributes.get("last_analysis_stats", {}) or {}

    result = {
        "status": "ok",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attributes.get("reputation"),
        "totalEngines": sum(stats.values()) if stats else 0,
    }

    # Optional metadata depending on object type — only added when present.
    if attributes.get("country"):
        result["country"] = attributes.get("country")
    if attributes.get("as_owner"):
        result["asOwner"] = attributes.get("as_owner")
    if attributes.get("categories"):
        result["categories"] = attributes.get("categories")
    if "last_dns_records" in attributes:
        result["hasDnsRecords"] = bool(attributes.get("last_dns_records"))
    if attributes.get("type_description"):
        result["fileType"] = attributes.get("type_description")
    if attributes.get("meaningful_name"):
        result["fileName"] = attributes.get("meaningful_name")
    if attributes.get("size") is not None:
        result["fileSize"] = attributes.get("size")

    return result


async def check_ip(ip: str) -> dict:
    return await _get(f"/ip_addresses/{ip}")


async def check_domain(domain: str) -> dict:
    return await _get(f"/domains/{domain}")


async def check_url(url: str) -> dict:
    return await _get(f"/urls/{_url_id(url)}")


async def check_file_hash(file_hash: str) -> dict:
    return await _get(f"/files/{file_hash}")