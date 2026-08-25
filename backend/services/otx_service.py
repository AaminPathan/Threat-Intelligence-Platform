"""
AlienVault OTX integration.
Docs: https://otx.alienvault.com/api
"""

import os
import urllib.parse
import httpx

OTX_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

TYPE_MAP = {
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "domain": "domain",
    "url": "url",
    "md5": "file",
    "sha1": "file",
    "sha256": "file",
}


async def check_indicator(ioc_type: str, value: str) -> dict:
    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        return {"status": "not_configured", "error": "OTX API key not configured"}

    otx_type = TYPE_MAP.get(ioc_type)
    if not otx_type:
        return {"status": "not_applicable", "error": "OTX does not support this IOC type"}

    headers = {"X-OTX-API-KEY": api_key}
    encoded_value = urllib.parse.quote(value, safe="")
    endpoint = f"{OTX_BASE_URL}/{otx_type}/{encoded_value}/general"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(endpoint, headers=headers)
    except httpx.TimeoutException:
        return {"status": "timeout", "error": "OTX request timed out"}
    except httpx.RequestError as exc:
        return {"status": "error", "error": f"OTX network error: {exc}"}

    if response.status_code == 403:
        return {"status": "error", "error": "Invalid OTX API key"}
    if response.status_code == 404:
        return {"status": "not_found", "error": "No OTX data found for this indicator"}
    if response.status_code == 429:
        return {"status": "rate_limited", "error": "OTX rate limit exceeded"}
    if response.status_code != 200:
        return {"status": "error", "error": f"OTX returned status {response.status_code}"}

    payload = response.json()
    pulse_info = payload.get("pulse_info", {}) or {}
    pulses = pulse_info.get("pulses", []) or []

    tags = list({tag for p in pulses for tag in (p.get("tags") or [])})
    malware_families = list({
        mf.get("display_name")
        for p in pulses
        for mf in (p.get("malware_families") or [])
        if mf.get("display_name")
    })

    return {
        "status": "ok",
        "pulseCount": pulse_info.get("count", 0),
        "pulseNames": [p.get("name") for p in pulses[:10] if p.get("name")],
        "tags": tags[:15],
        "malwareFamilies": malware_families[:10],
    }