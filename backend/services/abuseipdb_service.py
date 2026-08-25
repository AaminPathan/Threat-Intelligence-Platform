"""
AbuseIPDB integration. Used only for IP addresses.
Docs: https://docs.abuseipdb.com/
"""

import os
import httpx

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


async def check_ip(ip: str) -> dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"status": "not_configured", "error": "AbuseIPDB API key not configured"}

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(ABUSEIPDB_URL, headers=headers, params=params)
    except httpx.TimeoutException:
        return {"status": "timeout", "error": "AbuseIPDB request timed out"}
    except httpx.RequestError as exc:
        return {"status": "error", "error": f"AbuseIPDB network error: {exc}"}

    if response.status_code == 401:
        return {"status": "error", "error": "Invalid AbuseIPDB API key"}
    if response.status_code == 429:
        return {"status": "rate_limited", "error": "AbuseIPDB rate limit exceeded"}
    if response.status_code != 200:
        return {"status": "error", "error": f"AbuseIPDB returned status {response.status_code}"}

    payload = response.json().get("data", {})

    return {
        "status": "ok",
        "abuseConfidenceScore": payload.get("abuseConfidenceScore"),
        "totalReports": payload.get("totalReports"),
        "lastReportedAt": payload.get("lastReportedAt"),
        "countryCode": payload.get("countryCode"),
        "isp": payload.get("isp"),
        "domain": payload.get("domain"),
        "usageType": payload.get("usageType"),
        "isTor": payload.get("isTor"),
        "isWhitelisted": payload.get("isWhitelisted"),
        "numDistinctUsers": payload.get("numDistinctUsers"),
    }