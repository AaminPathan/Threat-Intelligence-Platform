def build_findings(ioc_type: str, sources: dict) -> list:
    """Builds a short human-readable findings list from normalized source data."""
    findings = []

    abuseipdb = sources.get("abuseipdb") or {}
    if abuseipdb.get("status") == "ok":
        if abuseipdb.get("abuseConfidenceScore") is not None:
            findings.append(f"AbuseIPDB confidence score: {abuseipdb['abuseConfidenceScore']}%")
        if abuseipdb.get("totalReports"):
            findings.append(f"AbuseIPDB total reports: {abuseipdb['totalReports']}")

    virustotal = sources.get("virustotal") or {}
    if virustotal.get("status") == "ok":
        findings.append(
            f"VirusTotal: {virustotal.get('malicious', 0)} malicious / "
            f"{virustotal.get('suspicious', 0)} suspicious / "
            f"{virustotal.get('totalEngines', 0)} engines"
        )

    otx = sources.get("otx") or {}
    if otx.get("status") == "ok" and otx.get("pulseCount"):
        findings.append(f"AlienVault OTX pulse count: {otx['pulseCount']}")

    if not findings:
        findings.append("No significant findings were returned by the configured sources")

    return findings


def sources_applicable_for(ioc_type: str) -> list:
    mapping = {
        "ipv4": ["abuseipdb", "virustotal", "otx"],
        "ipv6": ["abuseipdb", "virustotal", "otx"],
        "domain": ["virustotal", "otx"],
        "url": ["virustotal", "otx"],
        "md5": ["virustotal", "otx"],
        "sha1": ["virustotal", "otx"],
        "sha256": ["virustotal", "otx"],
    }
    return mapping.get(ioc_type, [])