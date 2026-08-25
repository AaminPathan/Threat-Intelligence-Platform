"""
Deterministic, rule-based risk scoring engine.

This is a CUSTOM HEURISTIC built for this project — it is NOT an
industry-standard security score (like CVSS) and should not be treated
as one. It gives analysts a rough, explainable starting point based on
the evidence gathered from the configured threat-intelligence sources.

The LLM never sets or influences this score; it only explains it.
"""

MAX_SCORE = 100


def _severity_for(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def calculate_risk(ioc_type: str, sources: dict) -> dict:
    score = 0
    reasons = []
    sources_with_findings = 0

    abuseipdb = sources.get("abuseipdb") or {}
    virustotal = sources.get("virustotal") or {}
    otx = sources.get("otx") or {}

    # --- AbuseIPDB ---
    if abuseipdb.get("status") == "ok":
        confidence = abuseipdb.get("abuseConfidenceScore") or 0
        total_reports = abuseipdb.get("totalReports") or 0

        if confidence >= 75:
            score += 30
            reasons.append(f"AbuseIPDB confidence score is high ({confidence}%)")
            sources_with_findings += 1
        elif confidence >= 40:
            score += 18
            reasons.append(f"AbuseIPDB confidence score is elevated ({confidence}%)")
            sources_with_findings += 1
        elif confidence > 0:
            score += 8
            reasons.append(f"AbuseIPDB confidence score is low but nonzero ({confidence}%)")

        if total_reports >= 50:
            score += 10
            reasons.append(f"A large number of abuse reports were found ({total_reports})")
        elif total_reports >= 5:
            score += 5
            reasons.append(f"Multiple abuse reports were found ({total_reports})")

        if abuseipdb.get("isTor"):
            score += 5
            reasons.append("Indicator is associated with a Tor exit node")

        if abuseipdb.get("isWhitelisted"):
            score -= 10
            reasons.append("Indicator is on AbuseIPDB's whitelist (reduces risk)")

    # --- VirusTotal ---
    if virustotal.get("status") == "ok":
        malicious = virustotal.get("malicious") or 0
        suspicious = virustotal.get("suspicious") or 0
        total_engines = virustotal.get("totalEngines") or 0

        if total_engines > 0:
            if malicious >= 10:
                score += 35
                reasons.append(f"{malicious} security vendors flagged this indicator as malicious")
                sources_with_findings += 1
            elif malicious >= 3:
                score += 22
                reasons.append(f"{malicious} security vendors flagged this indicator as malicious")
                sources_with_findings += 1
            elif malicious >= 1:
                score += 10
                reasons.append(f"{malicious} security vendor(s) flagged this indicator as malicious")
                sources_with_findings += 1

            if suspicious >= 3:
                score += 8
                reasons.append(f"{suspicious} vendors flagged this indicator as suspicious")

        reputation = virustotal.get("reputation")
        if reputation is not None and reputation < 0:
            score += 7
            reasons.append(f"VirusTotal community reputation is negative ({reputation})")

    # --- OTX ---
    if otx.get("status") == "ok":
        pulse_count = otx.get("pulseCount") or 0

        if pulse_count >= 10:
            score += 20
            reasons.append(f"Indicator appears in {pulse_count} OTX threat-intelligence pulses")
            sources_with_findings += 1
        elif pulse_count >= 3:
            score += 12
            reasons.append(f"Indicator appears in {pulse_count} OTX threat-intelligence pulses")
            sources_with_findings += 1
        elif pulse_count >= 1:
            score += 6
            reasons.append(f"Indicator appears in {pulse_count} OTX threat-intelligence pulse")

        if otx.get("malwareFamilies"):
            score += 5
            reasons.append("Indicator is linked to known malware families in OTX")

    # --- Cross-source correlation bonus (avoids rewarding one source twice) ---
    if sources_with_findings >= 2:
        score += 10
        reasons.append("Multiple independent threat-intelligence sources agree this indicator is risky")

    score = max(0, min(MAX_SCORE, round(score)))

    if not reasons:
        reasons.append("No significant risk indicators were found in the available intelligence sources")

    return {
        "score": score,
        "severity": _severity_for(score),
        "reasons": reasons,
        "methodology": (
            "Custom heuristic risk score based on available threat-intelligence "
            "evidence. This is NOT an industry-standard security score (e.g. CVSS) "
            "and should be used only as an analyst starting point."
        ),
    }