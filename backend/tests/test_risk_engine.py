import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.risk_engine import calculate_risk


def test_no_evidence_gives_low_score():
    sources = {
        "abuseipdb": {"status": "not_applicable"},
        "virustotal": {"status": "not_found"},
        "otx": {"status": "not_found"},
    }
    result = calculate_risk("domain", sources)
    assert result["score"] == 0
    assert result["severity"] == "LOW"


def test_high_abuseipdb_confidence_raises_score():
    sources = {
        "abuseipdb": {"status": "ok", "abuseConfidenceScore": 95, "totalReports": 60, "isTor": False},
        "virustotal": {"status": "not_applicable"},
        "otx": {"status": "not_applicable"},
    }
    result = calculate_risk("ipv4", sources)
    assert result["score"] >= 40


def test_multiple_sources_correlation_bonus():
    sources = {
        "abuseipdb": {"status": "ok", "abuseConfidenceScore": 80, "totalReports": 20, "isTor": False},
        "virustotal": {"status": "ok", "malicious": 15, "suspicious": 2, "totalEngines": 70, "reputation": -5},
        "otx": {"status": "ok", "pulseCount": 12, "malwareFamilies": ["TestMalware"]},
    }
    result = calculate_risk("ipv4", sources)
    assert result["score"] >= 80
    assert result["severity"] == "CRITICAL"


def test_score_capped_at_100():
    sources = {
        "abuseipdb": {"status": "ok", "abuseConfidenceScore": 100, "totalReports": 500, "isTor": True},
        "virustotal": {"status": "ok", "malicious": 60, "suspicious": 10, "totalEngines": 70, "reputation": -50},
        "otx": {"status": "ok", "pulseCount": 50, "malwareFamilies": ["A", "B"]},
    }
    result = calculate_risk("ipv4", sources)
    assert result["score"] <= 100