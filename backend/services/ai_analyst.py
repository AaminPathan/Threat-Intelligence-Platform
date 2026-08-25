"""
AI analyst module.

Turns already-collected, structured threat-intelligence evidence into a
plain-language analyst assessment. The AI is explicitly instructed to
only explain the evidence it is given — it must never invent new
threat intelligence, CVEs, malware families, or campaigns, and must
never set the risk score.

The provider call lives in `_call_ai_provider` so another LLM provider
could be swapped in later without touching the rest of the app.
"""

import os
import json
import httpx

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"

# NOTE: model names change over time — if you get a "model not found"
# error, check the current model list in your Anthropic Console and
# update AI_MODEL in your .env accordingly.
DEFAULT_MODEL = os.getenv("AI_MODEL", "claude-sonnet-4-5-20250929")

SYSTEM_PROMPT = """You are a cybersecurity threat intelligence analyst assistant.

You will be given structured evidence collected by automated tools from
threat-intelligence sources (AbuseIPDB, VirusTotal, AlienVault OTX) about
a single indicator of compromise (IOC), along with a deterministic risk
score already calculated by the backend.

Rules you MUST follow:
- Only use the evidence provided to you. Never invent detections, CVEs,
  malware family names, campaign names, geographic data, or any other
  fact that is not present in the supplied evidence.
- Do not state that an indicator is malicious unless the evidence
  supports it. If evidence is thin or absent, say so explicitly.
- Do not describe the risk score's methodology as an industry standard;
  it is a custom heuristic.
- Be concise and use plain, analyst-style language.

Respond ONLY with a JSON object (no markdown fences, no extra text) with
exactly these keys:
{
  "summary": "2-4 sentence analyst summary",
  "key_evidence": ["short bullet", "short bullet"],
  "recommended_investigation": ["short bullet", "short bullet"],
  "confidence_statement": "1-2 sentences on how confident this assessment is given the available evidence",
  "suggested_next_actions": ["short bullet", "short bullet"]
}
"""


def _build_user_prompt(indicator: str, ioc_type: str, risk: dict, sources: dict) -> str:
    evidence = {
        "indicator": indicator,
        "ioc_type": ioc_type,
        "risk_score": risk,
        "sources": sources,
    }
    return (
        "Here is the structured evidence collected for this indicator. "
        "Base your assessment strictly on this data:\n\n"
        f"{json.dumps(evidence, indent=2, default=str)}"
    )


async def _call_ai_provider(system_prompt: str, user_prompt: str) -> dict:
    api_key = os.getenv("AI_API_KEY")
    if not api_key:
        raise RuntimeError("AI_API_KEY not configured")

    headers = {
        "x-api-key": api_key,
        "anthropic-version": ANTHROPIC_VERSION,
        "content-type": "application/json",
    }
    body = {
        "model": DEFAULT_MODEL,
        "max_tokens": 1000,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_prompt}],
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(ANTHROPIC_URL, headers=headers, json=body)

    if response.status_code != 200:
        raise RuntimeError(f"AI provider returned status {response.status_code}: {response.text[:300]}")

    payload = response.json()
    text_blocks = [block.get("text", "") for block in payload.get("content", []) if block.get("type") == "text"]
    raw_text = "\n".join(text_blocks).strip()

    # Defensive cleanup in case the model wraps output in a code fence anyway.
    if raw_text.startswith("```"):
        raw_text = raw_text.strip("`")
        if raw_text.lower().startswith("json"):
            raw_text = raw_text[4:].strip()

    return json.loads(raw_text)


async def generate_assessment(indicator: str, ioc_type: str, risk: dict, sources: dict) -> dict:
    if not os.getenv("AI_API_KEY"):
        return {
            "summary": "AI analysis unavailable (no AI_API_KEY configured).",
            "key_evidence": [],
            "recommended_investigation": [],
            "confidence_statement": "N/A",
            "suggested_next_actions": [],
            "available": False,
        }

    user_prompt = _build_user_prompt(indicator, ioc_type, risk, sources)

    try:
        result = await _call_ai_provider(SYSTEM_PROMPT, user_prompt)
        result["available"] = True
        return result
    except (RuntimeError, json.JSONDecodeError, httpx.RequestError) as exc:
        return {
            "summary": "AI analysis unavailable due to an error contacting the AI provider.",
            "key_evidence": [],
            "recommended_investigation": [],
            "confidence_statement": "N/A",
            "suggested_next_actions": [],
            "available": False,
            "error": str(exc),
        }