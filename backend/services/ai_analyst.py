"""
AI analyst module.

Turns already-collected, structured threat-intelligence evidence into a
plain-language analyst assessment. The AI is explicitly instructed to
only explain the evidence it is given — it must never invent new
threat intelligence, CVEs, malware families, or campaigns, and must
never set the risk score.
"""

import os
import json
import httpx


GEMINI_MODEL = os.getenv("AI_MODEL", "gemini-3.6-flash")
GEMINI_URL = (
    f"https://generativelanguage.googleapis.com/v1beta/models/"
    f"{GEMINI_MODEL}:generateContent"
)


SYSTEM_PROMPT = """You are a cybersecurity threat intelligence analyst assistant.

You will be given structured evidence collected by automated tools from
threat-intelligence sources (AbuseIPDB, VirusTotal, AlienVault OTX) about
a single indicator of compromise (IOC), along with a deterministic risk
score already calculated by the backend.

Rules you MUST follow:
- Only use the evidence provided to you.
- Never invent detections, CVEs, malware family names, campaign names,
  geographic data, attribution, or facts not present in the evidence.
- Do not state that an indicator is malicious unless the supplied
  evidence supports that conclusion.
- If evidence is weak, conflicting, or absent, explicitly say so.
- Do NOT calculate or modify the risk score.
- The supplied risk score is a custom heuristic and is not an
  industry-standard security score.
- Be concise and use professional SOC/threat-intelligence analyst language.

Respond ONLY with valid JSON with exactly these keys:

{
  "summary": "2-4 sentence analyst summary",
  "key_evidence": ["short bullet", "short bullet"],
  "recommended_investigation": ["short bullet", "short bullet"],
  "confidence_statement": "1-2 sentences describing confidence based on available evidence",
  "suggested_next_actions": ["short bullet", "short bullet"]
}
"""


def _build_user_prompt(
    indicator: str,
    ioc_type: str,
    risk: dict,
    sources: dict
) -> str:

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


async def _call_ai_provider(
    system_prompt: str,
    user_prompt: str
) -> dict:

    api_key = os.getenv("AI_API_KEY")

    if not api_key:
        raise RuntimeError("AI_API_KEY not configured")

    url = f"{GEMINI_URL}?key={api_key}"

    body = {
        "system_instruction": {
            "parts": [
                {
                    "text": system_prompt
                }
            ]
        },
        "contents": [
            {
                "role": "user",
                "parts": [
                    {
                        "text": user_prompt
                    }
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 1000,
            "responseMimeType": "application/json"
        }
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, json=body)

    if response.status_code != 200:
        raise RuntimeError(
            f"AI provider returned status "
            f"{response.status_code}: {response.text[:300]}"
        )

    payload = response.json()

    try:
        raw_text = (
            payload["candidates"][0]
            ["content"]["parts"][0]["text"]
        ).strip()
    except (KeyError, IndexError, TypeError):
        raise RuntimeError(
            "Gemini returned an unexpected response format"
        )

    # Defensive cleanup if JSON is wrapped in a code block.
    if raw_text.startswith("```"):
        raw_text = raw_text.strip("`")

        if raw_text.lower().startswith("json"):
            raw_text = raw_text[4:].strip()

    return json.loads(raw_text)


async def generate_assessment(
    indicator: str,
    ioc_type: str,
    risk: dict,
    sources: dict
) -> dict:

    if not os.getenv("AI_API_KEY"):
        return {
            "summary": "AI analysis unavailable (no AI_API_KEY configured).",
            "key_evidence": [],
            "recommended_investigation": [],
            "confidence_statement": "N/A",
            "suggested_next_actions": [],
            "available": False,
        }

    user_prompt = _build_user_prompt(
        indicator,
        ioc_type,
        risk,
        sources
    )

    try:
        result = await _call_ai_provider(
            SYSTEM_PROMPT,
            user_prompt
        )

        result["available"] = True

        return result

    except (
        RuntimeError,
        json.JSONDecodeError,
        httpx.RequestError
    ) as exc:

        return {
            "summary": (
                "AI analysis unavailable due to an error "
                "contacting the AI provider."
            ),
            "key_evidence": [],
            "recommended_investigation": [],
            "confidence_statement": "N/A",
            "suggested_next_actions": [],
            "available": False,
            "error": str(exc),
        }