import asyncio
from dotenv import load_dotenv

load_dotenv()  # must run before importing services that read env vars at import time

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from models.schemas import AnalyzeRequest, AnalyzeResponse
from services.ioc_detector import detect_ioc_type
from services import abuseipdb_service, virustotal_service, otx_service, risk_engine, ai_analyst
from utils.helpers import build_findings, sources_applicable_for

app = FastAPI(title="AI-Powered Threat Intelligence Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173",  "http://localhost:5174",
        "http://127.0.0.1:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok"}


async def _query_virustotal(ioc_type: str, value: str) -> dict:
    if ioc_type in ("ipv4", "ipv6"):
        return await virustotal_service.check_ip(value)
    if ioc_type == "domain":
        return await virustotal_service.check_domain(value)
    if ioc_type == "url":
        return await virustotal_service.check_url(value)
    if ioc_type in ("md5", "sha1", "sha256"):
        return await virustotal_service.check_file_hash(value)
    return {"status": "not_applicable"}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest):
    detection = detect_ioc_type(request.indicator)

    if not detection["valid"]:
        return AnalyzeResponse(
            indicator=request.indicator,
            ioc_type=None,
            valid=False,
            error=detection.get("error", "Invalid indicator"),
        )

    ioc_type = detection["type"]
    value = detection["value"]
    applicable = sources_applicable_for(ioc_type)

    tasks = {}
    if "abuseipdb" in applicable:
        tasks["abuseipdb"] = abuseipdb_service.check_ip(value)
    if "virustotal" in applicable:
        tasks["virustotal"] = _query_virustotal(ioc_type, value)
    if "otx" in applicable:
        tasks["otx"] = otx_service.check_indicator(ioc_type, value)

    results = await asyncio.gather(*tasks.values(), return_exceptions=True)

    sources = {}
    for key, result in zip(tasks.keys(), results):
        sources[key] = {"status": "error", "error": str(result)} if isinstance(result, Exception) else result

    for name in ("abuseipdb", "virustotal", "otx"):
        sources.setdefault(name, {"status": "not_applicable"})

    risk = risk_engine.calculate_risk(ioc_type, sources)
    findings = build_findings(ioc_type, sources)
    ai_assessment = await ai_analyst.generate_assessment(value, ioc_type, risk, sources)

    return AnalyzeResponse(
        indicator=value,
        ioc_type=ioc_type,
        valid=True,
        risk=risk,
        sources=sources,
        findings=findings,
        ai_assessment=ai_assessment,
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)