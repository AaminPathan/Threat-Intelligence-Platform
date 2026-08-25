from typing import Optional, List, Any, Dict
from pydantic import BaseModel


class AnalyzeRequest(BaseModel):
    indicator: str


class RiskResult(BaseModel):
    score: int
    severity: str
    reasons: List[str]
    methodology: str


class AiAssessment(BaseModel):
    summary: str
    key_evidence: List[str] = []
    recommended_investigation: List[str] = []
    confidence_statement: str = "N/A"
    suggested_next_actions: List[str] = []
    available: bool = True
    error: Optional[str] = None


class AnalyzeResponse(BaseModel):
    indicator: str
    ioc_type: Optional[str] = None
    valid: bool
    risk: Optional[RiskResult] = None
    sources: Dict[str, Any] = {}
    findings: List[str] = []
    ai_assessment: Optional[AiAssessment] = None
    error: Optional[str] = None