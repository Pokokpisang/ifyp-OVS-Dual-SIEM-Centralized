from pydantic import BaseModel
from typing import Optional, List


class SOARRecommendationOut(BaseModel):
    recommended: bool
    action: Optional[str] = None
    requires_analyst_approval: bool = True
    reason: Optional[str] = None


class AITriageResult(BaseModel):
    summary: str
    priority: str                   # low|medium|high|critical
    confidence: str                 # low|medium|high
    false_positive_likelihood: str  # unlikely|possible|likely
    key_reasons: List[str]
    recommended_next_steps: List[str]
    soar_recommendation: Optional[SOARRecommendationOut] = None
