"""
Detection rule schema definitions using Pydantic.
"""
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field, field_validator
from enum import Enum

class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class DetectionRule(BaseModel):
    id: str
    name: str
    description: str
    enabled: bool = True
    platform: List[str] = Field(default_factory=lambda: ["linux"])
    log_source: Dict[str, Any]
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    mitre: Dict[str, Any]
    tags: List[str] = Field(default_factory=list)
    required_fields: List[str]
    condition: Dict[str, Any]
    risk_adjustment: Optional[Dict[str, Any]] = None
    false_positives: List[str] = Field(default_factory=list)
    investigation_guide: str
    references: List[str] = Field(default_factory=list)

    @field_validator('severity', mode='before')
    @classmethod
    def validate_severity(cls, v):
        if isinstance(v, str):
            v = v.lower()
            # Map common variations if needed, but the requirement is specific
        return v

# Future: Add EventSchema and AlertSchema in their respective files.
