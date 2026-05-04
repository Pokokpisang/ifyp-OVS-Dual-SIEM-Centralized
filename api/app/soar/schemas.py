from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class SOARActionAutomation(BaseModel):
    auto_run_allowed: bool = False


class SOARAction(BaseModel):
    id: str
    name: str
    type: str
    target_field: Optional[str] = None
    mode: Literal["simulation"]
    requires_approval: bool = True
    rollback_supported: bool = False
    description: str = ""
    automation: SOARActionAutomation = Field(default_factory=SOARActionAutomation)


class SOARCondition(BaseModel):
    field: str
    operator: str
    value: Optional[Any] = None


class SOARTrigger(BaseModel):
    alert_severity: Optional[Dict[str, List[str]]] = None
    detection_engine: Optional[Dict[str, List[str]]] = None
    mitre_technique: Optional[Dict[str, List[str]]] = None


class SOARPlaybook(BaseModel):
    id: str
    name: str
    description: str = ""
    enabled: bool = True
    trigger: SOARTrigger
    conditions: Dict[str, List[SOARCondition]]
    actions: List[SOARAction]


class SOARRecommendation(BaseModel):
    playbook_id: str
    playbook_name: str
    playbook_description: str
    action: SOARAction
    resolved_target: Optional[str] = None
    match_reasons: List[str]


class SOARExecutionResult(BaseModel):
    success: bool
    playbook_id: str
    action_id: str
    action_type: str
    target: Optional[str] = None
    mode: str
    message: str
    error: Optional[str] = None


class SOARRunRequest(BaseModel):
    playbook_id: str
    action_id: str
    executed_by: Optional[str] = "analyst"
