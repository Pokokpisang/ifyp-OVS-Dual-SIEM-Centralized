from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .. import models
from .schemas import SOARAction, SOARCondition, SOARPlaybook, SOARRecommendation

_SEVERITY_MAP: Dict[str, str] = {
    "HIGH": "high",
    "MED": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
    "CRITICAL": "critical",
    "INFO": "informational",
    "INFORMATIONAL": "informational",
}


def _build_alert_context(alert: models.Alert) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {
        "severity": _SEVERITY_MAP.get(
            (alert.severity or "").upper(),
            (alert.severity or "").lower(),
        ),
        "risk_score": alert.risk_score or 0,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "mitre_technique": alert.mitre_technique,
        "mitre_tactic": alert.mitre_tactic,
        "detection_engine": alert.detection_engine,
        "host": alert.host,
        "agent_id": alert.agent_id,
    }
    if alert.detection_metadata:
        try:
            meta = json.loads(alert.detection_metadata)
            if isinstance(meta, dict):
                ctx.update(meta)
        except (json.JSONDecodeError, TypeError):
            pass
    return ctx


def _eval_condition(condition: SOARCondition, ctx: Dict[str, Any]) -> bool:
    field = condition.field
    op = condition.operator
    value = condition.value
    field_value = ctx.get(field)

    if op == "exists":
        return field_value is not None and field_value != "" and field_value != []

    if op == "not_exists":
        return field_value is None or field_value == ""

    if op == "equals":
        return str(field_value) == str(value) if field_value is not None else False

    if op == "not_equals":
        return str(field_value) != str(value) if field_value is not None else True

    if op == "in":
        if not isinstance(value, list):
            return False
        return str(field_value).lower() in [str(v).lower() for v in value]

    if op == "not_in":
        if not isinstance(value, list):
            return True
        return str(field_value).lower() not in [str(v).lower() for v in value]

    if op == "contains":
        if field_value is None:
            return False
        return str(value).lower() in str(field_value).lower()

    if op == "greater_than_or_equal":
        try:
            return float(field_value) >= float(value)
        except (TypeError, ValueError):
            return False

    if op == "less_than_or_equal":
        try:
            return float(field_value) <= float(value)
        except (TypeError, ValueError):
            return False

    return False


# Maps SOARTrigger field name → alert context key used for matching.
# All trigger fields use the same {"in": [...]} structure.
_TRIGGER_FIELD_MAP: Dict[str, str] = {
    "alert_severity": "severity",
    "detection_engine": "detection_engine",
    "mitre_technique": "mitre_technique",
}


def _eval_trigger(playbook: SOARPlaybook, ctx: Dict[str, Any]) -> Optional[str]:
    trigger = playbook.trigger
    reasons: List[str] = []

    for trigger_field, ctx_field in _TRIGGER_FIELD_MAP.items():
        filter_dict = getattr(trigger, trigger_field, None)
        if filter_dict is None:
            continue
        in_list = filter_dict.get("in")
        if in_list is None:
            continue
        ctx_value = str(ctx.get(ctx_field) or "").lower()
        if ctx_value not in [str(v).lower() for v in in_list]:
            return None
        reasons.append(f"{trigger_field} '{ctx_value}' matches trigger")

    if not reasons:
        return "Trigger matched (no filters)"
    return "; ".join(reasons)


def _eval_conditions(playbook: SOARPlaybook, ctx: Dict[str, Any]) -> List[str]:
    reasons: List[str] = []
    conditions_map = playbook.conditions

    all_conditions: List[SOARCondition] = conditions_map.get("all", [])
    any_conditions: List[SOARCondition] = conditions_map.get("any", [])

    for cond in all_conditions:
        if not _eval_condition(cond, ctx):
            return []
        reasons.append(f"Field '{cond.field}' satisfies operator '{cond.operator}'")

    if any_conditions:
        matched_any = False
        for cond in any_conditions:
            if _eval_condition(cond, ctx):
                matched_any = True
                reasons.append(f"Field '{cond.field}' satisfies operator '{cond.operator}'")
                break
        if not matched_any:
            return []

    return reasons


def match(alert: models.Alert, playbooks: List[SOARPlaybook]) -> List[SOARRecommendation]:
    ctx = _build_alert_context(alert)
    recommendations: List[SOARRecommendation] = []

    for playbook in playbooks:
        if not playbook.enabled:
            continue

        trigger_reason = _eval_trigger(playbook, ctx)
        if trigger_reason is None:
            continue

        condition_reasons = _eval_conditions(playbook, ctx)
        if not condition_reasons:
            continue

        match_reasons = [trigger_reason] + condition_reasons

        for action in playbook.actions:
            resolved_target: Optional[str] = None
            if action.target_field:
                raw = ctx.get(action.target_field)
                resolved_target = str(raw) if raw is not None else None

            recommendations.append(
                SOARRecommendation(
                    playbook_id=playbook.id,
                    playbook_name=playbook.name,
                    playbook_description=playbook.description,
                    action=action,
                    resolved_target=resolved_target,
                    match_reasons=match_reasons,
                )
            )

    return recommendations
