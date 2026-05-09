import json
from typing import Optional

# Only these detection_metadata keys are forwarded to the AI prompt.
# Unknown keys are silently ignored to mitigate prompt-injection via alert content.
_SAFE_METADATA_KEYS = {"match_reasons", "adjustment_reasons", "risk_score", "source_ip"}

_RESPONSE_SCHEMA = """{
  "summary": "<short analyst-friendly explanation>",
  "priority": "low | medium | high | critical",
  "confidence": "low | medium | high",
  "false_positive_likelihood": "unlikely | possible | likely",
  "key_reasons": ["<reason 1>", "<reason 2>"],
  "recommended_next_steps": ["<step 1>", "<step 2>"],
  "soar_recommendation": {
    "recommended": true,
    "action": "<suggested_action_name>",
    "requires_analyst_approval": true,
    "reason": "<why this action is suggested>"
  }
}"""


def build_prompt(alert, assessment=None) -> tuple[str, dict]:
    """
    Build a deterministic Gemini prompt from an Alert ORM row.

    Returns (prompt_string, input_context_dict).
    input_context_dict is stored in the DB for audit purposes.
    """
    desc = (alert.description or "")[:500]

    safe_metadata: dict = {}
    if alert.detection_metadata:
        try:
            raw_meta = json.loads(alert.detection_metadata)
            if isinstance(raw_meta, dict):
                safe_metadata = {k: v for k, v in raw_meta.items() if k in _SAFE_METADATA_KEYS}
        except (json.JSONDecodeError, TypeError):
            pass

    input_ctx = {
        "alert_id": alert.id,
        "title": alert.title or "",
        "severity": alert.severity or "",
        "host": alert.host or "",
        "timestamp": str(alert.timestamp) if alert.timestamp else "",
        "mitre_tactic": alert.mitre_tactic or "",
        "mitre_technique": alert.mitre_technique or "",
        "detection_engine": alert.detection_engine or "",
        "risk_score": alert.risk_score or 0,
        "rule_name": alert.rule_name or "",
        "description_excerpt": desc,
        "safe_metadata": safe_metadata,
        "assessment_status": assessment.status if assessment else "New",
    }

    metadata_block = ""
    if safe_metadata:
        for k, v in safe_metadata.items():
            metadata_block += f"  - {k}: {str(v)[:300]}\n"
    else:
        metadata_block = "  (none available)\n"

    prompt = f"""You are a cybersecurity analyst assistant helping a security team triage SIEM alerts.

IMPORTANT RESTRICTIONS — you must follow these at all times:
- You are NOT allowed to execute any commands or response actions.
- You are NOT allowed to approve or trigger SOAR actions.
- You are NOT allowed to modify, create, or delete SIEM rules.
- You are NOT allowed to suppress or delete alerts.
- You are NOT allowed to invent facts not present in the context below.
- You provide advisory analysis only.

RESPONSE FORMAT — return ONLY valid JSON matching this exact schema, with no markdown, no code fences, no extra text:
{_RESPONSE_SCHEMA}

CONSTRAINTS on field values:
- priority: must be exactly one of: low, medium, high, critical
- confidence: must be exactly one of: low, medium, high
- false_positive_likelihood: must be exactly one of: unlikely, possible, likely
- soar_recommendation.requires_analyst_approval: MUST always be true

ALERT CONTEXT:
  Title            : {input_ctx["title"]}
  Severity         : {input_ctx["severity"]}
  Host             : {input_ctx["host"]}
  Timestamp        : {input_ctx["timestamp"]}
  MITRE Tactic     : {input_ctx["mitre_tactic"] or "Not mapped"}
  MITRE Technique  : {input_ctx["mitre_technique"] or "Not mapped"}
  Detection Engine : {input_ctx["detection_engine"]}
  Risk Score       : {input_ctx["risk_score"]}
  Rule Name        : {input_ctx["rule_name"] or "N/A"}
  Description      : {desc or "N/A"}
  Analyst Status   : {input_ctx["assessment_status"]}

DETECTION EVIDENCE:
{metadata_block}
Analyze the alert context above and return your JSON triage output now."""

    return prompt, input_ctx
