from __future__ import annotations

from typing import Any, Dict

from .action_registry import get_handler
from .schemas import SOARAction, SOARExecutionResult, SOARPlaybook


def execute_action(
    alert_context: Dict[str, Any],
    playbook: SOARPlaybook,
    action: SOARAction,
) -> SOARExecutionResult:
    base = dict(
        playbook_id=playbook.id,
        action_id=action.id,
        action_type=action.type,
        mode=action.mode,
        target=None,
    )

    if action.mode != "simulation":
        return SOARExecutionResult(
            success=False,
            message=f"Action mode '{action.mode}' is not permitted. Only 'simulation' is allowed in SOAR v1.",
            error="non_simulation_mode_rejected",
            **base,
        )

    try:
        handler = get_handler(action.type)
    except ValueError as exc:
        return SOARExecutionResult(
            success=False,
            message=str(exc),
            error="unknown_action_type",
            **base,
        )

    target: str | None = None
    if action.target_field:
        raw = alert_context.get(action.target_field)
        if raw is None or raw == "":
            return SOARExecutionResult(
                success=False,
                message=(
                    f"Required target field '{action.target_field}' is missing or empty in the alert context. "
                    "Action was not executed."
                ),
                error="missing_target_field",
                **base,
            )
        target = str(raw)

    result = handler.execute(target or "", alert_context)

    return SOARExecutionResult(
        success=result.get("success", False),
        message=result.get("message", ""),
        error=result.get("error"),
        target=target,
        **{k: v for k, v in base.items() if k != "target"},
    )
