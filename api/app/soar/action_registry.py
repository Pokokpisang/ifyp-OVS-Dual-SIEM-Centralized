from __future__ import annotations

from typing import Any, Dict, Protocol, runtime_checkable


@runtime_checkable
class ActionHandler(Protocol):
    def execute(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]: ...


class SimulatedBlockIpAction:
    def execute(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "message": (
                f"[SIMULATION] Source IP {target} would be blocked in a real deployment. "
                "No network change was made."
            ),
            "target": target,
        }


class CreateCaseNoteAction:
    def execute(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "[SIMULATION] Case note creation is a placeholder in SOAR v1.",
            "target": target,
        }


class MarkAlertStatusAction:
    def execute(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "[SIMULATION] Alert status update is a placeholder in SOAR v1.",
            "target": target,
        }


ACTION_REGISTRY: Dict[str, ActionHandler] = {
    "simulated_block_ip": SimulatedBlockIpAction(),
    "create_case_note": CreateCaseNoteAction(),
    "mark_alert_status": MarkAlertStatusAction(),
}


def get_handler(action_type: str) -> ActionHandler:
    handler = ACTION_REGISTRY.get(action_type)
    if handler is None:
        raise ValueError(
            f"Unknown SOAR action type '{action_type}'. "
            f"Registered types: {list(ACTION_REGISTRY.keys())}"
        )
    return handler
