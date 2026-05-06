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
        rule_name       = target or context.get("rule_name") or "Unknown Rule"
        mitre           = context.get("mitre_technique") or "Not mapped"
        engine          = context.get("detection_engine") or "Unknown"
        host_or_agent   = context.get("host") or context.get("agent_id") or "Unknown"

        message = (
            f"[SIMULATION] Investigation note created for rule: {rule_name}\n"
            f"MITRE Technique: {mitre}\n"
            f"Detection Engine: {engine}\n"
            f"Affected Host / Agent: {host_or_agent}\n"
            f"\n"
            f"Suggested analyst review items:\n"
            f"  1. Review the full command line and identify the network tool used.\n"
            f"  2. Inspect the parent process hierarchy for unexpected spawning chains.\n"
            f"  3. Check user context — was this a privileged or service account?\n"
            f"  4. Verify the execution path — /tmp, /dev/shm, or home directories are suspicious.\n"
            f"  5. Cross-reference with related timeline events in the ±10 minute window.\n"
            f"  6. Confirm whether this matches a known administrative task or CI/CD pipeline.\n"
            f"\n"
            f"No real system change was made. This note exists for analyst triage only."
        )
        return {"success": True, "message": message, "target": target}


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
