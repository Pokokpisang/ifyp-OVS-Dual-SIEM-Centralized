"""
Detection rule schema definitions using Pydantic.
"""
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field, field_validator, model_validator
from enum import Enum

# Operators understood by RuleEvaluator. Keep in sync with rule_evaluator.py.
ALLOWED_OPERATORS = {
    "equals", "not_equals", "contains", "not_contains",
    "contains_any", "not_contains_any", "contains_all",
    "in", "not_in", "list_intersects", "regex",
    "exists", "not_exists", "gte", "lte",
}
_VALUELESS_OPERATORS = {"exists", "not_exists"}
_LEAF_KEYS = {"field", "operator", "value"}
_ADJUSTMENT_META_KEYS = {"add_score", "subtract_score", "reason"}


def _validate_condition_node(node: Any, path: str) -> None:
    """Recursively validate a condition tree node.

    A node is one of: {all: [...]}, {any: [...]}, {not: {...}}, or a leaf
    {field, operator, value?}. Raises ValueError (with the node path) on any
    structural or operator error so RuleLoader records it and skips the rule.
    """
    if not isinstance(node, dict):
        raise ValueError(f"{path}: condition node must be a mapping, got {type(node).__name__}")

    for key in ("all", "any"):
        if key in node:
            seq = node[key]
            if not isinstance(seq, list) or not seq:
                raise ValueError(f"{path}.{key}: must be a non-empty list")
            for i, sub in enumerate(seq):
                _validate_condition_node(sub, f"{path}.{key}[{i}]")
            return

    if "not" in node:
        _validate_condition_node(node["not"], f"{path}.not")
        return

    # Leaf condition
    if "field" not in node or "operator" not in node:
        raise ValueError(
            f"{path}: leaf condition requires 'field' and 'operator' "
            f"(got keys {sorted(node.keys())})"
        )
    operator = str(node["operator"]).lower()
    if operator not in ALLOWED_OPERATORS:
        raise ValueError(f"{path}: unknown operator '{node['operator']}'")
    unexpected = set(node.keys()) - _LEAF_KEYS
    if unexpected:
        raise ValueError(f"{path}: unexpected keys {sorted(unexpected)} in leaf condition")
    if operator not in _VALUELESS_OPERATORS and "value" not in node:
        raise ValueError(f"{path}: operator '{operator}' requires a 'value'")


def _validate_risk_adjustment(adjustment: Any) -> None:
    """Validate the risk_adjustment block shape.

    Only increase_if / decrease_if lists are allowed; each block is a condition
    node plus an integer add_score / subtract_score (and optional reason). This
    rejects the legacy conditions:/increase_by: shape that risk_scoring cannot
    read.
    """
    if adjustment is None:
        return
    if not isinstance(adjustment, dict):
        raise ValueError("risk_adjustment must be a mapping")
    unexpected = set(adjustment.keys()) - {"increase_if", "decrease_if"}
    if unexpected:
        raise ValueError(f"risk_adjustment: unexpected keys {sorted(unexpected)}")

    for key, score_key in (("increase_if", "add_score"), ("decrease_if", "subtract_score")):
        blocks = adjustment.get(key)
        if blocks is None:
            continue
        if not isinstance(blocks, list):
            raise ValueError(f"risk_adjustment.{key} must be a list")
        for i, block in enumerate(blocks):
            path = f"risk_adjustment.{key}[{i}]"
            if not isinstance(block, dict):
                raise ValueError(f"{path}: must be a mapping")
            if score_key not in block:
                raise ValueError(f"{path}: missing '{score_key}'")
            if not isinstance(block[score_key], int) or isinstance(block[score_key], bool):
                raise ValueError(f"{path}: '{score_key}' must be an integer")
            condition_part = {k: v for k, v in block.items() if k not in _ADJUSTMENT_META_KEYS}
            _validate_condition_node(condition_part, path)


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

    @model_validator(mode='after')
    def validate_logic_blocks(self):
        """Validate the condition tree and risk_adjustment shape after field
        parsing, so malformed operators/blocks are rejected at load time rather
        than silently ignored at match time."""
        _validate_condition_node(self.condition, "condition")
        _validate_risk_adjustment(self.risk_adjustment)
        return self

# Future: Add EventSchema and AlertSchema in their respective files.
