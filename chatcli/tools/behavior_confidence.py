"""Shared confidence and evidence helpers for behavior analysis tools."""

from __future__ import annotations

from typing import Any


CONFIDENCE_RANK = {
    "confirmed": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "hypothesis": 1,
    "blocked": 0,
}


def rank_confidence(value: Any) -> int:
    return CONFIDENCE_RANK.get(str(value or "").strip().lower(), 0)


def downgrade_confidence(value: Any) -> str:
    value = str(value or "low").strip().lower()
    if value == "confirmed":
        return "high"
    if value == "high":
        return "medium"
    if value == "medium":
        return "low"
    return value or "low"


def lower_confidence(left: Any, right: Any | None) -> str:
    if not right:
        return str(left or "low")
    return str(left or "low") if rank_confidence(left) <= rank_confidence(right) else str(right)


def has_shared_evidence(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_evidence = {str(item).strip() for item in left.get("evidence", []) if str(item).strip()}
    right_evidence = {str(item).strip() for item in right.get("evidence", []) if str(item).strip()}
    if not left_evidence or not right_evidence:
        return False
    return bool(left_evidence & right_evidence)
