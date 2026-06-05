"""Build a family-first attack-technique analysis plan from behavior candidates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ._json_utils import load_json
from ._text_utils import short_text
from .base import Tool, ToolResult, coerce_int, coerce_str_list
from .behavior_confidence import rank_confidence
from .behavior_hierarchy import BEHAVIOR_FAMILIES, annotate_hierarchy


def _collect_capabilities(value: Any, out: list[dict[str, Any]]) -> None:
    if isinstance(value, dict):
        capabilities = value.get("capabilities")
        if isinstance(capabilities, list):
            out.extend(item for item in capabilities if isinstance(item, dict))
        hints = value.get("report_hints")
        if isinstance(hints, dict):
            candidates = hints.get("key_capability_candidates")
            if isinstance(candidates, list):
                for item in candidates:
                    if isinstance(item, dict):
                        out.append({
                            "category": item.get("category", "unknown"),
                            "label": item.get("category", "能力候选"),
                            "matched_terms": [item.get("technique", "")],
                            "evidence": [item.get("evidence", "")],
                            "confidence": item.get("confidence", "low"),
                            "required_validation": [],
                        })
        for child in value.values():
            _collect_capabilities(child, out)
    elif isinstance(value, list):
        for child in value:
            _collect_capabilities(child, out)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalize(capabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = [dict(item) for item in capabilities if isinstance(item, dict)]
    return annotate_hierarchy(normalized)


def _candidate_row(item: dict[str, Any]) -> dict[str, Any]:
    gates = [str(x) for x in _as_list(item.get("claim_gate")) if str(x).strip()]
    validation = [str(x) for x in _as_list(item.get("required_validation")) if str(x).strip()]
    suppressors = list(item.get("family_suppressed_by") or item.get("overlap_suppressed_by") or [])
    return {
        "category": str(item.get("category") or ""),
        "label": str(item.get("label") or item.get("category") or ""),
        "confidence": str(item.get("confidence") or "low"),
        "claim_level": str(item.get("claim_level") or "static capability"),
        "matched_terms": [str(x) for x in _as_list(item.get("matched_terms")) if str(x).strip()][:8],
        "evidence_count": len([x for x in _as_list(item.get("evidence")) if str(x).strip()]),
        "next_validation": (gates + validation)[:6],
        "noise_suppressed_by": [str(x) for x in suppressors],
    }


def build_attack_technique_plan(capabilities: list[dict[str, Any]], max_families: int) -> list[dict[str, Any]]:
    annotated = _normalize(capabilities)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in annotated:
        grouped.setdefault(str(item.get("analysis_family") or "uncategorized"), []).append(item)

    plan = []
    for family, items in grouped.items():
        data = BEHAVIOR_FAMILIES.get(family, {})
        items.sort(
            key=lambda item: (
                rank_confidence(item.get("confidence")),
                len(_as_list(item.get("matched_terms"))),
            ),
            reverse=True,
        )
        rows = [_candidate_row(item) for item in items]
        max_rank = max((rank_confidence(item.get("confidence")) for item in items), default=0)
        plan.append({
            "family": family,
            "label": str(data.get("label") or "未归类"),
            "description": str(data.get("description") or "No family description configured."),
            "family_validation": [str(x) for x in data.get("validation", [])],
            "max_confidence_rank": max_rank,
            "candidate_count": len(rows),
            "candidates": rows,
        })
    plan.sort(key=lambda item: (item["max_confidence_rank"], item["candidate_count"]), reverse=True)
    return plan[:max_families]


class AttackTechniquePlannerTool(Tool):
    name = "attack_technique_planner"
    description = (
        "Build a family-first defensive attack-technique planning queue from "
        "behavior capability candidates. Use before deep analysis to decide "
        "which major behavior families and child techniques need validation."
    )
    parameters = {
        "type": "object",
        "properties": {
            "capabilities": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Behavior capability candidate objects, usually from behavior_capability_map.",
            },
            "json_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional JSON files containing behavior capabilities or report hints.",
            },
            "max_families": {
                "type": "integer",
                "description": "Maximum behavior families to return. Default 8.",
            },
        },
    }

    def execute(
        self,
        capabilities: list[dict[str, Any]] | None = None,
        json_paths: list[str] | str | None = None,
        max_families: int = 8,
        **kwargs,
    ) -> ToolResult:
        max_families = coerce_int(max_families, 8, minimum=1, maximum=20)
        collected = [item for item in (capabilities or []) if isinstance(item, dict)]
        warnings: list[str] = []

        for raw_path in coerce_str_list(json_paths):
            data, error = load_json(Path(raw_path), label="attack technique planning")
            if error:
                warnings.append(error)
                continue
            _collect_capabilities(data, collected)

        if not collected:
            return ToolResult(
                content="Error: provide capabilities or json_paths containing behavior capability candidates.",
                is_error=True,
                metadata={"warnings": warnings},
            )

        plan = build_attack_technique_plan(collected, max_families)
        lines = [
            "# Attack Technique Planning",
            "",
            f"Capabilities scanned: {len(collected)}",
            f"Families returned: {len(plan)}",
        ]
        if warnings:
            lines.extend(["", "## Warnings"])
            lines.extend(f"- {warning}" for warning in warnings)
        lines.extend(["", "## Family-First Queue"])
        for family in plan:
            lines.extend([
                "",
                f"### {family['label']} ({family['family']})",
                f"- Description: {family['description']}",
                f"- Candidate categories: {family['candidate_count']}",
            ])
            if family["family_validation"]:
                lines.append("- Family validation:")
                lines.extend(f"  - {step}" for step in family["family_validation"][:4])
            lines.append("- Top child candidates:")
            for candidate in family["candidates"][:8]:
                terms = ", ".join(candidate["matched_terms"]) or "no matched terms listed"
                line = (
                    f"  - {candidate['label']} ({candidate['category']}): "
                    f"confidence={candidate['confidence']}, evidence={candidate['evidence_count']}, terms={short_text(terms, 100)}"
                )
                if candidate["noise_suppressed_by"]:
                    line += f", suppressed_by={', '.join(candidate['noise_suppressed_by'])}"
                lines.append(line)
                if candidate["next_validation"]:
                    lines.append(f"    next: {short_text(candidate['next_validation'][0], 140)}")

        return ToolResult(
            content="\n".join(lines),
            metadata={
                "warnings": warnings,
                "analysis_plan": plan,
                "families_returned": len(plan),
                "capabilities_scanned": len(collected),
                "report_hints": {"analysis_plan": plan},
            },
        )
