"""Map defensive malware behavior candidates to ATT&CK-style techniques."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ._json_utils import load_json
from ._text_utils import short_text
from .base import Tool, ToolResult, coerce_int, coerce_str_list
from .attack_technique_rules import HIGH_IMPACT, TECHNIQUE_MAP
from .behavior_confidence import lower_confidence, rank_confidence



def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]



def _collect(value: Any, caps: list[dict[str, Any]], chain: list[dict[str, Any]], audits: list[dict[str, Any]]) -> None:
    if isinstance(value, dict):
        capabilities = value.get("capabilities")
        if isinstance(capabilities, list):
            caps.extend(item for item in capabilities if isinstance(item, dict))
        steps = value.get("steps")
        if isinstance(steps, list):
            chain.extend(item for item in steps if isinstance(item, dict))
        attack_chain = value.get("attack_chain")
        if isinstance(attack_chain, list):
            chain.extend(item for item in attack_chain if isinstance(item, dict))
        audit = value.get("audit")
        if isinstance(audit, dict):
            audits.append(audit)
        hints = value.get("report_hints")
        if isinstance(hints, dict):
            hinted_chain = hints.get("attack_chain")
            if isinstance(hinted_chain, list):
                chain.extend(item for item in hinted_chain if isinstance(item, dict))
        for child in value.values():
            _collect(child, caps, chain, audits)
    elif isinstance(value, list):
        for child in value:
            _collect(child, caps, chain, audits)


def _unsupported_categories(audits: list[dict[str, Any]]) -> set[str]:
    categories: set[str] = set()
    for audit in audits:
        for item in audit.get("unsupported_capabilities", []) or []:
            category = str(item.get("category") or "")
            if category:
                categories.add(category)
    return categories


def _validation_categories(audits: list[dict[str, Any]]) -> set[str]:
    categories: set[str] = set()
    for audit in audits:
        for item in audit.get("validation_required", []) or []:
            category = str(item.get("category") or "")
            if category:
                categories.add(category)
    return categories


def _chain_category_state(attack_chain: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    state: dict[str, dict[str, Any]] = {}
    for step in attack_chain:
        raw = str(step.get("source_category") or "")
        categories = [part.strip() for part in raw.split("+") if part.strip()]
        if not categories:
            continue
        confidence = str(step.get("confidence") or "")
        gate_status = str(step.get("gate_status") or "")
        gaps = str(step.get("gaps") or "")
        needs_validation = gate_status == "needs_validation" or "Dependency gap:" in gaps
        for category in categories:
            item = state.setdefault(category, {
                "confidence": confidence or "low",
                "needs_validation": False,
            })
            item["confidence"] = lower_confidence(str(item.get("confidence") or "low"), confidence or None)
            item["needs_validation"] = bool(item.get("needs_validation")) or needs_validation
    return state


def _mapping_status(
    category: str,
    cap: dict[str, Any],
    unsupported: set[str],
    needs_validation: set[str],
    chain_state: dict[str, dict[str, Any]],
) -> tuple[str, str]:
    evidence = [x for x in _as_list(cap.get("evidence")) if str(x).strip()]
    if category in unsupported or not evidence:
        return "blocked", "mapping lacks direct supporting evidence"
    chain = chain_state.get(category, {})
    if cap.get("claim_gate") or category in needs_validation or chain.get("needs_validation"):
        return "needs_validation", "high-impact or gated behavior requires validation before confirmed ATT&CK mapping"
    chain_confidence = str(chain.get("confidence") or "")
    if rank_confidence(cap.get("confidence")) <= rank_confidence("low") or (
        chain_confidence and rank_confidence(chain_confidence) <= rank_confidence("low")
    ):
        return "hypothesis", "low-confidence behavior candidate"
    return "candidate", "evidence-backed candidate mapping"


def _build_mappings(
    capabilities: list[dict[str, Any]],
    attack_chain: list[dict[str, Any]],
    audits: list[dict[str, Any]],
    max_mappings: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    unsupported = _unsupported_categories(audits)
    needs_validation = _validation_categories(audits)
    by_category: dict[str, dict[str, Any]] = {}
    for cap in capabilities:
        category = str(cap.get("category") or "")
        if category and category not in by_category:
            by_category[category] = cap

    chain_categories: set[str] = set()
    for step in attack_chain:
        raw = str(step.get("source_category") or "")
        chain_categories.update(part.strip() for part in raw.split("+") if part.strip())
    chain_state = _chain_category_state(attack_chain)

    mappings: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    for category, cap in by_category.items():
        if category not in TECHNIQUE_MAP:
            issues.append({
                "severity": "low",
                "kind": "unmapped_category",
                "message": f"No ATT&CK-style mapping configured for category: {category}",
                "recommendation": "Keep as custom behavior category or add a reviewed mapping.",
            })
            continue
        status, reason = _mapping_status(category, cap, unsupported, needs_validation, chain_state)
        confidence = lower_confidence(str(cap.get("confidence", "low")), chain_state.get(category, {}).get("confidence"))
        if status == "blocked":
            issues.append({
                "severity": "high" if category in HIGH_IMPACT else "medium",
                "kind": "blocked_mapping",
                "message": f"Blocked ATT&CK-style mapping for {category}: {reason}.",
                "recommendation": "Add concrete evidence or remove/downgrade this mapping.",
            })
        elif status == "needs_validation":
            issues.append({
                "severity": "medium",
                "kind": "mapping_needs_validation",
                "message": f"ATT&CK-style mapping for {category} still needs validation.",
                "recommendation": "Use candidate/likely wording until code/config/runtime evidence satisfies the claim gate.",
            })
        for tactic, technique_id, technique in TECHNIQUE_MAP[category]:
            mappings.append({
                "category": category,
                "label": cap.get("label") or category,
                "analysis_family": cap.get("analysis_family", ""),
                "family_label": cap.get("family_label", ""),
                "tactic": tactic,
                "technique_id": technique_id,
                "technique": technique,
                "status": status,
                "status_reason": reason,
                "confidence": confidence,
                "matched_terms": cap.get("matched_terms", []),
                "evidence": cap.get("evidence", [])[:6] if isinstance(cap.get("evidence"), list) else _as_list(cap.get("evidence"))[:6],
                "in_attack_chain": category in chain_categories,
                "claim_gate": cap.get("claim_gate", []),
            })
            if len(mappings) >= max_mappings:
                return mappings, issues
    return mappings, issues


class AttackTechniqueMapperTool(Tool):
    name = "attack_technique_mapper"
    description = (
        "Map behavior capability candidates to ATT&CK-style technique candidates "
        "with evidence, confidence, validation status, and over-mapping issues."
    )
    parameters = {
        "type": "object",
        "properties": {
            "capabilities": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Behavior capability candidate objects.",
            },
            "attack_chain": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Optional attack-chain step objects.",
            },
            "evidence_graph": {
                "type": "object",
                "description": "Optional evidence_graph metadata/result containing audit.",
            },
            "json_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional JSON files containing capabilities, attack chain, or evidence graph audit.",
            },
            "max_mappings": {
                "type": "integer",
                "description": "Maximum mappings to return. Default 40.",
            },
        },
    }

    def execute(
        self,
        capabilities: list[dict[str, Any]] | None = None,
        attack_chain: list[dict[str, Any]] | None = None,
        evidence_graph: dict[str, Any] | None = None,
        json_paths: list[str] | str | None = None,
        max_mappings: int = 40,
        **kwargs,
    ) -> ToolResult:
        max_mappings = coerce_int(max_mappings, 40, minimum=1, maximum=200)
        caps = [item for item in (capabilities or []) if isinstance(item, dict)]
        chain = [item for item in (attack_chain or []) if isinstance(item, dict)]
        audits: list[dict[str, Any]] = []
        warnings: list[str] = []

        if isinstance(evidence_graph, dict):
            _collect(evidence_graph, caps, chain, audits)
        for raw_path in coerce_str_list(json_paths):
            data, error = load_json(Path(raw_path), label="technique mapping")
            if error:
                warnings.append(error)
                continue
            _collect(data, caps, chain, audits)

        if not caps:
            return ToolResult(
                content="Error: provide capabilities or json_paths containing behavior capabilities.",
                is_error=True,
                metadata={"warnings": warnings},
            )

        mappings, issues = _build_mappings(caps, chain, audits, max_mappings)
        severity_counts: dict[str, int] = {}
        for issue in issues:
            severity_counts[issue["severity"]] = severity_counts.get(issue["severity"], 0) + 1
        status = "pass"
        if any(issue["severity"] == "high" for issue in issues):
            status = "needs_revision"
        elif issues:
            status = "review_required"

        lines = [
            "# ATT&CK-Style Technique Mapping",
            "",
            f"Status: {status}",
            f"Capabilities scanned: {len(caps)}",
            f"Mappings returned: {len(mappings)}",
            f"Issues: {len(issues)}",
        ]
        if severity_counts:
            lines.extend(["", "## Severity Counts"])
            lines.extend(f"- {key}: {value}" for key, value in sorted(severity_counts.items()))
        if mappings:
            lines.extend(["", "## Candidate Mappings"])
            for item in mappings:
                technique = f"{item['technique_id']} {item['technique']}".strip()
                lines.extend([
                    "",
                    f"### {item['label']} -> {technique}",
                    f"- Analysis family: {item.get('family_label') or item.get('analysis_family') or '未归类'}",
                    f"- Tactic: {item['tactic']}",
                    f"- Status: {item['status']} ({item['status_reason']})",
                    f"- Confidence: {item['confidence']}",
                    f"- In attack chain: {item['in_attack_chain']}",
                    f"- Evidence: {'; '.join(short_text(ev, 120) for ev in item['evidence']) or 'none'}",
                ])
        if issues:
            lines.extend(["", "## Issues"])
            for issue in issues[:50]:
                lines.extend([
                    f"- [{issue['severity']}] {issue['kind']}: {issue['message']}",
                    f"  Recommendation: {issue['recommendation']}",
                ])
        if warnings:
            lines.extend(["", "## Warnings"])
            lines.extend(f"- {warning}" for warning in warnings)

        return ToolResult(
            content="\n".join(lines),
            metadata={
                "status": status,
                "warnings": warnings,
                "severity_counts": severity_counts,
                "issues": issues,
                "mappings": mappings,
                "report_hints": {"attack_technique_mappings": mappings},
            },
        )
