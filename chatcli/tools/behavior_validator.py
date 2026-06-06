"""Validate defensive malware behavior claims against evidence and gates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ._json_utils import load_json
from ._text_utils import short_text
from ._analysis_collectors import as_list, collect_analysis_items
from .base import Tool, ToolResult, coerce_str_list
from .behavior_rules import CAPABILITY_RULES
from .behavior_hierarchy import BEHAVIOR_FAMILIES, CATEGORY_TO_FAMILY
from .attack_technique_rules import HIGH_IMPACT
from .behavior_confidence import rank_confidence


def _collect(value: Any, caps: list[dict[str, Any]], chain: list[dict[str, Any]], audits: list[dict[str, Any]]) -> None:
    collect_analysis_items(value, capabilities=caps, attack_chain=chain, audits=audits)


def _add_issue(
    issues: list[dict[str, Any]],
    severity: str,
    kind: str,
    message: str,
    item: Any = None,
    recommendation: str = "",
) -> None:
    issues.append({
        "severity": severity,
        "kind": kind,
        "message": message,
        "item": item,
        "recommendation": recommendation,
    })


def _validate_capabilities(capabilities: list[dict[str, Any]], issues: list[dict[str, Any]]) -> None:
    for cap in capabilities:
        category = str(cap.get("category") or "")
        label = str(cap.get("label") or category or "capability")
        confidence = str(cap.get("confidence") or "low")
        evidence = [x for x in as_list(cap.get("evidence")) if str(x).strip()]
        gates = [x for x in as_list(cap.get("claim_gate")) if str(x).strip()]
        claim_level = str(cap.get("claim_level") or "")

        if claim_level.lower() == "static capability" and confidence.lower() == "confirmed":
            _add_issue(
                issues,
                "high",
                "static_marked_confirmed",
                f"{label} is marked confirmed while claim_level is static capability.",
                {"category": category, "confidence": confidence},
                "Downgrade to high/medium static capability or add concrete code/runtime evidence.",
            )
        if rank_confidence(confidence) >= rank_confidence("medium") and not evidence:
            _add_issue(
                issues,
                "high",
                "missing_evidence",
                f"{label} has {confidence} confidence but no evidence snippets.",
                {"category": category, "confidence": confidence},
                "Attach strings, imports, xrefs, pseudocode, config fields, runtime telemetry, or mark as hypothesis.",
            )
        if category in HIGH_IMPACT and rank_confidence(confidence) >= rank_confidence("medium") and not gates:
            _add_issue(
                issues,
                "medium",
                "missing_claim_gate",
                f"{label} is a high-impact category without a claim gate.",
                {"category": category, "confidence": confidence},
                "Add a validation gate before using this as a report conclusion.",
            )


def _validate_attack_chain(attack_chain: list[dict[str, Any]], issues: list[dict[str, Any]]) -> None:
    for step in attack_chain:
        step_no = step.get("step", "?")
        behavior = str(step.get("behavior") or step.get("stage") or "attack step")
        confidence = str(step.get("confidence") or "low")
        evidence = str(step.get("evidence") or "").strip()
        gaps = str(step.get("gaps") or "").strip()
        gate_status = str(step.get("gate_status") or "")

        if rank_confidence(confidence) >= rank_confidence("high") and (not evidence or evidence.lower() == "no direct evidence snippet provided."):
            _add_issue(
                issues,
                "high",
                "attack_step_missing_evidence",
                f"Attack step {step_no} ({short_text(behavior)}) has {confidence} confidence but no direct evidence.",
                {"step": step_no, "behavior": behavior, "confidence": confidence},
                "Add concrete evidence or downgrade the step.",
            )
        if gate_status == "needs_validation" and rank_confidence(confidence) >= rank_confidence("high"):
            severity = "high" if confidence.lower() == "confirmed" else "medium"
            _add_issue(
                issues,
                severity,
                "high_confidence_with_open_gate",
                f"Attack step {step_no} ({short_text(behavior)}) is high confidence while validation gates remain open.",
                {"step": step_no, "behavior": behavior, "confidence": confidence},
                "Keep as likely/static capability until the required validation is satisfied.",
            )
        if gaps and rank_confidence(confidence) >= rank_confidence("confirmed"):
            _add_issue(
                issues,
                "medium",
                "confirmed_with_gaps",
                f"Attack step {step_no} ({short_text(behavior)}) is confirmed but still has gaps.",
                {"step": step_no, "behavior": behavior},
                "Resolve the gaps or downgrade from confirmed.",
            )


def _validate_audits(audits: list[dict[str, Any]], issues: list[dict[str, Any]]) -> None:
    for audit in audits:
        for item in audit.get("unsupported_capabilities", []) or []:
            _add_issue(
                issues,
                "high" if rank_confidence(item.get("confidence")) >= rank_confidence("medium") else "medium",
                "unsupported_capability",
                f"Capability lacks evidence support in evidence graph: {short_text(item.get('label'))}.",
                item,
                "Add supporting evidence or downgrade/remove the claim.",
            )
        for item in audit.get("unsupported_attack_steps", []) or []:
            _add_issue(
                issues,
                "high" if rank_confidence(item.get("confidence")) >= rank_confidence("medium") else "medium",
                "unsupported_attack_step",
                f"Attack step lacks evidence support in evidence graph: {short_text(item.get('label'))}.",
                item,
                "Add supporting evidence or downgrade/remove the step.",
            )
        for item in audit.get("validation_required", []) or []:
            if rank_confidence(item.get("confidence")) >= rank_confidence("high"):
                _add_issue(
                    issues,
                    "medium",
                    "validation_required",
                    f"High-confidence capability still requires validation: {short_text(item.get('label'))}.",
                    item,
                    "Keep wording as static/likely unless the claim gate is satisfied.",
                )


class BehaviorClaimValidatorTool(Tool):
    name = "behavior_claim_validator"
    description = (
        "Validate malware behavior claims against capabilities, attack-chain steps, "
        "and evidence-graph audit metadata. Flags unsupported or over-confident "
        "high-impact conclusions. Defensive/static only."
    )
    parameters = {
        "type": "object",
        "properties": {
            "capabilities": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Behavior capability candidates.",
            },
            "attack_chain": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Attack-chain step objects.",
            },
            "evidence_graph": {
                "type": "object",
                "description": "Optional evidence_graph metadata or result containing audit.",
            },
            "report": {
                "type": "object",
                "description": "Optional malware report JSON to inspect for attack_chain/key_capabilities.",
            },
            "json_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional JSON files containing capabilities, attack-chain, evidence-graph, or report structures.",
            },
        },
    }

    def execute(
        self,
        capabilities: list[dict[str, Any]] | None = None,
        attack_chain: list[dict[str, Any]] | None = None,
        evidence_graph: dict[str, Any] | None = None,
        report: dict[str, Any] | None = None,
        json_paths: list[str] | str | None = None,
        **kwargs,
    ) -> ToolResult:
        caps = [item for item in (capabilities or []) if isinstance(item, dict)]
        chain = [item for item in (attack_chain or []) if isinstance(item, dict)]
        audits: list[dict[str, Any]] = []
        warnings: list[str] = []

        for obj in (evidence_graph, report):
            if isinstance(obj, dict):
                _collect(obj, caps, chain, audits)

        for raw_path in coerce_str_list(json_paths):
            data, error = load_json(Path(raw_path), label="behavior validation")
            if error:
                warnings.append(error)
                continue
            _collect(data, caps, chain, audits)

        if not caps and not chain and not audits:
            return ToolResult(
                content="Error: provide capabilities, attack_chain, evidence_graph, report, or json_paths.",
                is_error=True,
                metadata={"warnings": warnings},
            )

        issues: list[dict[str, Any]] = []
        _validate_capabilities(caps, issues)
        _validate_attack_chain(chain, issues)
        _validate_audits(audits, issues)

        severity_counts: dict[str, int] = {}
        for issue in issues:
            severity = issue["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        status = "pass"
        if any(issue["severity"] == "high" for issue in issues):
            status = "needs_revision"
        elif issues:
            status = "review_required"
        lines = [
            "# Behavior Claim Validation",
            "",
            f"Status: {status}",
            f"Capabilities checked: {len(caps)}",
            f"Attack-chain steps checked: {len(chain)}",
            f"Evidence audits checked: {len(audits)}",
            f"Issues: {len(issues)}",
        ]
        if severity_counts:
            lines.extend(["", "## Severity Counts"])
            lines.extend(f"- {key}: {value}" for key, value in sorted(severity_counts.items()))
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
            },
        )


def _coverage_status(cap: dict[str, Any]) -> str:
    confidence = str(cap.get("confidence") or "low").lower()
    if confidence == "confirmed":
        return "confirmed"
    if cap.get("claim_gate") and confidence in {"high", "medium"}:
        return "blocked"
    if confidence in {"high", "medium"}:
        return "likely"
    return "low_confidence"


class BehaviorCoverageMatrixTool(Tool):
    name = "behavior_coverage_matrix"
    description = (
        "Build a defensive behavior coverage matrix from capability candidates. "
        "Separates confirmed, likely, low-confidence, blocked, and not-observed "
        "areas for malware reports."
    )
    parameters = {
        "type": "object",
        "properties": {
            "capabilities": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Behavior capability candidates.",
            },
            "json_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional JSON files containing behavior capabilities.",
            },
            "not_analyzed": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional behavior areas that were not analyzed.",
            },
        },
    }

    def execute(
        self,
        capabilities: list[dict[str, Any]] | None = None,
        json_paths: list[str] | str | None = None,
        not_analyzed: list[str] | str | None = None,
        **kwargs,
    ) -> ToolResult:
        caps = [item for item in (capabilities or []) if isinstance(item, dict)]
        warnings: list[str] = []

        for raw_path in coerce_str_list(json_paths):
            data, error = load_json(Path(raw_path), label="behavior validation")
            if error:
                warnings.append(error)
                continue
            _collect(data, caps, [], [])

        analyzed_blockers = set(coerce_str_list(not_analyzed))
        by_category: dict[str, dict[str, Any]] = {}
        rows: list[dict[str, Any]] = []
        for cap in caps:
            category = str(cap.get("category") or "unknown")
            current = by_category.get(category)
            if current and rank_confidence(current.get("confidence")) >= rank_confidence(cap.get("confidence")):
                continue
            by_category[category] = cap

        coverage = {
            "confirmed": [],
            "likely": [],
            "low_confidence": [],
            "blocked": [],
            "not_observed": [],
            "not_analyzed": sorted(analyzed_blockers),
        }

        for category, rule in CAPABILITY_RULES.items():
            label = str(rule.get("label") or category)
            family = CATEGORY_TO_FAMILY.get(category, "uncategorized")
            family_label = str(BEHAVIOR_FAMILIES.get(family, {}).get("label") or "未归类")
            cap = by_category.get(category)
            if category in analyzed_blockers or label in analyzed_blockers:
                status = "not_analyzed"
                confidence = "blocked"
                evidence_count = 0
                gate_status = "not_analyzed"
            elif cap:
                status = _coverage_status(cap)
                confidence = str(cap.get("confidence") or "low")
                evidence_count = len([x for x in as_list(cap.get("evidence")) if str(x).strip()])
                gate_status = "needs_validation" if cap.get("claim_gate") else "not_required"
                coverage[status].append(label)
            else:
                status = "not_observed"
                confidence = ""
                evidence_count = 0
                gate_status = "not_required"
                coverage["not_observed"].append(label)
            rows.append({
                "category": category,
                "label": label,
                "analysis_family": family,
                "family_label": family_label,
                "status": status,
                "confidence": confidence,
                "evidence_count": evidence_count,
                "gate_status": gate_status,
            })

        for cap in by_category.values():
            category = str(cap.get("category") or "unknown")
            if category in CAPABILITY_RULES:
                continue
            label = str(cap.get("label") or category)
            family = str(cap.get("analysis_family") or CATEGORY_TO_FAMILY.get(category, "uncategorized"))
            family_label = str(cap.get("family_label") or BEHAVIOR_FAMILIES.get(family, {}).get("label") or "未归类")
            status = _coverage_status(cap)
            coverage[status].append(label)
            rows.append({
                "category": category,
                "label": label,
                "analysis_family": family,
                "family_label": family_label,
                "status": status,
                "confidence": str(cap.get("confidence") or "low"),
                "evidence_count": len([x for x in as_list(cap.get("evidence")) if str(x).strip()]),
                "gate_status": "needs_validation" if cap.get("claim_gate") else "not_required",
            })

        counts = {key: len(value) for key, value in coverage.items()}
        family_counts: dict[str, dict[str, int]] = {}
        for row in rows:
            family = str(row.get("analysis_family") or "uncategorized")
            status = str(row.get("status") or "")
            family_counts.setdefault(family, {})
            family_counts[family][status] = family_counts[family].get(status, 0) + 1
        lines = [
            "# Behavior Coverage Matrix",
            "",
            f"Capabilities scanned: {len(caps)}",
            f"Behavior areas tracked: {len(rows)}",
            "",
            "## Coverage Counts",
        ]
        lines.extend(f"- {key}: {value}" for key, value in counts.items())
        lines.extend(["", "## Family Counts"])
        for family, values in sorted(family_counts.items()):
            label = str(BEHAVIOR_FAMILIES.get(family, {}).get("label") or "未归类")
            summary = ", ".join(f"{key}={value}" for key, value in sorted(values.items()))
            lines.append(f"- {label} ({family}): {summary}")
        lines.extend(["", "## Observed Or Blocked"])
        for row in rows:
            if row["status"] in {"confirmed", "likely", "low_confidence", "blocked"}:
                lines.append(
                    f"- {row['family_label']} / {row['label']} ({row['category']}): {row['status']}, "
                    f"confidence={row['confidence']}, gate={row['gate_status']}, evidence={row['evidence_count']}"
                )
        if warnings:
            lines.extend(["", "## Warnings"])
            lines.extend(f"- {warning}" for warning in warnings)

        return ToolResult(
            content="\n".join(lines),
            metadata={
                "warnings": warnings,
                "coverage": coverage,
                "rows": rows,
                "counts": counts,
                "family_counts": family_counts,
                "report_hints": {
                    "coverage": coverage,
                    "family_counts": family_counts,
                },
            },
        )
