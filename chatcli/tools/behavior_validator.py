"""Validate defensive malware behavior claims against evidence and gates."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .base import Tool, ToolResult, coerce_str_list
from .behavior_rules import CAPABILITY_RULES

MAX_JSON_INPUT_SIZE = 50 * 1024 * 1024

HIGH_IMPACT_CATEGORIES = {
    "c2_network",
    "c2_variants",
    "rat_backdoor_control",
    "process_injection",
    "credential_access",
    "browser_cloud_credentials",
    "keylogging_capture",
    "wallet_clipboard_hijack",
    "exfiltration",
    "lateral_movement",
    "worm_propagation",
    "impact",
    "ransomware_anti_recovery",
    "security_tool_tampering",
    "rootkit_driver",
    "bootkit_uefi",
    "miner",
    "ddos_bot_proxy",
    "file_infector",
    "supply_chain_update_abuse",
}


def _short(value: Any, limit: int = 180) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _confidence_rank(value: Any) -> int:
    return {
        "confirmed": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "hypothesis": 1,
        "blocked": 0,
    }.get(str(value or "").strip().lower(), 0)


def _load_json(path: Path) -> tuple[Any | None, str | None]:
    if not path.exists():
        return None, f"missing JSON file: {path}"
    if path.is_dir():
        return None, f"path is a directory, not JSON: {path}"
    size = path.stat().st_size
    if size > MAX_JSON_INPUT_SIZE:
        return None, f"JSON file too large for behavior validation ({size} bytes): {path}"
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace")), None
    except Exception as exc:
        return None, f"failed to read JSON {path}: {exc}"


def _collect(value: Any, caps: list[dict[str, Any]], chain: list[dict[str, Any]], audits: list[dict[str, Any]]) -> None:
    if isinstance(value, dict):
        candidates = value.get("capabilities")
        if isinstance(candidates, list):
            caps.extend(item for item in candidates if isinstance(item, dict))
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
        evidence = [x for x in _as_list(cap.get("evidence")) if str(x).strip()]
        gates = [x for x in _as_list(cap.get("claim_gate")) if str(x).strip()]
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
        if _confidence_rank(confidence) >= 3 and not evidence:
            _add_issue(
                issues,
                "high",
                "missing_evidence",
                f"{label} has {confidence} confidence but no evidence snippets.",
                {"category": category, "confidence": confidence},
                "Attach strings, imports, xrefs, pseudocode, config fields, runtime telemetry, or mark as hypothesis.",
            )
        if category in HIGH_IMPACT_CATEGORIES and _confidence_rank(confidence) >= 3 and not gates:
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

        if _confidence_rank(confidence) >= 4 and (not evidence or evidence.lower() == "no direct evidence snippet provided."):
            _add_issue(
                issues,
                "high",
                "attack_step_missing_evidence",
                f"Attack step {step_no} ({_short(behavior)}) has {confidence} confidence but no direct evidence.",
                {"step": step_no, "behavior": behavior, "confidence": confidence},
                "Add concrete evidence or downgrade the step.",
            )
        if gate_status == "needs_validation" and _confidence_rank(confidence) >= 4:
            severity = "high" if confidence.lower() == "confirmed" else "medium"
            _add_issue(
                issues,
                severity,
                "high_confidence_with_open_gate",
                f"Attack step {step_no} ({_short(behavior)}) is high confidence while validation gates remain open.",
                {"step": step_no, "behavior": behavior, "confidence": confidence},
                "Keep as likely/static capability until the required validation is satisfied.",
            )
        if gaps and _confidence_rank(confidence) >= 5:
            _add_issue(
                issues,
                "medium",
                "confirmed_with_gaps",
                f"Attack step {step_no} ({_short(behavior)}) is confirmed but still has gaps.",
                {"step": step_no, "behavior": behavior},
                "Resolve the gaps or downgrade from confirmed.",
            )


def _validate_audits(audits: list[dict[str, Any]], issues: list[dict[str, Any]]) -> None:
    for audit in audits:
        for item in audit.get("unsupported_capabilities", []) or []:
            _add_issue(
                issues,
                "high" if _confidence_rank(item.get("confidence")) >= 3 else "medium",
                "unsupported_capability",
                f"Capability lacks evidence support in evidence graph: {_short(item.get('label'))}.",
                item,
                "Add supporting evidence or downgrade/remove the claim.",
            )
        for item in audit.get("unsupported_attack_steps", []) or []:
            _add_issue(
                issues,
                "high" if _confidence_rank(item.get("confidence")) >= 3 else "medium",
                "unsupported_attack_step",
                f"Attack step lacks evidence support in evidence graph: {_short(item.get('label'))}.",
                item,
                "Add supporting evidence or downgrade/remove the step.",
            )
        for item in audit.get("validation_required", []) or []:
            if _confidence_rank(item.get("confidence")) >= 4:
                _add_issue(
                    issues,
                    "medium",
                    "validation_required",
                    f"High-confidence capability still requires validation: {_short(item.get('label'))}.",
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
            data, error = _load_json(Path(raw_path))
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
            data, error = _load_json(Path(raw_path))
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
            if current and _confidence_rank(current.get("confidence")) >= _confidence_rank(cap.get("confidence")):
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
            cap = by_category.get(category)
            if category in analyzed_blockers or label in analyzed_blockers:
                status = "not_analyzed"
                confidence = "blocked"
                evidence_count = 0
                gate_status = "not_analyzed"
            elif cap:
                status = _coverage_status(cap)
                confidence = str(cap.get("confidence") or "low")
                evidence_count = len([x for x in _as_list(cap.get("evidence")) if str(x).strip()])
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
            status = _coverage_status(cap)
            coverage[status].append(label)
            rows.append({
                "category": category,
                "label": label,
                "status": status,
                "confidence": str(cap.get("confidence") or "low"),
                "evidence_count": len([x for x in _as_list(cap.get("evidence")) if str(x).strip()]),
                "gate_status": "needs_validation" if cap.get("claim_gate") else "not_required",
            })

        counts = {key: len(value) for key, value in coverage.items()}
        lines = [
            "# Behavior Coverage Matrix",
            "",
            f"Capabilities scanned: {len(caps)}",
            f"Behavior areas tracked: {len(rows)}",
            "",
            "## Coverage Counts",
        ]
        lines.extend(f"- {key}: {value}" for key, value in counts.items())
        lines.extend(["", "## Observed Or Blocked"])
        for row in rows:
            if row["status"] in {"confirmed", "likely", "low_confidence", "blocked"}:
                lines.append(
                    f"- {row['label']} ({row['category']}): {row['status']}, "
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
                "report_hints": {"coverage": coverage},
            },
        )
