"""Lint defensive YARA/Sigma/hunting drafts for malware reports."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .base import Tool, ToolResult, coerce_str_list

MAX_JSON_INPUT_SIZE = 20 * 1024 * 1024

GENERIC_TOKENS = {
    "http://",
    "https://",
    "cmd.exe",
    "powershell",
    "createprocess",
    "virtualalloc",
    "virtualprotect",
    "loadlibrary",
    "getprocaddress",
    "kernel32.dll",
    "ntdll.dll",
    "user-agent",
}


def _short(value: Any, limit: int = 180) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def _load_json(path: Path) -> tuple[Any | None, str | None]:
    if not path.exists():
        return None, f"missing JSON file: {path}"
    if path.is_dir():
        return None, f"path is a directory, not JSON: {path}"
    size = path.stat().st_size
    if size > MAX_JSON_INPUT_SIZE:
        return None, f"JSON file too large for detection lint ({size} bytes): {path}"
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace")), None
    except Exception as exc:
        return None, f"failed to read JSON {path}: {exc}"


def _collect(value: Any, drafts: dict[str, Any], weak_iocs: list[str]) -> None:
    if isinstance(value, dict):
        detection = value.get("detection")
        if isinstance(detection, dict):
            for key in ("yara", "sigma", "edr_hunting"):
                if detection.get(key) and not drafts.get(key):
                    drafts[key] = detection[key]
        for key in ("yara", "sigma", "edr_hunting"):
            if value.get(key) and not drafts.get(key):
                drafts[key] = value[key]
        buckets = value.get("buckets")
        if isinstance(buckets, dict):
            for key in ("weak", "noise", "scope_only"):
                for item in buckets.get(key, []) or []:
                    if isinstance(item, dict) and item.get("value"):
                        weak_iocs.append(str(item["value"]))
        hints = value.get("report_hints")
        if isinstance(hints, dict):
            _collect(hints, drafts, weak_iocs)
        for child in value.values():
            _collect(child, drafts, weak_iocs)
    elif isinstance(value, list):
        for child in value:
            _collect(child, drafts, weak_iocs)


def _add_issue(issues: list[dict[str, Any]], severity: str, kind: str, message: str, recommendation: str) -> None:
    issues.append({
        "severity": severity,
        "kind": kind,
        "message": message,
        "recommendation": recommendation,
    })


def _weak_ioc_hits(text: str, weak_iocs: list[str]) -> list[str]:
    low = text.lower()
    hits = []
    for ioc in weak_iocs:
        if ioc and ioc.lower() in low and ioc not in hits:
            hits.append(ioc)
    return hits[:20]


def _lint_yara(yara: str, weak_iocs: list[str], issues: list[dict[str, Any]]) -> None:
    text = yara or ""
    if not text.strip():
        return
    low = text.lower()
    if "rule " not in low or "condition:" not in low:
        _add_issue(issues, "high", "yara_malformed", "YARA draft lacks a rule header or condition.", "Provide a complete rule with strings and condition.")
    string_ids = set(re.findall(r"(?<![A-Za-z0-9_])(\$[A-Za-z0-9_*]+)\s*=", text))
    if len(string_ids) < 2:
        _add_issue(issues, "medium", "yara_too_few_strings", "YARA rule uses fewer than two string/byte features.", "Combine multiple sample-specific strings, byte patterns, or structural constraints.")
    generic_hits = sorted(token for token in GENERIC_TOKENS if token in low)
    if generic_hits and len(generic_hits) >= max(1, len(string_ids)):
        _add_issue(
            issues,
            "medium",
            "yara_generic_features",
            f"YARA rule appears dominated by generic features: {', '.join(generic_hits[:8])}.",
            "Prefer stable sample-specific decoded config, mutexes, paths, unique strings, or byte patterns.",
        )
    if re.search(r"condition:\s*(any of them|all of them)\b", low) and len(string_ids) <= 3:
        _add_issue(
            issues,
            "medium",
            "yara_broad_condition",
            "YARA condition is broad for a small string set.",
            "Use a tighter combination such as required unique strings plus file/section constraints.",
        )
    hits = _weak_ioc_hits(text, weak_iocs)
    if hits:
        _add_issue(
            issues,
            "high",
            "yara_uses_weak_ioc",
            f"YARA rule contains weak/noise/scope-only IOC(s): {', '.join(hits[:8])}.",
            "Remove low-quality IOCs or move them to a low-confidence hunting note.",
        )


def _lint_sigma(sigma: str, weak_iocs: list[str], issues: list[dict[str, Any]]) -> None:
    text = sigma or ""
    if not text.strip():
        return
    low = text.lower()
    for required in ("title:", "logsource:", "detection:", "condition:"):
        if required not in low:
            _add_issue(issues, "high", "sigma_missing_section", f"Sigma draft is missing {required}", "Add the required Sigma section before reporting the rule.")
    if low.count("selection") <= 1 and any(token in low for token in ("process_creation", "process_creation")):
        _add_issue(
            issues,
            "medium",
            "sigma_single_selector",
            "Sigma draft appears to rely on a single selector.",
            "Combine parent/child process, command line, image path, registry path, or network fields where evidence supports it.",
        )
    generic_hits = sorted(token for token in GENERIC_TOKENS if token in low)
    if len(generic_hits) >= 3:
        _add_issue(
            issues,
            "medium",
            "sigma_generic_features",
            f"Sigma draft contains multiple generic features: {', '.join(generic_hits[:8])}.",
            "Anchor the rule to sample-specific paths, command fragments, decoded config, or rare parent/child relationships.",
        )
    hits = _weak_ioc_hits(text, weak_iocs)
    if hits:
        _add_issue(
            issues,
            "high",
            "sigma_uses_weak_ioc",
            f"Sigma draft contains weak/noise/scope-only IOC(s): {', '.join(hits[:8])}.",
            "Remove low-quality IOCs or place them in a low-confidence hunting section.",
        )


def _lint_hunting(points: Any, issues: list[dict[str, Any]]) -> None:
    if points is None:
        return
    if isinstance(points, str):
        items = [line.strip() for line in points.splitlines() if line.strip()]
    elif isinstance(points, list):
        items = [str(item).strip() for item in points if str(item).strip()]
    else:
        items = [str(points).strip()]
    if not items:
        return
    generic = [item for item in items if len(item) < 24 or any(token in item.lower() for token in ("monitor createprocess", "monitor powershell", "watch network"))]
    if len(generic) == len(items):
        _add_issue(
            issues,
            "low",
            "hunting_points_generic",
            "All EDR hunting points appear generic.",
            "Tie hunting points to concrete artifacts such as command fragments, registry paths, mutexes, decoded endpoints, or process relationships.",
        )


class DetectionRuleLintTool(Tool):
    name = "detection_rule_lint"
    description = (
        "Lint defensive YARA, Sigma, and EDR hunting drafts for broad conditions, "
        "generic features, malformed sections, and weak IOC usage."
    )
    parameters = {
        "type": "object",
        "properties": {
            "yara": {"type": "string", "description": "YARA draft text."},
            "sigma": {"type": "string", "description": "Sigma draft text."},
            "edr_hunting": {
                "oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}],
                "description": "EDR hunting points.",
            },
            "ioc_quality": {
                "type": "object",
                "description": "Optional ioc_quality_classifier metadata/result containing buckets.",
            },
            "json_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional JSON reports or tool outputs containing detection drafts and IOC quality buckets.",
            },
        },
    }

    def execute(
        self,
        yara: str | None = None,
        sigma: str | None = None,
        edr_hunting: list[str] | str | None = None,
        ioc_quality: dict[str, Any] | None = None,
        json_paths: list[str] | str | None = None,
        **kwargs,
    ) -> ToolResult:
        drafts: dict[str, Any] = {"yara": yara or "", "sigma": sigma or "", "edr_hunting": edr_hunting}
        weak_iocs: list[str] = []
        warnings: list[str] = []

        if isinstance(ioc_quality, dict):
            _collect(ioc_quality, drafts, weak_iocs)
        for raw_path in coerce_str_list(json_paths):
            data, error = _load_json(Path(raw_path))
            if error:
                warnings.append(error)
                continue
            _collect(data, drafts, weak_iocs)

        if not any(drafts.get(key) for key in ("yara", "sigma", "edr_hunting")):
            return ToolResult(
                content="Error: provide yara, sigma, edr_hunting, or json_paths containing detection drafts.",
                is_error=True,
                metadata={"warnings": warnings},
            )

        issues: list[dict[str, Any]] = []
        _lint_yara(str(drafts.get("yara") or ""), weak_iocs, issues)
        _lint_sigma(str(drafts.get("sigma") or ""), weak_iocs, issues)
        _lint_hunting(drafts.get("edr_hunting"), issues)

        severity_counts: dict[str, int] = {}
        for issue in issues:
            severity_counts[issue["severity"]] = severity_counts.get(issue["severity"], 0) + 1
        status = "pass"
        if any(issue["severity"] == "high" for issue in issues):
            status = "needs_revision"
        elif issues:
            status = "review_required"

        lines = [
            "# Detection Rule Lint",
            "",
            f"Status: {status}",
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
