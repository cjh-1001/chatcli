"""Map static RAT/backdoor command-dispatcher clues to defensive capabilities."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ._json_utils import MAX_JSON_SIZE
from ._text_utils import short_text
from .base import Tool, ToolResult, coerce_int, coerce_str_list
from .command_capability_rules import COMMAND_RULES, ID_PATTERNS

MAX_COLLECTED_STRINGS = 6000
BOUNDARY_TERMS = {
    "shell",
    "install",
    "uninstall",
    "upload",
    "download",
    "token",
    "wallet",
    "plugin",
    "module",
    "proxy",
    "socks",
    "socks5",
    "spam",
    "ddos",
}


def _normalize_signal(item: Any) -> dict[str, str]:
    if isinstance(item, dict):
        value = str(item.get("value") or item.get("text") or item.get("signal") or "").strip()
        source = str(item.get("source") or item.get("kind") or "").strip().lower()
        confidence = str(item.get("confidence") or item.get("level") or "").strip().lower()
        return {"value": value, "source": source, "confidence": confidence}
    return {"value": str(item or "").strip(), "source": "", "confidence": ""}


def _coerce_signal_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, str):
        return coerce_str_list(value)
    if isinstance(value, (list, tuple, set)):
        out: list[Any] = []
        for item in value:
            if isinstance(item, dict):
                out.append(item)
            else:
                out.extend(coerce_str_list(item))
        return out
    return coerce_str_list(value)


def _source_weight(source: str, confidence: str) -> float:
    weight = 1.0
    if any(key in source for key in ("handler", "dispatcher", "pseudocode", "decompile", "xref")):
        weight = 1.8
    elif any(key in source for key in ("decoded", "config", "deobfus")):
        weight = 1.5
    elif any(key in source for key in ("runtime", "trace", "sandbox")):
        weight = 2.0
    elif any(key in source for key in ("string", "strings")):
        weight = 1.0
    elif source:
        weight = 1.1
    if confidence in {"observed", "confirmed", "high"}:
        weight += 0.3
    elif confidence in {"low", "hypothesis"}:
        weight -= 0.1
    return max(0.5, weight)


def _collect_json_strings(value: Any, out: list[Any], limit: int = MAX_COLLECTED_STRINGS) -> None:
    if len(out) >= limit:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if len(out) >= limit:
                break
            if isinstance(key, str):
                out.append(key)
            if isinstance(item, dict) and any(k in item for k in ("value", "text", "signal")):
                out.append(item)
            else:
                _collect_json_strings(item, out, limit)
    elif isinstance(value, list):
        for item in value:
            if len(out) >= limit:
                break
            _collect_json_strings(item, out, limit)
    elif isinstance(value, (str, int, float, bool)) and value is not None:
        out.append(str(value))


def _load_json_signals(path: Path) -> tuple[list[Any], str | None]:
    if not path.exists():
        return [], f"missing JSON file: {path}"
    if path.is_dir():
        return [], f"path is a directory, not JSON: {path}"
    size = path.stat().st_size
    if size > MAX_JSON_SIZE:
        return [], f"JSON file too large for command capability map ({size} bytes): {path}"
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        return [], f"failed to read JSON {path}: {exc}"
    out: list[Any] = []
    _collect_json_strings(data, out)
    return out, None


def _extract_command_ids(text: str) -> list[str]:
    ids: list[str] = []
    for pattern in ID_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(1) if match.groups() else match.group(0)
            value = short_text(value, 80)
            if value and value not in ids:
                ids.append(value)
    return ids


def _term_matches(term: str, text: str) -> bool:
    term_low = term.lower()
    if term_low in BOUNDARY_TERMS:
        return re.search(rf"(?<![a-z0-9]){re.escape(term_low)}(?![a-z0-9])", text) is not None
    return term_low in text


def _confidence(score: float, terms: set[str], command_ids: list[str]) -> tuple[str, str]:
    if score >= 4.0 or len(terms) >= 5 or (len(terms) >= 3 and command_ids):
        return "high", f"high because score={round(score, 2)}, terms={len(terms)}, command_ids={len(command_ids)}"
    if score >= 2.4 or len(terms) >= 3 or (len(terms) >= 2 and command_ids):
        return "medium", f"medium because score={round(score, 2)}, terms={len(terms)}, command_ids={len(command_ids)}"
    return "low", f"low because score={round(score, 2)}, terms={len(terms)}, command_ids={len(command_ids)}"


def _map_commands(signals: list[Any], max_commands: int) -> list[dict[str, Any]]:
    normalized = []
    for raw in signals:
        item = _normalize_signal(raw)
        if item["value"]:
            normalized.append((item["value"], item["value"].lower(), item["source"], item["confidence"]))

    results: list[dict[str, Any]] = []
    all_command_ids: list[str] = []
    for original, low, _source, _confidence_text in normalized:
        for command_id in _extract_command_ids(original):
            if command_id not in all_command_ids:
                all_command_ids.append(command_id)

    for category, rule in COMMAND_RULES.items():
        matched_terms: set[str] = set()
        evidence: list[str] = []
        evidence_sources: list[str] = []
        local_ids: list[str] = []
        score = 0.0
        for term in rule["terms"]:
            for original, low, source, confidence_text in normalized:
                if not _term_matches(term, low):
                    continue
                matched_terms.add(term)
                score += _source_weight(source, confidence_text)
                snippet = short_text(original)
                if snippet not in evidence:
                    evidence.append(snippet)
                if source and source not in evidence_sources:
                    evidence_sources.append(source)
                for command_id in _extract_command_ids(original):
                    if command_id not in local_ids:
                        local_ids.append(command_id)
                break
        if not matched_terms:
            continue
        confidence, reason = _confidence(score, matched_terms, local_ids)
        results.append({
            "category": category,
            "label": rule["label"],
            "analysis_family": "command_control_exfil",
            "family_label": "C2/远控/外传",
            "matched_terms": sorted(matched_terms),
            "command_ids": local_ids[:12],
            "global_command_ids": all_command_ids[:24],
            "evidence": evidence[:8],
            "evidence_sources": evidence_sources,
            "confidence": confidence,
            "confidence_reason": reason,
            "impact": rule["impact"],
            "required_validation": [rule["validation"]],
            "claim_level": "static command capability",
        })

    rank = {"high": 3, "medium": 2, "low": 1}
    results.sort(key=lambda item: (rank.get(item["confidence"], 0), len(item["matched_terms"])), reverse=True)
    return results[:max_commands]


class CommandCapabilityMapTool(Tool):
    name = "command_capability_map"
    description = (
        "Map static RAT/backdoor command-dispatcher strings, IDs, and handler clues "
        "to defensive command capability categories. Does not execute samples."
    )
    parameters = {
        "type": "object",
        "properties": {
            "signals": {
                "type": "array",
                "items": {"oneOf": [{"type": "string"}, {"type": "object"}]},
                "description": "Strings, pseudocode snippets, decoded config, or structured signal objects.",
            },
            "json_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional JSON files to mine for command-dispatcher clues.",
            },
            "max_commands": {
                "type": "integer",
                "description": "Maximum command capability groups to return. Default 12.",
            },
        },
    }

    def execute(
        self,
        signals: list[Any] | str | None = None,
        json_paths: list[str] | str | None = None,
        max_commands: int = 12,
        **kwargs,
    ) -> ToolResult:
        max_commands = coerce_int(max_commands, 12, minimum=1, maximum=40)
        collected = _coerce_signal_list(signals)
        warnings: list[str] = []

        for raw_path in coerce_str_list(json_paths):
            values, error = _load_json_signals(Path(raw_path))
            if error:
                warnings.append(error)
            else:
                collected.extend(values)

        if not collected:
            return ToolResult(
                content="Error: provide signals or json_paths to map command capabilities.",
                is_error=True,
                metadata={"warnings": warnings},
            )

        commands = _map_commands(collected, max_commands)
        lines = [
            "# Command Capability Map",
            "",
            f"Signals scanned: {len(collected)}",
            f"Command capability groups: {len(commands)}",
        ]
        if warnings:
            lines.extend(["", "## Warnings"])
            lines.extend(f"- {warning}" for warning in warnings)
        if not commands:
            lines.extend(["", "No command capability groups matched the current static rules."])
        else:
            lines.extend(["", "## Command Capability Groups"])
            for item in commands:
                lines.extend([
                    "",
                    f"### {item['label']} ({item['category']})",
                    f"- Confidence: {item['confidence']}",
                    f"- Confidence reason: {item['confidence_reason']}",
                    f"- Matched terms: {', '.join(item['matched_terms'])}",
                ])
                if item["command_ids"]:
                    lines.append(f"- Command IDs: {', '.join(item['command_ids'])}")
                if item["evidence_sources"]:
                    lines.append(f"- Evidence sources: {', '.join(item['evidence_sources'])}")
                lines.extend([
                    f"- Impact: {item['impact']}",
                    "- Evidence:",
                ])
                lines.extend(f"  - {short_text(ev)}" for ev in item["evidence"][:6])
                lines.extend([
                    "- Required validation:",
                    f"  - {item['required_validation'][0]}",
                ])

        report_hints = {
            "command_capabilities": [
                {
                    "category": item["label"],
                    "analysis_family": item.get("analysis_family", "command_control_exfil"),
                    "family_label": item.get("family_label", "C2/远控/外传"),
                    "technique": ", ".join(item["matched_terms"]),
                    "evidence": "\n".join(f"- {ev}" for ev in item["evidence"][:6]),
                    "impact": item["impact"],
                    "confidence": item["confidence"],
                    "confidence_reason": item["confidence_reason"],
                    "command_ids": item["command_ids"],
                }
                for item in commands
            ]
        }

        return ToolResult(
            content="\n".join(lines),
            metadata={
                "signals_scanned": len(collected),
                "warnings": warnings,
                "commands": commands,
                "report_hints": report_hints,
            },
        )
