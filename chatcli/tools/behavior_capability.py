"""Static behavior capability mapping for defensive malware triage."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ._json_utils import MAX_JSON_SIZE
from ._text_utils import short_text
from .base import Tool, ToolResult, coerce_int, coerce_str_list
from .behavior_rules import BOUNDARY_TERMS, CAPABILITY_RULES, CLAIM_GATES, STRONG_CLUSTERS
from .behavior_requirements import behavior_requirement_gaps, cap_confidence
from .behavior_taxonomy import apply_overlap_suppression
from .behavior_hierarchy import (
    annotate_hierarchy,
    apply_family_noise_reduction,
    build_family_plan,
)

MAX_COLLECTED_STRINGS = 5000


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
    if isinstance(value, dict):
        return [value]
    return coerce_str_list(value)


def _source_weight(source: str, confidence: str) -> float:
    base = 1.0
    source = source.lower()
    if any(key in source for key in ("xref", "crossref", "cross-ref")):
        base = 1.8
    elif any(key in source for key in ("decoded", "decrypt", "deobfus", "config")):
        base = 1.7
    elif any(key in source for key in ("pseudocode", "decompile", "ida", "ghidra")):
        base = 1.5
    elif any(key in source for key in ("runtime", "trace", "telemetry", "sandbox")):
        base = 2.0
    elif any(key in source for key in ("import", "imports")):
        base = 1.2
    elif any(key in source for key in ("string", "strings")):
        base = 1.0
    elif source:
        base = 1.1

    confidence = confidence.lower()
    if confidence in {"high", "confirmed", "observed"}:
        base += 0.3
    elif confidence in {"low", "hypothesis"}:
        base -= 0.1
    return max(0.5, base)


def _discounted_source_weight(source: str, confidence: str, evidence_hits: int) -> float:
    weight = _source_weight(source, confidence)
    if evidence_hits <= 0:
        return weight
    if evidence_hits == 1:
        return weight * 0.6
    return weight * 0.35


def _term_matches(term: str, text: str) -> bool:
    term_low = term.lower()
    if term_low in BOUNDARY_TERMS:
        return re.search(rf"(?<![a-z0-9]){re.escape(term_low)}(?![a-z0-9])", text) is not None
    return term_low in text


def _collect_json_strings(value: Any, out: list[str], limit: int = MAX_COLLECTED_STRINGS) -> None:
    if len(out) >= limit:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if len(out) >= limit:
                break
            if isinstance(key, str):
                out.append(key)
            _collect_json_strings(item, out, limit)
    elif isinstance(value, list):
        for item in value:
            if len(out) >= limit:
                break
            _collect_json_strings(item, out, limit)
    elif isinstance(value, (str, int, float, bool)) and value is not None:
        out.append(str(value))


def _load_json_signals(path: Path) -> tuple[list[str], str | None]:
    if not path.exists():
        return [], f"missing JSON file: {path}"
    if path.is_dir():
        return [], f"path is a directory, not JSON: {path}"
    size = path.stat().st_size
    if size > MAX_JSON_SIZE:
        return [], f"JSON file too large for behavior map ({size} bytes): {path}"
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        return [], f"failed to read JSON {path}: {exc}"
    out: list[str] = []
    _collect_json_strings(data, out)
    return out, None


def _confidence(category: str, matched_terms: set[str], score: float, evidence_count: int) -> tuple[str, str, str]:
    strong = STRONG_CLUSTERS.get(category, set())
    strong_hits = matched_terms & strong
    diverse_evidence = evidence_count >= 2
    if score >= 4.0 or (diverse_evidence and (len(strong_hits) >= 3 or len(matched_terms) >= 5)):
        reason = (
            f"high because {len(matched_terms)} terms matched, score={round(score, 2)}, "
            f"evidence_count={evidence_count}, strong_hits={sorted(strong_hits)}"
        )
        return "high", "static capability", reason
    if len(strong_hits) >= 2 or score >= 2.5 or len(matched_terms) >= 3:
        reason = (
            f"medium because {len(matched_terms)} terms matched, score={round(score, 2)}, "
            f"evidence_count={evidence_count}, strong_hits={sorted(strong_hits)}"
        )
        return "medium", "static capability", reason
    reason = (
        f"low because only {len(matched_terms)} weak/static term(s) matched, "
        f"score={round(score, 2)}, evidence_count={evidence_count}, strong_hits={sorted(strong_hits)}"
    )
    return "low", "hypothesis", reason


def _match_capabilities(signals: list[str], max_results: int) -> list[dict[str, Any]]:
    lowered = []
    for raw in signals:
        norm = _normalize_signal(raw)
        if norm["value"]:
            lowered.append((norm["value"], norm["value"].lower(), norm["source"], norm["confidence"]))
    capabilities: list[dict[str, Any]] = []
    for category, rule in CAPABILITY_RULES.items():
        matched_terms: set[str] = set()
        evidence: list[str] = []
        evidence_sources: list[str] = []
        evidence_hit_counts: dict[str, int] = {}
        score = 0.0
        for term in rule["terms"]:
            for original, low, source, confidence in lowered:
                if _term_matches(term, low):
                    matched_terms.add(term)
                    snippet = short_text(original)
                    evidence_key = snippet or original[:120]
                    hits = evidence_hit_counts.get(evidence_key, 0)
                    score += _discounted_source_weight(source, confidence, hits)
                    evidence_hit_counts[evidence_key] = hits + 1
                    if snippet and snippet not in evidence:
                        evidence.append(snippet)
                        if source:
                            evidence_sources.append(source)
                    break
        if not matched_terms:
            continue
        if len(matched_terms) < int(rule.get("min_terms", 1)):
            continue
        matched_terms_low = {x.lower() for x in matched_terms}
        confidence, claim_level, confidence_reason = _confidence(category, matched_terms_low, score, len(evidence))
        requirement_gaps, confidence_cap = behavior_requirement_gaps(category, matched_terms_low)
        if confidence_cap:
            capped = cap_confidence(confidence, confidence_cap)
            if capped != confidence:
                confidence_reason += (
                    f"; capped at {capped} because behavior composition is incomplete "
                    f"({'; '.join(requirement_gaps)})"
                )
                confidence = capped
            if confidence == "low":
                claim_level = "hypothesis"
        required_validation = list(rule["validation"])
        required_validation.extend(requirement_gaps)
        capabilities.append({
            "category": category,
            "label": rule["label"],
            "matched_terms": sorted(matched_terms),
            "evidence": evidence[:8],
            "evidence_sources": [x for x in dict.fromkeys(evidence_sources) if x],
            "confidence": confidence,
            "claim_level": claim_level,
            "confidence_reason": confidence_reason,
            "score": round(score, 2),
            "claim_gate": CLAIM_GATES.get(category, []),
            "required_validation": required_validation,
            "behavior_composition_gaps": requirement_gaps,
        })

    capabilities = apply_overlap_suppression(capabilities)
    capabilities = annotate_hierarchy(capabilities)
    capabilities = apply_family_noise_reduction(capabilities)
    rank = {"high": 3, "medium": 2, "low": 1}
    capabilities.sort(
        key=lambda item: (rank.get(item["confidence"], 0), item.get("analysis_family", ""), len(item["matched_terms"])),
        reverse=True,
    )
    return capabilities[:max_results]


class BehaviorCapabilityMapTool(Tool):
    name = "behavior_capability_map"
    description = (
        "Map static strings/imports/IOC/tool-output signals to defensive malware "
        "behavior capability candidates. Does not execute samples. Outputs "
        "confidence, claim level, evidence, and validation gaps."
    )
    parameters = {
        "type": "object",
        "properties": {
            "signals": {
                "type": "array",
                "items": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "object"},
                    ]
                },
                "description": "Raw strings, imports, API names, IOC values, evidence snippets, or structured signal objects with value/source/confidence.",
            },
            "json_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional JSON output files to mine for static behavior signals.",
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum capability candidates to return. Default 12.",
            },
        },
    }

    def execute(
        self,
        signals: list[str] | str | None = None,
        json_paths: list[str] | str | None = None,
        max_results: int = 12,
        **kwargs,
    ) -> ToolResult:
        max_results = coerce_int(max_results, 12, minimum=1, maximum=50)
        collected = _coerce_signal_list(signals)
        warnings = []

        for raw_path in coerce_str_list(json_paths):
            values, error = _load_json_signals(Path(raw_path))
            if error:
                warnings.append(error)
            else:
                collected.extend(values)

        if not collected:
            return ToolResult(
                content="Error: provide signals or json_paths to map behavior capabilities.",
                is_error=True,
                metadata={"warnings": warnings},
            )

        capabilities = _match_capabilities(collected, max_results)

        lines = [
            "# Behavior Capability Map",
            "",
            f"Signals scanned: {len(collected)}",
            f"Capabilities found: {len(capabilities)}",
        ]
        if warnings:
            lines.extend(["", "## Warnings"])
            lines.extend(f"- {warning}" for warning in warnings)
        if not capabilities:
            lines.extend([
                "",
                "No behavior capability candidates matched the current static rules.",
            ])
        else:
            lines.extend(["", "## Capability Candidates"])
            for item in capabilities:
                lines.append("")
                lines.append(f"### {item['label']} ({item['category']})")
                lines.append(f"- Confidence: {item['confidence']}")
                lines.append(f"- Claim level: {item['claim_level']}")
                lines.append(f"- Confidence reason: {item['confidence_reason']}")
                lines.append(f"- Score: {item['score']}")
                lines.append(f"- Analysis family: {item.get('family_label', '未归类')} ({item.get('analysis_family', 'uncategorized')})")
                if item.get("family_description"):
                    lines.append(f"- Family description: {item['family_description']}")
                lines.append(f"- Matched terms: {', '.join(item['matched_terms'])}")
                if item.get("overlap_suppressed_by"):
                    lines.append(f"- Overlap suppressed by: {', '.join(item['overlap_suppressed_by'])}")
                if item.get("family_suppressed_by"):
                    lines.append(f"- Family noise suppressed by: {', '.join(item['family_suppressed_by'])}")
                if item.get("evidence_sources"):
                    lines.append(f"- Evidence sources: {', '.join(item['evidence_sources'])}")
                if item.get("claim_gate"):
                    lines.append("- Claim gate:")
                    lines.extend(f"  - {gate}" for gate in item["claim_gate"])
                if item.get("family_validation"):
                    lines.append("- Family validation path:")
                    lines.extend(f"  - {step}" for step in item["family_validation"][:4])
                lines.append("- Evidence:")
                lines.extend(f"  - {short_text(ev)}" for ev in item["evidence"][:6])
                lines.append("- Required validation:")
                lines.extend(f"  - {step}" for step in item["required_validation"])

        report_hints = {
            "key_capability_candidates": [
                {
                    "category": item["label"],
                    "analysis_family": item.get("analysis_family", "uncategorized"),
                    "family_label": item.get("family_label", "未归类"),
                    "technique": ", ".join(item["matched_terms"]),
                    "evidence": "\n".join(f"- {ev}" for ev in item["evidence"][:6]),
                    "impact": "静态信号显示该类攻击行为能力候选；需结合代码路径或运行时证据确认影响。",
                    "confidence": item["confidence"],
                    "confidence_reason": item["confidence_reason"],
                    "overlap_suppressed_by": item.get("overlap_suppressed_by", []),
                    "family_suppressed_by": item.get("family_suppressed_by", []),
                }
                for item in capabilities
            ],
            "analysis_plan": build_family_plan(capabilities),
            "coverage_candidates": {
                "likely": [item["label"] for item in capabilities if item["confidence"] in {"high", "medium"}],
                "low_confidence": [item["label"] for item in capabilities if item["confidence"] == "low"],
            },
        }

        return ToolResult(
            content="\n".join(lines),
            metadata={
                "signals_scanned": len(collected),
                "warnings": warnings,
                "capabilities": capabilities,
                "report_hints": report_hints,
            },
        )
