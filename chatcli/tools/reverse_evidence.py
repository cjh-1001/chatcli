"""Evidence-map summarizer for reverse-analysis JSON outputs."""

import json
import re
from pathlib import Path

from .base import Tool, ToolResult
from .reverse_text import optimize_ida_text_data, rank_text_items, short_text


DEFAULT_KEYWORDS = [
    "DeviceIoControl",
    "CreateFile",
    "CreateEvent",
    "OpenEvent",
    "SetEvent",
    "KeDelay",
    "ZwOpenEvent",
    "ZwQueryVirtualMemory",
    "ZwSetEvent",
    "ProbeForRead",
    "ProbeForWrite",
    "RtlCompareMemory",
    "IoCreateDevice",
    "IoCreateSymbolicLink",
    "PsGetCurrentThreadId",
    "Shadow",
    "Maze",
    "Gate",
    "credential",
    "IOCTL",
    "reset",
    "move",
    "wall",
    "success",
    "fail",
]


def _load_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    if isinstance(data, dict):
        optimize_ida_text_data(data)
    return data


def _contains_keyword(text: str, keywords: list[str]) -> bool:
    lowered = str(text or "").lower()
    return any(str(k).lower() in lowered for k in keywords if str(k).strip())


def _short(text: str, limit: int = 180) -> str:
    return short_text(text, limit)


def _function_lookup(data: dict) -> dict[str, dict]:
    lookup = {}
    for fn in data.get("functions", []) or []:
        start = str(fn.get("start", "")).lower()
        if start:
            lookup[start] = fn
    for fn in data.get("function_maps", []) or []:
        start = str(fn.get("start", "")).lower()
        if start and start not in lookup:
            lookup[start] = fn
    return lookup


def _format_source_header(path: Path, data: dict) -> list[str]:
    parts = []
    for key in (
        "functions",
        "imports",
        "strings",
        "candidate_functions",
        "entry_analysis_order",
        "pseudocode",
        "flattened_candidates",
        "function_maps",
        "opaque_predicates",
        "junk_instructions",
    ):
        value = data.get(key)
        if isinstance(value, list):
            parts.append(f"{key}={len(value)}")
    return [
        f"## {path}",
        f"- Input: {data.get('input') or '(unknown)'}",
        f"- Counts: {', '.join(parts) if parts else '(none)'}",
    ]


class ReverseEvidenceMapTool(Tool):
    name = "reverse_evidence_map"
    description = (
        "Summarize existing ida_analyze/ida_deobfuscate JSON files into a compact "
        "reverse-engineering evidence map. Use after IDA produced large JSON so the "
        "agent can identify imports, strings, xrefs, candidate functions, pseudocode "
        "hits, function maps, and next analysis targets without brittle shell scripts."
    )
    parameters = {
        "type": "object",
        "properties": {
            "json_paths": {
                "type": "array",
                "description": "IDA/deobfuscation JSON paths to summarize.",
                "items": {"type": "string"},
            },
            "keywords": {
                "type": "array",
                "description": "Optional keywords to prioritize. Defaults cover IOCTL, events, maze, strings, and kernel APIs.",
                "items": {"type": "string"},
            },
            "max_items": {
                "type": "integer",
                "description": "Maximum items per category per JSON. Default 40.",
            },
        },
        "required": ["json_paths"],
    }

    def execute(
        self,
        json_paths: list[str],
        keywords: list[str] | None = None,
        max_items: int = 40,
        **kwargs,
    ) -> ToolResult:
        paths = [Path(p) for p in (json_paths or []) if str(p).strip()]
        if not paths:
            return ToolResult(content="Error: json_paths cannot be empty.", is_error=True)
        missing = [str(p) for p in paths if not p.exists()]
        if missing:
            return ToolResult(content=f"Missing JSON files: {', '.join(missing)}", is_error=True)

        keywords = [str(k) for k in (keywords or DEFAULT_KEYWORDS) if str(k).strip()]
        max_items = max(5, min(int(max_items or 40), 200))
        lines = ["# Reverse Evidence Map", "", f"Keywords: {', '.join(keywords)}"]
        metadata = {
            "files": len(paths),
            "matched_imports": 0,
            "matched_strings": 0,
            "candidate_functions": 0,
            "pseudocode_hits": 0,
            "function_maps": 0,
            "warnings": 0,
        }

        for path in paths:
            try:
                data = _load_json(path)
            except Exception as e:
                lines.extend(["", f"## {path}", f"- Error: {e}"])
                continue
            lines.extend(["", *_format_source_header(path, data)])
            fn_lookup = _function_lookup(data)

            warnings = data.get("warnings") or []
            if warnings:
                metadata["warnings"] += len(warnings)
                lines.append("- Warnings: " + "; ".join(_short(w, 120) for w in warnings[:5]))

            imports = [
                item for item in data.get("imports", []) or []
                if _contains_keyword(item.get("name", ""), keywords)
                or _contains_keyword(item.get("module", ""), keywords)
            ][:max_items]
            metadata["matched_imports"] += len(imports)
            if imports:
                lines.extend(["", "### Matched Imports"])
                for item in imports:
                    lines.append(
                        f"- {item.get('module', '')}!{item.get('name', '')} "
                        f"@ {item.get('ea', '')}"
                    )

            strings = [
                item for item in data.get("strings", []) or []
                if _contains_keyword(item.get("value", ""), keywords)
            ]
            strings = rank_text_items(strings)[:max_items]
            metadata["matched_strings"] += len(strings)
            if strings:
                lines.extend(["", "### Matched Strings"])
                for item in strings:
                    xrefs = ", ".join((item.get("xrefs") or [])[:6])
                    score = f" score={item.get('text_score')}" if item.get("text_score") is not None else ""
                    flags = f" flags={','.join(item.get('text_flags', []))}" if item.get("text_flags") else ""
                    lines.append(
                        f"- {item.get('ea', '')}{score}{flags}: {repr(_short(item.get('value', ''), 140))}"
                        f" xrefs=[{xrefs}]"
                    )

            candidates = data.get("candidate_functions", []) or []
            candidates = sorted(candidates, key=lambda x: x.get("score", 0), reverse=True)[:max_items]
            metadata["candidate_functions"] += len(candidates)
            if candidates:
                lines.extend(["", "### Candidate Functions"])
                for item in candidates:
                    evidence = "; ".join(_short(e, 90) for e in (item.get("evidence") or [])[:4])
                    lines.append(
                        f"- {item.get('start', '')} {item.get('name', '')} "
                        f"score={item.get('score', 0)} evidence={evidence}"
                    )

            pseudocode_hits = []
            for item in data.get("pseudocode", []) or []:
                text = item.get("text") or ""
                if _contains_keyword(text, keywords) or _contains_keyword(item.get("function", ""), keywords):
                    pseudocode_hits.append(item)
                if len(pseudocode_hits) >= max_items:
                    break
            metadata["pseudocode_hits"] += len(pseudocode_hits)
            if pseudocode_hits:
                lines.extend(["", "### Pseudocode Hits"])
                for item in pseudocode_hits:
                    sample_lines = [
                        _short(line, 160) for line in (item.get("text") or "").splitlines()
                        if _contains_keyword(line, keywords)
                    ][:4]
                    if not sample_lines:
                        sample_lines = [_short(line, 160) for line in (item.get("text") or "").splitlines()[:4]]
                    lines.append(
                        f"- {item.get('start', '')} {item.get('function', '')}: "
                        + " | ".join(sample_lines)
                    )

            function_maps = data.get("function_maps", []) or []
            interesting_maps = []
            for item in function_maps:
                strings_text = " ".join(s.get("value", "") for s in rank_text_items(item.get("strings", []) or []))
                role = item.get("api_role") or {}
                if (
                    _contains_keyword(strings_text, keywords)
                    or _contains_keyword(role.get("role", ""), keywords)
                    or item.get("flattened_candidate")
                    or item.get("junk_sampled", 0)
                    or item.get("size", 0) > 5000
                ):
                    interesting_maps.append(item)
            interesting_maps = sorted(interesting_maps, key=lambda x: x.get("size", 0), reverse=True)[:max_items]
            metadata["function_maps"] += len(interesting_maps)
            if interesting_maps:
                lines.extend(["", "### Function Maps"])
                for item in interesting_maps:
                    strings_text = "; ".join(
                        _short(s.get("value", ""), 80)
                        for s in rank_text_items(item.get("strings", []) or [])[:3]
                    )
                    role = (item.get("api_role") or {}).get("role", "")
                    lines.append(
                        f"- {item.get('start', '')} {item.get('name', '')} "
                        f"size={item.get('size', 0)} blocks={item.get('basic_blocks', 0)} "
                        f"mapped={len(item.get('mapped_blocks', []) or [])} role={role or '(none)'} "
                        f"strings={strings_text or '(none)'}"
                    )

            flattened = data.get("flattened_candidates") or []
            junk = data.get("junk_instructions") or []
            if flattened or junk:
                lines.extend(["", "### Obfuscation Signals"])
                for item in flattened[:max_items]:
                    lines.append(
                        f"- flattened {item.get('start', '')} {item.get('function', '')} "
                        f"score={item.get('score')} blocks={item.get('basic_blocks')}"
                    )
                if junk:
                    lines.append(f"- junk instructions: {len(junk)}")

            if fn_lookup:
                next_targets = []
                for string in strings[:10]:
                    for xref in (string.get("xrefs") or [])[:4]:
                        fn = fn_lookup.get(str(xref).lower())
                        if fn:
                            next_targets.append(f"{xref} -> {fn.get('name', '')}")
                if next_targets:
                    lines.extend(["", "### Xref Function Hints"])
                    for target in next_targets[:max_items]:
                        lines.append(f"- {target}")

        lines.extend([
            "",
            "## Recommended Use",
            "- Use matched imports/strings to choose the next specific function, not another broad IDA pass.",
            "- Feed candidate starts into targeted hexdump, pseudocode review, or child-window function analysis.",
            "- Update `.chatcli/task.md` Analyzed Functions with confirmed roles and blockers.",
        ])
        return ToolResult(content="\n".join(lines), metadata=metadata)
