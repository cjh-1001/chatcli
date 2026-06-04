"""Structured extraction for large JSON files."""

import json
import re
from pathlib import Path
from typing import Any

from .base import Tool, ToolResult, coerce_int, coerce_str_list


MAX_JSON_SIZE = 200 * 1024 * 1024


def _short(text: Any, limit: int = 180) -> str:
    value = re.sub(r"\s+", " ", str(text)).strip()
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 3)].rstrip() + "..."


def _resolve_path(data: Any, path: str) -> Any:
    if not path:
        return data
    current = data
    for part in path.split("."):
        if part == "":
            continue
        if isinstance(current, list):
            current = current[int(part)]
        elif isinstance(current, dict):
            current = current[part]
        else:
            raise KeyError(path)
    return current


def _get_field(item: Any, field: str) -> Any:
    try:
        return _resolve_path(item, field)
    except Exception:
        return None


def _contains_keywords(value: Any, keywords: list[str]) -> bool:
    if not keywords:
        return True
    text = json.dumps(value, ensure_ascii=False, default=str).lower()
    return any(k.lower() in text for k in keywords if k.strip())


def _iter_arrays(value: Any, prefix: str = ""):
    if isinstance(value, list):
        yield prefix or "$", value
        for idx, item in enumerate(value[:20]):
            yield from _iter_arrays(item, f"{prefix}.{idx}" if prefix else str(idx))
    elif isinstance(value, dict):
        for key, item in value.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            yield from _iter_arrays(item, child)


def _summarize(value: Any, prefix: str = "$", depth: int = 0, max_depth: int = 3) -> list[str]:
    if depth > max_depth:
        return []
    lines = []
    if isinstance(value, dict):
        keys = list(value.keys())
        lines.append(f"- {prefix}: object keys={len(keys)} sample={', '.join(map(str, keys[:12]))}")
        for key in keys[:30]:
            lines.extend(_summarize(value[key], f"{prefix}.{key}", depth + 1, max_depth))
    elif isinstance(value, list):
        lines.append(f"- {prefix}: array len={len(value)}")
        if value:
            lines.extend(_summarize(value[0], f"{prefix}[0]", depth + 1, max_depth))
    else:
        lines.append(f"- {prefix}: {type(value).__name__} sample={_short(value, 80)}")
    return lines


def _project_item(item: Any, fields: list[str]) -> Any:
    if not fields:
        return item
    if not isinstance(item, (dict, list)):
        return item
    projected = {}
    for field in fields:
        projected[field] = _get_field(item, field)
    return projected


class JsonExtractTool(Tool):
    name = "json_extract"
    description = (
        "Inspect and slice large JSON files without loading the whole file into "
        "conversation context. Use summary to find useful paths, then filter arrays "
        "by keywords and selected fields."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "JSON file path."},
            "mode": {
                "type": "string",
                "description": "summary, paths, or filter. Default summary.",
                "enum": ["summary", "paths", "filter"],
            },
            "path": {
                "type": "string",
                "description": "Dot path to a JSON value or array, e.g. candidate_functions or function_maps.0.mapped_blocks.",
            },
            "keywords": {
                "type": "array",
                "description": "Keywords used in filter mode. Matches serialized item text.",
                "items": {"type": "string"},
            },
            "fields": {
                "type": "array",
                "description": "Fields to keep from matched objects, e.g. start,name,score,evidence.",
                "items": {"type": "string"},
            },
            "max_items": {"type": "integer", "description": "Maximum items to return. Default 40."},
            "max_depth": {"type": "integer", "description": "Summary recursion depth. Default 3."},
        },
        "required": ["file_path"],
    }

    def execute(
        self,
        file_path: str,
        mode: str = "summary",
        path: str = "",
        keywords: list[str] | None = None,
        fields: list[str] | None = None,
        max_items: int = 40,
        max_depth: int = 3,
        **kwargs,
    ) -> ToolResult:
        target = Path(file_path)
        if not target.exists():
            return ToolResult(content=f"File not found: {file_path}", is_error=True)
        if target.is_dir():
            return ToolResult(content=f"Path is a directory, not a JSON file: {file_path}", is_error=True)
        size = target.stat().st_size
        if size > MAX_JSON_SIZE:
            return ToolResult(content=f"Error: JSON file too large ({size} bytes).", is_error=True)
        try:
            data = json.loads(target.read_text(encoding="utf-8", errors="replace"))
        except Exception as e:
            return ToolResult(content=f"Error reading JSON: {e}", is_error=True)

        mode = (mode or "summary").lower()
        max_items = coerce_int(max_items, 40, minimum=1, maximum=500)
        max_depth = coerce_int(max_depth, 3, minimum=1, maximum=8)
        keywords = coerce_str_list(keywords)
        fields = coerce_str_list(fields)

        lines = ["# JSON Extract", "", f"Path: {target}", f"Size: {size} bytes", f"Mode: {mode}"]
        metadata = {"path": str(target), "size": size, "mode": mode}

        try:
            selected = _resolve_path(data, path) if path else data
        except Exception as e:
            return ToolResult(content=f"Error resolving path `{path}`: {e}", is_error=True)

        if mode == "summary":
            lines.extend(["", "## Structure"])
            lines.extend(_summarize(selected, "$" if not path else path, max_depth=max_depth)[:max_items * 4])
            arrays = sorted(_iter_arrays(selected), key=lambda x: len(x[1]), reverse=True)[:max_items]
            if arrays:
                lines.extend(["", "## Largest Arrays"])
                for array_path, items in arrays:
                    lines.append(f"- {array_path}: len={len(items)}")
            metadata["arrays"] = len(arrays)
            return ToolResult(content="\n".join(lines), metadata=metadata)

        if mode == "paths":
            arrays = sorted(_iter_arrays(selected), key=lambda x: len(x[1]), reverse=True)[:max_items]
            lines.extend(["", "## Array Paths"])
            for array_path, items in arrays:
                sample = items[0] if items else None
                sample_type = type(sample).__name__ if sample is not None else "empty"
                lines.append(f"- {array_path}: len={len(items)} sample={sample_type}")
            metadata["arrays"] = len(arrays)
            return ToolResult(content="\n".join(lines), metadata=metadata)

        if mode != "filter":
            return ToolResult(content=f"Error: unsupported mode {mode}", is_error=True)

        candidates = selected if isinstance(selected, list) else [selected]
        matches = []
        for item in candidates:
            if _contains_keywords(item, keywords):
                matches.append(_project_item(item, fields))
            if len(matches) >= max_items:
                break
        lines.extend([
            "",
            f"## Filter Results",
            f"- Source path: {path or '$'}",
            f"- Keywords: {', '.join(keywords) if keywords else '(none)'}",
            f"- Fields: {', '.join(fields) if fields else '(full item)'}",
            f"- Matches returned: {len(matches)}",
            "",
            "```json",
            json.dumps(matches, ensure_ascii=False, indent=2, default=str),
            "```",
        ])
        metadata["matches"] = len(matches)
        return ToolResult(content="\n".join(lines), metadata=metadata)
