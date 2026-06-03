"""Text cleanup helpers for reverse-engineering tool output."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SPACE_RE = re.compile(r"[ \t]+")
WS_RE = re.compile(r"\s+")
REPEATED_CHAR_RE = re.compile(r"^(.)\1{7,}$")
INTERESTING_RE = re.compile(
    r"(https?://|/[A-Za-z0-9_.-]+|\\\\|\\[A-Za-z]:\\|"
    r"registry|software\\|currentversion|run\\|service|schtasks|"
    r"cmd\.exe|powershell|curl|wget|socket|connect|send|recv|http|"
    r"password|passwd|credential|token|cookie|wallet|keylog|"
    r"encrypt|decrypt|ransom|shadow|defender|edr|av|debug|vm|sandbox|"
    r"flag|success|fail|serial|license|auth|admin|login)",
    re.I,
)


def normalize_text(value: Any, max_len: int = 500, preserve_lines: bool = False) -> str:
    """Normalize IDA strings/pseudocode without guessing encodings aggressively."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)
    text = text.replace("\ufeff", "").replace("\x00", "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = CONTROL_RE.sub("", text)
    if preserve_lines:
        lines = [SPACE_RE.sub(" ", line).rstrip() for line in text.splitlines()]
        compact: list[str] = []
        blank = False
        for line in lines:
            if not line:
                if not blank:
                    compact.append("")
                blank = True
                continue
            compact.append(line)
            blank = False
        text = "\n".join(compact).strip()
    else:
        text = WS_RE.sub(" ", text).strip()
    if len(text) > max_len:
        return text[: max(0, max_len - 3)].rstrip() + "..."
    return text


def text_signal_score(value: Any) -> tuple[int, list[str]]:
    text = normalize_text(value, max_len=2000)
    flags: list[str] = []
    if not text:
        return 0, ["empty"]
    score = 0
    if len(text) >= 4:
        score += 1
    if len(text) >= 16:
        score += 1
    if any(ch.isalpha() for ch in text):
        score += 1
    if any(ch.isdigit() for ch in text):
        score += 1
    if any(ch in text for ch in "/\\:._-{}[]=,&?%"):
        score += 1
    if INTERESTING_RE.search(text):
        score += 6
        flags.append("interesting")
    replacement_ratio = text.count("\ufffd") / max(1, len(text))
    if replacement_ratio > 0.2:
        score -= 4
        flags.append("decode_noise")
    if REPEATED_CHAR_RE.match(text):
        score -= 4
        flags.append("repeated_char")
    if not any(ch.isalnum() for ch in text):
        score -= 3
        flags.append("no_alnum")
    if len(set(text)) <= 2 and len(text) >= 8:
        score -= 3
        flags.append("low_variety")
    if score <= 0:
        flags.append("low_signal")
    return max(0, score), flags


def short_text(value: Any, limit: int = 180, preserve_lines: bool = False) -> str:
    return normalize_text(value, max_len=limit, preserve_lines=preserve_lines)


def optimize_string_item(item: dict[str, Any], value_key: str = "value") -> bool:
    before = item.get(value_key, "")
    after = normalize_text(before, max_len=500)
    changed = after != before
    item[value_key] = after
    score, flags = text_signal_score(after)
    item["text_score"] = score
    if flags:
        item["text_flags"] = flags
    elif "text_flags" in item:
        item.pop("text_flags", None)
    return changed


def optimize_pseudocode_item(item: dict[str, Any], value_key: str = "text") -> bool:
    before = item.get(value_key, "")
    after = normalize_text(before, max_len=12000, preserve_lines=True)
    changed = after != before
    item[value_key] = after
    item["line_count"] = len(after.splitlines()) if after else 0
    return changed


def rank_text_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(item: dict[str, Any]) -> tuple[int, int, str]:
        xrefs = item.get("xrefs") or []
        return (
            int(item.get("text_score") or 0),
            len(xrefs) if isinstance(xrefs, list) else 0,
            str(item.get("ea") or item.get("from") or ""),
        )

    return sorted(items, key=key, reverse=True)


def dedupe_text_items(items: list[dict[str, Any]], value_key: str = "value") -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        key = (
            str(item.get("ea") or ""),
            str(item.get("from") or ""),
            str(item.get(value_key) or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def optimize_ida_text_data(data: dict[str, Any]) -> dict[str, int]:
    """Normalize IDA JSON text fields in place and return processing stats."""
    stats = {
        "strings_seen": 0,
        "strings_changed": 0,
        "low_signal_strings": 0,
        "pseudocode_seen": 0,
        "pseudocode_changed": 0,
    }

    def visit_strings(items: Any) -> list[dict[str, Any]]:
        if not isinstance(items, list):
            return []
        cleaned: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            stats["strings_seen"] += 1
            if optimize_string_item(item):
                stats["strings_changed"] += 1
            if "low_signal" in (item.get("text_flags") or []):
                stats["low_signal_strings"] += 1
            cleaned.append(item)
        return dedupe_text_items(cleaned)

    data["strings"] = visit_strings(data.get("strings"))
    for item in data.get("function_maps", []) or []:
        if isinstance(item, dict):
            item["strings"] = visit_strings(item.get("strings"))
    for item in data.get("targets", []) or []:
        if isinstance(item, dict):
            item["strings"] = visit_strings(item.get("strings"))
            if item.get("pseudocode"):
                stats["pseudocode_seen"] += 1
                if optimize_pseudocode_item(item, "pseudocode"):
                    stats["pseudocode_changed"] += 1
    for item in data.get("pseudocode", []) or []:
        if isinstance(item, dict):
            stats["pseudocode_seen"] += 1
            if optimize_pseudocode_item(item):
                stats["pseudocode_changed"] += 1

    data["text_processing"] = stats
    return stats


def persist_optimized_json(path: Path, data: dict[str, Any]) -> None:
    try:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass
