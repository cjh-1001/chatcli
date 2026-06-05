"""Classify IOC quality for defensive malware reports."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from .base import Tool, ToolResult, coerce_int, coerce_str_list

MAX_JSON_INPUT_SIZE = 50 * 1024 * 1024
MAX_IOCS = 5000

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
REGISTRY_RE = re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)\\[^\r\n\"']+", re.IGNORECASE)
WIN_PATH_RE = re.compile(r"\b[a-z]:\\[^\r\n\"'<>|]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b", re.IGNORECASE)

NOISE_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "localhost.localdomain",
}
NOISE_SUFFIXES = (".local", ".localhost", ".invalid", ".example", ".test")
GENERIC_FILENAMES = {"readme.txt", "license.txt", "debug.log", "test.txt", "sample.txt"}


def _short(value: Any, limit: int = 220) -> str:
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
        return None, f"JSON file too large for IOC quality classification ({size} bytes): {path}"
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace")), None
    except Exception as exc:
        return None, f"failed to read JSON {path}: {exc}"


def _source_strength(source: str, context: str, confidence: str) -> int:
    text = f"{source} {context} {confidence}".lower()
    score = 0
    if any(key in text for key in ("decoded config", "config", "c2", "beacon", "runtime", "sandbox", "traffic", "pcap")):
        score += 2
    if any(key in text for key in ("xref", "pseudocode", "handler", "dispatcher", "decompile")):
        score += 1
    if any(key in text for key in ("string", "strings", "import")):
        score -= 1
    if any(key in text for key in ("observed", "confirmed", "high")):
        score += 1
    if any(key in text for key in ("low", "hypothesis", "weak", "noise")):
        score -= 1
    return score


def _normalize_input(item: Any) -> list[dict[str, str]]:
    if isinstance(item, dict):
        value = str(item.get("value") or item.get("ioc") or item.get("indicator") or item.get("ip") or item.get("url") or item.get("domain") or item.get("path") or "").strip()
        if not value:
            return []
        return [{
            "value": value,
            "type": str(item.get("type") or "").strip().lower(),
            "context": str(item.get("context") or item.get("source_context") or "").strip(),
            "source": str(item.get("source") or item.get("kind") or "").strip().lower(),
            "confidence": str(item.get("confidence") or "").strip().lower(),
        }]
    return [{"value": str(item or "").strip(), "type": "", "context": "", "source": "", "confidence": ""}] if str(item or "").strip() else []


def _extract_from_text(text: str, base: dict[str, str]) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    spans: list[tuple[int, int]] = []
    for regex, kind in (
        (URL_RE, "url"),
        (HASH_RE, "hash"),
        (IP_RE, "ip"),
        (EMAIL_RE, "email"),
        (REGISTRY_RE, "registry"),
        (WIN_PATH_RE, "path"),
        (DOMAIN_RE, "domain"),
    ):
        for match in regex.finditer(text):
            if any(match.start() >= s and match.end() <= e for s, e in spans):
                continue
            spans.append((match.start(), match.end()))
            item = dict(base)
            item["value"] = match.group(0).strip().rstrip(".,);]")
            item["type"] = kind
            found.append(item)
    return found


def _collect_iocs(value: Any, out: list[dict[str, str]], limit: int = MAX_IOCS) -> None:
    if len(out) >= limit:
        return
    if isinstance(value, dict):
        normalized = _normalize_input(value)
        if normalized:
            for item in normalized:
                extracted = _extract_from_text(item["value"], item)
                out.extend(extracted or [item])
                if len(out) >= limit:
                    return
        for child in value.values():
            _collect_iocs(child, out, limit)
            if len(out) >= limit:
                return
    elif isinstance(value, list):
        for child in value:
            _collect_iocs(child, out, limit)
            if len(out) >= limit:
                return
    elif isinstance(value, (str, int, float, bool)) and value is not None:
        base = {"value": "", "type": "", "context": "", "source": "", "confidence": ""}
        out.extend(_extract_from_text(str(value), base))


def _infer_type(value: str, supplied: str) -> str:
    if supplied:
        supplied = supplied.lower()
        if any(key in supplied for key in ("url", "domain", "ip", "hash", "registry", "path", "email")):
            return supplied
    if URL_RE.fullmatch(value):
        return "url"
    if IP_RE.fullmatch(value):
        return "ip"
    if HASH_RE.fullmatch(value):
        return "hash"
    if EMAIL_RE.fullmatch(value):
        return "email"
    if REGISTRY_RE.match(value):
        return "registry"
    if WIN_PATH_RE.match(value):
        return "path"
    if DOMAIN_RE.fullmatch(value):
        return "domain"
    return supplied or "unknown"


def _classify_ip(value: str, strength: int) -> tuple[str, str]:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "weak", "invalid IP-looking value"
    if not ip.is_global:
        return "scope_only", "non-public IP; keep as local/scope indicator and do not enrich externally"
    if strength >= 2:
        return "strong", "public IP from config/runtime/C2-like context"
    if strength >= 0:
        return "medium", "public IP with limited static context"
    return "weak", "public IP from weak generic string context"


def _classify_domain(value: str, kind: str, strength: int) -> tuple[str, str]:
    host = value.lower()
    if kind == "url":
        host = re.sub(r"^https?://", "", host).split("/", 1)[0].split(":", 1)[0]
    if host in NOISE_DOMAINS or host.endswith(NOISE_SUFFIXES):
        return "noise", "documentation/test/local domain pattern"
    if any(part in host for part in ("example", "localhost")):
        return "weak", "domain contains example/localhost-like token"
    if strength >= 2:
        return "strong", "network indicator from config/runtime/C2-like context"
    if strength >= 0:
        return "medium", "network indicator with limited static context"
    return "weak", "network indicator from generic string context"


def _classify_path(value: str, kind: str, strength: int) -> tuple[str, str]:
    low = value.lower()
    if kind == "registry":
        if any(key in low for key in ("currentversion\\run", "runonce", "services\\", "winlogon", "policies\\microsoft\\windows defender")):
            return "strong" if strength >= 0 else "medium", "registry path is tied to persistence or security settings"
        return "medium" if strength >= 0 else "weak", "registry path requires code-path validation"
    filename = low.rsplit("\\", 1)[-1]
    if filename in GENERIC_FILENAMES:
        return "weak", "generic filename commonly appears in tests or benign resources"
    if any(key in low for key in ("\\appdata\\", "\\programdata\\", "\\startup\\", "\\temp\\", "\\public\\")):
        return "medium" if strength < 2 else "strong", "host path in commonly abused writable or startup location"
    return "medium" if strength >= 1 else "weak", "host path with limited malware-specific context"


def _classify_item(item: dict[str, str]) -> dict[str, Any]:
    value = item["value"]
    kind = _infer_type(value, item.get("type", ""))
    strength = _source_strength(item.get("source", ""), item.get("context", ""), item.get("confidence", ""))
    if kind == "ip":
        quality, reason = _classify_ip(value, strength)
    elif kind in {"url", "domain"}:
        quality, reason = _classify_domain(value, kind, strength)
    elif kind == "hash":
        quality, reason = "strong", "cryptographic hash indicator"
    elif kind in {"registry", "path"}:
        quality, reason = _classify_path(value, kind, strength)
    elif kind == "email":
        quality, reason = ("medium", "email-like indicator") if strength >= 0 else ("weak", "email from weak string context")
    else:
        quality, reason = ("weak", "unknown IOC type")
    return {
        "type": kind,
        "value": value,
        "quality": quality,
        "reason": reason,
        "context": item.get("context", ""),
        "source": item.get("source", ""),
        "confidence": item.get("confidence", ""),
    }


class IocQualityClassifierTool(Tool):
    name = "ioc_quality_classifier"
    description = (
        "Classify extracted malware IOCs into strong, medium, weak, noise, and "
        "scope-only buckets for defensive reporting. Performs local static "
        "classification only; use ip_lookup separately for public IP enrichment."
    )
    parameters = {
        "type": "object",
        "properties": {
            "iocs": {
                "type": "array",
                "items": {"oneOf": [{"type": "string"}, {"type": "object"}]},
                "description": "IOC strings or objects with value/type/context/source/confidence.",
            },
            "json_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional JSON files to mine for IOCs.",
            },
            "max_iocs": {
                "type": "integer",
                "description": "Maximum IOCs to classify. Default 500.",
            },
        },
    }

    def execute(
        self,
        iocs: list[Any] | str | None = None,
        json_paths: list[str] | str | None = None,
        max_iocs: int = 500,
        **kwargs,
    ) -> ToolResult:
        max_iocs = coerce_int(max_iocs, 500, minimum=1, maximum=MAX_IOCS)
        collected: list[dict[str, str]] = []
        warnings: list[str] = []

        raw_items = [iocs] if isinstance(iocs, str) else (iocs or [])
        for raw in raw_items:
            if isinstance(raw, str):
                base = {"value": "", "type": "", "context": "", "source": "", "confidence": ""}
                collected.extend(_extract_from_text(raw, base))
                continue
            for item in _normalize_input(raw):
                extracted = _extract_from_text(item["value"], item)
                collected.extend(extracted or [item])

        for raw_path in coerce_str_list(json_paths):
            data, error = _load_json(Path(raw_path))
            if error:
                warnings.append(error)
                continue
            _collect_iocs(data, collected)

        deduped: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for item in collected:
            kind = _infer_type(item["value"], item.get("type", ""))
            key = (kind, item["value"].lower())
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
            if len(deduped) >= max_iocs:
                break

        if not deduped:
            return ToolResult(
                content="Error: provide iocs or json_paths containing IOC values.",
                is_error=True,
                metadata={"warnings": warnings},
            )

        classified = [_classify_item(item) for item in deduped]
        buckets = {key: [] for key in ("strong", "medium", "weak", "noise", "scope_only")}
        for item in classified:
            buckets.setdefault(item["quality"], []).append(item)
        counts = {key: len(value) for key, value in buckets.items()}

        lines = [
            "# IOC Quality Classification",
            "",
            f"IOCs classified: {len(classified)}",
            "",
            "## Quality Counts",
        ]
        lines.extend(f"- {key}: {value}" for key, value in counts.items())
        lines.extend(["", "## Classified IOCs"])
        for quality in ("strong", "medium", "weak", "scope_only", "noise"):
            if not buckets.get(quality):
                continue
            lines.append("")
            lines.append(f"### {quality}")
            for item in buckets[quality][:50]:
                lines.append(f"- {item['type']}: {item['value']} ({item['reason']})")
        if warnings:
            lines.extend(["", "## Warnings"])
            lines.extend(f"- {warning}" for warning in warnings)

        return ToolResult(
            content="\n".join(lines),
            metadata={
                "warnings": warnings,
                "counts": counts,
                "classified": classified,
                "buckets": buckets,
                "report_hints": {"ioc_quality": buckets},
            },
        )
