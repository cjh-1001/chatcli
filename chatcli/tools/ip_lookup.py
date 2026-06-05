"""IP lookup tool for defensive IOC enrichment."""

from __future__ import annotations

import ipaddress
from typing import Any

import httpx

from ._http_utils import HEADERS, SEARCH_TIMEOUT
from .base import Tool, ToolResult, coerce_str_list

_MAX_CACHE_ITEMS = 512
_LOOKUP_CACHE: dict[str, dict[str, Any]] = {}


def _scope(ip: ipaddress._BaseAddress) -> str:
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reserved"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_private:
        return "private"
    if not ip.is_global:
        return "non-global"
    return "public"


def _format_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _cache_set(ip: str, result: dict[str, Any]) -> None:
    if ip not in _LOOKUP_CACHE and len(_LOOKUP_CACHE) >= _MAX_CACHE_ITEMS:
        oldest = next(iter(_LOOKUP_CACHE), None)
        if oldest is not None:
            _LOOKUP_CACHE.pop(oldest, None)
    _LOOKUP_CACHE[ip] = result


class IPLookupTool(Tool):
    name = "ip_lookup"
    description = (
        "Look up public IP addresses for defensive IOC enrichment. Returns "
        "scope, country/region/city, ASN/org, timezone, and source when "
        "available. Private, loopback, multicast, reserved, or invalid IPs are "
        "classified locally and are not sent to third-party services."
    )
    parameters = {
        "type": "object",
        "properties": {
            "ips": {
                "type": "array",
                "items": {"type": "string"},
                "description": "IP address or list of IP addresses to query.",
            },
        },
        "required": ["ips"],
    }

    def execute(self, ips: list[str] | str) -> ToolResult:
        values = coerce_str_list(ips)
        if not values:
            return ToolResult(content="Error: ips cannot be empty.", is_error=True)

        results: list[dict[str, Any]] = []
        cache_hits = 0
        for raw in values[:50]:
            item = self._lookup_one(raw)
            if item.get("cache") == "hit":
                cache_hits += 1
            results.append(item)

        lines = ["IP lookup results", ""]
        for item in results:
            status = item.get("status", "")
            ip = item.get("ip", item.get("input", ""))
            lines.append(f"- {ip}: {status}")
            details = []
            for key in (
                "scope", "country", "region", "city", "asn", "org",
                "timezone", "source", "cache", "error",
            ):
                value = item.get(key)
                if value:
                    details.append(f"{key}={value}")
            if details:
                lines.append(f"  {', '.join(details)}")

        return ToolResult(
            content="\n".join(lines).strip(),
            metadata={"count": len(results), "cache_hits": cache_hits, "results": results},
        )

    def _lookup_one(self, raw: str) -> dict[str, Any]:
        value = str(raw or "").strip()
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return {"input": value, "status": "invalid", "error": "invalid IP address"}

        scope = _scope(parsed)
        base: dict[str, Any] = {"ip": str(parsed), "scope": scope}
        if scope != "public":
            return {
                **base,
                "status": "skipped",
                "queried": False,
                "notes": "non-public address; no external lookup performed",
            }

        cached = _LOOKUP_CACHE.get(str(parsed))
        if cached:
            return {**base, **cached, "cache": "hit"}

        result: dict[str, Any] = {"status": "error", "error": "lookup failed"}
        for provider in (self._lookup_ipinfo, self._lookup_ipapi):
            result = provider(str(parsed))
            if result.get("status") == "ok":
                cached_result = {**result, "queried": True}
                _cache_set(str(parsed), cached_result)
                return {**base, **cached_result, "cache": "miss"}

        cached_result = {**result, "queried": True}
        _cache_set(str(parsed), cached_result)
        return {**base, **cached_result, "cache": "miss"}

    def _lookup_ipinfo(self, ip: str) -> dict[str, Any]:
        try:
            response = httpx.get(
                f"https://ipinfo.io/{ip}/json",
                headers=HEADERS,
                timeout=SEARCH_TIMEOUT,
                follow_redirects=True,
            )
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            return {"status": "error", "source": "ipinfo.io", "error": str(exc)}

        if data.get("bogon"):
            return {"status": "skipped", "source": "ipinfo.io", "error": "bogon address"}

        org = _format_value(data.get("org"))
        asn = org.split()[0] if org.upper().startswith("AS") else ""
        return {
            "status": "ok",
            "source": "ipinfo.io",
            "country": _format_value(data.get("country")),
            "region": _format_value(data.get("region")),
            "city": _format_value(data.get("city")),
            "asn": asn,
            "org": org,
            "timezone": _format_value(data.get("timezone")),
        }

    def _lookup_ipapi(self, ip: str) -> dict[str, Any]:
        try:
            response = httpx.get(
                f"https://ipapi.co/{ip}/json/",
                headers=HEADERS,
                timeout=SEARCH_TIMEOUT,
                follow_redirects=True,
            )
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            return {"status": "error", "source": "ipapi.co", "error": str(exc)}

        if data.get("error"):
            return {
                "status": "error",
                "source": "ipapi.co",
                "error": _format_value(data.get("reason") or data.get("error")),
            }

        return {
            "status": "ok",
            "source": "ipapi.co",
            "country": _format_value(data.get("country_name") or data.get("country")),
            "region": _format_value(data.get("region")),
            "city": _format_value(data.get("city")),
            "asn": _format_value(data.get("asn")),
            "org": _format_value(data.get("org")),
            "timezone": _format_value(data.get("timezone")),
        }
