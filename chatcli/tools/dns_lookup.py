"""DNS lookup tool — resolve domains to IPs and optionally enrich with IP info."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any

import httpx

from ._http_utils import HEADERS, SEARCH_TIMEOUT
from .base import Tool, ToolResult, coerce_str_list

# ── IP enrichment (shared with ip_lookup, kept independent to avoid circular imports) ──

_IP_CACHE: dict[str, dict[str, Any]] = {}
_MAX_CACHE = 256


def _ip_scope(ip: ipaddress._BaseAddress) -> str:
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


def _cache_ip(ip: str, data: dict[str, Any]) -> None:
    if ip not in _IP_CACHE and len(_IP_CACHE) >= _MAX_CACHE:
        oldest = next(iter(_IP_CACHE), None)
        if oldest:
            _IP_CACHE.pop(oldest, None)
    _IP_CACHE[ip] = data


def _enrich_ip(ip_str: str) -> dict[str, Any]:
    """Look up IP geolocation/ASN info. Returns a dict with status and fields."""
    try:
        parsed = ipaddress.ip_address(ip_str)
    except ValueError:
        return {"status": "invalid", "error": "invalid IP address"}

    scope = _ip_scope(parsed)
    base: dict[str, Any] = {"ip": str(parsed), "scope": scope}

    if scope != "public":
        return {**base, "status": "skipped", "reason": "non-public address"}

    cached = _IP_CACHE.get(str(parsed))
    if cached:
        return {**base, **cached, "cache": "hit"}

    # Try ipinfo.io first, then ipapi.co as fallback
    for provider in (_enrich_ipinfo, _enrich_ipapi):
        result = provider(str(parsed))
        if result.get("status") == "ok":
            _cache_ip(str(parsed), result)
            return {**base, **result, "cache": "miss"}

    result = {"status": "error", "error": "all providers failed"}
    _cache_ip(str(parsed), result)
    return {**base, **result, "cache": "miss"}


def _enrich_ipinfo(ip: str) -> dict[str, Any]:
    try:
        resp = httpx.get(
            f"https://ipinfo.io/{ip}/json",
            headers=HEADERS,
            timeout=SEARCH_TIMEOUT,
            follow_redirects=True,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return {"status": "error", "source": "ipinfo.io", "error": str(e)}

    if data.get("bogon"):
        return {"status": "skipped", "source": "ipinfo.io", "error": "bogon"}

    org = str(data.get("org") or "").strip()
    asn = org.split()[0] if org.upper().startswith("AS") else ""
    return {
        "status": "ok",
        "source": "ipinfo.io",
        "country": str(data.get("country") or "").strip(),
        "region": str(data.get("region") or "").strip(),
        "city": str(data.get("city") or "").strip(),
        "asn": asn,
        "org": org,
        "timezone": str(data.get("timezone") or "").strip(),
    }


def _enrich_ipapi(ip: str) -> dict[str, Any]:
    try:
        resp = httpx.get(
            f"https://ipapi.co/{ip}/json/",
            headers=HEADERS,
            timeout=SEARCH_TIMEOUT,
            follow_redirects=True,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return {"status": "error", "source": "ipapi.co", "error": str(e)}

    if data.get("error"):
        return {
            "status": "error",
            "source": "ipapi.co",
            "error": str(data.get("reason") or data.get("error") or "").strip(),
        }

    return {
        "status": "ok",
        "source": "ipapi.co",
        "country": str(data.get("country_name") or data.get("country") or "").strip(),
        "region": str(data.get("region") or "").strip(),
        "city": str(data.get("city") or "").strip(),
        "asn": str(data.get("asn") or "").strip(),
        "org": str(data.get("org") or "").strip(),
        "timezone": str(data.get("timezone") or "").strip(),
    }


# ── Reverse DNS ──────────────────────────────────────────────────────────

def _reverse_dns(ip: str, timeout: float = 3.0) -> str:
    """PTR lookup — resolve IP back to hostname."""
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return ""


# ── DNS resolution ───────────────────────────────────────────────────────

def _resolve_domain(domain: str, timeout: float = 5.0) -> dict[str, Any]:
    """Resolve a single domain to IP addresses."""
    domain = domain.strip().lower()
    result: dict[str, Any] = {
        "domain": domain,
        "status": "error",
        "ipv4": [],
        "ipv6": [],
    }

    # Check if it's already an IP
    try:
        ip = ipaddress.ip_address(domain)
        ver = "ipv4" if ip.version == 4 else "ipv6"
        result[ver] = [str(ip)]
        result["status"] = "ok"
        result["already_ip"] = True
        return result
    except ValueError:
        pass

    # Resolve via getaddrinfo — returns both IPv4 and IPv6
    try:
        socket.setdefaulttimeout(timeout)
        addrs = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        result["error"] = f"DNS resolution failed: {e}"
        return result
    except Exception as e:
        result["error"] = f"Resolution error: {type(e).__name__}: {e}"
        return result

    ipv4_set: set[str] = set()
    ipv6_set: set[str] = set()

    for family, _, _, _, sockaddr in addrs:
        ip = sockaddr[0]
        if family == socket.AF_INET:
            ipv4_set.add(ip)
        elif family == socket.AF_INET6:
            # Strip scope ID if present (e.g. fe80::1%eth0)
            ip = ip.split("%")[0]
            ipv6_set.add(ip)

    result["ipv4"] = sorted(ipv4_set, key=lambda x: ipaddress.IPv4Address(x))
    result["ipv6"] = sorted(ipv6_set)
    result["status"] = "ok" if (ipv4_set or ipv6_set) else "no_ips"
    result["ip_count"] = len(ipv4_set) + len(ipv6_set)

    return result


# ── Tool ──────────────────────────────────────────────────────────────────


class DnsLookupTool(Tool):
    name = "dns_lookup"
    description = (
        "Resolve domain names to IP addresses with optional IP geolocation "
        "enrichment. Returns IPv4, IPv6, reverse DNS (PTR), and — when "
        "enrich=True — country, city, ASN/org, and timezone for each "
        "public IP. Non-public IPs are classified locally without external "
        "API calls. Supports batch resolution of up to 20 domains at once."
    )
    parameters = {
        "type": "object",
        "properties": {
            "domains": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Domain name(s) to resolve. Max 20 per call. "
                    "Bare IP addresses are also accepted (no resolution needed)."
                ),
            },
            "enrich": {
                "type": "boolean",
                "description": (
                    "If true, enrich each resolved public IP with geolocation "
                    "and ASN info via ipinfo.io / ipapi.co. Default: true."
                ),
            },
            "ptr": {
                "type": "boolean",
                "description": (
                    "If true, perform reverse DNS (PTR) lookup on each "
                    "resolved IP to find its hostname. Default: true."
                ),
            },
        },
        "required": ["domains"],
    }

    def execute(
        self,
        domains: list[str] | str,
        enrich: bool = True,
        ptr: bool = True,
    ) -> ToolResult:
        values = coerce_str_list(domains)
        if not values:
            return ToolResult(content="Error: domains cannot be empty.", is_error=True)
        if len(values) > 20:
            return ToolResult(
                content=f"Error: max 20 domains per call, got {len(values)}.",
                is_error=True,
            )

        results: list[dict[str, Any]] = []
        total_ips = 0
        enriched_count = 0

        for domain in values:
            entry = _resolve_domain(domain)

            if entry["status"] != "ok":
                results.append(entry)
                continue

            # Collect all IPs
            all_ips: list[str] = list(entry["ipv4"]) + list(entry["ipv6"])

            # Reverse DNS
            if ptr and all_ips:
                entry["ptr_records"] = {}
                for ip in all_ips:
                    rdns = _reverse_dns(ip)
                    if rdns:
                        entry["ptr_records"][ip] = rdns

            # IP enrichment
            if enrich and all_ips:
                entry["ip_info"] = {}
                for ip in all_ips:
                    info = _enrich_ip(ip)
                    entry["ip_info"][ip] = info
                    if info.get("status") == "ok":
                        enriched_count += 1

            total_ips += entry.get("ip_count", 0)
            results.append(entry)

        # ── Build readable output ──────────────────────────────
        lines = ["DNS lookup results", ""]
        for entry in results:
            if entry["status"] == "error":
                lines.append(
                    f"[FAIL] {entry['domain']}: FAILED — {entry.get('error', 'unknown error')}"
                )
                continue

            domain = entry["domain"]
            ipv4 = entry.get("ipv4", [])
            ipv6 = entry.get("ipv6", [])
            already = " (already an IP)" if entry.get("already_ip") else ""

            lines.append(f"[OK] {domain}{already}")
            if ipv4:
                lines.append(f"  IPv4 ({len(ipv4)}): {', '.join(ipv4)}")
            if ipv6:
                lines.append(f"  IPv6 ({len(ipv6)}): {', '.join(ipv6)}")

            # PTR records
            ptr_records = entry.get("ptr_records", {})
            if ptr_records:
                for ip, hostname in sorted(ptr_records.items()):
                    lines.append(f"  PTR {ip} → {hostname}")

            # IP enrichment
            ip_info = entry.get("ip_info", {})
            if ip_info:
                for ip, info in sorted(ip_info.items()):
                    if info.get("status") != "ok":
                        lines.append(
                            f"  {ip}: {info.get('scope', '?')} — {info.get('error', 'not enriched')}"
                        )
                        continue
                    parts = []
                    for field in ("country", "region", "city"):
                        v = info.get(field, "")
                        if v:
                            parts.append(v)
                    location = ", ".join(parts) if parts else "unknown"
                    asn = info.get("asn", "")
                    org = info.get("org", "")
                    asn_org = f" | ASN: {asn} {org}".strip() if asn or org else ""
                    lines.append(f"  {ip}: {location}{asn_org} [{info.get('source', '?')}]")

            lines.append("")

        return ToolResult(
            content="\n".join(lines).strip(),
            metadata={
                "domains_queried": len(values),
                "total_ips": total_ips,
                "enriched": enriched_count,
                "results": results,
            },
        )
