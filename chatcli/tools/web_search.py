"""WebSearch tool — multi-backend web search.

Tries Bing first (works in China), falls back to DuckDuckGo.
Supports configurable backend: auto, bing, duckduckgo.
"""

import re
import httpx
import sys
from html import unescape
from urllib.parse import parse_qs, unquote, urlparse, urlunparse
from .base import Tool, ToolResult, coerce_int
from ._http_utils import HEADERS, SEARCH_TIMEOUT, MAX_FILE_SIZE

_TAG_RE = re.compile(r"<[^>]+>")
_SPACE_RE = re.compile(r"\s+")
_TRACKING_PARAMS = {"fbclid", "gclid", "mc_cid", "mc_eid", "igshid"}


def _clean_html(raw: str) -> str:
    """Strip HTML tags and decode common entities."""
    text = _TAG_RE.sub(" ", raw)
    text = unescape(text)
    text = text.replace("\xa0", " ")
    text = _SPACE_RE.sub(" ", text)
    return text.strip()


def _decode_result_url(raw_url: str) -> str:
    """Decode search-engine redirect URLs and remove common tracking params."""
    raw_url = unescape(raw_url or "").strip()
    if raw_url.startswith("//"):
        raw_url = "https:" + raw_url

    parsed = urlparse(raw_url)
    qs = parse_qs(parsed.query)
    if "uddg" in qs and qs["uddg"]:
        raw_url = unquote(qs["uddg"][0])
        parsed = urlparse(raw_url)

    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return ""

    clean_qs = []
    for part in parsed.query.split("&"):
        if not part:
            continue
        key = part.split("=", 1)[0]
        if key.startswith("utm_") or key in _TRACKING_PARAMS:
            continue
        clean_qs.append(part)

    parsed = parsed._replace(query="&".join(clean_qs), fragment="")
    return urlunparse(parsed)


def _host(url: str) -> str:
    return urlparse(url).netloc.lower().removeprefix("www.")


def _valid_result_url(url: str) -> bool:
    host = _host(url)
    if not host:
        return False
    internal_hosts = {
        "bing.com", "r.bing.com", "cc.bingj.com", "duckduckgo.com",
        "html.duckduckgo.com", "lite.duckduckgo.com",
    }
    return host not in internal_hosts


def _dedupe_results(results: list[dict], max_results: int) -> list[dict]:
    deduped = []
    seen = set()
    for r in results:
        url = _decode_result_url(r.get("url", ""))
        if not url or not _valid_result_url(url):
            continue
        key = url.rstrip("/").lower()
        title_key = _clean_html(r.get("title", "")).lower()
        if key in seen or (title_key, _host(url)) in seen:
            continue
        seen.add(key)
        seen.add((title_key, _host(url)))
        snippet = _clean_html(r.get("snippet", ""))
        if len(snippet) > 320:
            snippet = snippet[:317] + "..."
        deduped.append({
            "title": _clean_html(r.get("title", "")) or "(untitled)",
            "url": url,
            "domain": _host(url),
            "snippet": snippet or "(no description)",
        })
        if len(deduped) >= max_results:
            break
    return deduped


# ═══════════════════════════════════════════════════════════════════
# Bing backend
# ═══════════════════════════════════════════════════════════════════

_BING_URL = "https://www.bing.com/search"
_BING_RESULT_RE = re.compile(
    r'<li[^>]*class="b_algo"[^>]*>(.*?)</li>', re.DOTALL,
)
# Title link inside <h2>
_BING_TITLE_RE = re.compile(
    r'<h2[^>]*>.*?<a[^>]*href="(https?://[^"]*)"[^>]*>(.*?)</a>', re.DOTALL,
)
# Fallback: any link with href
_BING_ANY_LINK_RE = re.compile(
    r'<a[^>]*href="(https?://[^"]*)"[^>]*>(.*?)</a>', re.DOTALL,
)
_BING_SNIPPET_RE = re.compile(
    r'<p[^>]*class="(?:b_lineclamp|b_algoSlug|b_algoabstract)[^"]*"[^>]*>(.*?)</p>', re.DOTALL,
)
_BING_CAPTION_RE = re.compile(
    r'<div[^>]*class="b_caption"[^>]*>(.*?)</div>', re.DOTALL,
)


def _search_bing(query: str) -> str | None:
    """Fetch Bing search results page. Returns HTML or None on failure."""
    try:
        response = httpx.get(
            _BING_URL,
            params={"q": query, "setlang": "en"},
            headers=HEADERS,
            timeout=SEARCH_TIMEOUT,
            follow_redirects=True,
        )
        response.raise_for_status()
        # Safety: reject oversized responses
        if len(response.content) > MAX_FILE_SIZE:
            print(f"[chatcli] Warning: Bing response too large ({len(response.content)} bytes), skipping", file=sys.stderr)
            return None
        return response.text
    except Exception as e:
        print(f"[chatcli] Warning: Bing fetch failed: {e}", file=sys.stderr)
        return None


def _parse_bing(html: str, max_results: int) -> list[dict]:
    """Parse Bing HTML results."""
    results = []
    blocks = _BING_RESULT_RE.findall(html)

    for block in blocks:
        if len(results) >= max_results:
            break

        # Extract title + url — prefer h2 link, fall back to any link
        title_match = _BING_TITLE_RE.search(block)
        if title_match:
            url = _decode_result_url(title_match.group(1))
            title = _clean_html(title_match.group(2))
        else:
            link_match = _BING_ANY_LINK_RE.search(block)
            if not link_match:
                continue
            url = _decode_result_url(link_match.group(1))
            title = _clean_html(link_match.group(2))

        if not title or not url:
            continue

        if not _valid_result_url(url):
            continue

        # Extract snippet
        snippet = ""
        snippet_match = _BING_SNIPPET_RE.search(block)
        if snippet_match:
            snippet = _clean_html(snippet_match.group(1))
        else:
            caption_match = _BING_CAPTION_RE.search(block)
            if caption_match:
                cap_text = caption_match.group(1)
                cap_text = _BING_ANY_LINK_RE.sub(" ", cap_text)
                snippet = _clean_html(cap_text)

        results.append({
            "title": title,
            "url": url,
            "snippet": snippet or "(no description)",
        })

    return results


# ═══════════════════════════════════════════════════════════════════
# DuckDuckGo backend
# ═══════════════════════════════════════════════════════════════════

_DDG_URL = "https://html.duckduckgo.com/html/"
_DDG_LITE_URL = "https://lite.duckduckgo.com/lite/"


def _search_duckduckgo(query: str) -> str | None:
    """Fetch DuckDuckGo search results. Returns HTML or None on failure."""
    for label, url in [("html", _DDG_URL), ("lite", _DDG_LITE_URL)]:
        try:
            response = httpx.post(
                url, data={"q": query, "b": ""},
                headers=HEADERS, timeout=SEARCH_TIMEOUT,
                follow_redirects=True,
            )
            response.raise_for_status()
            # Safety: reject oversized responses
            if len(response.content) > MAX_FILE_SIZE:
                print(f"[chatcli] Warning: {label} fetch too large ({len(response.content)} bytes), trying next", file=sys.stderr)
                continue
            return response.text
        except Exception as e:
            print(f"[chatcli] Warning: DuckDuckGo fetch failed: {e}", file=sys.stderr)
            continue
    return None


def _parse_duckduckgo(html: str, max_results: int) -> list[dict]:
    """Parse DuckDuckGo HTML results."""
    results = []
    blocks = html.split('class="result__body"')

    for block in blocks[1:] if len(blocks) > 1 else []:
        if len(results) >= max_results:
            break

        link_match = re.search(
            r'<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>',
            block, re.DOTALL,
        )
        if not link_match:
            continue

        raw_url = link_match.group(1)
        title = _clean_html(link_match.group(2))

        url = _decode_result_url(raw_url)

        if not title or not url:
            continue
        if not _valid_result_url(url):
            continue

        snippet_match = re.search(
            r'<a[^>]*class="result__snippet"[^>]*>(.*?)</a>',
            block, re.DOTALL,
        )
        snippet = _clean_html(snippet_match.group(1)) if snippet_match else ""

        skip_prefixes = ("Ad", "Shop ", "Sponsored")
        if title.startswith(skip_prefixes):
            continue

        results.append({
            "title": title,
            "url": url,
            "snippet": snippet[:300] if snippet else "(no description)",
        })

    if results:
        return results

    return _parse_duckduckgo_lite(html, max_results)


def _parse_duckduckgo_lite(html: str, max_results: int) -> list[dict]:
    """Fallback parser for DuckDuckGo lite HTML."""
    results = []
    link_re = re.compile(
        r'<a[^>]*href="([^"]*(?:uddg=|https?://)[^"]*)"[^>]*>(.*?)</a>',
        re.DOTALL,
    )
    for raw_url, raw_title in link_re.findall(html):
        if len(results) >= max_results:
            break
        title = _clean_html(raw_title)
        url = _decode_result_url(raw_url)
        if not title or not url or not _valid_result_url(url):
            continue
        if title.lower() in {"next page", "previous page"}:
            continue
        results.append({
            "title": title,
            "url": url,
            "snippet": "(no description)",
        })
    return results


# ═══════════════════════════════════════════════════════════════════
# Unified tool
# ═══════════════════════════════════════════════════════════════════

_SOURCES = {
    "bing":        (_search_bing,        _parse_bing),
    "duckduckgo":  (_search_duckduckgo,  _parse_duckduckgo),
}

# Order to try when backend="auto"
_AUTO_ORDER = ["bing", "duckduckgo"]


class WebSearchTool(Tool):
    name = "web_search"
    description = (
        "Search the web and return results with titles, URLs, and snippets. "
        "Use this to find current information, documentation, or answers "
        "that may not be in your training data."
    )
    parameters = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "The search query to use.",
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of results (default 10, max 20).",
            },
            "backend": {
                "type": "string",
                "description": "Search backend: auto (try Bing then DuckDuckGo), bing, duckduckgo.",
            },
        },
        "required": ["query"],
    }

    def execute(self, query: str, max_results: int = 10,
                backend: str = "auto") -> ToolResult:
        query = (query or "").strip()
        if not query:
            return ToolResult(content="Error: query cannot be empty.", is_error=True)
        max_results = coerce_int(max_results, 10, minimum=1, maximum=20)
        backend = backend.lower()

        if backend == "auto":
            order = _AUTO_ORDER
        elif backend in _SOURCES:
            order = [backend]
        else:
            return ToolResult(
                content=f"Error: Unknown search backend '{backend}'. "
                        f"Valid options: auto, bing, duckduckgo.",
                is_error=True,
            )

        html = None
        last_error = None

        for name in order:
            fetcher, _parser = _SOURCES[name]
            html = fetcher(query)
            if html:
                results = _parser(html, max_results)
                results = _dedupe_results(results, max_results)
                if results:
                    return self._format(results, query, name)
                else:
                    last_error = f"{name} returned no results"
            else:
                last_error = f"{name} is unreachable (timeout or blocked)"

        return ToolResult(
            content=(
                f"Error: All search backends failed. {last_error}. "
                f"Bing and DuckDuckGo may both be blocked in your region. "
                f"Try using a VPN or HTTP proxy."
            ),
            is_error=True,
        )

    def _format(self, results: list[dict], query: str,
                source: str) -> ToolResult:
        lines = [
            f"Search results for: {query}",
            f"Backend: {source}",
            "",
        ]
        for i, r in enumerate(results, 1):
            lines.append(f"{i}. {r['title']}")
            lines.append(f"   URL: {r['url']}")
            lines.append(f"   Source: {r.get('domain', _host(r['url']))}")
            lines.append(f"   Snippet: {r['snippet']}")
            lines.append("")

        return ToolResult(
            content="\n".join(lines).strip(),
            metadata={
                "count": len(results),
                "query": query,
                "backend": source,
                "results": results,
            },
        )
