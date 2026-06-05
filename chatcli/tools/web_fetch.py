"""WebFetch tool — fetch a URL and extract readable content."""

import json
import re
import httpx
from urllib.parse import urlparse
from .base import Tool, ToolResult
from ._http_utils import HEADERS, SEARCH_TIMEOUT, MAX_FILE_SIZE

MAX_CONTENT_LENGTH = 50_000  # truncate fetched content

# Elements to COMPLETELY remove (with all content inside)
_REMOVE_RE = re.compile(
    r"<(?:script|style|nav|footer|header|aside|noscript|iframe|svg"
    r"|form|select|button|textarea)[^>]*>.*?</(?:script|style|nav"
    r"|footer|header|aside|noscript|iframe|svg|form|select|button"
    r"|textarea)>",
    re.DOTALL | re.IGNORECASE,
)

# Self-closing / metadata tags to remove (no content)
_META_RE = re.compile(
    r"<(?:meta|link|base|input|img|br|hr|wbr|source|track"
    r"|embed|param|area|col)[^>]*/?>",
    re.IGNORECASE,
)

# Structural wrappers — strip the tags, keep content
_STRUCT_RE = re.compile(
    r"</?(?:html|head|body|title|span|em|strong|b|i|u|s|sub|sup"
    r"|code|pre|kbd|var|samp|mark|small|big|abbr|cite|dfn"
    r"|time|address|label|caption|thead|tbody|tfoot|colgroup"
    r"|map|optgroup|option|datalist|output|progress|meter"
    r"|canvas|audio|video|object|param|source|picture"
    r"|font|center|strike|tt|ins|del|ruby|rt|rp|bdi|bdo"
    r"|data|template|slot|dialog|menu|menuitem|summary"
    r"|details|fieldset|legend)[^>]*>",
    re.IGNORECASE,
)

# Block-level elements → insert newlines
_BLOCK_RE = re.compile(
    r"</?(?:div|p|h[1-6]|li|tr|table|section|article|main"
    r"|blockquote|figure|figcaption"
    r"|ul|ol|dl|dt|dd)[^>]*>",
    re.IGNORECASE,
)

# Strip remaining HTML tags
_TAG_RE = re.compile(r"<[^>]+>")

# Collapse horizontal whitespace (multiple spaces/tabs)
_SPACE_WS_RE = re.compile(r"[ \t]{2,}")


def _html_to_text(html: str) -> str:
    """Extract readable text from HTML."""
    # 1. Remove completely (scripts, styles, nav, etc.)
    text = _REMOVE_RE.sub("", html)
    # 2. Remove self-closing / metadata tags
    text = _META_RE.sub("", text)
    # 3. Strip structural wrappers (keep inner content)
    text = _STRUCT_RE.sub("", text)
    # 4. Insert newlines for block elements
    text = _BLOCK_RE.sub("\n", text)
    # 5. Strip any remaining HTML tags
    text = _TAG_RE.sub("", text)
    # 6. Decode common entities
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    text = text.replace("&quot;", '"').replace("&#x27;", "'").replace("&nbsp;", " ")
    text = text.replace("&rsquo;", "'").replace("&lsquo;", "'")
    text = text.replace("&rdquo;", '"').replace("&ldquo;", '"')
    text = text.replace("&mdash;", "—").replace("&ndash;", "–")
    text = text.replace("&hellip;", "...")
    # 7. Collapse horizontal whitespace
    text = _SPACE_WS_RE.sub(" ", text)
    # 8. Per-line: strip whitespace, remove blank-only lines
    raw_lines = text.split("\n")
    clean_lines = []
    prev_blank = False
    for line in raw_lines:
        stripped = line.strip()
        if not stripped:
            if not prev_blank and clean_lines:
                clean_lines.append("")  # single blank = paragraph break
            prev_blank = True
        else:
            clean_lines.append(stripped)
            prev_blank = False
    # Remove leading/trailing blanks
    while clean_lines and not clean_lines[0]:
        clean_lines.pop(0)
    while clean_lines and not clean_lines[-1]:
        clean_lines.pop()
    return "\n".join(clean_lines)


def _summarize(content: str, prompt: str, max_len: int = 3000) -> str:
    """Simple keyword-based extraction when a prompt is given.

    For a real implementation, this would use the LLM. Here we do a
    best-effort keyword match to find relevant paragraphs.
    """
    keywords = [w.lower() for w in re.findall(r"\w{4,}", prompt)]
    if not keywords:
        return content[:max_len]

    paragraphs = content.split("\n\n")
    scored = []
    for para in paragraphs:
        para_lower = para.lower()
        score = sum(1 for kw in keywords if kw in para_lower)
        if score > 0:
            scored.append((score, para))

    if not scored:
        return content[:max_len]

    scored.sort(key=lambda x: x[0], reverse=True)
    relevant = [p for _, p in scored[:10]]
    result = "\n\n".join(relevant)
    if len(result) > max_len:
        result = result[:max_len] + "\n... (truncated)"
    return result


def _looks_like_json(content_type: str, text: str) -> bool:
    content_type = (content_type or "").lower()
    if "json" in content_type or content_type.endswith("+json"):
        return True
    stripped = text.lstrip()
    return stripped.startswith("{") or stripped.startswith("[")


def _json_metadata(value):
    if isinstance(value, dict):
        return {
            "json_type": "object",
            "json_keys": list(value.keys())[:30],
        }
    if isinstance(value, list):
        return {
            "json_type": "array",
            "json_length": len(value),
            "json_sample_type": type(value[0]).__name__ if value else "empty",
        }
    return {"json_type": type(value).__name__}


class WebFetchTool(Tool):
    name = "web_fetch"
    description = (
        "Fetch the content of a URL and extract readable text. "
        "Returns page content as plain text, structured JSON, or raw text. "
        "Max response size: 5MB. Timeout: 20s. "
        "Optionally provide a prompt to extract the most relevant "
        "sections of the page based on your question."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "The URL to fetch content from.",
            },
            "prompt": {
                "type": "string",
                "description": (
                    "Optional: a specific question about the page. "
                    "When provided, returns the most relevant sections "
                    "instead of the full page content."
                ),
            },
            "mode": {
                "type": "string",
                "description": "Fetch mode: auto, text, json, or raw. Default auto.",
                "enum": ["auto", "text", "json", "raw"],
            },
        },
        "required": ["url"],
    }

    def execute(self, url: str, prompt: str = "", mode: str = "auto") -> ToolResult:
        mode = (mode or "auto").strip().lower()
        if mode not in {"auto", "text", "json", "raw"}:
            return ToolResult(
                content=f"Error: unsupported mode '{mode}'. Valid modes: auto, text, json, raw.",
                is_error=True,
            )

        # Validate URL
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return ToolResult(
                    content=f"Error: Unsupported URL scheme '{parsed.scheme}'. Only http and https are supported.",
                    is_error=True,
                )
        except Exception:
            return ToolResult(
                content=f"Error: Invalid URL: {url}",
                is_error=True,
            )

        # Fetch
        try:
            response = httpx.get(
                url,
                headers=HEADERS,
                timeout=SEARCH_TIMEOUT,
                follow_redirects=True,
            )
            response.raise_for_status()
        except httpx.TimeoutException:
            return ToolResult(
                content=f"Error: Request to {url} timed out after {int(SEARCH_TIMEOUT)} seconds.",
                is_error=True,
            )
        except httpx.HTTPStatusError as e:
            return ToolResult(
                content=f"Error: HTTP {e.response.status_code} when fetching {url}",
                is_error=True,
            )
        except httpx.HTTPError as e:
            return ToolResult(
                content=f"Error: Failed to fetch {url}: {e}",
                is_error=True,
            )

        response_metadata = {
            "url": url,
            "final_url": str(response.url),
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type", ""),
            "content_length_bytes": len(response.content),
        }

        # Check content type
        content_type = response.headers.get("content-type", "")
        content_type_lower = content_type.lower()
        if (
            mode == "text"
            and "text/html" not in content_type_lower
            and "text/plain" not in content_type_lower
        ):
            # Still try to extract text — some sites have wrong content-type
            pass

        # Check size
        if len(response.content) > MAX_FILE_SIZE:
            return ToolResult(
                content=f"Error: Response too large ({len(response.content)} bytes). Maximum is {MAX_FILE_SIZE} bytes.",
                is_error=True,
            )

        # Decode
        try:
            raw_text = response.text
        except UnicodeDecodeError:
            raw_text = response.content.decode("latin-1", errors="replace")

        if mode == "json" or (mode == "auto" and _looks_like_json(content_type, raw_text)):
            try:
                data = response.json()
            except Exception as exc:
                if mode == "json":
                    return ToolResult(
                        content=f"Error: Response is not valid JSON: {exc}",
                        is_error=True,
                        metadata=response_metadata,
                    )
            else:
                text = json.dumps(data, ensure_ascii=False, indent=2)
                original_len = len(text)
                truncated = False
                if len(text) > MAX_CONTENT_LENGTH:
                    text = text[:MAX_CONTENT_LENGTH] + "\n... (JSON truncated)"
                    truncated = True
                metadata = {
                    **response_metadata,
                    **_json_metadata(data),
                    "mode": "json",
                    "content_length": original_len,
                    "truncated": truncated,
                    "prompt_used": False,
                }
                return ToolResult(content=text, metadata=metadata)

        if mode == "raw":
            text = raw_text
            original_len = len(text)
            truncated = False
            if len(text) > MAX_CONTENT_LENGTH:
                text = text[:MAX_CONTENT_LENGTH] + "\n... (raw content truncated)"
                truncated = True
            return ToolResult(
                content=text,
                metadata={
                    **response_metadata,
                    "mode": "raw",
                    "content_length": original_len,
                    "truncated": truncated,
                    "prompt_used": False,
                },
            )

        # Extract text
        if "text/html" in content_type_lower or "<html" in raw_text[:1000].lower():
            text = _html_to_text(raw_text)
        else:
            text = raw_text.strip()

        if not text or not text.strip():
            return ToolResult(
                content=(
                    "No readable text content found on this page. It may be a "
                    "JavaScript-only site, JSON that failed to parse, or an image/media file."
                ),
                metadata={**response_metadata, "mode": "text", "content_length": 0},
            )

        # Apply prompt-based extraction if requested
        if prompt:
            text = _summarize(text, prompt)

        # Truncate
        original_len = len(text)
        if len(text) > MAX_CONTENT_LENGTH:
            text = text[:MAX_CONTENT_LENGTH] + "\n\n... (content truncated)"
            text += f"\n[Page URL: {url}]"

        return ToolResult(
            content=text,
            metadata={
                **response_metadata,
                "mode": "text",
                "content_length": original_len,
                "truncated": original_len > MAX_CONTENT_LENGTH,
                "prompt_used": bool(prompt),
            },
        )
