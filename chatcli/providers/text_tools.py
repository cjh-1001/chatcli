"""Text-based tool calling provider.

For APIs that don't support native tool calling or reject tool_calls
in message history. Tools are injected into the system prompt, and
tool calls are parsed from the model's text output.
"""

import json
import re
import ast
from collections.abc import Callable
from openai import OpenAI
from .base import BaseProvider, LLMResponse


TOOL_CALL_PATTERN = re.compile(
    r"<tool_call>\s*(.*?)\s*</tool_call>", re.DOTALL
)

# Also match tool calls wrapped in markdown code blocks.
# Uses a two-step approach: first strip code fences, then the
# normal patterns handle whatever is inside.
_CODE_FENCE_RE = re.compile(r"```(?:\w+)?\s*\n?(.*?)\n?```", re.DOTALL)

# Match bare JSON tool calls like {"tool_name": {...}} without xml wrapper
BARE_TOOL_PATTERN = re.compile(
    r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL
)

# ── Fallback: malformed tool call formats ─────────────────────────

# Match <tool_call name="x"> or <tool_calls> with XML-attribute parameters.
# Many models mistakenly use XML attribute syntax or plural <tool_calls>.
TOOL_CALL_XML_PATTERN = re.compile(
    r"<tool_calls?\s+name\s*=\s*[\"'](\w+)[\"'][^>]*>(.*?)</tool_calls?>",
    re.DOTALL | re.IGNORECASE,
)

# Bare <tool_call name="x"> without closing tag (common fragment)
TOOL_CALL_OPEN_PATTERN = re.compile(
    r"<tool_call\s+name\s*=\s*[\"'](\w+)[\"']\s*/?>",
    re.IGNORECASE,
)

# Extract <parameter name="x">value</parameter> from XML-style tool calls
PARAM_XML_PATTERN = re.compile(
    r"<parameter\s+name\s*=\s*[\"'](\w+)[\"'][^>]*>(.*?)</parameter>",
    re.DOTALL | re.IGNORECASE,
)

# Direct XML-ish tool tags some text models emit:
# <tool_call><write_file file_path="..." content="..."></write_file></tool_call>
DIRECT_TOOL_TAG_PATTERN = re.compile(
    r"<tool_call>\s*<(?P<name>[A-Za-z_]\w*)\s+(?P<body>.*?)</(?P=name)>\s*</tool_call>",
    re.DOTALL | re.IGNORECASE,
)
SIMPLE_ATTR_RE = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*\"([^\"]*)\"")

# Some models emit <function=tool_name>...<parameter=name>v</parameter>...</function>
# inside <tool_call> blocks. This is a hybrid format combining XML-like tags
# with equals-sign syntax instead of proper attributes.
FUNCTION_EQ_PATTERN = re.compile(
    r"<function=(\w+)>\s*(.*?)\s*</function>",
    re.DOTALL | re.IGNORECASE,
)
PARAM_EQ_PATTERN = re.compile(
    r"<parameter=(\w+)>\s*(.*?)\s*</parameter>",
    re.DOTALL | re.IGNORECASE,
)

# Some models emit JavaScript/Python-style numeric literals inside otherwise
# valid JSON tool calls, e.g. {"offset": 0x1e00}. JSON does not allow that, but
# these literals are unambiguous for integer tool parameters.
HEX_LITERAL_RE = re.compile(
    r"(:\s*)0x([0-9a-fA-F]+)(?=\s*[,}\]])"
)
WINDOWS_PATH_STRING_RE = re.compile(
    r'"([A-Za-z]:\\[^"]*)"'
)


def _escape_windows_path_strings(raw: str) -> str:
    def repl(match: re.Match) -> str:
        value = match.group(1)
        value = re.sub(r"(?<!\\)\\(?![\\\"])", r"\\\\", value)
        return '"' + value + '"'

    return WINDOWS_PATH_STRING_RE.sub(repl, raw)


def _loads_tool_json(raw: str) -> dict | None:
    text = raw.strip()
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass

    path_normalized = _escape_windows_path_strings(text)
    normalized = HEX_LITERAL_RE.sub(
        lambda m: f"{m.group(1)}{int(m.group(2), 16)}",
        path_normalized,
    )
    if normalized == text:
        normalized = text
    try:
        parsed = json.loads(normalized)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass

    # Last-resort tolerant parse for model-emitted "JSON-like" Python literals.
    # This accepts hex integers and often handles Windows paths better than JSON
    # when the model forgot to double every backslash.
    for candidate in (text, normalized):
        try:
            parsed = ast.literal_eval(candidate)
            return parsed if isinstance(parsed, dict) else None
        except (SyntaxError, ValueError):
            continue
    return None


def _json_object_spans(text: str) -> list[str]:
    objects: list[str] = []
    start: int | None = None
    depth = 0
    in_string = False
    escape = False

    for idx, ch in enumerate(text):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            if depth == 0:
                start = idx
            depth += 1
            continue
        if ch == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                objects.append(text[start:idx + 1])
                start = None

    return objects


def _tool_call_from_parsed(parsed: dict, call_id: str) -> dict | None:
    if "name" in parsed:
        return {
            "id": call_id,
            "name": parsed["name"],
            "input": parsed.get("arguments", {}),
        }

    for key, value in parsed.items():
        if isinstance(value, dict):
            return {
                "id": call_id,
                "name": key,
                "input": value,
            }
    return None


def _parse_direct_tool_tags(text: str) -> list[dict]:
    calls = []
    for i, match in enumerate(DIRECT_TOOL_TAG_PATTERN.finditer(text)):
        name = match.group("name")
        body = match.group("body").strip()
        args: dict[str, str] = {}

        content_match = re.search(r"\bcontent\s*=\s*\"(.*)\"\s*>?\s*$", body, re.DOTALL)
        attr_source = body
        if content_match:
            args["content"] = content_match.group(1)
            attr_source = body[:content_match.start()]

        for key, value in SIMPLE_ATTR_RE.findall(attr_source):
            if key not in args:
                args[key] = value

        if args:
            calls.append({
                "id": f"text_direct_{i}",
                "name": name,
                "input": args,
            })
    return calls


def build_text_tools_prompt(tools: list[dict]) -> str:
    """Generate the tool usage instructions for the system prompt."""
    tool_descriptions = []
    for t in tools:
        name = t["name"]
        desc = t["description"]
        props = json.dumps(t["input_schema"].get("properties", {}), indent=2, ensure_ascii=False)
        required = t["input_schema"].get("required", [])
        tool_descriptions.append(
            f"### {name}\n"
            f"Description: {desc}\n"
            f"Parameters: {props}\n"
            f"Required: {required}\n"
        )

    nl = chr(10)
    return f"""
## Available Tools

You have access to local tools. To use a tool, output a tool call block in
one of these two formats (both are accepted):

**Format A (preferred):**
<tool_call>
{{"name": "<tool_name>", "arguments": {{"param1": "value1"}}}}
</tool_call>

**Format B (shorthand):**
<tool_call>
{{"<tool_name>": {{"param1": "value1"}}}}
</tool_call>

After a tool call, the user will respond with a <tool_results> block containing
the output. You may then make additional tool calls or reply naturally.

**Available tools:**

{nl.join(tool_descriptions)}

**Rules:**
- Use exact <tool_call> XML tags with JSON inside
- JSON must be valid (double quotes, no trailing commas)
- After receiving tool results, continue working or reply to the user
- Do NOT wrap tool calls in markdown code blocks (no ```)

**WRONG — do NOT use these formats:**
- `<parameter name="x">v</parameter>`  ← WRONG! Tool name goes in JSON, not as a parameter tag
- `<tool_call name="tool_name">`        ← WRONG! Name goes in JSON, not as XML attribute
- `<tool_calls>`                        ← WRONG! Must be singular <tool_call>
- `<tool_call><tool_call>...`           ← WRONG! Do not nest
"""


def parse_tool_calls(text: str) -> list[dict]:
    """Extract tool calls from model output text.

    Supports multiple formats:
    - <tool_call>{"name": "tool_name", "arguments": {...}}</tool_call>
    - <tool_call>{"tool_name": {...}}</tool_call>  (shorthand)
    - ```<tool_call>...</tool_call>```  (code block wrapped)
    - <tool_call name="tool_name"> (XML attribute, fallback)
    - <parameter name="x">value</parameter> inside (XML element, fallback)
    """
    # ── Phase 1: JSON-based formats ──
    # First unwrap any code fences so inner content is exposed to all patterns
    text_unwrapped = text
    fence_match = _CODE_FENCE_RE.search(text)
    if fence_match:
        text_unwrapped = fence_match.group(1)

    matches = TOOL_CALL_PATTERN.findall(text)
    if not matches:
        matches = TOOL_CALL_PATTERN.findall(text_unwrapped)

    tool_calls = []
    for i, match in enumerate(matches):
        parsed = _loads_tool_json(match)
        if parsed is None:
            continue

        tc = _tool_call_from_parsed(parsed, f"text_call_{i}")
        if tc:
            tool_calls.append(tc)
            continue

    if tool_calls:
        return tool_calls

    # ── Phase 2a: direct XML-ish tool tags ──
    tool_calls = _parse_direct_tool_tags(text_unwrapped)
    if tool_calls:
        return tool_calls

    # ── Phase 2: XML-attribute fallback ──
    # Handles <tool_call name="list_dir"> with <parameter name="x">v</parameter>
    xml_matches = TOOL_CALL_XML_PATTERN.findall(text)
    if not xml_matches:
        xml_matches = TOOL_CALL_XML_PATTERN.findall(text_unwrapped)
    for i, (tool_name, inner) in enumerate(xml_matches):
        params = {}
        for pname, pvalue in PARAM_XML_PATTERN.findall(inner):
            params[pname] = pvalue.strip()
        tool_calls.append({
            "id": f"text_xml_{i}",
            "name": tool_name,
            "input": params,
        })

    if tool_calls:
        return tool_calls

    # ── Phase 2b: JSON fragments inside malformed wrappers ──
    # Handles outputs like <tool_call><tool>{...}</tool> or nested/missing tags.
    if _HAS_TOOL_ATTEMPT.search(text) or _HAS_TOOL_ATTEMPT.search(text_unwrapped):
        seen = set()
        for i, fragment in enumerate(_json_object_spans(text_unwrapped)):
            parsed = _loads_tool_json(fragment)
            if parsed is None:
                continue
            tc = _tool_call_from_parsed(parsed, f"text_json_{i}")
            if not tc:
                continue
            key = (
                str(tc.get("name", "")),
                json.dumps(tc.get("input", {}), sort_keys=True, ensure_ascii=False),
            )
            if key in seen:
                continue
            seen.add(key)
            tool_calls.append(tc)
        if tool_calls:
            return tool_calls

    # ── Phase 2c: <function=NAME> / <parameter=NAME> hybrid ──
    # Handles <tool_call><function=hexdump><parameter=offset>0x10</parameter>...
    # This is a malformed format some models emit with equals-sign syntax.
    func_matches = FUNCTION_EQ_PATTERN.findall(text)
    if not func_matches:
        func_matches = FUNCTION_EQ_PATTERN.findall(text_unwrapped)
    for i, (tool_name, inner) in enumerate(func_matches):
        params = {}
        for pname, pvalue in PARAM_EQ_PATTERN.findall(inner):
            params[pname] = pvalue.strip()
        if params:
            tool_calls.append({
                "id": f"text_func_eq_{i}",
                "name": tool_name,
                "input": params,
            })
    if tool_calls:
        return tool_calls

    # ── Phase 3: Bare opening tag without content ──
    # Handles <tool_call name="x"/> or <tool_call name="x">
    open_matches = TOOL_CALL_OPEN_PATTERN.findall(text)
    if not open_matches:
        open_matches = TOOL_CALL_OPEN_PATTERN.findall(text_unwrapped)
    for i, tool_name in enumerate(open_matches):
        # Try to find <parameter> elements anywhere in the surrounding text
        params = {}
        for pname, pvalue in PARAM_XML_PATTERN.findall(text):
            params[pname] = pvalue.strip()
        tool_calls.append({
            "id": f"text_open_{i}",
            "name": tool_name,
            "input": params,
        })

    return tool_calls


# Detect if the model tried to use tool calls (even if malformed).
# Matches: <tool_call>, <tool_calls>, <parameter name="...">, or
# bare {"name": "tool_name"...} JSON fragments.
_HAS_TOOL_ATTEMPT = re.compile(
    r"<tool_calls?|<function=|<parameter\s+(?:name\s*)?=",
    re.IGNORECASE,
)

# Clean up any bare <tool_call> or <tool_calls> tags (including
# opening tags without closing, closing tags without opening, etc.)
_TOOL_TAG_CLEANUP_RE = re.compile(
    r"</?tool_calls?\s*(?:name\s*=\s*[\"'][^\"']*[\"'])?\s*/?>",
    re.IGNORECASE,
)


def strip_tool_calls(text: str) -> str:
    """Remove tool call blocks from text, returning clean content."""
    # Unwrap code fences first so inner tool calls can be stripped
    text = _CODE_FENCE_RE.sub(r"\1", text)
    text = TOOL_CALL_PATTERN.sub("", text)
    text = TOOL_CALL_XML_PATTERN.sub("", text)
    text = PARAM_XML_PATTERN.sub("", text)
    text = PARAM_EQ_PATTERN.sub("", text)
    text = FUNCTION_EQ_PATTERN.sub("", text)
    text = TOOL_CALL_OPEN_PATTERN.sub("", text)
    text = _TOOL_TAG_CLEANUP_RE.sub("", text)
    # Collapse multiple blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _log_parsed_calls(raw_text: str, tool_calls: list[dict]) -> None:
    """Diagnostic log: show raw model output and what parse_tool_calls extracted."""
    import sys
    if not tool_calls:
        return  # Only log when tool calls were actually parsed
    print("\n" + "=" * 60, file=sys.stderr)
    print("[text-tools DEBUG] Parsed tool calls:", file=sys.stderr)
    for tc in tool_calls:
        name = tc.get("name", "?")
        inp = tc.get("input", {})
        print(f"  name={name}  input_keys={list(inp.keys())}  input={inp!r}", file=sys.stderr)
    print("-" * 40, file=sys.stderr)
    print("Raw model output (last 2000 chars):", file=sys.stderr)
    print(raw_text[-2000:], file=sys.stderr)
    print("=" * 60 + "\n", file=sys.stderr)


class TextToolsProvider(BaseProvider):
    """Provider that implements tool calling via text prompts.

    Works with ANY chat model - no native tool calling support needed.
    """

    message_format = "openai"  # Uses simple {role, content} messages

    def __init__(self, config):
        self.config = config
        self.client = OpenAI(
            api_key=config.provider.api_key or "sk-placeholder",
            base_url=config.provider.api_base or None,
            timeout=config.request_timeout,
            max_retries=config.max_retries,
        )

    def chat(
        self, messages: list[dict], tools: list[dict],
        stream: bool = True, on_text: Callable[[str], None] | None = None,
    ) -> LLMResponse:
        # Inject tools prompt into the system message
        augmented = self._inject_tools_prompt(messages, tools)

        kwargs = {
            "model": self.config.provider.model,
            "max_tokens": self.config.provider.max_tokens,
            "messages": augmented,
        }

        if stream:
            return self._stream_and_parse(kwargs, on_text)
        else:
            return self._sync_and_parse(kwargs)

    def _inject_tools_prompt(self, messages: list[dict], tools: list[dict]) -> list[dict]:
        """Add tool definitions to the system prompt."""
        tools_prompt = build_text_tools_prompt(tools)
        augmented = []
        for m in messages:
            if m["role"] == "system":
                augmented.append({
                    "role": "system",
                    "content": m["content"] + "\n" + tools_prompt,
                })
            else:
                augmented.append(m)
        return augmented

    def _stream_and_parse(self, kwargs: dict, on_text: Callable[[str], None] | None) -> LLMResponse:
        text_parts = []
        kwargs["stream"] = True
        stream = self.client.chat.completions.create(**kwargs)

        for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                t = chunk.choices[0].delta.content
                text_parts.append(t)
                if on_text:
                    on_text(t)

        full_text = "".join(text_parts)
        tool_calls = parse_tool_calls(full_text)

        # Debug: log raw model output and parsed tool calls
        _log_parsed_calls(full_text, tool_calls)

        # If model tried to use tools but format was unparseable,
        # keep raw text so the agent's self-correction can detect
        # the malformed <tool_call> fragments and retry.
        if not tool_calls and _HAS_TOOL_ATTEMPT.search(full_text):
            clean_text = full_text
        else:
            clean_text = strip_tool_calls(full_text)

        return LLMResponse(
            text=clean_text,
            tool_calls=tool_calls,
            stop_reason="tool_calls" if tool_calls else "stop",
        )

    def _sync_and_parse(self, kwargs: dict) -> LLMResponse:
        resp = self.client.chat.completions.create(**kwargs)
        full_text = resp.choices[0].message.content or ""
        tool_calls = parse_tool_calls(full_text)

        # Debug: log raw model output and parsed tool calls
        _log_parsed_calls(full_text, tool_calls)

        if not tool_calls and _HAS_TOOL_ATTEMPT.search(full_text):
            clean_text = full_text
        else:
            clean_text = strip_tool_calls(full_text)

        usage = {}
        if resp.usage:
            usage = {
                "input_tokens": resp.usage.prompt_tokens or 0,
                "output_tokens": resp.usage.completion_tokens or 0,
            }

        return LLMResponse(
            text=clean_text,
            tool_calls=tool_calls,
            stop_reason="tool_calls" if tool_calls else "stop",
            usage=usage,
        )

    def format_tool_results(self, results: list[dict]) -> list[dict]:
        """Format tool results as a simple user message."""
        parts = ["<tool_results>"]
        for r in results:
            status = "ERROR" if r.get("is_error") else "OK"
            parts.append(
                f"<result tool=\"{r['tool_use_id']}\" status=\"{status}\">\n"
                f"{r['content']}\n"
                f"</result>"
            )
        parts.append("</tool_results>")
        return [{"role": "user", "content": "\n".join(parts)}]

    def format_assistant_message(self, text: str, tool_calls: list[dict]) -> dict:
        """Build assistant message with tool calls as text."""
        parts = []
        if text and text.strip():
            parts.append(text.strip())
        for tc in tool_calls:
            parts.append(
                "<tool_call>\n"
                + json.dumps({"name": tc["name"], "arguments": tc["input"]}, ensure_ascii=False)
                + "\n</tool_call>"
            )
        content = "\n".join(parts)
        if not content.strip():
            content = "(thinking...)"
        return {"role": "assistant", "content": content}
