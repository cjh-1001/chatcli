"""Minimal HTTP MCP client for IDA MCP servers."""

import json
import hashlib
import re
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx

from .base import Tool, ToolResult, coerce_int


DEFAULT_IDA_MCP_URL = "http://127.0.0.1:13337/mcp"
DEFAULT_TIMEOUT_MS = 30000
_SESSION_IDS: dict[str, str] = {}


def _coerce_url(value: str | None, default_url: str = "") -> str:
    text = (value or default_url or DEFAULT_IDA_MCP_URL).strip()
    if not text:
        text = DEFAULT_IDA_MCP_URL
    if text.startswith("http://") or text.startswith("https://"):
        return text
    if ":" in text and "/" not in text:
        host, port = text.rsplit(":", 1)
        return f"http://{host}:{port}/mcp"
    if text.isdigit():
        return f"http://127.0.0.1:{text}/mcp"
    return text


def _format_mcp_content(result: dict[str, Any]) -> str:
    content = result.get("content")
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if not isinstance(item, dict):
                parts.append(str(item))
                continue
            if item.get("type") == "text":
                parts.append(str(item.get("text", "")))
            elif "text" in item:
                parts.append(str(item.get("text", "")))
            else:
                parts.append(json.dumps(item, ensure_ascii=False))
        return "\n".join(part for part in parts if part)
    if content is not None:
        return str(content)
    structured = result.get("structuredContent")
    if structured is not None:
        return json.dumps(structured, ensure_ascii=False, indent=2)
    return json.dumps(result, ensure_ascii=False, indent=2)


def _parse_sse_response(text: str, request_id: int) -> dict[str, Any]:
    events: list[str] = []
    current: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if not line:
            if current:
                events.append("\n".join(current))
                current = []
            continue
        if line.startswith("data:"):
            current.append(line[5:].lstrip())
    if current:
        events.append("\n".join(current))

    for event in events:
        try:
            payload = json.loads(event)
        except Exception:
            continue
        if payload.get("id") == request_id:
            return payload
    if events:
        try:
            payload = json.loads(events[-1])
            if isinstance(payload, dict):
                return payload
        except Exception:
            pass
    raise ValueError("MCP server returned SSE without a JSON-RPC response")


class _McpHttpClient:
    def __init__(self, url: str, timeout_ms: int):
        self.url = url
        self.timeout = max(1.0, min(timeout_ms, 300000) / 1000)
        self.request_id = 0
        self.session_id = _SESSION_IDS.get(url, "")

    def _next_id(self) -> int:
        self.request_id += 1
        return self.request_id

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        return headers

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        request_id = self._next_id()
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params is not None:
            payload["params"] = params
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(self.url, headers=self._headers(), json=payload)
        response.raise_for_status()
        header_session = response.headers.get("Mcp-Session-Id") or response.headers.get("mcp-session-id")
        if header_session:
            self.session_id = header_session
            _SESSION_IDS[self.url] = header_session

        if not response.text.strip():
            return {}
        content_type = response.headers.get("content-type", "").lower()
        if "text/event-stream" in content_type:
            data = _parse_sse_response(response.text, request_id)
        else:
            data = response.json()
        if data.get("error"):
            error = data["error"]
            message = error.get("message") if isinstance(error, dict) else str(error)
            raise RuntimeError(message or "MCP JSON-RPC error")
        return data.get("result") if isinstance(data.get("result"), dict) else data

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(self.url, headers=self._headers(), json=payload)
            header_session = response.headers.get("Mcp-Session-Id") or response.headers.get("mcp-session-id")
            if header_session:
                self.session_id = header_session
                _SESSION_IDS[self.url] = header_session
        except Exception:
            pass

    def initialize(self) -> dict[str, Any]:
        result = self.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "chatcli", "version": "0.1.0"},
            },
        )
        self.notify("notifications/initialized")
        return result

    def ensure_initialized(self) -> dict[str, Any]:
        if self.session_id:
            return {}
        return self.initialize()


def _tool_items(result: dict[str, Any]) -> list[dict[str, Any]]:
    tools = result.get("tools", [])
    return tools if isinstance(tools, list) else []


def discover_ida_mcp_tools(mcp_url: str | None = None, default_url: str = "", timeout_ms: int = DEFAULT_TIMEOUT_MS) -> tuple[str, list[dict[str, Any]], str]:
    """Return (url, tools, session_id) for a running IDA MCP endpoint."""
    url = _coerce_url(mcp_url, default_url)
    client = _McpHttpClient(url, coerce_int(timeout_ms, DEFAULT_TIMEOUT_MS, 1000, 300000))
    client.ensure_initialized()
    listed = client.request("tools/list")
    return url, _tool_items(listed), client.session_id


def _sanitize_dynamic_name(original: str, used: set[str]) -> str:
    stem = re.sub(r"[^A-Za-z0-9_]+", "_", original).strip("_").lower()
    stem = stem or "tool"
    base = "ida_mcp_" + stem
    if len(base) > 64:
        digest = hashlib.sha1(original.encode("utf-8", errors="replace")).hexdigest()[:8]
        base = base[:55] + "_" + digest
    name = base
    if name in used:
        digest = hashlib.sha1(original.encode("utf-8", errors="replace")).hexdigest()[:8]
        name = (base[:55] + "_" + digest)[:64]
    index = 2
    while name in used:
        suffix = f"_{index}"
        name = base[:64 - len(suffix)] + suffix
        index += 1
    used.add(name)
    return name


def _tool_input_schema(tool: dict[str, Any]) -> dict[str, Any]:
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    if not isinstance(schema, dict):
        return {"type": "object", "properties": {}}
    try:
        schema = json.loads(json.dumps(schema))
    except Exception:
        schema = dict(schema)
    if schema.get("type") != "object":
        schema = {"type": "object", "properties": {}}
    schema.setdefault("properties", {})
    return schema


class IdaMcpDynamicTool(Tool):
    """Chatcli wrapper around one concrete MCP tool exposed by IDA."""

    def __init__(self, name: str, original_name: str, description: str, parameters: dict[str, Any], mcp_url: str):
        self.name = name
        self.original_name = original_name
        self.description = description
        self.parameters = parameters
        self.mcp_url = mcp_url

    def execute(self, **kwargs) -> ToolResult:
        arguments = {
            key: value
            for key, value in kwargs.items()
            if key not in {"workspace", "mcp_url"} and not key.startswith("_")
        }
        result = IdaMcpCallTool(self.mcp_url).execute(
            tool_name=self.original_name,
            arguments=arguments,
            mcp_url=self.mcp_url,
        )
        result.metadata.setdefault("dynamic_tool", self.name)
        result.metadata.setdefault("mcp_tool_name", self.original_name)
        return result


def make_ida_mcp_dynamic_tools(
    mcp_url: str,
    mcp_tools: list[dict[str, Any]],
    existing_names: set[str] | None = None,
    limit: int = 80,
) -> list[IdaMcpDynamicTool]:
    used = set(existing_names or set())
    out: list[IdaMcpDynamicTool] = []
    for tool in mcp_tools[: max(0, limit)]:
        original_name = str(tool.get("name") or "").strip()
        if not original_name:
            continue
        dynamic_name = _sanitize_dynamic_name(original_name, used)
        description = str(tool.get("description") or f"IDA MCP tool: {original_name}")
        description = f"IDA MCP tool `{original_name}` via {mcp_url}. {description}"
        out.append(IdaMcpDynamicTool(
            dynamic_name,
            original_name,
            description[:900],
            _tool_input_schema(tool),
            mcp_url,
        ))
    return out


def _format_tool_list(tools: list[dict[str, Any]], url: str, limit: int) -> str:
    lines = [
        "# IDA MCP Tools",
        "",
        f"URL: {url}",
        f"Tools: {len(tools)}",
    ]
    shown = tools[:limit]
    for tool in shown:
        name = str(tool.get("name", ""))
        description = str(tool.get("description", "")).replace("\r", " ").replace("\n", " ")
        if len(description) > 220:
            description = description[:217] + "..."
        lines.append(f"- {name}: {description}" if description else f"- {name}")
    if len(tools) > len(shown):
        lines.append(f"- ... {len(tools) - len(shown)} more")
    return "\n".join(lines)


class IdaMcpProbeTool(Tool):
    name = "ida_mcp_probe"
    description = (
        "Probe a running IDA MCP HTTP endpoint. Initializes the MCP session and lists "
        "available IDA MCP tools. Does not start IDA or execute the target binary."
    )
    parameters = {
        "type": "object",
        "properties": {
            "mcp_url": {
                "type": "string",
                "description": "IDA MCP HTTP endpoint. Default: http://127.0.0.1:13337/mcp.",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in milliseconds. Default 30000.",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum tools to show. Default 80.",
            },
        },
    }

    def __init__(self, default_mcp_url: str = ""):
        self.default_mcp_url = default_mcp_url

    def execute(self, mcp_url: str | None = None, timeout: int = DEFAULT_TIMEOUT_MS, limit: int = 80, **kwargs) -> ToolResult:
        url = _coerce_url(mcp_url, self.default_mcp_url)
        client = _McpHttpClient(url, coerce_int(timeout, DEFAULT_TIMEOUT_MS, 1000, 300000))
        try:
            init = client.initialize()
            listed = client.request("tools/list")
        except Exception as e:
            return ToolResult(
                content=(
                    f"IDA MCP endpoint unavailable: {url}\n"
                    f"Error: {type(e).__name__}: {e}\n\n"
                    "Start an IDA MCP server first, then retry. Common endpoints are "
                    "http://127.0.0.1:13337/mcp for ida-pro-mcp GUI plugin and "
                    "http://127.0.0.1:8745/mcp for idalib-mcp."
                ),
                is_error=True,
                metadata={"url": url, "found": False},
            )
        tools = _tool_items(listed)
        server_info = init.get("serverInfo") if isinstance(init, dict) else {}
        content = _format_tool_list(tools, url, coerce_int(limit, 80, 1, 500))
        if isinstance(server_info, dict) and server_info:
            content += "\n\nServer: " + json.dumps(server_info, ensure_ascii=False)
        return ToolResult(
            content=content,
            metadata={
                "url": url,
                "found": True,
                "session_id": client.session_id,
                "tools": len(tools),
                "server": server_info,
            },
        )


class IdaMcpListToolsTool(Tool):
    name = "ida_mcp_list_tools"
    description = "List tools exposed by a running IDA MCP HTTP endpoint."
    parameters = {
        "type": "object",
        "properties": {
            "mcp_url": {"type": "string", "description": "IDA MCP HTTP endpoint."},
            "timeout": {"type": "integer", "description": "Timeout in milliseconds. Default 30000."},
            "limit": {"type": "integer", "description": "Maximum tools to show. Default 120."},
        },
    }

    def __init__(self, default_mcp_url: str = ""):
        self.default_mcp_url = default_mcp_url

    def execute(self, mcp_url: str | None = None, timeout: int = DEFAULT_TIMEOUT_MS, limit: int = 120, **kwargs) -> ToolResult:
        url = _coerce_url(mcp_url, self.default_mcp_url)
        client = _McpHttpClient(url, coerce_int(timeout, DEFAULT_TIMEOUT_MS, 1000, 300000))
        try:
            client.ensure_initialized()
            listed = client.request("tools/list")
        except Exception as e:
            return ToolResult(
                content=f"IDA MCP tools/list failed at {url}: {type(e).__name__}: {e}",
                is_error=True,
                metadata={"url": url},
            )
        tools = _tool_items(listed)
        return ToolResult(
            content=_format_tool_list(tools, url, coerce_int(limit, 120, 1, 500)),
            metadata={"url": url, "session_id": client.session_id, "tools": len(tools)},
        )


class IdaMcpCallTool(Tool):
    name = "ida_mcp_call"
    description = (
        "Call a named tool on a running IDA MCP HTTP endpoint. Use ida_mcp_list_tools "
        "first to discover supported tool names and arguments. Does not execute the "
        "target binary, but the remote IDA MCP tool may mutate the IDB depending on "
        "the selected tool."
    )
    parameters = {
        "type": "object",
        "properties": {
            "tool_name": {
                "type": "string",
                "description": "MCP tool name to call, for example decompile_function or idalib_open.",
            },
            "arguments": {
                "type": "object",
                "description": "Arguments object passed to the MCP tool.",
            },
            "mcp_url": {"type": "string", "description": "IDA MCP HTTP endpoint."},
            "timeout": {"type": "integer", "description": "Timeout in milliseconds. Default 60000."},
        },
        "required": ["tool_name"],
    }

    def __init__(self, default_mcp_url: str = ""):
        self.default_mcp_url = default_mcp_url

    def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        mcp_url: str | None = None,
        timeout: int = 60000,
        **kwargs,
    ) -> ToolResult:
        if not str(tool_name or "").strip():
            return ToolResult(content="Error: tool_name is required.", is_error=True)
        url = _coerce_url(mcp_url, self.default_mcp_url)
        client = _McpHttpClient(url, coerce_int(timeout, 60000, 1000, 300000))
        args = arguments if isinstance(arguments, dict) else {}
        try:
            client.ensure_initialized()
            result = client.request("tools/call", {"name": str(tool_name), "arguments": args})
        except Exception as e:
            return ToolResult(
                content=f"IDA MCP tools/call failed at {url}: {type(e).__name__}: {e}",
                is_error=True,
                metadata={"url": url, "tool_name": tool_name},
            )
        is_error = bool(result.get("isError")) if isinstance(result, dict) else False
        output = _format_mcp_content(result if isinstance(result, dict) else {"result": result})
        content = "\n".join([
            "# IDA MCP Call",
            "",
            f"URL: {url}",
            f"Tool: {tool_name}",
            "",
            output or "(no output)",
        ])
        return ToolResult(
            content=content,
            is_error=is_error,
            metadata={
                "url": url,
                "session_id": client.session_id,
                "tool_name": tool_name,
                "is_mcp_error": is_error,
                "chars": len(output or ""),
            },
        )


class IdaMcpEnsureTool(Tool):
    name = "ida_mcp_ensure"
    description = (
        "Ensure an IDA MCP HTTP endpoint is running. First probes the endpoint; if "
        "unavailable and a start_command is configured or supplied, starts it as a "
        "background process and polls until tools/list succeeds. Use this before "
        "ida_mcp_call when the user wants autonomous IDA MCP startup."
    )
    parameters = {
        "type": "object",
        "properties": {
            "mcp_url": {"type": "string", "description": "IDA MCP HTTP endpoint."},
            "start_command": {
                "type": "string",
                "description": "Command to start the IDA MCP server, for example: py -m idalib_mcp.server --port 8745.",
            },
            "startup_timeout": {
                "type": "integer",
                "description": "Milliseconds to wait for the endpoint to become ready. Default 30000.",
            },
            "probe_timeout": {
                "type": "integer",
                "description": "Per-probe timeout in milliseconds. Default 3000.",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum tools to show when ready. Default 80.",
            },
        },
    }

    def __init__(self, default_mcp_url: str = "", default_start_command: str = ""):
        self.default_mcp_url = default_mcp_url
        self.default_start_command = default_start_command

    def _probe(self, url: str, timeout_ms: int) -> tuple[bool, list[dict[str, Any]], str, str]:
        client = _McpHttpClient(url, timeout_ms)
        try:
            client.ensure_initialized()
            listed = client.request("tools/list")
            return True, _tool_items(listed), client.session_id, ""
        except Exception as e:
            return False, [], "", f"{type(e).__name__}: {e}"

    def execute(
        self,
        mcp_url: str | None = None,
        start_command: str | None = None,
        startup_timeout: int = 30000,
        probe_timeout: int = 3000,
        limit: int = 80,
        **kwargs,
    ) -> ToolResult:
        url = _coerce_url(mcp_url, self.default_mcp_url)
        probe_ms = coerce_int(probe_timeout, 3000, 500, 30000)
        ready, tools, session_id, first_error = self._probe(url, probe_ms)
        if ready:
            return ToolResult(
                content=_format_tool_list(tools, url, coerce_int(limit, 80, 1, 500)) + "\n\n[ready] IDA MCP is already running.",
                metadata={
                    "url": url,
                    "ready": True,
                    "started": False,
                    "session_id": session_id,
                    "tools": len(tools),
                },
            )

        command = (start_command or self.default_start_command or "").strip()
        if not command:
            return ToolResult(
                content=(
                    f"IDA MCP is not reachable at {url}.\n"
                    f"Probe error: {first_error}\n\n"
                    "No start command is configured. Set ida_mcp_start_command in "
                    "config.yaml or pass start_command to ida_mcp_ensure. GUI IDA MCP "
                    "plugins usually require opening IDA and loading the plugin; "
                    "headless idalib-mcp can usually be started by a command."
                ),
                is_error=True,
                metadata={"url": url, "ready": False, "started": False},
            )

        workspace = Path(str(kwargs.get("workspace") or "."))
        log_dir = workspace / ".chatcli" / "tmp"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "ida_mcp_start.log"
        try:
            log_file = open(log_path, "a", encoding="utf-8", errors="replace")
            log_file.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] {command}\n")
            creationflags = 0
            if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
                creationflags |= subprocess.CREATE_NEW_PROCESS_GROUP
            if hasattr(subprocess, "DETACHED_PROCESS"):
                creationflags |= subprocess.DETACHED_PROCESS
            popen_kwargs = {
                "cwd": str(workspace),
                "shell": True,
                "stdout": log_file,
                "stderr": subprocess.STDOUT,
                "stdin": subprocess.DEVNULL,
            }
            if creationflags:
                popen_kwargs["creationflags"] = creationflags
            proc = subprocess.Popen(command, **popen_kwargs)
        except Exception as e:
            return ToolResult(
                content=f"Failed to start IDA MCP command: {type(e).__name__}: {e}",
                is_error=True,
                metadata={"url": url, "ready": False, "started": False, "command": command},
            )

        deadline = time.monotonic() + (coerce_int(startup_timeout, 30000, 1000, 300000) / 1000)
        last_error = first_error
        while time.monotonic() < deadline:
            time.sleep(1.0)
            if proc.poll() is not None:
                last_error = f"start command exited with code {proc.returncode}"
                break
            ready, tools, session_id, last_error = self._probe(url, probe_ms)
            if ready:
                try:
                    log_file.close()
                except Exception:
                    pass
                return ToolResult(
                    content=(
                        _format_tool_list(tools, url, coerce_int(limit, 80, 1, 500))
                        + f"\n\n[started] IDA MCP became ready. pid={proc.pid} log={log_path}"
                    ),
                    metadata={
                        "url": url,
                        "ready": True,
                        "started": True,
                        "pid": proc.pid,
                        "log": str(log_path),
                        "session_id": session_id,
                        "tools": len(tools),
                    },
                )

        try:
            log_file.close()
        except Exception:
            pass
        return ToolResult(
            content=(
                f"Started IDA MCP command but endpoint did not become ready: {url}\n"
                f"pid: {proc.pid}\n"
                f"log: {log_path}\n"
                f"last probe error: {last_error}"
            ),
            is_error=True,
            metadata={
                "url": url,
                "ready": False,
                "started": True,
                "pid": proc.pid,
                "log": str(log_path),
            },
        )
