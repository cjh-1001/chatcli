"""Tool execution, context truncation, and worklog support for Agent."""

import time
from pathlib import Path

from .agent_tool_display import AgentToolDisplayMixin, _PRIMARY_PARAM


class AgentToolMixin(AgentToolDisplayMixin):
    def _execute_tool(self, name: str, params: dict) -> str:
        """Execute a tool with permission check."""
        perm = self.permissions.check(name, params)

        if not perm.allowed and perm.level.value == "deny":
            self._safe_print(f"  [red]x Blocked: {perm.reason}[/]")
            return f"Error: {perm.reason}"

        if not perm.allowed and perm.level.value == "ask":
            if self.auto_approve:
                if self.debug:
                    self._safe_print(f"  [dim]auto-approved {self._tool_label(name)}[/]")
            else:
                approved = self.permissions.ask_user(name, params, perm.reason)
                if not approved:
                    return "Error: User denied tool execution."

        # Auto-backup before self-modification
        if name in ("write_file", "edit_file", "multi_edit"):
            from .checkpoint import backup_file, _is_own_source
            target = params.get("file_path", "")
            if target and _is_own_source(target):
                backup_file(target)
                self._safe_print(f"  [dim]● auto-backup: {Path(target).name}[/]")

        # Inject config defaults for certain tools
        if name == "web_search" and "backend" not in params:
            params["backend"] = self.config.search_backend
        if name in ("ida_analyze", "ida_focus_decompile", "ida_deobfuscate"):
            params["_progress_callback"] = lambda message: self._safe_print(
                f"    [dim]{message}[/]"
            )
        params.setdefault("workspace", self.workspace)
        if name == "chatcli_auto_request":
            params.setdefault("_chatcli_task_id", getattr(self, "_chatcli_task_id", ""))
            params.setdefault("_chatcli_agent_role", getattr(self, "_chatcli_agent_role", "main"))
            params.setdefault("_chatcli_child_name", getattr(self, "_chatcli_child_name", ""))

        # Render the tool call
        self._close_stream_line()
        self._safe_print(self._render_tool_call(name, params))

        diff_info = self._prepare_file_diff(name, params)
        tool_start = time.monotonic()
        result = self.tools.execute(name, params)
        elapsed = time.monotonic() - tool_start
        self._tool_calls_total += 1

        self._render_tool_result(name, result, elapsed)
        if not result.is_error:
            self._render_file_diff(diff_info)

        # Auto-log to work session if active
        self._log_work_action(name, params, result)

        # Truncate tool output before it enters history — prevents context
        # explosion from large file reads, binary_inspect dumps, etc.
        return self._truncate_tool_output(name, result.content)

    def _truncate_tool_output(self, name: str, content: str) -> str:
        """Limit tool output size before it enters conversation history.

        Large tool outputs (file reads, binary dumps, grep on big repos)
        are the #1 cause of context blowup. This keeps the history lean
        while preserving the most useful parts for the model.
        """
        limit = getattr(self.config, "max_tool_output_chars", 40000)
        if not content or len(content) <= limit:
            return content

        # For read_file: keep the first N chars (top of file is most useful)
        # plus a heads-up that the output was truncated
        if name == "read_file":
            truncated = content[:limit]
            return (
                f"{truncated}\n\n"
                f"[TRUNCATED: file output was {len(content)} chars, "
                f"showing first {limit}. Use read_file with offset/limit "
                f"to read other parts if needed.]"
            )

        # For grep with many results: keep first N chars
        if name == "grep":
            truncated = content[:limit]
            return (
                f"{truncated}\n\n"
                f"[TRUNCATED: grep output was {len(content)} chars, "
                f"showing first {limit}. Narrow your search pattern "
                f"or limit to specific directories.]"
            )

        # For binary/reverse-analysis tools: keep header + first part.
        if name in (
            "binary_inspect",
            "ida_analyze",
            "ida_focus_decompile",
            "ida_deobfuscate",
            "ida_mcp_ensure",
            "ida_mcp_probe",
            "ida_mcp_list_tools",
            "ida_mcp_call",
            "ghidra_analyze",
            "angr_triage",
            "encoded_string_extract",
            "obfuscated_data_map",
            "reverse_evidence_map",
        ):
            truncated = content[:limit]
            return (
                f"{truncated}\n\n"
                f"[TRUNCATED: output was {len(content)} chars, "
                f"showing first {limit}. Use targeted queries for "
                f"specific sections/imports/strings.]"
            )

        # Generic: keep first limit chars
        truncated = content[:limit]
        return (
            f"{truncated}\n\n"
            f"[TRUNCATED: output was {len(content)} chars → {limit}]"
        )

    def _log_work_action(self, name: str, params: dict, result) -> None:
        """Log tool execution to the active work session, if any."""
        from .worklog import _read_text_compat, _task_file, log_action
        tf = _task_file(self.workspace)
        if not tf.exists():
            return
        # Only log if task is in progress
        content = _read_text_compat(tf)
        if "**Status:** in_progress" not in content:
            return

        key = _PRIMARY_PARAM.get(name)
        detail = str(params.get(key, "")) if key else ""
        if len(detail) > 60:
            detail = detail[:57] + "..."

        icon = "+" if not result.is_error else "x"
        log_action(self.workspace, f"{icon} {name} {detail}")

