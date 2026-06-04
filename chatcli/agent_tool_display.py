"""Tool call rendering and diff display."""

import difflib
from pathlib import Path

from .agent_tool_preview import AgentToolPreviewMixin
from .agent_tool_summary import AgentToolSummaryMixin


class AgentToolDisplayMixin(AgentToolSummaryMixin, AgentToolPreviewMixin):
    # ── Tool call display ──────────────────────────────────────────

    _TOOL_LABEL = {
        "read_file": "Read",
        "glob": "Glob",
        "grep": "Search",
        "list_dir": "List",
        "write_file": "Write",
        "edit_file": "Edit",
        "multi_edit": "Edit",
        "bash": "Run",
        "git_status": "Git status",
        "git_diff": "Git diff",
        "binary_inspect": "Inspect binary",
        "binary_find": "Find bytes",
        "binary_hexdump": "Hexdump",
        "ida_probe": "IDA probe",
        "ida_analyze": "IDA analyze",
        "ida_focus_decompile": "IDA focus",
        "ida_deobfuscate": "IDA deobf",
        "ida_mcp_ensure": "IDA MCP ensure",
        "ida_mcp_probe": "IDA MCP probe",
        "ida_mcp_list_tools": "IDA MCP tools",
        "ida_mcp_call": "IDA MCP call",
        "encoded_string_extract": "Extract strings",
        "obfuscated_data_map": "Map data",
        "reverse_technique_map": "Plan route",
        "reverse_evidence_map": "Map evidence",
        "runtime_string_hooks": "Generate hooks",
        "external_static_analyze": "External scan",
        "ghidra_probe": "Ghidra probe",
        "ghidra_analyze": "Ghidra analyze",
        "angr_triage": "angr triage",
        "yara_scan": "YARA",
        "upx_unpack": "UPX",
        "tool_health_check": "Tool check",
        "web_search": "Web search",
        "web_fetch": "Fetch",
    }

    # Tool categories → (icon, color)
    _TOOL_STYLE = {
        "read_file": (">", "cyan"),
        "glob":      (">", "cyan"),
        "grep":      (">", "cyan"),
        "list_dir":  (">", "cyan"),
        "write_file":(">", "yellow"),
        "edit_file": (">", "yellow"),
        "multi_edit":(">", "yellow"),
        "bash":      (">", "green"),
        "git_status":(">", "cyan"),
        "git_diff":  (">", "cyan"),
        "binary_inspect":(">", "cyan"),
        "binary_find":(">", "magenta"),
        "binary_hexdump":(">", "magenta"),
        "ida_probe":(">", "magenta"),
        "ida_analyze":(">", "magenta"),
        "ida_focus_decompile":(">", "magenta"),
        "ida_deobfuscate":(">", "magenta"),
        "ida_mcp_ensure":(">", "magenta"),
        "ida_mcp_probe":(">", "magenta"),
        "ida_mcp_list_tools":(">", "magenta"),
        "ida_mcp_call":(">", "magenta"),
        "encoded_string_extract":(">", "magenta"),
        "obfuscated_data_map":(">", "magenta"),
        "reverse_technique_map":(">", "magenta"),
        "reverse_evidence_map":(">", "magenta"),
        "runtime_string_hooks":(">", "magenta"),
        "external_static_analyze":(">", "magenta"),
        "ghidra_probe":(">", "magenta"),
        "ghidra_analyze":(">", "magenta"),
        "angr_triage":(">", "magenta"),
        "yara_scan":(">", "magenta"),
        "upx_unpack":(">", "yellow"),
        "tool_health_check":(">", "cyan"),
        "web_search":(">", "magenta"),
        "web_fetch": (">", "magenta"),
    }

    def _render_tool_call(self, name: str, params: dict) -> str:
        """Render a one-line tool call indicator with icon and color."""
        from rich.markup import escape as _escape
        icon, color = self._TOOL_STYLE.get(name, (">", "dim"))
        primary = {
            "bash": "command", "read_file": "file_path",
            "write_file": "file_path", "edit_file": "file_path",
            "multi_edit": "file_path",
            "glob": "pattern", "grep": "pattern", "list_dir": "path",
            "web_search": "query", "web_fetch": "url",
            "git_diff": "path",
            "binary_inspect": "file_path", "binary_find": "file_path",
            "binary_hexdump": "file_path", "ida_probe": "ida_path",
            "ida_analyze": "file_path",
            "ida_focus_decompile": "targets",
            "ida_deobfuscate": "file_path",
            "ida_mcp_ensure": "mcp_url",
            "ida_mcp_probe": "mcp_url",
            "ida_mcp_list_tools": "mcp_url",
            "ida_mcp_call": "tool_name",
            "encoded_string_extract": "file_path",
            "obfuscated_data_map": "file_path",
            "reverse_technique_map": "goal",
            "reverse_evidence_map": "json_paths",
            "runtime_string_hooks": "output_dir",
            "external_static_analyze": "file_path",
            "ghidra_probe": "ghidra_path",
            "ghidra_analyze": "file_path",
            "angr_triage": "file_path",
            "yara_scan": "target_path",
            "upx_unpack": "file_path",
            "tool_health_check": "tools",
        }
        key = primary.get(name)
        if key and key in params:
            val = _escape(str(params[key]))
            if len(val) > 80:
                val = val[:77] + "..."
            return f"  [{color}]{icon}[/] [bold]{self._tool_label(name)}[/] [dim]{val}[/]"
        return f"  [{color}]{icon}[/] [bold]{self._tool_label(name)}[/]"

    def _tool_label(self, name: str) -> str:
        return self._TOOL_LABEL.get(name, name)

    def _should_show_success_result(self, name: str, summary: str) -> bool:
        if name in ("write_file", "edit_file", "multi_edit"):
            return False
        if name in (
            "read_file",
            "glob",
            "grep",
            "list_dir",
            "git_status",
            "git_diff",
            "binary_find",
            "binary_hexdump",
            "ida_probe",
        ):
            return bool(summary and len([p for p in summary.split(" | ") if p.strip()]) > 1)
        return True

    def _prepare_file_diff(self, name: str, params: dict):
        """Return (path, old, new) for edit/write calls, or None."""
        if not getattr(self.config, "show_diffs", True):
            return None
        if name not in ("write_file", "edit_file", "multi_edit"):
            return None
        file_path = params.get("file_path")
        if not file_path:
            return None
        path = Path(file_path)
        try:
            old = path.read_text(encoding="utf-8") if path.exists() else ""
        except Exception:
            return None
        if name == "write_file":
            new = str(params.get("content", ""))
        elif name == "edit_file":
            old_string = params.get("old_string", "")
            new_string = params.get("new_string", "")
            if not old_string or old.count(old_string) != 1:
                return None
            new = old.replace(old_string, new_string, 1)
        else:
            new = old
            edits = params.get("edits", [])
            if not isinstance(edits, list) or not edits:
                return None
            for edit in edits:
                old_string = edit.get("old_string", "")
                new_string = edit.get("new_string", "")
                if not old_string or new.count(old_string) != 1:
                    return None
                new = new.replace(old_string, new_string, 1)
        if old == new:
            return None
        return path, old, new

    def _render_file_diff(self, diff_info) -> None:
        """Render a compact numbered diff with full-line add/delete colors."""
        if not diff_info:
            return
        path, old, new = diff_info
        try:
            rel = Path(path).resolve().relative_to(Path(self.workspace).resolve())
        except Exception:
            rel = Path(path)
        limit = max(20, int(getattr(self.config, "max_diff_lines", 200)))
        from rich.markup import escape

        old_lines = old.splitlines()
        new_lines = new.splitlines()
        matcher = difflib.SequenceMatcher(None, old_lines, new_lines)
        groups = list(matcher.get_grouped_opcodes(3))
        if not groups:
            return

        additions = 0
        deletions = 0
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag in ("delete", "replace"):
                deletions += i2 - i1
            if tag in ("insert", "replace"):
                additions += j2 - j1

        rendered = 0
        truncated = False
        summary = []
        if additions:
            summary.append(f"[green]+{additions}[/]")
        if deletions:
            summary.append(f"[red]-{deletions}[/]")
        suffix = " " + " ".join(summary) if summary else ""
        self._safe_print(f"  [bold]Changes[/] [dim]{rel}[/]{suffix}")

        def print_line(style: str, sign: str, old_no: int | None, new_no: int | None, text: str) -> None:
            old_s = f"{old_no:>4}" if old_no is not None else "    "
            new_s = f"{new_no:>4}" if new_no is not None else "    "
            body = escape(text)
            if style == "add":
                self._safe_print(f"  [green]+[/] [dim]{old_s} {new_s} |[/] [green]{body}[/]")
            elif style == "delete":
                self._safe_print(f"  [red]-[/] [dim]{old_s} {new_s} |[/] [red]{body}[/]")
            else:
                self._safe_print(f"  [dim]  {old_s} {new_s} | {body}[/]")

        for group in groups:
            if rendered >= limit:
                truncated = True
                break
            first = group[0]
            last = group[-1]
            old_start = first[1] + 1
            old_len = max(0, last[2] - first[1])
            new_start = first[3] + 1
            new_len = max(0, last[4] - first[3])
            self._safe_print(
                f"  [dim]@@ -{old_start},{old_len} +{new_start},{new_len} @@[/]"
            )
            rendered += 1
            for tag, i1, i2, j1, j2 in group:
                if tag == "equal":
                    for offset, line in enumerate(old_lines[i1:i2]):
                        if rendered >= limit:
                            truncated = True
                            break
                        print_line("context", " ", i1 + offset + 1, j1 + offset + 1, line)
                        rendered += 1
                elif tag == "delete":
                    for offset, line in enumerate(old_lines[i1:i2]):
                        if rendered >= limit:
                            truncated = True
                            break
                        print_line("delete", "-", i1 + offset + 1, j1 + 1, line)
                        rendered += 1
                elif tag == "insert":
                    for offset, line in enumerate(new_lines[j1:j2]):
                        if rendered >= limit:
                            truncated = True
                            break
                        print_line("add", "+", i1 + 1, j1 + offset + 1, line)
                        rendered += 1
                elif tag == "replace":
                    for offset, line in enumerate(old_lines[i1:i2]):
                        if rendered >= limit:
                            truncated = True
                            break
                        print_line("delete", "-", i1 + offset + 1, j1 + 1, line)
                        rendered += 1
                    for offset, line in enumerate(new_lines[j1:j2]):
                        if rendered >= limit:
                            truncated = True
                            break
                        print_line("add", "+", i1 + 1, j1 + offset + 1, line)
                        rendered += 1
                if truncated:
                    break
            if truncated:
                break
        if truncated:
            self._safe_print("  [dim]... diff truncated[/]")

    def _render_tool_result(self, name: str, result, elapsed: float) -> None:
        """Render status and preview for a tool result."""
        status = "err" if result.is_error else "ok"
        style = "red" if result.is_error else "green"
        summary = self._tool_result_summary(name, result, elapsed)
        if not result.is_error and not self._should_show_success_result(name, summary):
            self._render_tool_output_preview(name, result)
            return
        if summary:
            self._safe_print(f"    [{style}]{status}[/] [dim]{summary}[/]")
        else:
            self._safe_print(f"    [{style}]{status}[/]")
        self._render_tool_output_preview(name, result)
