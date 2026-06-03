"""Permission manager for tool execution."""

import re
import fnmatch
from pathlib import Path
from enum import Enum
from dataclasses import dataclass

from .config import PermissionConfig


class PermissionLevel(Enum):
    AUTO = "auto"
    ASK = "ask"
    DENY = "deny"


DANGEROUS_PATTERNS = [
    r"rm\s+-rf\s+/",
    r"rm\s+-rf\s+~",
    r"sudo\s+rm",
    r"mkfs\.",
    r"dd\s+if=",
    r">\s*/dev/sd",
    r"chmod\s+777\s+/",
    r"curl.*\|\s*(ba)?sh",
    r"wget.*\|\s*(ba)?sh",
    r"git\s+push\s+--force.*main",
    r"git\s+push\s+--force.*master",
    r"git\s+reset\s+--hard",
    r"eval\s+",
    r"\$\(.*\)",
    r"`[^`]+`",
]


@dataclass
class PermissionResult:
    allowed: bool
    level: PermissionLevel
    reason: str = ""


class PermissionManager:
    def __init__(self, config: PermissionConfig):
        self.config = config

    @staticmethod
    def _normalize_path(value: str) -> tuple[str, str]:
        path = str(value or "").replace("\\", "/").lower()
        name = Path(path).name.lower()
        return path, name

    def _matches_sensitive_path(self, value: str) -> str | None:
        if not value:
            return None
        path, name = self._normalize_path(value)
        for raw_pattern in self.config.sensitive:
            pattern = str(raw_pattern).replace("\\", "/").lower()
            if (
                fnmatch.fnmatch(path, pattern)
                or fnmatch.fnmatch(name, pattern)
                or ("/" not in pattern and fnmatch.fnmatch(path, f"*/{pattern}"))
            ):
                return raw_pattern
        return None

    def _sensitive_match(self, tool_name: str, tool_input: dict | None) -> str | None:
        if not self.config.protect_sensitive_files or not tool_input:
            return None
        if tool_name not in {"read_file", "write_file", "edit_file", "multi_edit", "grep"}:
            return None
        for key in ("file_path", "path"):
            match = self._matches_sensitive_path(str(tool_input.get(key, "")))
            if match:
                return match
        return None

    def _mode_override(self, tool_name: str) -> PermissionResult | None:
        mode = (self.config.mode or "default").strip().lower().replace("-", "_")
        if mode in ("", "default"):
            return None
        if mode == "auto":
            return PermissionResult(True, PermissionLevel.AUTO, "permission mode is auto")
        if mode in ("dont_ask", "deny_ask", "non_interactive"):
            if tool_name in self.config.ask:
                return PermissionResult(False, PermissionLevel.DENY, "permission mode denies ask-level tools")
            return None
        if mode in ("accept_edits", "accept_edits_only"):
            if tool_name in {"write_file", "edit_file", "multi_edit"}:
                return PermissionResult(True, PermissionLevel.AUTO, "permission mode accepts file edits")
            return None
        if mode == "ask":
            if tool_name not in self.config.deny:
                return PermissionResult(False, PermissionLevel.ASK, "permission mode asks for all tools")
        return None

    def check(self, tool_name: str, tool_input: dict | None = None) -> PermissionResult:
        """Check if a tool call is allowed."""
        if tool_name in self.config.deny:
            return PermissionResult(False, PermissionLevel.DENY, f"'{tool_name}' is denied in config")

        sensitive = self._sensitive_match(tool_name, tool_input)
        if sensitive:
            return PermissionResult(
                False,
                PermissionLevel.DENY,
                f"Sensitive file protection matched pattern: {sensitive}",
            )

        if tool_name == "bash" and tool_input:
            command = tool_input.get("command", "")
            for pattern in DANGEROUS_PATTERNS:
                if re.search(pattern, command):
                    return PermissionResult(
                        False, PermissionLevel.DENY,
                        f"Command matches dangerous pattern: {pattern}"
                    )

        # Check path-based rules (Claude Code style)
        for rule in self.config.path_rules:
            rule_tool = rule.get("tool", "")
            rule_path = rule.get("path", "")
            rule_permission = rule.get("permission", "ask")
            if rule_tool == tool_name and rule_path and tool_input:
                file_path = tool_input.get("file_path", "")
                if file_path and fnmatch.fnmatch(file_path, rule_path):
                    if rule_permission == "auto":
                        return PermissionResult(True, PermissionLevel.AUTO,
                            f"'{tool_name}' on '{file_path}' matches path rule '{rule_path}'")
                    elif rule_permission == "deny":
                        return PermissionResult(False, PermissionLevel.DENY,
                            f"'{tool_name}' on '{file_path}' matches deny rule '{rule_path}'")

        mode_result = self._mode_override(tool_name)
        if mode_result:
            return mode_result

        if tool_name in self.config.auto:
            return PermissionResult(True, PermissionLevel.AUTO, "")

        if tool_name in self.config.ask:
            return PermissionResult(False, PermissionLevel.ASK, f"'{tool_name}' requires confirmation")

        return PermissionResult(False, PermissionLevel.ASK, f"'{tool_name}' requires confirmation (default)")

    def ask_user(self, tool_name: str, tool_input: dict, reason: str) -> bool:
        """Prompt the user for tool execution permission. Returns True if approved."""
        import sys
        from rich.console import Console
        from rich.panel import Panel
        import json
        from .interactive import confirm

        console = Console()

        payload = json.dumps(tool_input, indent=2, ensure_ascii=False)
        if len(payload) > 500:
            payload = payload[:500] + "\n... (truncated)"

        console.print(Panel(
            f"[bold yellow]> {tool_name}[/]\n"
            f"[dim]{payload}[/]",
            title="[bold]Confirm[/]",
            border_style="yellow", padding=(0, 1),
        ))

        if not sys.stdin.isatty() or not sys.stdout.isatty():
            console.print(
                "[yellow]Tool confirmation requires an interactive terminal; "
                "denied by default.[/]"
            )
            return False

        try:
            return confirm(f"Execute {tool_name}?", default=False)
        except Exception as e:
            console.print(
                f"[yellow]Tool confirmation unavailable; denied by default.[/] "
                f"[dim]{type(e).__name__}: {e}[/]"
            )
            return False
