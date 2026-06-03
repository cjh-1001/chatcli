"""Bash execution tool."""

import subprocess
import time
from .base import Tool, ToolResult


class BashTool(Tool):
    name = "bash"
    description = "Execute a bash command in the workspace directory. Returns stdout and stderr. Max timeout: 600s (10 min)."
    parameters = {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "The command to execute in bash",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in milliseconds (max 600000)",
                "default": 120000,
            },
        },
        "required": ["command"],
    }

    def execute(self, command: str, timeout: int = 120000, **kwargs) -> ToolResult:
        # Safety: reject excessively long commands (prevents prompt injection loop)
        if len(command) > 100000:
            return ToolResult(
                content=f"Error: command too long ({len(command)} chars). Max 100000.",
                is_error=True,
            )
        timeout_sec = min(timeout, 600000) / 1000  # cap at 10 min, matching description
        start = time.monotonic()

        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                cwd=kwargs.get("workspace", "."),
                encoding="utf-8",
                errors="replace",
            )
            elapsed = time.monotonic() - start

            content_parts = []
            if proc.stdout:
                content_parts.append(proc.stdout.strip())
            if proc.stderr:
                content_parts.append(f"[stderr]\n{proc.stderr.strip()}")
            if not content_parts:
                content_parts.append("(no output)")

            # Always include exit code so the model can detect failures
            if proc.returncode != 0:
                content_parts.append(f"\n[exit code: {proc.returncode}]")

            return ToolResult(
                content="\n".join(content_parts),
                is_error=proc.returncode != 0,
                metadata={
                    "exit_code": proc.returncode,
                    "elapsed_ms": int(elapsed * 1000),
                },
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                content=f"Command timed out after {int(timeout_sec)}s.",
                is_error=True,
            )
