"""Remote command execution via SSH."""

from __future__ import annotations

from .base import Tool, ToolResult


STDOUT_CONTENT_LIMIT = 60000
STDERR_CONTENT_LIMIT = 12000


def _truncate_text(value: str, limit: int) -> tuple[str, bool, int]:
    text = "" if value is None else str(value)
    size = len(text)
    if size <= limit:
        return text, False, size
    return (
        text[:limit] + f"\n[TRUNCATED: remote output was {size} chars, showing first {limit}]",
        True,
        size,
    )


class RemoteExecTool(Tool):
    """Execute a command on the remote analysis server via SSH."""

    name = "remote_exec"
    description = (
        "Execute a command on the remote analysis server via SSH and return "
        "stdout, stderr, and exit code. Use this to run analysis tools "
        "(binary_inspect, capa, yara, etc.) or check file status on the remote "
        "server. The remote server must have OpenSSH Server installed and the "
        "SSH key configured."
    )
    parameters = {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "Command to execute on the remote server.",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in seconds. Default 300 (5 min), max 600.",
            },
            "workdir": {
                "type": "string",
                "description": "Working directory on the remote server. Default C:\\analysis\\tmp.",
            },
        },
        "required": ["command"],
    }

    def __init__(self, config=None) -> None:
        self._config = config

    def execute(
        self,
        command: str,
        timeout: int = 300,
        workdir: str = "",
        **kwargs,
    ) -> ToolResult:
        remote = getattr(self._config, "remote", None) if self._config else None
        if remote is None or not remote.enabled:
            return ToolResult(
                content="remote_exec: remote server is not configured. "
                "Set `remote.enabled: true` and configure SSH connection in config.",
                is_error=True,
            )

        from chatcli.remote.ssh_client import SSHClient

        client = SSHClient(
            host=remote.host,
            user=remote.user,
            port=remote.port,
            key_file=remote.key_file,
            password=remote.password,
        )
        try:
            timeout = max(10, min(int(timeout or 300), 600))
            exit_code, stdout, stderr = client.exec(
                command, timeout=timeout, workdir=workdir or remote.remote_analysis_dir
            )
        except Exception as exc:
            return ToolResult(
                content=f"SSH command failed: {exc}",
                is_error=True,
            )
        finally:
            client.close()

        safe_stdout, stdout_truncated, stdout_chars = _truncate_text(stdout, STDOUT_CONTENT_LIMIT)
        safe_stderr, stderr_truncated, stderr_chars = _truncate_text(stderr, STDERR_CONTENT_LIMIT)

        output = safe_stdout
        if safe_stderr:
            output += f"\n[stderr]\n{safe_stderr}"
        if exit_code != 0:
            output = f"[exit_code={exit_code}]\n{output}"

        return ToolResult(
            content=output,
            is_error=exit_code != 0,
            metadata={
                "exit_code": exit_code,
                "stdout": safe_stdout,
                "stderr": safe_stderr,
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
                "stdout_chars": stdout_chars,
                "stderr_chars": stderr_chars,
            },
        )
