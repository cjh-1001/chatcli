"""Unified Guest Agent interaction tool — HTTP main channel."""

from __future__ import annotations

from .base import Tool, ToolResult


class RemoteGuestTool(Tool):
    """Interact with the remote Guest Agent via HTTP. Unified entry point for
    all remote analysis operations — replaces individual remote_exec/submit/fetch."""

    name = "remote_guest"
    description = (
        "Interact with the remote analysis Guest Agent on Tencent Cloud. "
        "This is the main channel for remote operations. Actions:\n"
        "  health    — Check if Guest Agent is running\n"
        "  tools     — List configured analysis tools and their paths\n"
        "  exec      — Execute an analysis command directly on the remote server\n"
        "  prepare   — Create a new analysis case\n"
        "  upload    — Upload sample file to a case\n"
        "  run       — Trigger static/dynamic analysis on uploaded sample\n"
        "  status    — Check case progress and result file list\n"
        "  download  — Download all results as ZIP and extract locally\n"
        "  list      — List all cases on the remote server\n"
        "\n"
        "Quick path (file already on remote server):\n"
        "  exec command='binary_inspect C:\\samples\\mal.exe' → direct output\n"
        "  exec command='capa C:\\samples\\mal.exe -j' → direct output\n"
        "\n"
        "Full workflow (file needs upload):\n"
        "  1. prepare → get case_id\n"
        "  2. upload case_id=<id> file_path=<sample>\n"
        "  3. run case_id=<id>  (may take minutes)\n"
        "  4. status case_id=<id>  (check if done)\n"
        "  5. download case_id=<id>  (pull results to local)\n"
        "\n"
        "No SSH keys needed — just a Bearer token in CHATCLI_GUEST_AGENT_TOKEN."
    )
    parameters = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["health", "tools", "exec", "prepare", "upload", "run", "status", "download", "list"],
                "description": "Action to perform.",
            },
            "case_id": {
                "type": "string",
                "description": "Case ID (required for upload, run, status, download).",
            },
            "file_path": {
                "type": "string",
                "description": "Local file path to upload (required for upload).",
            },
            "mode": {
                "type": "string",
                "description": "Analysis mode: real | dry_run. Default real.",
            },
            "output_dir": {
                "type": "string",
                "description": "Local directory for downloaded results.",
            },
        },
        "required": ["action"],
    }

    def __init__(self, config=None) -> None:
        self._config = config

    def _get_client(self):
        """Build GuestAgentClient from config."""
        remote = getattr(self._config, "remote", None) if self._config else None
        if remote is None or not remote.enabled:
            raise ValueError("Remote server is not configured")

        base_url = getattr(remote, "base_url", "") or (
            f"http://{remote.host}:{remote.guest_agent_port}"
        )
        if not base_url:
            raise ValueError("Remote base_url or host is not set")

        token = remote.guest_agent_token
        if not token:
            raise ValueError(
                "Guest Agent token is not set. "
                "Set CHATCLI_GUEST_AGENT_TOKEN env var or "
                "remote.guest_agent_token in config."
            )

        from chatcli.remote.guest_client import GuestAgentClient
        return GuestAgentClient(base_url=base_url, token=token)

    def execute(
        self,
        action: str,
        case_id: str = "",
        file_path: str = "",
        mode: str = "real",
        output_dir: str = "",
        **kwargs,
    ) -> ToolResult:
        try:
            client = self._get_client()
        except ValueError as exc:
            return ToolResult(content=str(exc), is_error=True)

        try:
            if action == "health":
                data = client.health()
                return ToolResult(
                    content=(
                        f"Guest Agent: {data.get('status', 'unknown')}\n"
                        f"Version: {data.get('version', '?')}\n"
                        f"Cases dir: {data.get('cases_dir', '?')}\n"
                        f"Auth: {'configured' if data.get('auth_configured') else 'MISSING'}"
                    ),
                    metadata=data,
                )

            elif action == "tools":
                data = client.list_tools()
                tools = data.get("tools", {})
                lines = ["Remote analysis tools:"]
                for name, info in sorted(tools.items()):
                    status = "✅" if info.get("available") else "❌"
                    lines.append(f"  {status} {name}: {info.get('path', '?')}")
                return ToolResult(content="\n".join(lines), metadata=data)

            elif action == "exec":
                command = kwargs.get("command", "") or file_path
                if not command:
                    return ToolResult(content="exec requires command='...'", is_error=True)
                timeout = int(kwargs.get("timeout", 300))
                workdir = output_dir or ""
                data = client.exec_command(command, timeout=timeout, workdir=workdir)
                exit_code = data.get("exit_code", -1)
                stdout = data.get("stdout", "")
                stderr = data.get("stderr", "")
                elapsed = data.get("elapsed_ms", 0)
                output = stdout
                if stderr:
                    output += f"\n[stderr]\n{stderr}"
                return ToolResult(
                    content=f"[exit={exit_code} | {elapsed}ms]\n{output}" if output else f"[exit={exit_code} | {elapsed}ms] (no output)",
                    is_error=exit_code != 0,
                    metadata=data,
                )

            elif action == "prepare":
                data = client.prepare_case(case_id=case_id)
                return ToolResult(
                    content=(
                        f"Case prepared: {data['case_id']}\n"
                        f"Status: {data['status']}"
                    ),
                    metadata=data,
                )

            elif action == "upload":
                if not case_id or not file_path:
                    return ToolResult(
                        content="upload requires case_id and file_path",
                        is_error=True,
                    )
                data = client.upload_sample(case_id, file_path)
                return ToolResult(
                    content=(
                        f"Uploaded: {data['filename']}\n"
                        f"Case: {data['case_id']}\n"
                        f"SHA-256: {data['sha256']}\n"
                        f"Size: {data['size_bytes']:,} bytes"
                    ),
                    metadata=data,
                )

            elif action == "run":
                if not case_id:
                    return ToolResult(
                        content="run requires case_id", is_error=True
                    )
                data = client.run_analysis(case_id, mode=mode)
                return ToolResult(
                    content=(
                        f"Analysis: {data['case_id']}\n"
                        f"Status: {data['status']}"
                        + (f"\nError: {data.get('error', '')}" if data.get('error') else "")
                    ),
                    is_error=data.get("status") in ("failed", "timeout", "already_running"),
                    metadata=data,
                )

            elif action == "status":
                if not case_id:
                    return ToolResult(
                        content="status requires case_id", is_error=True
                    )
                data = client.case_status(case_id)

                done = data.get("done_marker", False)
                failed = data.get("failed_marker", False)
                status = data.get("status", "unknown")
                files = data.get("outbox_files", [])

                lines = [
                    f"Case: {case_id}",
                    f"Status: {status}",
                    f"Completed: {'✅ _DONE' if done else '❌ _FAILED' if failed else '⏳ running'}",
                ]
                if failed:
                    lines.append(f"Error: {data.get('error', '')}")
                if files:
                    lines.append(f"\nResult files ({len(files)}):")
                    for f in sorted(files, key=lambda x: x["path"])[:30]:
                        lines.append(f"  {f['path']} ({f['size']:,} bytes)")

                return ToolResult(
                    content="\n".join(lines),
                    metadata=data,
                )

            elif action == "download":
                if not case_id:
                    return ToolResult(
                        content="download requires case_id", is_error=True
                    )
                local_dir = client.download_results(case_id, output_dir)

                # Count files
                import os
                file_count = sum(1 for _ in Path(local_dir).rglob("*") if _.is_file())

                return ToolResult(
                    content=(
                        f"Downloaded case: {case_id}\n"
                        f"Local path: {local_dir}\n"
                        f"Files: {file_count}"
                    ),
                    metadata={
                        "case_id": case_id,
                        "local_dir": str(local_dir),
                        "file_count": file_count,
                    },
                )

            elif action == "list":
                data = client.list_cases()
                cases = data.get("cases", [])
                if not cases:
                    return ToolResult(content="No cases on remote server.")

                lines = [f"Cases: {len(cases)}"]
                for c in cases:
                    lines.append(
                        f"  {c['case_id']} — {c.get('status', '?')}"
                    )
                return ToolResult(
                    content="\n".join(lines),
                    metadata=data,
                )

            else:
                return ToolResult(
                    content=f"Unknown action: {action}", is_error=True
                )

        except Exception as exc:
            return ToolResult(
                content=f"Guest Agent request failed: {exc}",
                is_error=True,
            )
        finally:
            client.close()
