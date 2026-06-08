"""Unified Guest Agent interaction tool — HTTP main channel."""

from __future__ import annotations

from pathlib import Path

from chatcli.remote.analysis_plans import default_dynamic_config, dynamic_ida_verify_plan

from .base import Tool, ToolResult, coerce_bool
from ._remote_client import build_guest_agent_client


def _truncate_remote_text(value: str, limit: int) -> tuple[str, bool, int]:
    text = value or ""
    size = len(text)
    if size <= limit:
        return text, False, size
    return (
        text[:limit]
        + f"\n[TRUNCATED: remote output was {size} chars, showing first {limit}]",
        True,
        size,
    )


class RemoteGuestTool(Tool):
    """Interact with the remote Guest Agent via HTTP. Unified entry point for
    all remote analysis operations — replaces individual remote_exec/submit/fetch."""

    name = "remote_guest"
    description = (
        "Interact with the remote analysis Guest Agent on Tencent Cloud. "
        "This is the main channel for remote operations. Actions:\n"
        "  health    — Check if Guest Agent is running\n"
        "  metrics   — Show remote server metrics and recent cases\n"
        "  security  — Collect post-analysis server compromise indicators\n"
        "  monitor   — Collect live process/network/registry/task/file telemetry\n"
        "  tools     — List configured analysis tools and their paths\n"
        "  exec      — Execute an analysis command directly on the remote server\n"
        "  prepare   — Create a new analysis case\n"
        "  upload    — Upload sample file to a case\n"
        "  run       — Trigger static/dynamic analysis on uploaded or remote-path sample\n"
        "  analyze   — Prepare and run static→dynamic→network→verify for a remote sample\n"
        "  status    — Check case progress and result file list\n"
        "  download  — Download all results as ZIP and extract locally\n"
        "  list      — List all cases on the remote server\n"
        "\n"
        "Quick path (file already on remote server):\n"
        "  prepare sample_path='C:\\samples\\mal.exe' → create case without upload\n"
        "  run case_id=<id> → analyze that remote sample path\n"
        "  exec command='binary_inspect C:\\samples\\mal.exe' → direct output\n"
        "  exec command='capa C:\\samples\\mal.exe -j' → direct output\n"
        "\n"
        "Full workflow (file needs upload):\n"
        "  1. prepare → get case_id\n"
        "  2. upload case_id=<id> file_path=<sample>\n"
        "  3. run case_id=<id>  (defaults to background submission; poll status/monitor)\n"
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
                "enum": [
                    "health", "metrics", "security", "monitor", "tools", "exec",
                    "prepare", "upload", "run", "analyze", "status", "download", "list"
                ],
                "description": "Action to perform.",
            },
            "case_id": {
                "type": "string",
                "description": "Case ID (required for upload, run, status, download; optional for monitor).",
            },
            "file_path": {
                "type": "string",
                "description": "Local file path to upload (required for upload).",
            },
            "sample_path": {
                "type": "string",
                "description": "Remote sample path already present on the Guest Agent server.",
            },
            "analysis_plan": {
                "type": "object",
                "description": "Optional analysis plan, e.g. {'static': true, 'dynamic': true, 'network': true}.",
            },
            "dynamic_config": {
                "type": "object",
                "description": "Optional dynamic-analysis settings for the remote job runner.",
            },
            "include_probes": {
                "type": "boolean",
                "description": "For metrics: include command probes such as netstat/tasklist. Default false.",
            },
            "mode": {
                "type": "string",
                "description": "Analysis mode: real | dry_run. Default real.",
            },
            "output_dir": {
                "type": "string",
                "description": "Local directory for downloaded results.",
            },
            "background": {
                "type": "boolean",
                "description": "For run/analyze: submit the remote job in background and return immediately. Default true.",
            },
            "request_timeout": {
                "type": "integer",
                "description": "HTTP request timeout in seconds for run/analyze submission. Default 60 in background mode, otherwise client default.",
            },
        },
        "required": ["action"],
    }

    def __init__(self, config=None) -> None:
        self._config = config

    def _get_client(self):
        """Build GuestAgentClient from config."""
        return build_guest_agent_client(self._config)

    def execute(
        self,
        action: str,
        case_id: str = "",
        file_path: str = "",
        sample_path: str = "",
        analysis_plan: dict | None = None,
        dynamic_config: dict | None = None,
        mode: str = "real",
        output_dir: str = "",
        include_probes: bool = False,
        background: bool | None = None,
        request_timeout: int | None = None,
        **kwargs,
    ) -> ToolResult:
        progress = kwargs.get("_progress_callback")

        def emit(message: str) -> None:
            if callable(progress):
                progress(message)

        def background_enabled() -> bool:
            if background is not None:
                return coerce_bool(background, True)
            if "background" in kwargs:
                return coerce_bool(kwargs.get("background"), True)
            return True

        def submission_timeout(is_background: bool) -> int | None:
            raw = request_timeout if request_timeout is not None else kwargs.get("request_timeout")
            if raw is not None:
                try:
                    return max(5, int(raw))
                except (TypeError, ValueError):
                    return 60 if is_background else None
            return 60 if is_background else None

        def emit_step(action_name: str, state: str, detail: str = "") -> None:
            message = f"remote_guest {action_name} {state}"
            if detail:
                message = f"{message}: {detail}"
            emit(message)

        try:
            client = self._get_client()
        except ValueError as exc:
            return ToolResult(content=str(exc), is_error=True)

        try:
            if action == "health":
                emit_step("health", "requesting", "/api/v1/health")
                data = client.health()
                emit_step("health", "ok", str(data.get("status", "unknown")))
                return ToolResult(
                    content=(
                        f"Guest Agent: {data.get('status', 'unknown')}\n"
                        f"Version: {data.get('version', '?')}\n"
                        f"Cases dir: {data.get('cases_dir', '?')}\n"
                        f"Auth: {'configured' if data.get('auth_configured') else 'MISSING'}"
                    ),
                    metadata=data,
                )

            elif action == "metrics":
                emit_step("metrics", "requesting", "/api/v1/status")
                data = client.server_status(probes=bool(include_probes or kwargs.get("include_probes")))
                disk = data.get("disk", {})
                tools_total = data.get("tool_count", 0)
                tools_ok = data.get("tools_available", 0)
                cases = data.get("cases", [])
                emit_step("metrics", "ok", f"{tools_ok}/{tools_total} tools, {len(cases)} cases")
                lines = [
                    f"Remote server: {data.get('hostname', '?')}",
                    f"Platform: {data.get('platform', '?')}",
                    f"Workdir: {data.get('workdir', '?')}",
                    f"Disk free: {int(disk.get('free_bytes', 0)):,} / {int(disk.get('total_bytes', 0)):,} bytes",
                    f"Tools: {tools_ok}/{tools_total} available",
                    f"Recent cases: {len(cases)}",
                ]
                for case in cases[-10:]:
                    lines.append(f"  {case.get('case_id')} — {case.get('status')}")
                return ToolResult(content="\n".join(lines), metadata=data)

            elif action == "security":
                emit_step("security", "requesting", "/api/v1/security/status")
                data = client.security_status()
                findings = data.get("findings", [])
                emit_step("security", "ok", f"{len(findings)} findings")
                lines = [
                    f"Security snapshot: {data.get('hostname', '?')}",
                    f"Risk level: {data.get('risk_level', 'unknown')}",
                    f"Findings: {len(findings)}",
                ]
                for finding in findings:
                    lines.append(
                        f"  [{finding.get('severity', '?')}] {finding.get('title', '')}: "
                        f"{finding.get('detail', '')}"
                    )
                lines.append(f"Recent result dirs: {len(data.get('recent_results', []))}")
                return ToolResult(content="\n".join(lines), metadata=data)

            elif action == "monitor":
                emit_step("monitor", "requesting", "/api/v1/monitor/snapshot")
                data = client.monitor_snapshot(
                    case_id=case_id,
                    probes=bool(include_probes or kwargs.get("include_probes", True)),
                )
                agents = data.get("observer_agents", [])
                traffic = data.get("traffic_capture", {})
                dyn = data.get("dynamic_status", {})
                process_metrics = data.get("process_metrics", {})
                emit_step("monitor", "ok", f"status={dyn.get('status', 'none')} agents={len(agents)}")
                lines = [
                    f"Monitor snapshot: {data.get('hostname', '?')}",
                    f"Case: {data.get('case_id') or '(latest)'}",
                    f"Dynamic status: {dyn.get('status', 'none')}",
                    f"Traffic capture: {traffic.get('pcap_bytes', 0)} bytes"
                    + (" active" if traffic.get("active") else ""),
                    f"Processes: {process_metrics.get('count', 0)} ({process_metrics.get('status', 'not_collected')})",
                    f"Recent files: {len(data.get('file_activity', []))}",
                    f"Observer agents: {len(agents)}",
                ]
                for agent in agents:
                    lines.append(
                        f"  {agent.get('name', '?')} [{agent.get('status', '?')}]: "
                        f"{agent.get('summary', '')}"
                    )
                return ToolResult(content="\n".join(lines), metadata=data)

            elif action == "tools":
                emit_step("tools", "requesting", "/api/v1/tools")
                data = client.list_tools()
                tools = data.get("tools", {})
                emit_step("tools", "ok", f"{sum(1 for info in tools.values() if info.get('available'))}/{len(tools)} available")
                lines = ["Remote server analysis tools:"]
                for name, info in sorted(tools.items()):
                    status = "OK" if info.get("available") else "MISSING"
                    detail = (
                        info.get("path")
                        or info.get("command")
                        or info.get("module")
                        or info.get("description")
                        or info.get("kind")
                        or "?"
                    )
                    kind = info.get("kind", "")
                    suffix = f" [{kind}]" if kind else ""
                    package = f" package={info.get('package')}" if info.get("package") else ""
                    lines.append(f"  {status} {name}{suffix}: {detail}{package}")
                return ToolResult(content="\n".join(lines), metadata=data)

            elif action == "exec":
                command = kwargs.get("command", "") or file_path
                if not command:
                    return ToolResult(content="exec requires command='...'", is_error=True)
                timeout = int(kwargs.get("timeout", 300))
                workdir = output_dir or ""
                emit(f"remote_guest exec started (timeout={timeout}s)")
                emit_step("exec", "requesting", "/api/v1/exec")
                data = client.exec_command(command, timeout=timeout, workdir=workdir)
                exit_code = data.get("exit_code", -1)
                stdout, stdout_truncated, stdout_size = _truncate_remote_text(data.get("stdout", ""), 60000)
                stderr, stderr_truncated, stderr_size = _truncate_remote_text(data.get("stderr", ""), 12000)
                elapsed = data.get("elapsed_ms", 0)
                emit_step("exec", "ok", f"exit={exit_code} elapsed={elapsed}ms")
                output = stdout
                if stderr:
                    output += f"\n[stderr]\n{stderr}"
                safe_metadata = dict(data)
                safe_metadata["stdout"] = stdout
                safe_metadata["stderr"] = stderr
                safe_metadata["stdout_truncated"] = stdout_truncated
                safe_metadata["stderr_truncated"] = stderr_truncated
                safe_metadata["stdout_chars"] = stdout_size
                safe_metadata["stderr_chars"] = stderr_size
                return ToolResult(
                    content=f"[exit={exit_code} | {elapsed}ms]\n{output}" if output else f"[exit={exit_code} | {elapsed}ms] (no output)",
                    is_error=exit_code != 0,
                    metadata=safe_metadata,
                )

            elif action == "prepare":
                remote_sample = sample_path or str(kwargs.get("sample_path", "") or "")
                emit_step("prepare", "requesting", "/api/v1/cases/prepare")
                data = client.prepare_case(
                    case_id=case_id,
                    analysis_plan=analysis_plan or kwargs.get("analysis_plan"),
                    sample_path=remote_sample,
                    dynamic_config=dynamic_config or kwargs.get("dynamic_config"),
                )
                return ToolResult(
                    content=(
                        f"Case prepared: {data['case_id']}\n"
                        f"Status: {data['status']}"
                        + (f"\nRemote sample: {data.get('sample_path', '')}" if data.get("sample_path") else "")
                        + (f"\nSample exists: {data.get('sample_exists')}" if data.get("sample_path") else "")
                    ),
                    metadata=data,
                )

            elif action == "upload":
                if not case_id or not file_path:
                    return ToolResult(
                        content="upload requires case_id and file_path",
                        is_error=True,
                    )
                emit_step("upload", "requesting", f"case={case_id}")
                data = client.upload_sample(case_id, file_path)
                emit_step("upload", "ok", f"{data['filename']} {data['size_bytes']:,} bytes")
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
                bg = background_enabled()
                timeout = submission_timeout(bg)
                emit(
                    f"remote_guest run submitting case={case_id} "
                    f"background={str(bg).lower()}"
                )
                emit_step("run", "requesting", f"case={case_id}")
                data = client.run_analysis(
                    case_id,
                    mode=mode,
                    sample_path=sample_path or str(kwargs.get("sample_path", "") or ""),
                    analysis_plan=analysis_plan or kwargs.get("analysis_plan"),
                    dynamic_config=dynamic_config or kwargs.get("dynamic_config"),
                    background=bg,
                    request_timeout=timeout,
                )
                emit_step("run", "ok", f"status={data.get('status', '?')}")
                if bg:
                    emit(f"remote_guest run submitted case={data.get('case_id', case_id)} status={data.get('status')}")
                return ToolResult(
                    content=(
                        f"Analysis: {data['case_id']}\n"
                        f"Status: {data['status']}"
                        + (f"\nBackground: {data.get('background')}" if "background" in data else "")
                        + ("\nNext: use remote_guest action=status/monitor, then download when done" if bg else "")
                        + (f"\nError: {data.get('error', '')}" if data.get('error') else "")
                    ),
                    is_error=data.get("status") in ("failed", "timeout", "already_running"),
                    metadata=data,
                )

            elif action == "analyze":
                remote_sample = sample_path or str(kwargs.get("sample_path", "") or "")
                if not remote_sample:
                    return ToolResult(
                        content="analyze requires sample_path pointing to the remote server file",
                        is_error=True,
                    )
                plan = analysis_plan or kwargs.get("analysis_plan") or dynamic_ida_verify_plan()
                dyn = dynamic_config or kwargs.get("dynamic_config") or default_dynamic_config()
                emit(f"remote_guest analyze preparing sample={remote_sample}")
                emit_step("analyze", "preparing", remote_sample)
                prepared = client.prepare_case(
                    case_id=case_id,
                    analysis_plan=plan,
                    sample_path=remote_sample,
                    dynamic_config=dyn,
                )
                cid = prepared["case_id"]
                bg = background_enabled()
                timeout = submission_timeout(bg)
                emit(
                    f"remote_guest analyze submitting case={cid} "
                    f"background={str(bg).lower()}"
                )
                emit_step("analyze", "requesting", f"case={cid}")
                result = client.run_analysis(
                    cid,
                    mode=mode,
                    background=bg,
                    request_timeout=timeout,
                )
                emit_step("analyze", "ok", f"status={result.get('status', '?')}")
                if bg:
                    emit(f"remote_guest analyze submitted case={cid} status={result.get('status')}")
                return ToolResult(
                    content=(
                        f"Analysis case: {cid}\n"
                        f"Remote sample: {remote_sample}\n"
                        f"Sample exists: {prepared.get('sample_exists')}\n"
                        f"Status: {result.get('status')}"
                        + (f"\nBackground: {result.get('background')}" if "background" in result else "")
                        + ("\nNext: use remote_guest action=status/monitor, then download when done" if bg else "")
                        + (f"\nError: {result.get('error', '')}" if result.get("error") else "")
                    ),
                    is_error=result.get("status") in ("failed", "timeout", "already_running"),
                    metadata={"prepared": prepared, "run": result},
                )

            elif action == "status":
                if not case_id:
                    return ToolResult(
                        content="status requires case_id", is_error=True
                    )
                emit_step("status", "requesting", f"case={case_id}")
                data = client.case_status(case_id)

                done = data.get("done_marker", False)
                failed = data.get("failed_marker", False)
                status = data.get("status", "unknown")
                files = data.get("outbox_files", [])
                emit_step("status", "ok", f"{status}, files={len(files)}")

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
                emit_step("download", "requesting", f"case={case_id}")
                local_dir = client.download_results(case_id, output_dir)

                # Count files
                import os
                file_count = sum(1 for _ in Path(local_dir).rglob("*") if _.is_file())
                report = None
                try:
                    from chatcli.remote.result_report import build_malware_report_from_results

                    report = build_malware_report_from_results(local_dir)
                except Exception as exc:
                    emit_step("download", "report_failed", str(exc))
                emit_step("download", "ok", f"{file_count} files")

                report_lines = []
                report_meta = {}
                if report is not None:
                    report_lines = [
                        f"Report JSON: {report.json_path}",
                        f"Report HTML: {report.html_path}",
                    ]
                    if report.errors:
                        report_lines.append(f"Report validation warnings: {len(report.errors)}")
                    report_meta = {
                        "report_json": str(report.json_path),
                        "report_html": str(report.html_path),
                        "report_errors": report.errors,
                    }

                return ToolResult(
                    content=(
                        f"Downloaded case: {case_id}\n"
                        f"Local path: {local_dir}\n"
                        f"Files: {file_count}"
                        + ("\n" + "\n".join(report_lines) if report_lines else "")
                    ),
                    metadata={
                        "case_id": case_id,
                        "local_dir": str(local_dir),
                        "file_count": file_count,
                        **report_meta,
                    },
                )

            elif action == "list":
                data = client.list_cases()
                cases = data.get("cases", [])
                if not cases:
                    emit_step("list", "ok", "no cases")
                    return ToolResult(content="No cases on remote server.")

                emit_step("list", "ok", f"{len(cases)} cases")
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
            emit_step(action, "failed", str(exc))
            return ToolResult(
                content=f"Guest Agent request failed: {exc}",
                is_error=True,
            )
        finally:
            client.close()
