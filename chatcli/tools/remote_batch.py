"""Sequential remote malware-analysis batch workflow."""

from __future__ import annotations

from datetime import datetime, timezone
import re
import time
from pathlib import PureWindowsPath
from typing import Any

import httpx

from chatcli.remote.analysis_plans import static_ida_verify_plan

from .base import Tool, ToolResult, coerce_bool, coerce_int, coerce_str_list
from ._remote_client import build_guest_agent_client


_TERMINAL_STATUSES = {"done", "failed", "timeout"}


def _ps_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _slug(value: str, default: str = "sample") -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip(".-")
    return (text or default)[:48]


def _sample_stem(remote_path: str) -> str:
    try:
        name = PureWindowsPath(remote_path).name
    except Exception:
        name = remote_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    stem = name.rsplit(".", 1)[0] if "." in name else name
    return _slug(stem)


class RemoteBatchAnalyzeTool(Tool):
    """Run remote Guest Agent cases one sample at a time."""

    name = "remote_batch_analyze"
    description = (
        "Run a sequential Tencent Cloud Guest Agent analysis workflow for malware "
        "samples already present on the remote server. It prepares, runs, waits, "
        "and optionally downloads each case before starting the next sample. This "
        "is separate from the agent polling loop and does not change normal chatcli "
        "tool-round behavior. Dynamic execution is controlled only by analysis_plan."
    )
    parameters = {
        "type": "object",
        "properties": {
            "sample_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Explicit remote sample paths. Can also be a newline/comma separated string.",
            },
            "sample_dir": {
                "type": "string",
                "description": "Remote directory to scan when sample_paths is omitted.",
            },
            "pattern": {
                "type": "string",
                "description": "Filename pattern for sample_dir, e.g. *.exe. Default *.exe.",
            },
            "recursive": {
                "type": "boolean",
                "description": "Scan sample_dir recursively. Default false.",
            },
            "max_samples": {
                "type": "integer",
                "description": "Optional cap on samples to analyze. 0 means no cap.",
            },
            "case_prefix": {
                "type": "string",
                "description": "Prefix for generated case IDs. Default batch.",
            },
            "analysis_plan": {
                "type": "object",
                "description": "Guest Agent plan, e.g. {'static': true, 'dynamic': true, 'network': true, 'verify': true}. Default is static+verify only.",
            },
            "dynamic_config": {
                "type": "object",
                "description": "Dynamic settings such as timeout_seconds and collectors.",
            },
            "mode": {
                "type": "string",
                "description": "Guest Agent mode: real or dry_run. Default real.",
            },
            "wait": {
                "type": "boolean",
                "description": "Wait for each case to finish before continuing. Default true.",
            },
            "poll_interval_seconds": {
                "type": "integer",
                "description": "Status polling interval for async-compatible servers. Default 15.",
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Maximum time to wait per case. Default 3600.",
            },
            "run_request_timeout_seconds": {
                "type": "integer",
                "description": "HTTP timeout for the run submission request. Default 60.",
            },
            "download": {
                "type": "boolean",
                "description": "Download result ZIP/extract after each case completes. Default true.",
            },
            "output_dir": {
                "type": "string",
                "description": "Local directory for downloaded results.",
            },
            "stop_on_failure": {
                "type": "boolean",
                "description": "Stop the batch after the first missing/failed sample. Default true.",
            },
        },
        "required": [],
    }

    def __init__(self, config=None) -> None:
        self._config = config

    def _get_client(self, timeout: float = 300.0):
        return build_guest_agent_client(self._config, timeout=timeout)

    def _list_remote_samples(
        self,
        client: Any,
        sample_dir: str,
        pattern: str,
        recursive: bool,
        max_samples: int,
    ) -> list[str]:
        recurse_flag = " -Recurse" if recursive else ""
        limit_script = ""
        if max_samples > 0:
            limit_script = f" | Select-Object -First {max_samples}"
        script = (
            "$ErrorActionPreference='Stop'; "
            f"$items = Get-ChildItem -LiteralPath {_ps_single_quote(sample_dir)} -File{recurse_flag}; "
            f"$items | Where-Object {{ $_.Name -like {_ps_single_quote(pattern)} }} "
            f"| Sort-Object FullName{limit_script} | Select-Object -ExpandProperty FullName"
        )
        command = f'powershell -NoProfile -ExecutionPolicy Bypass -Command "{script}"'
        data = client.exec_command(command, timeout=120)
        if data.get("exit_code", 1) != 0:
            stderr = (data.get("stderr") or data.get("stdout") or "").strip()
            raise RuntimeError(f"remote sample listing failed: {stderr[:500]}")
        return [line.strip() for line in (data.get("stdout") or "").splitlines() if line.strip()]

    def _wait_case(
        self,
        client: Any,
        case_id: str,
        timeout_seconds: int,
        poll_interval_seconds: int,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        last: dict[str, Any] = {"case_id": case_id, "status": "unknown"}
        while time.monotonic() <= deadline:
            last = client.case_status(case_id)
            status = str(last.get("status", "") or "").lower()
            if last.get("done_marker") or last.get("failed_marker") or status in _TERMINAL_STATUSES:
                return last
            time.sleep(poll_interval_seconds)
        last["status"] = "timeout"
        last["timeout_seconds"] = timeout_seconds
        return last

    def execute(
        self,
        sample_paths: Any = None,
        sample_dir: str = "",
        pattern: str = "*.exe",
        recursive: bool = False,
        max_samples: int = 0,
        case_prefix: str = "batch",
        analysis_plan: dict | None = None,
        dynamic_config: dict | None = None,
        mode: str = "real",
        wait: bool = True,
        poll_interval_seconds: int = 15,
        timeout_seconds: int = 3600,
        run_request_timeout_seconds: int = 60,
        download: bool = True,
        output_dir: str = "",
        stop_on_failure: bool = True,
        **kwargs,
    ) -> ToolResult:
        paths = coerce_str_list(sample_paths)
        max_samples = coerce_int(max_samples, 0, minimum=0)
        wait = coerce_bool(wait, True)
        recursive = coerce_bool(recursive, False)
        download = coerce_bool(download, True)
        stop_on_failure = coerce_bool(stop_on_failure, True)
        poll_interval_seconds = coerce_int(poll_interval_seconds, 15, minimum=1, maximum=300)
        timeout_seconds = coerce_int(timeout_seconds, 3600, minimum=1)
        run_request_timeout_seconds = coerce_int(run_request_timeout_seconds, 60, minimum=5, maximum=300)
        mode = (mode or "real").strip() or "real"
        plan = analysis_plan or static_ida_verify_plan()
        dyn = dynamic_config or {}

        if mode not in {"real", "dry_run"}:
            return ToolResult(content="mode must be real or dry_run", is_error=True)

        request_timeout = max(300, timeout_seconds + 120)
        try:
            client = self._get_client(timeout=float(request_timeout))
        except ValueError as exc:
            return ToolResult(content=str(exc), is_error=True)

        results: list[dict[str, Any]] = []
        try:
            if not paths:
                sample_dir = (sample_dir or "").strip()
                if not sample_dir:
                    return ToolResult(
                        content="remote_batch_analyze requires sample_paths or sample_dir",
                        is_error=True,
                    )
                paths = self._list_remote_samples(
                    client=client,
                    sample_dir=sample_dir,
                    pattern=pattern or "*.exe",
                    recursive=recursive,
                    max_samples=max_samples,
                )
            elif max_samples > 0:
                paths = paths[:max_samples]

            if not paths:
                return ToolResult(content="No remote samples matched the batch request.", metadata={"samples": []})

            batch_stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
            prefix = _slug(case_prefix or "batch", default="batch")
            lines = [
                f"Remote batch analysis: {len(paths)} sample(s)",
                f"Mode: {mode}",
                f"Plan: {plan}",
            ]
            if len(paths) > 1 and plan.get("dynamic"):
                lines.append(
                    "Warning: dynamic batch runs samples sequentially without VM snapshot "
                    "restore between samples. Use a per-sample restore workflow when strong "
                    "isolation is required."
                )

            for index, remote_sample in enumerate(paths, start=1):
                case_id = f"{prefix}-{batch_stamp}-{index:03d}-{_sample_stem(remote_sample)}"
                item: dict[str, Any] = {
                    "index": index,
                    "sample_path": remote_sample,
                    "case_id": case_id,
                    "status": "pending",
                }
                try:
                    prepared = client.prepare_case(
                        case_id=case_id,
                        analysis_plan=plan,
                        sample_path=remote_sample,
                        dynamic_config=dyn,
                    )
                    item["prepared"] = prepared
                    if prepared.get("sample_exists") is False:
                        item["status"] = "missing_sample"
                        results.append(item)
                        lines.append(f"{index}. {case_id}: missing remote sample: {remote_sample}")
                        if stop_on_failure:
                            break
                        continue

                    try:
                        run_result = client.run_analysis(
                            case_id,
                            mode=mode,
                            analysis_plan=plan,
                            dynamic_config=dyn,
                            background=True,
                            request_timeout=run_request_timeout_seconds,
                        )
                    except httpx.TimeoutException as exc:
                        run_result = {
                            "case_id": case_id,
                            "status": "running",
                            "background": True,
                            "warning": f"run request timed out after {run_request_timeout_seconds}s; polling status",
                            "error": str(exc),
                        }
                    item["run"] = run_result
                    status = str(run_result.get("status", "unknown") or "unknown").lower()
                    if wait and status not in _TERMINAL_STATUSES:
                        status_data = self._wait_case(
                            client=client,
                            case_id=case_id,
                            timeout_seconds=timeout_seconds,
                            poll_interval_seconds=poll_interval_seconds,
                        )
                        item["status_data"] = status_data
                        status = str(status_data.get("status", status) or status).lower()
                    item["status"] = status

                    if download and item["status"] == "done":
                        try:
                            item["local_dir"] = client.download_results(case_id, output_dir)
                            try:
                                from chatcli.remote.result_report import build_malware_report_from_results

                                report = build_malware_report_from_results(item["local_dir"])
                                if report is not None:
                                    item["report_json"] = str(report.json_path)
                                    item["report_html"] = str(report.html_path)
                                    if report.errors:
                                        item["report_errors"] = report.errors
                            except Exception as exc:
                                item["report_error"] = str(exc)
                        except Exception as exc:
                            item["download_error"] = str(exc)

                    local = f" -> {item['local_dir']}" if item.get("local_dir") else ""
                    if item["status"] == "done":
                        lines.append(f"{index}. {case_id}: {item['status']}{local}")
                        if item.get("report_html"):
                            lines.append(f"   report: {item['report_html']}")
                    else:
                        lines.append(
                            f"{index}. {case_id}: {item['status']} "
                            f"(check: remote_guest action=status case_id={case_id}; "
                            f"download when done: remote_guest action=download case_id={case_id})"
                        )
                    results.append(item)

                    if wait and item["status"] != "done" and stop_on_failure:
                        break
                except Exception as exc:
                    item["status"] = "error"
                    item["error"] = str(exc)
                    results.append(item)
                    lines.append(f"{index}. {case_id}: error: {exc}")
                    if stop_on_failure:
                        break

            failures = [
                item for item in results
                if item.get("status") in {"error", "failed", "timeout", "missing_sample"}
            ]
            incomplete = [
                item for item in results
                if item.get("status") not in {"done", "error", "failed", "timeout", "missing_sample"}
            ]
            done_count = sum(1 for item in results if item.get("status") == "done")
            lines.append(f"Completed: {done_count}/{len(paths)} done")
            if failures:
                lines.append(f"Failures/stopped: {len(failures)}")
            if incomplete:
                lines.append(f"Still running/submitted: {len(incomplete)}")

            return ToolResult(
                content="\n".join(lines),
                is_error=bool(failures) or (wait and bool(incomplete)),
                metadata={
                    "samples": paths,
                    "results": results,
                    "analysis_plan": plan,
                    "dynamic_config": dyn,
                    "mode": mode,
                },
            )
        except Exception as exc:
            return ToolResult(content=f"Remote batch analysis failed: {exc}", is_error=True)
        finally:
            client.close()
