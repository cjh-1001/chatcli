"""Poll remote outbox for completed analysis jobs."""

from __future__ import annotations

import json

from .base import Tool, ToolResult


class RemoteWatchTool(Tool):
    """Check the remote server's outbox for completed or failed jobs."""

    name = "remote_watch"
    description = (
        "Check the remote analysis server's outbox for completed jobs. "
        "A job is complete when its outbox directory contains a _DONE "
        "or _FAILED marker file. Returns a list of job IDs with their "
        "status, completion time (from marker file mtime), and available "
        "result files."
    )
    parameters = {
        "type": "object",
        "properties": {
            "job_id": {
                "type": "string",
                "description": "Check a specific job ID. If empty, list all completed jobs.",
            },
        },
    }

    def __init__(self, config=None) -> None:
        self._config = config

    def execute(self, job_id: str = "", **kwargs) -> ToolResult:
        remote = getattr(self._config, "remote", None) if self._config else None
        if remote is None or not remote.enabled:
            return ToolResult(
                content="remote_watch: remote server is not configured.",
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
            outbox = remote.remote_analysis_dir + "\\outbox"

            if job_id:
                # Check specific job
                return self._check_job(client, outbox, job_id)
            else:
                # List all jobs
                return self._list_jobs(client, outbox)
        except Exception as exc:
            return ToolResult(
                content=f"Watch failed: {exc}",
                is_error=True,
            )
        finally:
            client.close()

    def _check_job(
        self, client, outbox: str, job_id: str
    ) -> ToolResult:
        """Check a single job's status."""
        remote_dir = f"{outbox}\\{job_id}"

        # Check markers
        exit_code, done_out, _ = client.exec(
            f'if exist "{remote_dir}\\_DONE" echo DONE', timeout=10
        )
        exit_code2, fail_out, _ = client.exec(
            f'if exist "{remote_dir}\\_FAILED" type "{remote_dir}\\_FAILED"',
            timeout=10,
        )

        has_done = "DONE" in done_out
        has_failed = bool(fail_out.strip())

        if not has_done and not has_failed:
            # Check if job exists at all
            exit_code3, _, _ = client.exec(
                f'if exist "{remote_dir}" echo EXISTS', timeout=10
            )
            if exit_code3 == 0:
                # Job exists but not complete — check status.json
                status = self._read_status(client, remote_dir)
                return ToolResult(
                    content=(
                        f"Job: {job_id}\n"
                        f"Status: {status.get('status', 'running')}\n"
                        f"Steps: {', '.join(status.get('steps_completed', [])) or 'none'}\n"
                    ),
                    metadata={"job_id": job_id, "status": "running", **status},
                )
            else:
                return ToolResult(
                    content=f"Job not found: {job_id}",
                    is_error=True,
                )

        # Job is complete — list files
        files = client.list_dir(remote_dir)
        file_list = []
        for f in files:
            if not f["is_dir"]:
                file_list.append(f"{f['name']} ({f['size']:,} bytes)")

        status = "completed" if has_done else "failed"
        error = fail_out.strip() if has_failed else ""

        lines = [
            f"Job: {job_id}",
            f"Status: {status}",
        ]
        if error:
            lines.append(f"Error: {error}")
        if file_list:
            lines.append(f"\nResult files ({len(file_list)}):")
            for f in file_list[:30]:  # cap at 30
                lines.append(f"  {f}")

        return ToolResult(
            content="\n".join(lines),
            metadata={
                "job_id": job_id,
                "status": status,
                "error": error,
                "file_count": len(file_list),
                "files": file_list,
            },
        )

    def _list_jobs(self, client, outbox: str) -> ToolResult:
        """List all jobs in outbox with their status."""
        items = client.list_dir(outbox)
        job_dirs = [i["name"] for i in items if i["is_dir"] and not i["name"].startswith(".")]

        if not job_dirs:
            return ToolResult(content="No completed jobs in remote outbox.")

        results = []
        for jid in sorted(job_dirs):
            remote_dir = f"{outbox}\\{jid}"
            exit_code, done_out, _ = client.exec(
                f'if exist "{remote_dir}\\_DONE" echo DONE', timeout=5
            )
            exit_code2, fail_out, _ = client.exec(
                f'if exist "{remote_dir}\\_FAILED" type "{remote_dir}\\_FAILED"',
                timeout=5,
            )
            has_done = "DONE" in done_out
            has_failed = bool(fail_out.strip())

            if has_done:
                results.append(f"  ✅ {jid} — completed")
            elif has_failed:
                results.append(f"  ❌ {jid} — failed: {fail_out.strip()[:80]}")
            else:
                # Check if running
                status = self._read_status(client, remote_dir)
                steps = status.get("steps_completed", [])
                results.append(
                    f"  ⏳ {jid} — running ({len(steps)} steps done)"
                )

        count_done = sum(1 for r in results if "✅" in r)
        count_fail = sum(1 for r in results if "❌" in r)
        count_run = sum(1 for r in results if "⏳" in r)

        return ToolResult(
            content=(
                f"Remote outbox: {count_done} done, {count_fail} failed, "
                f"{count_run} running\n\n" + "\n".join(results)
            ),
            metadata={
                "total": len(results),
                "done": count_done,
                "failed": count_fail,
                "running": count_run,
                "jobs": [
                    {"job_id": r.split()[1], "status": r.split("—")[0].strip()}
                    for r in results
                ],
            },
        )

    @staticmethod
    def _read_status(client, remote_dir: str) -> dict:
        """Read status.json from a remote job directory."""
        exit_code, stdout, _ = client.exec(
            f'type "{remote_dir}\\status.json"', timeout=10
        )
        if exit_code == 0 and stdout.strip():
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                pass
        return {}
