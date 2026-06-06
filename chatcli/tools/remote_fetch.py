"""Download analysis results from remote server."""

from __future__ import annotations

from pathlib import Path

from .base import Tool, ToolResult


class RemoteFetchTool(Tool):
    """Download result files from the remote analysis server."""

    name = "remote_fetch"
    description = (
        "Download analysis result files from the remote server's outbox. "
        "Fetches all files for a given job ID and saves them to a local "
        "directory (default: .chatcli/remote_results/<job_id>/). "
        "Returns a manifest of downloaded files."
    )
    parameters = {
        "type": "object",
        "properties": {
            "job_id": {
                "type": "string",
                "description": "Job ID to fetch results for.",
            },
            "output_dir": {
                "type": "string",
                "description": "Local directory to save results. Default: .chatcli/remote_results/<job_id>/",
            },
            "files": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific file patterns to fetch. Empty = fetch all.",
            },
        },
        "required": ["job_id"],
    }

    def __init__(self, config=None) -> None:
        self._config = config

    def execute(
        self,
        job_id: str,
        output_dir: str = "",
        files: list[str] | None = None,
        **kwargs,
    ) -> ToolResult:
        remote = getattr(self._config, "remote", None) if self._config else None
        if remote is None or not remote.enabled:
            return ToolResult(
                content="remote_fetch: remote server is not configured.",
                is_error=True,
            )

        outbox = f"{remote.remote_analysis_dir}\\outbox"
        remote_job_dir = f"{outbox}\\{job_id}"

        local_dir = (
            Path(output_dir).expanduser().resolve()
            if output_dir
            else Path(".chatcli/remote_results") / job_id
        )
        local_dir.mkdir(parents=True, exist_ok=True)

        from chatcli.remote.ssh_client import SSHClient

        client = SSHClient(
            host=remote.host,
            user=remote.user,
            port=remote.port,
            key_file=remote.key_file,
            password=remote.password,
        )
        try:
            # List remote files
            remote_items = client.list_dir(remote_job_dir)
            if not remote_items:
                # Check if job dir exists at all
                exit_code, stdout, stderr = client.exec(
                    f"dir {remote_job_dir}", timeout=10
                )
                if exit_code != 0:
                    return ToolResult(
                        content=f"Remote job directory not found: {remote_job_dir}",
                        is_error=True,
                    )

            # Download all files recursively (simplified: handle flat + subdirs)
            downloaded = []
            errors = []

            def _fetch_dir(remote_dir: str, local_base: Path, prefix: str = ""):
                for item in client.list_dir(remote_dir):
                    if item["is_dir"]:
                        sub = local_base / item["name"]
                        sub.mkdir(parents=True, exist_ok=True)
                        _fetch_dir(
                            f"{remote_dir}\\{item['name']}",
                            sub,
                            f"{prefix}{item['name']}\\",
                        )
                    else:
                        remote_file = f"{remote_dir}\\{item['name']}"
                        local_file = local_base / item["name"]
                        if client.get_file(remote_file, str(local_file)):
                            downloaded.append(
                                f"{prefix}{item['name']} ({item['size']:,} bytes)"
                            )
                        else:
                            errors.append(
                                f"Failed: {prefix}{item['name']}"
                            )

            _fetch_dir(remote_job_dir, local_dir)
        except Exception as exc:
            return ToolResult(
                content=f"Fetch failed: {exc}",
                is_error=True,
            )
        finally:
            client.close()

        has_done = any("_DONE" in d for d in downloaded)
        has_failed = any("_FAILED" in d for d in downloaded)

        status = "complete" if has_done else ("failed" if has_failed else "partial")
        lines = [
            f"Job: {job_id}",
            f"Status: {status}",
            f"Downloaded to: {local_dir}",
            f"Files: {len(downloaded)} downloaded, {len(errors)} failed",
        ]
        if downloaded:
            lines.append("\nDownloaded:")
            for d in downloaded:
                lines.append(f"  {d}")
        if errors:
            lines.append("\nErrors:")
            for e in errors:
                lines.append(f"  {e}")

        return ToolResult(
            content="\n".join(lines),
            metadata={
                "job_id": job_id,
                "status": status,
                "local_dir": str(local_dir),
                "downloaded_count": len(downloaded),
                "error_count": len(errors),
                "files": downloaded,
                "errors": errors,
            },
        )
