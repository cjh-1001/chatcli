"""Download completed job results from remote server."""

from __future__ import annotations

import json
from pathlib import Path

from .base import Tool, ToolResult


class RemoteConsumeTool(Tool):
    """Download all results for a completed analysis job."""

    name = "remote_consume"
    description = (
        "Download all result files for a completed analysis job from the "
        "remote server's outbox. Saves to .chatcli/remote_results/<job_id>/ "
        "by default. Returns a structured manifest of downloaded files "
        "categorized by analysis type (static, reverse, dynamic, network). "
        "Use this after remote_watch confirms a job is complete (_DONE marker)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "job_id": {
                "type": "string",
                "description": "Job ID to download results for.",
            },
            "output_dir": {
                "type": "string",
                "description": "Local output directory. Default: .chatcli/remote_results/<job_id>/",
            },
            "clean_remote": {
                "type": "boolean",
                "description": "Delete remote job files after successful download. Default false.",
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
        clean_remote: bool = False,
        **kwargs,
    ) -> ToolResult:
        remote = getattr(self._config, "remote", None) if self._config else None
        if remote is None or not remote.enabled:
            return ToolResult(
                content="remote_consume: remote server is not configured.",
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
            remote_job_dir = f"{outbox}\\{job_id}"

            # Verify job is done
            exit_code, done_check, _ = client.exec(
                f'if exist "{remote_job_dir}\\_DONE" echo DONE', timeout=10
            )
            exit_code2, fail_check, _ = client.exec(
                f'if exist "{remote_job_dir}\\_FAILED" type "{remote_job_dir}\\_FAILED"',
                timeout=10,
            )

            has_done = "DONE" in done_check
            has_failed = bool(fail_check.strip()) if exit_code2 == 0 else False

            if not has_done and not has_failed:
                return ToolResult(
                    content=(
                        f"Job {job_id} is not complete yet. "
                        "Use remote_watch to check status, then consume when done."
                    ),
                    is_error=True,
                )

            # Prepare local directory
            local_dir = (
                Path(output_dir).expanduser().resolve()
                if output_dir
                else Path(".chatcli/remote_results") / job_id
            )
            if local_dir.exists():
                import shutil
                shutil.rmtree(local_dir)
            local_dir.mkdir(parents=True, exist_ok=True)

            # Download all files recursively
            manifest = self._download_tree(client, remote_job_dir, local_dir)

            # Clean remote if requested
            if clean_remote and has_done:
                client.exec(f'rmdir /s /q "{remote_job_dir}"', timeout=30)

            # Build summary
            status_text = "completed" if has_done else "failed"
            lines = [
                f"Job: {job_id}",
                f"Status: {status_text}",
                f"Downloaded to: {local_dir}",
                f"Total files: {manifest['total_files']}",
                f"Total size: {manifest['total_size_bytes']:,} bytes",
                "",
            ]

            for category, files in sorted(manifest.get("categories", {}).items()):
                if files:
                    lines.append(f"── {category} ({len(files)} files) ──")
                    for f in files[:10]:
                        lines.append(f"  {f}")
                    if len(files) > 10:
                        lines.append(f"  ... and {len(files) - 10} more")

            if has_failed:
                lines.insert(2, f"Error: {fail_check.strip()[:200]}")

            return ToolResult(
                content="\n".join(lines),
                metadata={
                    "job_id": job_id,
                    "status": status_text,
                    "local_dir": str(local_dir),
                    "error": fail_check.strip() if has_failed else "",
                    **manifest,
                },
            )
        except Exception as exc:
            return ToolResult(
                content=f"Consume failed: {exc}",
                is_error=True,
            )
        finally:
            client.close()

    def _download_tree(
        self, client, remote_dir: str, local_dir: Path, prefix: str = ""
    ) -> dict:
        """Recursively download all files from remote directory.

        Returns a manifest dict with file counts, sizes, and categories.
        """
        manifest = {
            "total_files": 0,
            "total_size_bytes": 0,
            "categories": {},
            "files": [],
        }

        items = client.list_dir(remote_dir)
        for item in items:
            name = item["name"]
            if name.startswith("."):
                continue

            if item["is_dir"]:
                sub_local = local_dir / name
                sub_local.mkdir(parents=True, exist_ok=True)
                sub_prefix = f"{prefix}{name}/"
                sub_manifest = self._download_tree(
                    client,
                    f"{remote_dir}\\{name}",
                    sub_local,
                    sub_prefix,
                )
                manifest["total_files"] += sub_manifest["total_files"]
                manifest["total_size_bytes"] += sub_manifest["total_size_bytes"]
                for cat, files in sub_manifest.get("categories", {}).items():
                    manifest["categories"].setdefault(cat, []).extend(files)
            else:
                remote_file = f"{remote_dir}\\{name}"
                local_file = local_dir / name
                ok = client.get_file(remote_file, str(local_file))
                if ok:
                    rel_path = f"{prefix}{name}"
                    size = local_file.stat().st_size
                    manifest["total_files"] += 1
                    manifest["total_size_bytes"] += size
                    manifest["files"].append(rel_path)

                    # Categorize
                    category = self._categorize_file(rel_path)
                    manifest["categories"].setdefault(category, []).append(rel_path)

        return manifest

    @staticmethod
    def _categorize_file(path: str) -> str:
        """Categorize a result file by its path prefix."""
        path_lower = path.lower()
        if path_lower.startswith("static/"):
            return "static"
        elif path_lower.startswith("reverse/"):
            return "reverse"
        elif path_lower.startswith("dynamic/"):
            return "dynamic"
        elif path_lower.endswith("_done") or path_lower.endswith("_failed"):
            return "markers"
        elif path_lower.endswith("status.json"):
            return "meta"
        else:
            return "other"
