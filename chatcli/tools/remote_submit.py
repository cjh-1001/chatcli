"""Upload samples to remote analysis server."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .base import Tool, ToolResult


class RemoteSubmitTool(Tool):
    """Upload a local file to the remote analysis server's inbox directory."""

    name = "remote_submit"
    description = (
        "Upload a local file or sample to the remote analysis server. The file "
        "is placed in the remote inbox directory for analysis. Returns the "
        "remote path and SHA-256 hash of the uploaded file."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Local file path to upload.",
            },
            "job_id": {
                "type": "string",
                "description": "Optional job ID for organizing analysis tasks. "
                "Auto-generated from file hash if not provided.",
            },
            "remote_dir": {
                "type": "string",
                "description": "Remote target directory. Default: C:\\analysis\\inbox.",
            },
        },
        "required": ["file_path"],
    }

    def __init__(self, config=None) -> None:
        self._config = config

    def execute(
        self,
        file_path: str,
        job_id: str = "",
        remote_dir: str = "",
        **kwargs,
    ) -> ToolResult:
        remote = getattr(self._config, "remote", None) if self._config else None
        if remote is None or not remote.enabled:
            return ToolResult(
                content="remote_submit: remote server is not configured.",
                is_error=True,
            )

        local = Path(file_path).expanduser().resolve()
        if not local.is_file():
            return ToolResult(
                content=f"File not found: {local}",
                is_error=True,
            )

        # Compute SHA-256
        sha256 = hashlib.sha256()
        with open(local, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()

        if not job_id:
            job_id = file_hash[:16]

        inbox = remote_dir or f"{remote.remote_analysis_dir}\\inbox"
        remote_path = f"{inbox}\\{job_id}\\sample\\{local.name}"

        from chatcli.remote.ssh_client import SSHClient

        client = SSHClient(
            host=remote.host,
            user=remote.user,
            port=remote.port,
            key_file=remote.key_file,
            password=remote.password,
        )
        try:
            # Ensure remote directory exists
            remote_sample_dir = f"{inbox}\\{job_id}\\sample"
            client.exec(f"mkdir {remote_sample_dir}", timeout=10)

            # Upload
            ok = client.put_file(str(local), remote_path)
        except Exception as exc:
            return ToolResult(
                content=f"Upload failed: {exc}",
                is_error=True,
            )
        finally:
            client.close()

        if not ok:
            return ToolResult(
                content=f"SFTP upload failed: {local} -> {remote_path}",
                is_error=True,
            )

        return ToolResult(
            content=(
                f"Uploaded: {local.name}\n"
                f"  Remote path: {remote_path}\n"
                f"  SHA-256: {file_hash}\n"
                f"  Job ID: {job_id}\n"
                f"  Size: {local.stat().st_size:,} bytes"
            ),
            metadata={
                "job_id": job_id,
                "remote_path": remote_path,
                "sha256": file_hash,
                "size_bytes": local.stat().st_size,
                "filename": local.name,
            },
        )
