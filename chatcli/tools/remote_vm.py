"""Tencent Cloud Lighthouse VM control via chatcli tool."""

from __future__ import annotations

import json

from .base import Tool, ToolResult


class RemoteVMControlTool(Tool):
    """Control Tencent Cloud Lighthouse VM: start, stop, restore snapshot, query status."""

    name = "remote_vm_control"
    description = (
        "Control the Tencent Cloud Lighthouse VM used for dynamic analysis. "
        "Supports: status (query instance state), start, stop, restore_snapshot. "
        "All write operations (start/stop/restore) have dual-gate protection: "
        "they only execute when confirmed_instance_id matches the real instance ID. "
        "Use dry_run=true to preview what would happen without actually executing."
    )
    parameters = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "description": "Action: status, start, stop, restore_snapshot.",
                "enum": ["status", "start", "stop", "restore_snapshot"],
            },
            "dry_run": {
                "type": "boolean",
                "description": "If true, preview the action without executing. Default true for write ops.",
            },
        },
        "required": ["action"],
    }

    def __init__(self, config=None) -> None:
        self._config = config

    def execute(
        self,
        action: str,
        dry_run: bool | None = None,
        **kwargs,
    ) -> ToolResult:
        remote = getattr(self._config, "remote", None) if self._config else None
        if remote is None or not remote.enabled:
            return ToolResult(
                content="remote_vm_control: remote server is not configured.",
                is_error=True,
            )

        # Resolve Tencent Cloud credentials
        secret_id = remote.tencent_secret_id
        secret_key = remote.tencent_secret_key
        region = remote.tencent_region or "ap-guangzhou"
        instance_id = remote.tencent_instance_id
        confirmed_instance_id = remote.tencent_instance_id  # must match for writes
        confirmed_snapshot_id = remote.tencent_snapshot_id

        if not instance_id:
            return ToolResult(
                content="remote_vm_control: tencent_instance_id is not configured. "
                "Set it in config.yaml under remote: tencent_instance_id.",
                is_error=True,
            )

        from chatcli.remote.tencent.adapter import LighthouseAdapter

        write_ops = {"start", "stop", "restore_snapshot"}
        is_write = action in write_ops
        effective_dry_run = dry_run if dry_run is not None else is_write

        adapter = LighthouseAdapter(
            secret_id=secret_id,
            secret_key=secret_key,
            region=region,
            instance_id=instance_id,
            confirmed_instance_id=confirmed_instance_id,
            confirmed_snapshot_id=confirmed_snapshot_id,
            mode="real" if secret_id and secret_key else "mock",
            dry_run=effective_dry_run,
        )

        try:
            if action == "status":
                status = adapter.get_instance_status()
                return ToolResult(
                    content=(
                        f"Instance: {status.instance_id} ({status.name})\n"
                        f"  State: {status.state}\n"
                        f"  Control plane: {'ready' if status.control_plane_ready else 'busy'}\n"
                        f"  Guest access: {'ready' if status.guest_access_ready else 'not ready'}\n"
                        f"  Public IPs: {list(status.public_ipv4) if status.public_ipv4 else 'none'}\n"
                        f"  OS: {status.os_name}\n"
                        f"  Latest operation: {status.latest_operation or 'none'} "
                        f"({status.latest_operation_state or 'n/a'})\n"
                        f"  Blocked reason: {status.blocked_reason or 'none'}\n"
                        f"  Operations allowed: {json.dumps(status.operation_allowed())}"
                    ),
                    metadata={"instance_status": status.to_dict()},
                )

            elif action == "start":
                resp = adapter.start_vm()
                return ToolResult(
                    content=resp.message,
                    is_error=resp.status not in ("success", "dry-run", "mock"),
                    metadata={"response": resp.data, "dry_run": resp.dry_run},
                )

            elif action == "stop":
                resp = adapter.stop_vm()
                return ToolResult(
                    content=resp.message,
                    is_error=resp.status not in ("success", "dry-run", "mock"),
                    metadata={"response": resp.data, "dry_run": resp.dry_run},
                )

            elif action == "restore_snapshot":
                resp = adapter.restore_snapshot()
                return ToolResult(
                    content=resp.message,
                    is_error=resp.status not in ("success", "dry-run", "mock"),
                    metadata={"response": resp.data, "dry_run": resp.dry_run},
                )

            else:
                return ToolResult(
                    content=f"Unknown action: {action}",
                    is_error=True,
                )

        except Exception as exc:
            return ToolResult(
                content=f"VM operation failed: {exc}",
                is_error=True,
            )
