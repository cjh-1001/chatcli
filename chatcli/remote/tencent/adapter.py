"""Tencent Cloud Lighthouse adapter — VM lifecycle management.

Adapted from Cloud-AV-Agent-Lab adapter.py. Simplified for chatcli:
- Uses httpx instead of custom NetworkClient
- VM identified by instance_id string instead of VmProfile
- Dual-gate: all write ops require mode="real" + dry_run=False + confirmed_id match

API version pinned to 2020-03-24 (Lighthouse).
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx

from .auth import resolve_tencent_cloud_auth
from .errors import TencentCloudApiError, TencentCloudConfigError
from .models import (
    DEFAULT_POLL_INTERVAL_SECONDS,
    DEFAULT_POLL_TIMEOUT_SECONDS,
    LighthouseInstanceStatus,
    TencentCloudAuth,
)
from .signing import build_tc3_headers

logger = logging.getLogger("chatcli.remote.tencent")

LIGHTHOUSE_ENDPOINT = "https://lighthouse.tencentcloudapi.com"
LIGHTHOUSE_VERSION = "2020-03-24"


# ── Response type ─────────────────────────────────────────────────


@dataclass(frozen=True)
class VMOperationResponse:
    """Result of a Lighthouse API operation."""

    status: str  # "success" | "dry-run" | "error"
    task_id: str  # RequestId from API
    message: str
    action: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=dict)
    dry_run: bool = False

    def __str__(self) -> str:
        return self.message


# ── Adapter ───────────────────────────────────────────────────────


class LighthouseAdapter:
    """Tencent Cloud Lighthouse API client with dual-gate safety.

    All write operations (start, stop, restore_snapshot) require three
    conditions to execute for real:
      1. mode == "real" (not "mock")
      2. dry_run == False
      3. confirmed_instance_id matches the target instance

    Without all three, operations return a dry-run response with a
    "[DRY-RUN] Would call: ..." message.
    """

    def __init__(
        self,
        secret_id: str = "",
        secret_key: str = "",
        region: str = "ap-guangzhou",
        instance_id: str = "",
        confirmed_instance_id: str = "",
        confirmed_snapshot_id: str = "",
        mode: str = "real",
        dry_run: bool = True,
        poll_timeout_seconds: float = DEFAULT_POLL_TIMEOUT_SECONDS,
        poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
        client: httpx.Client | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        self.auth = resolve_tencent_cloud_auth(
            secret_id=secret_id,
            secret_key=secret_key,
            region=region,
            env=env,
        )
        self.instance_id = instance_id.strip()
        self.confirmed_instance_id = confirmed_instance_id.strip()
        self.confirmed_snapshot_id = confirmed_snapshot_id.strip()
        self.mode = mode.casefold()
        if self.mode not in {"real", "mock"}:
            raise TencentCloudConfigError(
                "LighthouseAdapter mode must be 'real' or 'mock'"
            )
        self.dry_run = dry_run
        self.poll_timeout_seconds = poll_timeout_seconds
        self.poll_interval_seconds = poll_interval_seconds
        self._client = client

    @property
    def supports_execution(self) -> bool:
        return (
            self.mode == "real"
            and not self.dry_run
            and bool(self.confirmed_instance_id)
        )

    def _build_client(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        return httpx.Client(timeout=httpx.Timeout(30.0))

    # ── Public API ────────────────────────────────────────────

    def describe_instance(self) -> VMOperationResponse:
        """Query instance status via DescribeInstances."""
        return self._operation(
            "DescribeInstances",
            {"InstanceIds": [self.instance_id]},
        )

    def start_vm(self) -> VMOperationResponse:
        """Start the instance (must be STOPPED)."""
        return self._write_operation(
            "StartInstances",
            {"InstanceIds": [self.instance_id]},
            target_state="RUNNING",
        )

    def stop_vm(self) -> VMOperationResponse:
        """Stop the instance (must be RUNNING)."""
        return self._write_operation(
            "StopInstances",
            {"InstanceIds": [self.instance_id]},
            target_state="STOPPED",
        )

    def restore_snapshot(self, snapshot_id: str = "") -> VMOperationResponse:
        """Restore instance from a baseline snapshot."""
        snap = snapshot_id or self.confirmed_snapshot_id
        return self._restore_snapshot_operation(
            "ApplyInstanceSnapshot",
            {"InstanceId": self.instance_id, "SnapshotId": snap},
        )

    def wait_instance_status(
        self,
        target_state: str,
        timeout_seconds: float | None = None,
    ) -> LighthouseInstanceStatus:
        """Poll until the instance reaches target_state."""
        return self._wait_instance_statuses(
            (target_state.upper(),),
            timeout_seconds=timeout_seconds,
        )

    def get_instance_status(self) -> LighthouseInstanceStatus:
        """Get parsed LighthouseInstanceStatus (convenience, raises on error)."""
        response = self.describe_instance()
        if response.status != "success":
            raise TencentCloudConfigError(
                f"Failed to get instance status: {response.message}"
            )
        return parse_lighthouse_instance_status(
            response.data, expected_instance_id=self.instance_id
        )

    # ── Internal: operation dispatch ──────────────────────────

    def _operation(
        self,
        action: str,
        params: Mapping[str, object] | None = None,
    ) -> VMOperationResponse:
        params = dict(params or {})
        if self.dry_run:
            return VMOperationResponse(
                status="dry-run",
                action=action,
                params=params,
                message=(
                    f"[DRY-RUN] Would call: {action} with "
                    f"Params: {params}"
                ),
                dry_run=True,
                task_id="",
            )

        if self.mode == "mock":
            return VMOperationResponse(
                status="mock",
                action=action,
                params=params,
                message=(
                    f"tencent-cloud mock: {action} {self.instance_id} "
                    f"in {self.auth.region}"
                ),
                dry_run=False,
                task_id="",
            )

        return self._call_api(action, params)

    def _write_operation(
        self,
        action: str,
        params: Mapping[str, object],
        target_state: str,
    ) -> VMOperationResponse:
        instance_id = self.instance_id
        if (
            self.mode == "real"
            and not self.dry_run
            and self.confirmed_instance_id != instance_id
        ):
            return VMOperationResponse(
                status="dry-run",
                action=action,
                params=dict(params),
                message=(
                    f"[DRY-RUN] Would call: {action} with "
                    f"Params: {dict(params)} "
                    "(write confirmation missing or mismatched — "
                    "set confirmed_instance_id to enable real writes)"
                ),
                dry_run=True,
                task_id="",
            )

        response = self._operation(action, params)
        if response.status != "success" or self.dry_run or self.mode != "real":
            return response

        logger.info(
            "API Request Accepted, RequestId: %s",
            response.task_id or "<empty>",
        )
        final_status = self._wait_instance_statuses(
            (target_state.upper(),),
            expected_latest_operation=action,
            expected_operation_request_id=response.task_id,
        )
        data = dict(response.data)
        data["FinalInstanceStatus"] = final_status.to_dict()
        return VMOperationResponse(
            status=response.status,
            task_id=response.task_id,
            message=(
                f"{response.message}; {final_status.instance_id} "
                f"reached {final_status.state}"
            ),
            action=action,
            params=response.params,
            data=data,
            dry_run=False,
        )

    def _restore_snapshot_operation(
        self,
        action: str,
        params: Mapping[str, object],
    ) -> VMOperationResponse:
        instance_id = self.instance_id
        snapshot_id = str(params.get("SnapshotId", ""))
        if (
            self.mode == "real"
            and not self.dry_run
            and (
                self.confirmed_instance_id != instance_id
                or self.confirmed_snapshot_id != snapshot_id
            )
        ):
            return VMOperationResponse(
                status="dry-run",
                action=action,
                params=dict(params),
                message=(
                    f"[DRY-RUN] Would call: {action} with "
                    f"Params: {dict(params)} "
                    "(restore confirmation missing or mismatched — "
                    "set confirmed_instance_id and confirmed_snapshot_id)"
                ),
                dry_run=True,
                task_id="",
            )

        if self.mode != "real" or self.dry_run:
            return self._operation(action, params)

        # Precheck: instance must be STOPPED
        precheck = self.get_instance_status()
        if precheck.latest_operation_state == "FAILED":
            raise TencentCloudConfigError(
                "Cannot restore snapshot because latest operation failed: "
                f"{precheck.latest_operation or '<unknown>'}"
            )
        if precheck.state == "RUNNING":
            raise TencentCloudConfigError(
                f"Cannot restore snapshot for {instance_id}: instance is "
                "RUNNING; stop the instance first"
            )
        if precheck.state != "STOPPED":
            raise TencentCloudConfigError(
                f"Cannot restore snapshot for {instance_id}: instance state "
                f"is {precheck.state}; expected STOPPED"
            )

        response = self._operation(action, params)
        if response.status != "success":
            return response

        logger.info(
            "API Request Accepted, RequestId: %s",
            response.task_id or "<empty>",
        )
        post = self._wait_snapshot_restore_settled(action, response.task_id)
        data = dict(response.data)
        data["PrecheckInstanceStatus"] = precheck.to_dict()
        data["PostRestoreInstanceStatus"] = post.to_dict()

        if post.state != "RUNNING":
            logger.info(
                "Snapshot restore completed with state=%s; starting %s",
                post.state,
                post.instance_id,
            )
            start_resp = self.start_vm()
            data["StartAfterRestore"] = start_resp.data
            final = start_resp.data.get("FinalInstanceStatus", {})
            data["FinalInstanceStatus"] = final
        else:
            data["FinalInstanceStatus"] = post.to_dict()

        final_data = data.get("FinalInstanceStatus")
        final_state = (
            final_data.get("state", "<unknown>")
            if isinstance(final_data, dict)
            else "<unknown>"
        )
        return VMOperationResponse(
            status=response.status,
            task_id=response.task_id,
            message=(
                f"{response.message}; {instance_id} snapshot restored "
                f"and reached {final_state}"
            ),
            action=action,
            params=response.params,
            data=data,
            dry_run=False,
        )

    # ── Internal: API call ────────────────────────────────────

    def _call_api(
        self, action: str, params: Mapping[str, object]
    ) -> VMOperationResponse:
        if not self.auth.secret_id or not self.auth.secret_key:
            raise TencentCloudConfigError(
                "TENCENTCLOUD_SECRET_ID and TENCENTCLOUD_SECRET_KEY are "
                "required for real Tencent Cloud API calls"
            )

        timestamp = int(time.time())
        headers = build_tc3_headers(
            secret_id=self.auth.secret_id,
            secret_key=self.auth.secret_key,
            endpoint=LIGHTHOUSE_ENDPOINT,
            action=action,
            version=LIGHTHOUSE_VERSION,
            region=self.auth.region,
            payload=params,
            timestamp=timestamp,
        )

        client = self._build_client()
        try:
            resp = client.post(
                LIGHTHOUSE_ENDPOINT,
                json=dict(params),
                headers=headers,
            )
            resp.raise_for_status()
            body = resp.json()
        except httpx.HTTPError as exc:
            raise TencentCloudConfigError(
                f"Tencent Cloud {action} request failed: {exc}"
            ) from exc

        if not isinstance(body, dict):
            raise TencentCloudConfigError(
                f"Tencent Cloud {action} response JSON must be an object"
            )

        response_payload = body.get("Response")
        if not isinstance(response_payload, dict):
            raise TencentCloudConfigError(
                f"Tencent Cloud {action} response missing Response object"
            )

        error = response_payload.get("Error")
        request_id = str(response_payload.get("RequestId", ""))
        if isinstance(error, dict):
            raise TencentCloudApiError(
                code=str(error.get("Code", "UnknownError")),
                message=str(error.get("Message", "")),
                request_id=request_id,
            )

        data: dict[str, object] = dict(response_payload)
        instance_status: LighthouseInstanceStatus | None = None
        if action == "DescribeInstances":
            instance_status = parse_lighthouse_instance_status(
                response_payload,
                expected_instance_id=self.instance_id,
            )
            data["InstanceStatus"] = instance_status.to_dict()

        message = (
            f"tencent-cloud lighthouse: {action} accepted"
            + (f" (RequestId: {request_id})" if request_id else "")
        )
        if instance_status is not None:
            message = (
                f"{message}; {instance_status.instance_id} "
                f"state={instance_status.state} "
                f"guest_access_ready={instance_status.guest_access_ready}"
            )

        return VMOperationResponse(
            status="success",
            action=action,
            params=dict(params),
            data=data,
            message=message,
            dry_run=False,
            task_id=request_id,
        )

    # ── Internal: polling ─────────────────────────────────────

    def _wait_instance_statuses(
        self,
        target_states: tuple[str, ...],
        timeout_seconds: float | None = None,
        expected_latest_operation: str = "",
        expected_operation_request_id: str = "",
    ) -> LighthouseInstanceStatus:
        timeout = (
            self.poll_timeout_seconds
            if timeout_seconds is None
            else float(timeout_seconds)
        )
        poll_interval = self.poll_interval_seconds
        started_at = time.monotonic()
        deadline = started_at + timeout

        while True:
            response = self.describe_instance()
            if response.status != "success":
                raise TencentCloudConfigError(
                    f"Polling DescribeInstances failed: {response.message}"
                )
            status = parse_lighthouse_instance_status(
                response.data,
                expected_instance_id=self.instance_id,
            )
            elapsed = time.monotonic() - started_at
            logger.info(
                "Polling %s: state=%s, latest_operation=%s, "
                "latest_operation_state=%s, waited=%.1fs",
                status.instance_id,
                status.state,
                status.latest_operation or "<none>",
                status.latest_operation_state or "<none>",
                elapsed,
            )

            if status.latest_operation_state == "FAILED":
                raise TencentCloudConfigError(
                    "Lighthouse operation failed while waiting for "
                    f"{self.instance_id}: "
                    f"{status.latest_operation or '<unknown>'}"
                )

            if (
                status.state in target_states
                and status.control_plane_ready
                and _matches_expected_operation(
                    status,
                    expected_latest_operation,
                    expected_operation_request_id,
                )
            ):
                return status

            now = time.monotonic()
            if now >= deadline:
                raise TencentCloudConfigError(
                    f"Timed out waiting for {self.instance_id} to reach "
                    f"{'/'.join(target_states)}; "
                    f"last state={status.state}, "
                    f"latest_operation_state={status.latest_operation_state}"
                )

            time.sleep(
                min(max(poll_interval, 0.0), max(deadline - now, 0.0))
            )

    def _wait_snapshot_restore_settled(
        self,
        action: str,
        request_id: str,
    ) -> LighthouseInstanceStatus:
        timeout = self.poll_timeout_seconds
        poll_interval = self.poll_interval_seconds
        started_at = time.monotonic()
        deadline = started_at + timeout

        while True:
            response = self.describe_instance()
            if response.status != "success":
                raise TencentCloudConfigError(
                    f"Polling after snapshot restore failed: {response.message}"
                )
            status = parse_lighthouse_instance_status(
                response.data,
                expected_instance_id=self.instance_id,
            )
            elapsed = time.monotonic() - started_at
            logger.info(
                "Polling snapshot restore %s: state=%s, latest_operation=%s, "
                "latest_operation_state=%s, waited=%.1fs",
                status.instance_id,
                status.state,
                status.latest_operation or "<none>",
                status.latest_operation_state or "<none>",
                elapsed,
            )

            if status.latest_operation_state == "FAILED":
                raise TencentCloudConfigError(
                    "Lighthouse snapshot restore failed for "
                    f"{self.instance_id}: "
                    f"{status.latest_operation or '<unknown>'}"
                )

            restore_settled = (
                status.latest_operation == action
                and status.latest_operation_request_id == request_id
                and status.state in {"STOPPED", "RUNNING"}
                and status.control_plane_ready
            )
            already_running = (
                status.state == "RUNNING"
                and status.control_plane_ready
            )
            if restore_settled or already_running:
                return status

            now = time.monotonic()
            if now >= deadline:
                raise TencentCloudConfigError(
                    f"Timed out waiting for snapshot restore on "
                    f"{self.instance_id}; "
                    f"last state={status.state}, "
                    f"latest_operation_state={status.latest_operation_state}"
                )

            time.sleep(
                min(max(poll_interval, 0.0), max(deadline - now, 0.0))
            )


# ── Parsing helpers ───────────────────────────────────────────────


def parse_lighthouse_instance_status(
    response_payload: Mapping[str, object],
    expected_instance_id: str = "",
) -> LighthouseInstanceStatus:
    """Parse DescribeInstances response into LighthouseInstanceStatus."""
    instance_set = response_payload.get("InstanceSet")
    if not isinstance(instance_set, list):
        raise TencentCloudConfigError(
            "DescribeInstances response missing InstanceSet list"
        )

    instances = [item for item in instance_set if isinstance(item, Mapping)]
    if expected_instance_id:
        instances = [
            item
            for item in instances
            if _as_str(item.get("InstanceId")) == expected_instance_id
        ]

    if not instances:
        suffix = f" for {expected_instance_id}" if expected_instance_id else ""
        raise TencentCloudConfigError(
            f"DescribeInstances returned no Lighthouse instance{suffix}"
        )
    if len(instances) > 1:
        raise TencentCloudConfigError(
            "DescribeInstances returned multiple instances; "
            "specify a single expected instance"
        )

    instance = instances[0]
    internet = _as_mapping(instance.get("InternetAccessible"))
    return LighthouseInstanceStatus(
        instance_id=_as_str(instance.get("InstanceId")),
        name=_as_str(instance.get("InstanceName")),
        state=_as_str(instance.get("InstanceState")),
        restrict_state=_as_str(instance.get("InstanceRestrictState")),
        latest_operation=_as_str(instance.get("LatestOperation")),
        latest_operation_state=_as_str(instance.get("LatestOperationState")),
        latest_operation_request_id=_as_str(
            instance.get("LatestOperationRequestId")
        ),
        zone=_as_str(instance.get("Zone")),
        platform=_as_str(instance.get("Platform")),
        os_name=_as_str(instance.get("OsName")),
        private_ipv4=_as_string_tuple(instance.get("PrivateAddresses")),
        public_ipv4=_as_string_tuple(instance.get("PublicAddresses")),
        public_ipv4_assigned=_as_bool(internet.get("PublicIpAssigned")),
        created_time=_as_str(instance.get("CreatedTime")),
        expired_time=_as_str(instance.get("ExpiredTime")),
        request_id=_as_str(response_payload.get("RequestId")),
        total_count=_as_int(response_payload.get("TotalCount")),
    )


def _matches_expected_operation(
    status: LighthouseInstanceStatus,
    expected_latest_operation: str,
    expected_operation_request_id: str,
) -> bool:
    if (
        expected_latest_operation
        and status.latest_operation != expected_latest_operation
    ):
        return False
    if (
        expected_operation_request_id
        and status.latest_operation_request_id != expected_operation_request_id
    ):
        return False
    return True


# ── Type coercion helpers ─────────────────────────────────────────


def _as_mapping(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    return {}


def _as_str(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return False


def _as_int(value: object) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    try:
        return int(_as_str(value))
    except ValueError:
        return 0


def _as_string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(_as_str(item) for item in value if item is not None)
