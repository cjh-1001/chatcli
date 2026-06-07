"""HTTP client for Guest Agent — chatcli side.

Synchronous wrapper around httpx for all Guest Agent endpoints.
Used by the remote_guest tool.
"""

from __future__ import annotations

import logging
from pathlib import Path

import httpx

logger = logging.getLogger("chatcli.remote.guest_client")


class GuestAgentClient:
    """HTTP client for the remote chatcli Guest Agent."""

    def __init__(
        self,
        base_url: str,
        token: str,
        timeout: float = 300.0,
        verify: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.verify = verify
        self._client: httpx.Client | None = None

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                timeout=httpx.Timeout(self.timeout),
                verify=self.verify,
            )
        return self._client

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    # ── Health ──────────────────────────────────────────────

    def health(self) -> dict:
        r = self.client.get(f"{self.base_url}/api/v1/health")
        r.raise_for_status()
        return r.json()

    def server_status(self, probes: bool = False) -> dict:
        """Return remote server metrics and recent case status."""
        r = self.client.get(
            f"{self.base_url}/api/v1/status",
            params={"probes": "true" if probes else "false"},
            headers=self._headers(),
        )
        r.raise_for_status()
        return r.json()

    def security_status(self) -> dict:
        """Return defensive post-analysis indicators from the remote server."""
        r = self.client.get(
            f"{self.base_url}/api/v1/security/status",
            headers=self._headers(),
        )
        r.raise_for_status()
        return r.json()

    def monitor_snapshot(self, case_id: str = "", probes: bool = True) -> dict:
        """Return live monitor telemetry and observer-agent summaries."""
        params: dict[str, str] = {"probes": "true" if probes else "false"}
        if case_id:
            params["case_id"] = case_id
        r = self.client.get(
            f"{self.base_url}/api/v1/monitor/snapshot",
            params=params,
            headers=self._headers(),
        )
        r.raise_for_status()
        return r.json()

    # ── Case management ─────────────────────────────────────

    def prepare_case(
        self,
        case_id: str = "",
        analysis_plan: dict | None = None,
        sample_path: str = "",
        dynamic_config: dict | None = None,
    ) -> dict:
        """Create a new analysis case. Returns {case_id, status, case_dir}."""
        body = {}
        if case_id:
            body["case_id"] = case_id
        if analysis_plan:
            body["analysis_plan"] = analysis_plan
        else:
            body["analysis_plan"] = {"static": True}
        if sample_path:
            body["sample_path"] = sample_path
        if dynamic_config:
            body["dynamic_config"] = dynamic_config

        r = self.client.post(
            f"{self.base_url}/api/v1/cases/prepare",
            json=body,
            headers=self._headers(),
        )
        r.raise_for_status()
        return r.json()

    def upload_sample(self, case_id: str, file_path: str) -> dict:
        """Upload a sample file. Returns {case_id, filename, sha256, size_bytes}."""
        path = Path(file_path).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"Sample not found: {path}")

        with open(path, "rb") as f:
            r = self.client.post(
                f"{self.base_url}/api/v1/cases/{case_id}/sample",
                files={"file": (path.name, f, "application/octet-stream")},
                headers=self._headers(),
            )
        r.raise_for_status()
        return r.json()

    def run_analysis(
        self,
        case_id: str,
        mode: str = "real",
        sample_path: str = "",
        analysis_plan: dict | None = None,
        dynamic_config: dict | None = None,
    ) -> dict:
        """Trigger analysis. Returns {case_id, status}."""
        body: dict = {"mode": mode}
        if sample_path:
            body["sample_path"] = sample_path
        if analysis_plan:
            body["analysis_plan"] = analysis_plan
        if dynamic_config:
            body["dynamic_config"] = dynamic_config
        r = self.client.post(
            f"{self.base_url}/api/v1/cases/{case_id}/run",
            json=body,
            headers=self._headers(),
        )
        r.raise_for_status()
        return r.json()

    def case_status(self, case_id: str) -> dict:
        """Get case status including progress and result files."""
        r = self.client.get(
            f"{self.base_url}/api/v1/cases/{case_id}/status",
            headers=self._headers(),
        )
        r.raise_for_status()
        return r.json()

    def download_results(self, case_id: str, output_dir: str = "") -> str:
        """Download results ZIP. Returns local file path."""
        out = Path(output_dir) if output_dir else Path(".chatcli/remote_results")
        out.mkdir(parents=True, exist_ok=True)

        r = self.client.get(
            f"{self.base_url}/api/v1/cases/{case_id}/results",
            headers=self._headers(),
        )
        r.raise_for_status()

        zip_path = out / f"{case_id}_results.zip"
        zip_path.write_bytes(r.content)
        logger.info("Downloaded %d bytes to %s", len(r.content), zip_path)

        # Extract
        import zipfile
        extract_dir = out / case_id
        if extract_dir.exists():
            import shutil
            shutil.rmtree(extract_dir)
        extract_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(extract_dir)
        logger.info("Extracted to %s", extract_dir)

        return str(extract_dir)

    def exec_command(self, command: str, timeout: int = 300, workdir: str = "") -> dict:
        """Execute an analysis command on the remote server via /api/v1/exec."""
        body: dict = {"command": command, "timeout": timeout}
        if workdir:
            body["workdir"] = workdir
        r = self.client.post(
            f"{self.base_url}/api/v1/exec",
            json=body,
            headers=self._headers(),
        )
        r.raise_for_status()
        return r.json()

    def list_tools(self) -> dict:
        """Get configured tool paths and availability."""
        r = self.client.get(
            f"{self.base_url}/api/v1/tools",
            headers=self._headers(),
        )
        r.raise_for_status()
        return r.json()

    def list_cases(self) -> dict:
        """List all cases."""
        r = self.client.get(
            f"{self.base_url}/api/v1/cases",
            headers=self._headers(),
        )
        r.raise_for_status()
        return r.json()

    def close(self):
        if self._client is not None:
            self._client.close()
            self._client = None
