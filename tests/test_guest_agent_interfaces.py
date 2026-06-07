import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

import chatcli.remote.guest_agent.app as guest_app
from chatcli.remote.job_runner import run_job
from chatcli.tools.remote_guest import RemoteGuestTool


class GuestAgentInterfaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        guest_app.DEFAULT_WORKDIR = self.base
        guest_app.DEFAULT_CASES_DIR = self.base / "cases"
        guest_app.DEFAULT_CASES_DIR.mkdir(parents=True, exist_ok=True)
        (self.base / "outbox").mkdir(parents=True, exist_ok=True)
        guest_app._AGENT_TOKEN = "test-token"
        self.client = TestClient(guest_app.app)
        self.headers = {"Authorization": "Bearer test-token"}

    def tearDown(self):
        self.tmp.cleanup()

    def test_tools_endpoint_exists_and_reports_python(self):
        response = self.client.get("/api/v1/tools", headers=self.headers)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("python", data["tools"])
        self.assertTrue(data["tools"]["python"]["available"])

    def test_tools_endpoint_reports_remote_static_tool_inventory(self):
        ida = self.base / "Program Files" / "IDA Professional 9.0" / "idat.exe"
        ida.parent.mkdir(parents=True)
        ida.write_text("", encoding="utf-8")

        with patch.dict("os.environ", {"IDA_PATH": str(ida)}, clear=False):
            response = self.client.get("/api/v1/tools", headers=self.headers)

        self.assertEqual(response.status_code, 200)
        tools = response.json()["tools"]
        self.assertIn("binary_inspect", tools)
        self.assertIn("strings", tools)
        self.assertIn("capa", tools)
        self.assertIn("floss", tools)
        self.assertIn("yara-python", tools)
        self.assertIn("diec", tools)
        self.assertIn("ida", tools)
        self.assertTrue(tools["ida"]["available"])
        self.assertEqual(tools["ida"]["path"], str(ida))
        self.assertEqual(tools["capa"]["command"].split()[1:3], ["-m", "capa.main"])

    def test_tools_endpoint_auto_detects_common_ida_install_without_env_path(self):
        program_files = self.base / "Program Files"
        ida = program_files / "IDA Professional 9.0" / "idat.exe"
        ida.parent.mkdir(parents=True)
        ida.write_text("", encoding="utf-8")

        with patch.dict(
            "os.environ",
            {
                "CHATCLI_TOOL_IDA": "",
                "IDA_PATH": "",
                "IDAT64_PATH": "",
                "IDAT_PATH": "",
                "IDA64_PATH": "",
                "ProgramFiles": str(program_files),
            },
            clear=False,
        ):
            response = self.client.get("/api/v1/tools", headers=self.headers)

        self.assertEqual(response.status_code, 200)
        tools = response.json()["tools"]
        self.assertTrue(tools["ida"]["available"])
        self.assertEqual(tools["ida"]["path"], str(ida))

    def test_exec_endpoint_runs_authenticated_command(self):
        command = f'"{sys.executable}" -c "print(\'hello-agent\')"'
        response = self.client.post(
            "/api/v1/exec",
            json={"command": command, "workdir": str(self.base)},
            headers=self.headers,
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["exit_code"], 0)
        self.assertIn("hello-agent", data["stdout"])

    def test_status_endpoint_reports_server_metrics(self):
        response = self.client.get("/api/v1/status", headers=self.headers)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("disk", data)
        self.assertIn("tools", data)
        self.assertIn("python", data["tools"])

    def test_security_endpoint_collects_review_snapshot(self):
        response = self.client.get("/api/v1/security/status", headers=self.headers)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "collected")
        self.assertIn("risk_level", data)
        self.assertIn("probes", data)

    def test_monitor_endpoint_collects_observer_snapshot(self):
        case_id = "case-monitor"
        case_dir = guest_app.DEFAULT_CASES_DIR / case_id
        dynamic_dir = self.base / "outbox" / case_id / "dynamic"
        case_dir.mkdir(parents=True)
        dynamic_dir.mkdir(parents=True)
        pcap = dynamic_dir / "network.pcapng"
        pcap.write_bytes(b"pcap")
        (dynamic_dir / "dynamic_status.json").write_text(
            json.dumps({
                "status": "collecting",
                "outputs": {"network_pcap": str(pcap)},
                "events": [{"event": "packet_capture_started"}],
            }),
            encoding="utf-8",
        )

        response = self.client.get(
            f"/api/v1/monitor/snapshot?case_id={case_id}&probes=false",
            headers=self.headers,
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "collected")
        self.assertEqual(data["case_id"], case_id)
        self.assertEqual(data["traffic_capture"]["pcap_bytes"], 4)
        self.assertIn("observer_agents", data)
        self.assertIn("file_activity", data)

    def test_prepare_accepts_remote_sample_path_and_writes_job_json(self):
        sample = self.base / "samples" / "sample.bin"
        sample.parent.mkdir()
        sample.write_bytes(b"sample-bytes")

        response = self.client.post(
            "/api/v1/cases/prepare",
            json={
                "case_id": "case-remote-path",
                "sample_path": str(sample),
                "analysis_plan": {"static": False, "dynamic": True, "network": True},
                "dynamic_config": {"timeout_seconds": 60},
            },
            headers=self.headers,
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["sample_exists"])

        job_path = guest_app.DEFAULT_CASES_DIR / "case-remote-path" / "job.json"
        job = json.loads(job_path.read_text(encoding="utf-8"))
        self.assertEqual(job["sample_path"], str(sample))
        self.assertEqual(job["analysis_plan"]["dynamic"], True)
        self.assertEqual(job["dynamic_config"]["timeout_seconds"], 60)

    def test_job_runner_uses_remote_sample_path(self):
        sample = self.base / "remote-sample.bin"
        sample.write_bytes(b"MZsample")
        job_dir = self.base / "cases" / "case-job-runner"
        job_dir.mkdir(parents=True)
        (job_dir / "job.json").write_text(
            json.dumps({
                "job_id": "case-job-runner",
                "sample_path": str(sample),
                "analysis_plan": {"static": True},
            }),
            encoding="utf-8",
        )

        state = run_job(job_dir, mode="dry_run", outbox_root=self.base / "outbox")

        self.assertEqual(state.status, "done")
        self.assertEqual(state.sample_path, sample)
        self.assertTrue((self.base / "outbox" / "case-job-runner" / "_DONE").exists())

    def test_job_runner_writes_verify_snapshot(self):
        sample = self.base / "remote-sample.bin"
        sample.write_bytes(b"MZsample")
        job_dir = self.base / "cases" / "case-verify"
        job_dir.mkdir(parents=True)
        (job_dir / "job.json").write_text(
            json.dumps({
                "job_id": "case-verify",
                "sample_path": str(sample),
                "analysis_plan": {"static": False, "verify": True},
            }),
            encoding="utf-8",
        )

        state = run_job(job_dir, mode="dry_run", outbox_root=self.base / "outbox")

        verify_path = self.base / "outbox" / "case-verify" / "verify" / "server_status_after.json"
        self.assertEqual(state.status, "done")
        self.assertTrue(verify_path.exists())
        data = json.loads(verify_path.read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "dry_run")
        self.assertEqual(data["sample_sha256"], state.sample_sha256)

    def test_job_runner_dynamic_dry_run_starts_collectors_before_sample(self):
        sample = self.base / "remote-sample.bin"
        sample.write_bytes(b"MZsample")
        job_dir = self.base / "cases" / "case-dynamic-order"
        job_dir.mkdir(parents=True)
        (job_dir / "job.json").write_text(
            json.dumps({
                "job_id": "case-dynamic-order",
                "sample_path": str(sample),
                "analysis_plan": {"static": False, "dynamic": True},
                "dynamic_config": {
                    "timeout_seconds": 30,
                    "collectors": ["pcap", "procmon", "tshark"],
                    "network_interface": "1",
                },
            }),
            encoding="utf-8",
        )

        state = run_job(job_dir, mode="dry_run", outbox_root=self.base / "outbox")

        dynamic_status = self.base / "outbox" / "case-dynamic-order" / "dynamic" / "dynamic_status.json"
        self.assertEqual(state.status, "done")
        data = json.loads(dynamic_status.read_text(encoding="utf-8"))
        events = [event["event"] for event in data["events"]]
        self.assertLess(events.index("would_start_packet_capture"), events.index("would_execute_sample"))
        self.assertLess(events.index("would_start_procmon"), events.index("would_execute_sample"))
        self.assertIn("would_parse_pcap", events)

    def test_remote_guest_tools_formats_remote_inventory(self):
        class FakeClient:
            def list_tools(self):
                return {
                    "tools": {
                        "ida": {
                            "kind": "headless_reverse",
                            "path": r"C:\Program Files\IDA Professional 9.0\idat.exe",
                            "available": True,
                        },
                        "capa": {
                            "kind": "analysis_python",
                            "package": "flare-capa",
                            "command": r'"C:\Python310\python.exe" -m capa.main <sample> -j',
                            "available": True,
                        },
                        "diec": {
                            "kind": "static_external",
                            "path": "diec",
                            "available": False,
                        },
                    }
                }

            def close(self):
                pass

        config = SimpleNamespace(
            remote=SimpleNamespace(
                enabled=True,
                base_url="http://remote:8443",
                host="",
                guest_agent_port=8443,
                guest_agent_token="token",
            )
        )
        tool = RemoteGuestTool(config)
        with patch.object(tool, "_get_client", return_value=FakeClient()):
            result = tool.execute(action="tools")

        self.assertFalse(result.is_error)
        self.assertIn("Remote server analysis tools", result.content)
        self.assertIn("OK ida [headless_reverse]", result.content)
        self.assertIn("OK capa [analysis_python]", result.content)
        self.assertIn("MISSING diec [static_external]", result.content)

    def test_remote_guest_monitor_formats_observer_snapshot(self):
        class FakeClient:
            def monitor_snapshot(self, case_id="", probes=True):
                return {
                    "hostname": "remote-host",
                    "case_id": case_id,
                    "dynamic_status": {"status": "collecting"},
                    "traffic_capture": {"pcap_bytes": 42, "active": True},
                    "file_activity": [{"path": "x", "mtime": 1, "size": 1}],
                    "observer_agents": [
                        {
                            "name": "process-observer",
                            "status": "ok",
                            "summary": "Process snapshot collected.",
                        }
                    ],
                }

            def close(self):
                pass

        config = SimpleNamespace(
            remote=SimpleNamespace(
                enabled=True,
                base_url="http://remote:8443",
                host="",
                guest_agent_port=8443,
                guest_agent_token="token",
            )
        )
        tool = RemoteGuestTool(config)
        with patch.object(tool, "_get_client", return_value=FakeClient()):
            result = tool.execute(action="monitor", case_id="case-monitor")

        self.assertFalse(result.is_error)
        self.assertIn("Monitor snapshot: remote-host", result.content)
        self.assertIn("Dynamic status: collecting", result.content)
        self.assertIn("process-observer", result.content)


if __name__ == "__main__":
    unittest.main()
