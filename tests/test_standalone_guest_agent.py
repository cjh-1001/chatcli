import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from fastapi.testclient import TestClient

import server.chatcli_guest_agent as standalone


class StandaloneGuestAgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        standalone.BASE_DIR = self.base
        standalone.CASES_DIR = self.base / "cases"
        standalone.OUTBOX_DIR = self.base / "outbox"
        standalone.AGENT_TOKEN = "test-token"
        standalone.CASES_DIR.mkdir(parents=True, exist_ok=True)
        standalone.OUTBOX_DIR.mkdir(parents=True, exist_ok=True)
        self.client = TestClient(standalone.app)
        self.headers = {"Authorization": "Bearer test-token"}

    def tearDown(self):
        self.tmp.cleanup()

    def test_health_and_status_do_not_need_chatcli_package(self):
        health = self.client.get("/api/v1/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()["status"], "healthy")

        status = self.client.get("/api/v1/status", headers=self.headers)
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json()["status"], "ok")

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

    def test_remote_sample_path_dry_run(self):
        sample = self.base / "sample.exe"
        sample.write_bytes(b"MZsample")

        prepared = self.client.post(
            "/api/v1/cases/prepare",
            json={
                "case_id": "case-standalone",
                "sample_path": str(sample),
                "analysis_plan": {"static": True, "ida": True, "ghidra": True, "dynamic": True, "network": True, "verify": True},
            },
            headers=self.headers,
        )
        self.assertEqual(prepared.status_code, 200)
        self.assertTrue(prepared.json()["sample_exists"])

        run = self.client.post(
            "/api/v1/cases/case-standalone/run",
            json={"mode": "dry_run"},
            headers=self.headers,
        )
        self.assertEqual(run.status_code, 200)
        self.assertEqual(run.json()["status"], "done")
        self.assertIn("reverse.ida_headless (dry_run)", run.json()["steps_completed"])
        self.assertIn("reverse.ghidra_headless (dry_run)", run.json()["steps_completed"])
        self.assertTrue((self.base / "outbox" / "case-standalone" / "_DONE").exists())
        dynamic_status = self.base / "outbox" / "case-standalone" / "dynamic" / "dynamic_status.json"
        self.assertTrue(dynamic_status.exists())
        self.assertIn("procmon", dynamic_status.read_text(encoding="utf-8"))
        self.assertTrue(
            (self.base / "outbox" / "case-standalone" / "verify" / "server_status_after.json").exists()
        )


if __name__ == "__main__":
    unittest.main()
