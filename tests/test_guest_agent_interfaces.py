import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

import chatcli.remote.guest_agent.app as guest_app
from chatcli.remote.behavior_hypotheses import derive_static_behavior_targets
from chatcli.remote.job_runner import run_job
from chatcli.remote.procmon_screen import screen_procmon_csv
from chatcli.tools.remote_batch import RemoteBatchAnalyzeTool
from chatcli.tools.remote_guest import RemoteGuestTool
from chatcli.ui_work import WorkCommandMixin


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
        self.assertIn("sysmon", tools)
        self.assertIn("x64dbg", tools)
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

    def test_exec_endpoint_truncates_large_output_before_response(self):
        command = (
            f'"{sys.executable}" -c "import sys; '
            "sys.stdout.write('A'*70000); sys.stderr.write('B'*13000)\""
        )
        response = self.client.post(
            "/api/v1/exec",
            json={"command": command, "workdir": str(self.base)},
            headers=self.headers,
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["exit_code"], 0)
        self.assertTrue(data["stdout_truncated"])
        self.assertTrue(data["stderr_truncated"])
        self.assertEqual(data["stdout_chars"], 70000)
        self.assertEqual(data["stderr_chars"], 13000)
        self.assertLess(len(data["stdout"]), 61000)
        self.assertLess(len(data["stderr"]), 13000)

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
        self.assertEqual(data["process_metrics"]["status"], "not_collected")
        self.assertEqual(data["process_metrics"]["count"], 0)
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

    def test_run_case_background_returns_running_without_blocking(self):
        sample = self.base / "samples" / "background.bin"
        sample.parent.mkdir()
        sample.write_bytes(b"MZsample")
        prepared = self.client.post(
            "/api/v1/cases/prepare",
            json={
                "case_id": "case-background",
                "sample_path": str(sample),
                "analysis_plan": {"static": True},
            },
            headers=self.headers,
        )
        self.assertEqual(prepared.status_code, 200)

        with patch("chatcli.remote.guest_agent.app.threading.Thread") as thread_cls:
            response = self.client.post(
                "/api/v1/cases/case-background/run",
                json={"mode": "dry_run", "background": True},
                headers=self.headers,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "running")
        self.assertTrue(response.json()["background"])
        thread_cls.assert_called_once()
        thread_cls.return_value.start.assert_called_once()

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

    def test_job_runner_dynamic_dry_run_documents_extended_collectors(self):
        sample = self.base / "remote-sample.bin"
        sample.write_bytes(b"MZsample")
        job_dir = self.base / "cases" / "case-dynamic-extended"
        job_dir.mkdir(parents=True)
        (job_dir / "job.json").write_text(
            json.dumps({
                "job_id": "case-dynamic-extended",
                "sample_path": str(sample),
                "analysis_plan": {"static": False, "dynamic": True},
                "dynamic_config": {
                    "timeout_seconds": 30,
                    "collectors": ["pcap", "procmon", "tshark", "sysmon", "zeek", "suricata"],
                    "network_interface": "1",
                    "validation_targets": {
                        "network_indicators": {
                            "domains": ["example.test"],
                            "ips": ["203.0.113.10"],
                            "ports": [443],
                            "uri_paths": ["/gate.php"],
                        },
                        "watch_processes": ["remote-sample.bin"],
                        "watch_registry": ["Run"],
                    },
                },
            }),
            encoding="utf-8",
        )

        state = run_job(job_dir, mode="dry_run", outbox_root=self.base / "outbox")

        dynamic_dir = self.base / "outbox" / "case-dynamic-extended" / "dynamic"
        data = json.loads((dynamic_dir / "dynamic_status.json").read_text(encoding="utf-8"))
        events = [event["event"] for event in data["events"]]
        self.assertEqual(state.status, "done")
        self.assertIn("would_export_sysmon", events)
        self.assertIn("would_run_zeek", events)
        self.assertIn("would_run_suricata", events)
        self.assertIn("would_export_procmon_csv", events)
        self.assertIn("would_screen_dynamic_targets", events)
        self.assertTrue((dynamic_dir / "targeting_plan.json").exists())
        self.assertTrue((dynamic_dir / "dynamic_targeting_plan.json").exists())
        self.assertEqual(data["outputs"]["procmon_csv"], str(dynamic_dir / "procmon.csv"))
        self.assertEqual(data["outputs"]["sysmon_evtx"], str(dynamic_dir / "sysmon.evtx"))
        self.assertEqual(data["outputs"]["zeek_dir"], str(dynamic_dir / "zeek"))
        self.assertEqual(data["outputs"]["suricata_dir"], str(dynamic_dir / "suricata"))
        self.assertEqual(data["outputs"]["dynamic_targeting_plan"], str(dynamic_dir / "dynamic_targeting_plan.json"))

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
                    "process_metrics": {"status": "ok", "count": 3},
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
        self.assertIn("Processes: 3 (ok)", result.content)
        self.assertIn("process-observer", result.content)

    def test_remote_guest_exec_truncates_large_stdout_metadata(self):
        class FakeClient:
            def exec_command(self, command, timeout=300, workdir=""):
                return {
                    "exit_code": 0,
                    "stdout": "A" * 70000,
                    "stderr": "B" * 13000,
                    "elapsed_ms": 12,
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
            result = tool.execute(action="exec", command="big-output")

        self.assertFalse(result.is_error)
        self.assertIn("[TRUNCATED: remote output was 70000 chars", result.content)
        self.assertTrue(result.metadata["stdout_truncated"])
        self.assertTrue(result.metadata["stderr_truncated"])
        self.assertLess(len(result.metadata["stdout"]), 61000)
        self.assertLess(len(result.metadata["stderr"]), 13000)

    def test_smart_input_detects_remote_batch_language(self):
        mixin = WorkCommandMixin()
        mixin.config = SimpleNamespace(smart_work=True)

        self.assertTrue(mixin._should_start_remote_batch_analysis(
            r"把腾讯云服务器 C:\samples 文件夹里的恶意样本依次分析"
        ))
        self.assertTrue(mixin._should_start_remote_batch_analysis(
            "remote server sample directory batch malware analysis"
        ))
        self.assertFalse(mixin._should_start_remote_batch_analysis(
            "我不是想给参数，只是想知道这个功能怎么对话触发"
        ))
        self.assertFalse(mixin._should_start_smart_work(
            "我想做一个类似工作流，应该怎么设计？"
        ))
        self.assertFalse(mixin._should_start_malware_triage(
            "恶意样本分析应该怎么做？"
        ))
        self.assertFalse(mixin._looks_like_work_followup(r"用 C:\samples"))
        self.assertTrue(mixin._looks_like_work_followup("继续"))

    def test_repl_prompt_session_is_paste_friendly(self):
        from chatcli import ui as ui_module

        class DummyAgent:
            def auto_restore(self):
                pass

        class FakePromptSession:
            kwargs = {}

            def __init__(self, **kwargs):
                FakePromptSession.kwargs = kwargs

        config = SimpleNamespace(
            auto_resume=False,
            workspace=str(self.base),
            provider=SimpleNamespace(provider="text-tools", model="test"),
        )
        with (
            patch.object(ui_module, "Agent", return_value=DummyAgent()),
            patch.object(ui_module, "PromptSession", FakePromptSession),
            patch("sys.stdin.isatty", return_value=True),
            patch("sys.stdout.isatty", return_value=True),
        ):
            repl = ui_module.REPL(config)

        self.assertIsInstance(repl.session, FakePromptSession)
        self.assertIs(FakePromptSession.kwargs["multiline"], True)
        self.assertIs(FakePromptSession.kwargs["mouse_support"], False)
        self.assertEqual(FakePromptSession.kwargs["prompt_continuation"], "    ")
        bindings = FakePromptSession.kwargs["key_bindings"].bindings
        key_sets = {
            tuple(getattr(key, "value", key) for key in binding.keys)
            for binding in bindings
        }
        self.assertIn(("c-j",), key_sets)
        self.assertIn(("c-m",), key_sets)
        self.assertIn(("escape",), key_sets)

    def test_dashboard_callbacks_pass_case_id_and_probe_flag(self):
        from chatcli.ui_dashboard import build_dashboard_callbacks

        class Response:
            def __init__(self, status_code, data):
                self.status_code = status_code
                self._data = data

            def json(self):
                return self._data

        calls = []

        def fake_get(url, **kwargs):
            calls.append((url, kwargs))
            if url.endswith("/api/v1/health"):
                return Response(200, {"status": "healthy", "version": "test"})
            if url.endswith("/api/v1/cases"):
                return Response(200, {"cases": [{"case_id": "case-1", "status": "running"}]})
            if url.endswith("/api/v1/monitor/snapshot"):
                return Response(200, {"case_id": kwargs["params"]["case_id"], "observer_agents": []})
            return Response(404, {})

        with patch("httpx.get", side_effect=fake_get):
            remote_fn, _child_fn = build_dashboard_callbacks(
                remote_base_url="http://remote:8443",
                remote_token="token",
                case_id="case-1",
                include_probes=False,
            )
            data = remote_fn()

        self.assertEqual(data["monitor"]["case_id"], "case-1")
        monitor_calls = [item for item in calls if item[0].endswith("/api/v1/monitor/snapshot")]
        self.assertEqual(len(monitor_calls), 1)
        self.assertEqual(monitor_calls[0][1]["params"], {"probes": "false", "case_id": "case-1"})

    def test_remote_client_helper_resolves_base_url_consistently(self):
        from chatcli.tools._remote_client import guest_agent_token, remote_base_url

        remote = SimpleNamespace(
            base_url="http://configured:8443/",
            host="fallback",
            guest_agent_port=9443,
            guest_agent_token=" token ",
        )
        self.assertEqual(remote_base_url(remote), "http://configured:8443")
        self.assertEqual(guest_agent_token(remote), "token")

        remote.base_url = ""
        self.assertEqual(remote_base_url(remote), "http://fallback:9443")

    def test_procmon_screening_keeps_concise_high_signal_rows(self):
        csv_path = self.base / "procmon.csv"
        dynamic_dir = self.base / "dynamic-screen"
        dynamic_dir.mkdir()
        csv_path.write_text(
            "\n".join(
                [
                    '"Time of Day","Process Name","PID","Operation","Path","Result","Detail"',
                    '"00:00:01","sample.exe","100","Process Start","","SUCCESS","Command line: sample.exe Environment: CHATCLI_GUEST_AGENT_TOKEN=secret"',
                    '"00:00:02","sample.exe","100","Load Image","C:\\Windows\\System32\\kernel32.dll","SUCCESS",""',
                    '"00:00:03","sample.exe","100","Thread Create","","SUCCESS","Thread ID: 200"',
                    '"00:00:04","sample.exe","100","Process Create","C:\\Windows\\System32\\schtasks.exe","SUCCESS","PID: 300, Command line: schtasks /create /tn SecurityScript /sc minute"',
                    '"00:00:05","schtasks.exe","300","Process Start","","SUCCESS","Command line: schtasks /create /tn SecurityScript"',
                    '"00:00:06","schtasks.exe","300","RegOpenKey","HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options","SUCCESS",""',
                    '"00:00:07","sample.exe","100","RegSetValue","HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityScript","SUCCESS",""',
                    '"00:00:08","sample.exe","100","WriteFile","C:\\Users\\Public\\payload.exe","SUCCESS",""',
                ]
            ),
            encoding="utf-8",
        )

        outputs = screen_procmon_csv(
            csv_path,
            dynamic_dir,
            {
                "max_procmon_lines_per_file": 25,
                "validation_targets": {
                    "watch_processes": ["sample.exe", "schtasks.exe"],
                    "watch_services_tasks": ["SecurityScript"],
                    "watch_registry": [r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"],
                },
            },
            "sample.exe",
        )

        process_tree = (dynamic_dir / "targeted_process_tree.txt").read_text(encoding="utf-8")
        persistence = (dynamic_dir / "targeted_persistence.txt").read_text(encoding="utf-8")
        summary = json.loads((dynamic_dir / "targeted_procmon_summary.json").read_text(encoding="utf-8"))

        self.assertIn("schtasks /create", process_tree)
        self.assertNotIn("Load Image", process_tree)
        self.assertNotIn("Thread Create", process_tree)
        self.assertNotIn("CHATCLI_GUEST_AGENT_TOKEN", process_tree)
        self.assertIn("RegSetValue", persistence)
        self.assertIn("targeted_procmon_summary.json", [path.name for path in outputs])
        self.assertEqual(summary["rows_scanned"], 8)
        self.assertLessEqual(summary["output_counts"]["targeted_process_tree.txt"], 3)

    def test_static_hypotheses_drive_dynamic_targets(self):
        outbox = self.base / "outbox-case"
        static_dir = outbox / "static"
        static_dir.mkdir(parents=True)
        (static_dir / "floss.txt").write_text(
            "schtasks\n/create\n/query\n/tn SecurityScript\n"
            "C:\\Windows\\System32\\calc.exe\n",
            encoding="utf-8",
        )

        derived = derive_static_behavior_targets(outbox, "sample.exe")

        hypotheses = derived["hypotheses"]
        targets = derived["dynamic_config"]["validation_targets"]
        self.assertTrue(any(item["id"] == "scheduled_task_persistence" for item in hypotheses))
        self.assertIn("schtasks.exe", targets["watch_processes"])
        self.assertIn("SecurityScript", targets["watch_services_tasks"])
        self.assertTrue((static_dir / "behavior_hypotheses.json").is_file())

    def test_remote_batch_default_plan_uses_shared_static_ida_verify_plan(self):
        from chatcli.remote.analysis_plans import static_ida_verify_plan

        class FakeClient:
            def __init__(self):
                self.plan = None

            def prepare_case(self, case_id="", analysis_plan=None, sample_path="", dynamic_config=None):
                self.plan = analysis_plan
                return {"case_id": case_id, "status": "prepared", "sample_exists": True}

            def run_analysis(
                self,
                case_id,
                mode="real",
                analysis_plan=None,
                dynamic_config=None,
                background=False,
                request_timeout=None,
            ):
                return {"case_id": case_id, "status": "done"}

            def download_results(self, case_id, output_dir=""):
                return f".chatcli/remote_results/{case_id}"

            def close(self):
                pass

        config = SimpleNamespace(remote=SimpleNamespace(enabled=True))
        fake = FakeClient()
        tool = RemoteBatchAnalyzeTool(config)
        with patch.object(tool, "_get_client", return_value=fake):
            result = tool.execute(sample_paths=[r"C:\samples\a.exe"])

        self.assertFalse(result.is_error)
        self.assertEqual(fake.plan, static_ida_verify_plan())

    def test_remote_guest_analyze_default_plan_uses_shared_dynamic_plan(self):
        from chatcli.remote.analysis_plans import default_dynamic_config, dynamic_ida_verify_plan

        class FakeClient:
            def __init__(self):
                self.plan = None
                self.dynamic_config = None
                self.background = None
                self.request_timeout = None

            def prepare_case(self, case_id="", analysis_plan=None, sample_path="", dynamic_config=None):
                self.plan = analysis_plan
                self.dynamic_config = dynamic_config
                return {"case_id": case_id or "case-default", "status": "prepared", "sample_exists": True}

            def run_analysis(
                self,
                case_id,
                mode="real",
                sample_path="",
                analysis_plan=None,
                dynamic_config=None,
                background=False,
                request_timeout=None,
            ):
                self.background = background
                self.request_timeout = request_timeout
                return {"case_id": case_id, "status": "running", "background": background}

            def close(self):
                pass

        config = SimpleNamespace(remote=SimpleNamespace(enabled=True))
        fake = FakeClient()
        tool = RemoteGuestTool(config)
        with patch.object(tool, "_get_client", return_value=fake):
            progress = []
            result = tool.execute(
                action="analyze",
                sample_path=r"C:\samples\a.exe",
                _progress_callback=progress.append,
            )

        self.assertFalse(result.is_error)
        self.assertEqual(fake.plan, dynamic_ida_verify_plan())
        self.assertEqual(fake.dynamic_config, default_dynamic_config())
        self.assertTrue(fake.background)
        self.assertEqual(fake.request_timeout, 60)
        self.assertIn("Background: True", result.content)
        self.assertTrue(any("submitting case=case-default" in item for item in progress))

    def test_remote_guest_run_accepts_string_background_false(self):
        class FakeClient:
            def __init__(self):
                self.background = None
                self.request_timeout = None

            def run_analysis(
                self,
                case_id,
                mode="real",
                sample_path="",
                analysis_plan=None,
                dynamic_config=None,
                background=False,
                request_timeout=None,
            ):
                self.background = background
                self.request_timeout = request_timeout
                return {"case_id": case_id, "status": "done", "background": background}

            def close(self):
                pass

        config = SimpleNamespace(remote=SimpleNamespace(enabled=True))
        fake = FakeClient()
        tool = RemoteGuestTool(config)
        with patch.object(tool, "_get_client", return_value=fake):
            result = tool.execute(action="run", case_id="case-sync", background="false")

        self.assertFalse(result.is_error)
        self.assertFalse(fake.background)
        self.assertIsNone(fake.request_timeout)
        self.assertIn("Background: False", result.content)

    def test_remote_batch_analyze_runs_samples_sequentially(self):
        class FakeClient:
            def __init__(self):
                self.events = []

            def prepare_case(self, case_id="", analysis_plan=None, sample_path="", dynamic_config=None):
                self.events.append(("prepare", case_id, sample_path))
                return {"case_id": case_id, "status": "prepared", "sample_exists": True}

            def run_analysis(
                self,
                case_id,
                mode="real",
                analysis_plan=None,
                dynamic_config=None,
                background=False,
                request_timeout=None,
            ):
                self.events.append(("run", case_id, background, request_timeout))
                return {"case_id": case_id, "status": "done"}

            def download_results(self, case_id, output_dir=""):
                self.events.append(("download", case_id))
                return f".chatcli/remote_results/{case_id}"

            def close(self):
                self.events.append(("close", ""))

        config = SimpleNamespace(
            remote=SimpleNamespace(
                enabled=True,
                base_url="http://remote:8443",
                host="",
                guest_agent_port=8443,
                guest_agent_token="token",
            )
        )
        fake = FakeClient()
        tool = RemoteBatchAnalyzeTool(config)
        with patch.object(tool, "_get_client", return_value=fake):
            result = tool.execute(
                sample_paths=[r"C:\samples\a.exe", r"C:\samples\b.exe"],
                analysis_plan={"static": True, "dynamic": True, "network": True, "verify": True},
            )

        self.assertFalse(result.is_error)
        self.assertIn("Remote batch analysis: 2 sample(s)", result.content)
        self.assertIn("without VM snapshot restore between samples", result.content)
        self.assertEqual([event[0] for event in fake.events], [
            "prepare", "run", "download",
            "prepare", "run", "download",
            "close",
        ])
        self.assertEqual(len(result.metadata["results"]), 2)
        self.assertEqual(result.metadata["results"][0]["status"], "done")

    def test_remote_batch_analyze_can_expand_remote_directory(self):
        class FakeClient:
            def __init__(self):
                self.commands = []
                self.prepared_paths = []

            def exec_command(self, command, timeout=300, workdir=""):
                self.commands.append(command)
                return {
                    "exit_code": 0,
                    "stdout": "C:\\samples\\one.exe\nC:\\samples\\two.exe\n",
                    "stderr": "",
                }

            def prepare_case(self, case_id="", analysis_plan=None, sample_path="", dynamic_config=None):
                self.prepared_paths.append(sample_path)
                return {"case_id": case_id, "status": "prepared", "sample_exists": True}

            def run_analysis(
                self,
                case_id,
                mode="real",
                analysis_plan=None,
                dynamic_config=None,
                background=False,
                request_timeout=None,
            ):
                return {"case_id": case_id, "status": "done"}

            def download_results(self, case_id, output_dir=""):
                return f".chatcli/remote_results/{case_id}"

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
        fake = FakeClient()
        tool = RemoteBatchAnalyzeTool(config)
        with patch.object(tool, "_get_client", return_value=fake):
            result = tool.execute(sample_dir=r"C:\samples", pattern="*.exe", recursive=True)

        self.assertFalse(result.is_error)
        self.assertIn("Get-ChildItem", fake.commands[0])
        self.assertIn("-Recurse", fake.commands[0])
        self.assertEqual(fake.prepared_paths, [r"C:\samples\one.exe", r"C:\samples\two.exe"])

    def test_remote_batch_no_wait_submits_all_without_downloading_running_cases(self):
        class FakeClient:
            def __init__(self):
                self.events = []

            def prepare_case(self, case_id="", analysis_plan=None, sample_path="", dynamic_config=None):
                self.events.append(("prepare", case_id, sample_path))
                return {"case_id": case_id, "status": "prepared", "sample_exists": True}

            def run_analysis(
                self,
                case_id,
                mode="real",
                analysis_plan=None,
                dynamic_config=None,
                background=False,
                request_timeout=None,
            ):
                self.events.append(("run", case_id, background, request_timeout))
                return {"case_id": case_id, "status": "running", "background": background}

            def download_results(self, case_id, output_dir=""):
                self.events.append(("download", case_id))
                return f".chatcli/remote_results/{case_id}"

            def close(self):
                self.events.append(("close", ""))

        config = SimpleNamespace(
            remote=SimpleNamespace(
                enabled=True,
                base_url="http://remote:8443",
                host="",
                guest_agent_port=8443,
                guest_agent_token="token",
            )
        )
        fake = FakeClient()
        tool = RemoteBatchAnalyzeTool(config)
        with patch.object(tool, "_get_client", return_value=fake):
            result = tool.execute(
                sample_paths=[r"C:\samples\a.exe", r"C:\samples\b.exe"],
                wait=False,
                download=True,
                run_request_timeout_seconds=7,
            )

        self.assertFalse(result.is_error)
        self.assertIn("Still running/submitted: 2", result.content)
        self.assertNotIn("download", [event[0] for event in fake.events])
        self.assertEqual([event[0] for event in fake.events], [
            "prepare", "run",
            "prepare", "run",
            "close",
        ])
        run_events = [event for event in fake.events if event[0] == "run"]
        self.assertTrue(all(event[2] is True for event in run_events))
        self.assertTrue(all(event[3] == 7 for event in run_events))


if __name__ == "__main__":
    unittest.main()
