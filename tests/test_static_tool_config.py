import subprocess
import tempfile
import unittest
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from chatcli.tools.external_static import ExternalStaticAnalyzeTool
from chatcli.tools.external_static import YaraScanTool
from chatcli.tools.tool_health import _probe_external
import server.chatcli_guest_agent as standalone


class StaticToolConfigTests(unittest.TestCase):
    def test_external_static_uses_capa_main_for_python_package_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.exe"
            sample.write_bytes(b"MZsample")

            calls = []

            def fake_run(cmd, **kwargs):
                calls.append(cmd)
                return SimpleNamespace(stdout="capa ok", stderr="", returncode=0)

            with patch("chatcli.tools.external_static.shutil.which", return_value=None), \
                    patch("chatcli.tools.external_static.importlib.util.find_spec", return_value=object()), \
                    patch("chatcli.tools.external_static.subprocess.run", side_effect=fake_run):
                result = ExternalStaticAnalyzeTool().execute(
                    file_path=str(sample),
                    analyzers=["capa"],
                )

        self.assertFalse(result.is_error)
        self.assertEqual(calls[0][1:3], ["-m", "capa.main"])

    def test_tool_health_reports_executable_capa_module_entry(self):
        with patch("chatcli.tools.tool_health._which_any", return_value=None), \
                patch("chatcli.tools.tool_health._probe_python_package") as probe_package:
            probe_package.return_value = {
                "name": "flare-capa",
                "kind": "python-package",
                "available": True,
                "path": "python import: capa",
            }

            row = _probe_external("capa", include_versions=False)

        self.assertTrue(row["available"])
        self.assertEqual(row["name"], "capa")
        self.assertEqual(row["path"], "python -m capa.main")

    def test_server_guest_agent_uses_capa_main_for_static_capa(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            outbox = base / "outbox" / "case-static"
            sample = base / "sample.exe"
            sample.write_bytes(b"MZsample")

            calls = []

            def fake_run(cmd, **kwargs):
                calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

            with patch.object(standalone, "_python_package_available", side_effect=lambda name: name == "capa"), \
                    patch.object(
                        standalone,
                        "_resolve_tool_paths",
                        return_value={
                            "diec": "missing-diec",
                            "exiftool": "missing-exiftool",
                            "upx": "missing-upx",
                        },
                    ), \
                    patch.object(standalone, "_tool_available", return_value=False), \
                    patch.object(standalone.subprocess, "run", side_effect=fake_run):
                done, failed = standalone._run_static("case-static", outbox, sample, "real")

        self.assertIn("static.capa", done)
        self.assertEqual(calls[0][1:3], ["-m", "capa.main"])
        self.assertIn("static.floss (not available)", failed)

    @unittest.skipUnless(importlib.util.find_spec("yara"), "yara-python is not installed")
    def test_yara_scan_supports_current_yara_python_string_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.txt"
            sample.write_text("hello malware-test-string", encoding="ascii")

            result = YaraScanTool().execute(
                target_path=str(sample),
                rule_source='rule ChatcliTest { strings: $a = "malware-test-string" condition: $a }',
            )

        self.assertFalse(result.is_error)
        self.assertIn("ChatcliTest", result.content)
        self.assertEqual(result.metadata["rules_matched"], 1)
        self.assertEqual(result.metadata["rules"][0]["strings"][0]["identifier"], "$a")

    @unittest.skipUnless(importlib.util.find_spec("yara"), "yara-python is not installed")
    def test_yara_scan_expands_directories_with_python_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "nested"
            nested.mkdir()
            (nested / "hit.txt").write_text("hello malware-test-string", encoding="ascii")
            (root / "miss.txt").write_text("hello benign", encoding="ascii")

            result = YaraScanTool().execute(
                target_path=str(root),
                rule_source='rule ChatcliTest { strings: $a = "malware-test-string" condition: $a }',
                recursive=True,
            )

        self.assertFalse(result.is_error)
        self.assertIn("hit.txt", result.content)
        self.assertEqual(result.metadata["files_scanned"], 2)
        self.assertEqual(result.metadata["rules_matched"], 1)


if __name__ == "__main__":
    unittest.main()
