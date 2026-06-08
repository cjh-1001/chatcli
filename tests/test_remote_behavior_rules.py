import json
import tempfile
from pathlib import Path

from chatcli.remote.behavior_hypotheses import derive_static_behavior_targets
from chatcli.remote.procmon_screen import screen_procmon_csv


def _static_case(text: str):
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    static_dir = root / "static"
    static_dir.mkdir()
    (static_dir / "floss.txt").write_text(text, encoding="utf-8")
    return tmp, root


def _rule_ids(payload: dict) -> set[str]:
    return {item["id"] for item in payload.get("hypotheses", [])}


def test_static_rules_detect_core_persistence_families():
    tmp, root = _static_case(
        "schtasks /create /tn SecurityScript\n"
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
        "CreateServiceW sc create EvilSvc\n"
    )
    with tmp:
        payload = derive_static_behavior_targets(root, "sample.exe")

    ids = _rule_ids(payload)
    targets = payload["dynamic_config"]["validation_targets"]
    assert {"scheduled_task_persistence", "run_key_persistence", "service_persistence"} <= ids
    assert "schtasks.exe" in targets["watch_processes"]
    assert "sc.exe" in targets["watch_processes"]
    assert any("CurrentVersion\\Run" in value for value in targets["watch_registry"])


def test_static_rules_detect_network_only_from_strong_indicators():
    tmp, root = _static_case("https://c2.example.com/a\nWinHttpOpen\n")
    with tmp:
        payload = derive_static_behavior_targets(root, "sample.exe")

    targets = payload["dynamic_config"]["validation_targets"]
    assert "network_or_c2_activity" in _rule_ids(payload)
    assert "https://c2.example.com/a" in targets["network_indicators"]["urls"]
    assert "c2.example.com" in targets["network_indicators"]["domains"]


def test_static_rules_do_not_treat_go_runtime_noise_as_c2_or_service():
    tmp, root = _static_case(
        "OpenServiceW OpenSCManagerW WSAStartup connect socket\n"
        "godebugs.info eq.io b.idata b.symtab exec.cmd abi.type\n"
    )
    with tmp:
        payload = derive_static_behavior_targets(root, "sample.exe")

    assert "network_or_c2_activity" not in _rule_ids(payload)
    assert "service_persistence" not in _rule_ids(payload)


def test_static_rules_cover_common_dynamic_validation_families():
    tmp, root = _static_case(
        "Start Menu\\Programs\\Startup shell:startup\n"
        "__EventFilter CommandLineEventConsumer root\\subscription\n"
        "WriteFile FindResource AppData payload.exe\n"
        "VirtualAllocEx WriteProcessMemory CreateRemoteThread\n"
        "fodhelper DelegateExecute ms-settings\\Shell\\Open\\command\n"
        "Set-MpPreference DisableRealtimeMonitoring netsh advfirewall\n"
        "MiniDumpWriteDump lsass.exe comsvcs.dll\n"
    )
    with tmp:
        payload = derive_static_behavior_targets(root, "sample.exe")

    ids = _rule_ids(payload)
    targets = payload["dynamic_config"]["validation_targets"]
    assert "startup_folder_persistence" in ids
    assert "wmi_persistence" in ids
    assert "payload_dropper" in ids
    assert "process_injection" in ids
    assert "uac_bypass" in ids
    assert "defense_evasion_security_tool_tampering" in ids
    assert "credential_access" in ids
    assert "wmic.exe" in targets["watch_processes"]
    assert any("Startup" in value for value in targets["watch_paths"])
    assert any("Windows Defender" in value for value in targets["watch_registry"])


def test_static_rules_extract_quoted_task_and_service_names():
    tmp, root = _static_case(
        'schtasks /create /tn "Security Script" /tr calc.exe\n'
        "sc.exe create EvilSvc binPath= C:\\Temp\\evil.exe\n"
    )
    with tmp:
        payload = derive_static_behavior_targets(root, "sample.exe")

    targets = payload["dynamic_config"]["validation_targets"]
    assert "Security Script" in targets["watch_services_tasks"]
    assert "EvilSvc" in targets["watch_services_tasks"]


def test_procmon_screening_tracks_sample_descendants_not_watch_process_noise():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        csv_path = root / "procmon.csv"
        out = root / "dynamic"
        out.mkdir()
        csv_path.write_text(
            "\n".join(
                [
                    '"Time of Day","Process Name","PID","Operation","Path","Result","Detail"',
                    '"00","Explorer.EXE","10","Process Create","C:\\Windows\\System32\\powershell.exe","SUCCESS","PID: 20, Command line: powershell.exe"',
                    '"01","sample.exe","100","Process Create","C:\\Windows\\System32\\schtasks.exe","SUCCESS","PID: 300, Command line: schtasks /create /tn SecurityScript"',
                    '"02","schtasks.exe","300","Process Start","","SUCCESS","Command line: schtasks /create /tn SecurityScript Environment: SECRET=1"',
                ]
            ),
            encoding="utf-8",
        )

        outputs = screen_procmon_csv(
            csv_path,
            out,
            {
                "validation_targets": {
                    "watch_processes": ["powershell.exe", "schtasks.exe"],
                    "watch_services_tasks": ["SecurityScript"],
                }
            },
            "sample.exe",
        )

        tree = (out / "targeted_process_tree.txt").read_text(encoding="utf-8")
        summary = json.loads((out / "targeted_procmon_summary.json").read_text(encoding="utf-8"))
        assert "schtasks /create" in tree
        assert "powershell.exe" not in tree
        assert "SECRET=1" not in tree
        assert "300" in summary["relevant_pids"]
        assert "20" not in summary["relevant_pids"]
        assert "targeted_procmon_summary.json" in [path.name for path in outputs]
