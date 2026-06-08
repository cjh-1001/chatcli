import json

from chatcli.tools.reverse.runtime_hooks import RuntimeStringHooksTool


def test_runtime_string_hooks_infers_x64dbg_breakpoints_from_static_artifacts(tmp_path):
    static = tmp_path / "case-a" / "static"
    static.mkdir(parents=True)
    (static / "binary_inspect.json").write_text(
        json.dumps(
            {
                "path": r"C:\Users\Administrator\Desktop\eval\sample.exe",
                "sha256": "abc",
                "is_pe": True,
            }
        ),
        encoding="utf-8",
    )
    (static / "exiftool.txt").write_text(
        "File Type                       : Win64 EXE\n"
        "Entry Point                     : 0x770e0\n",
        encoding="utf-8",
    )
    (static / "strings.txt").write_text(
        "[ERROR] schtasks create failed\n"
        'Go build ID: "abc/def/ghi"\n'
        "path\\tschtasks_persistence\n"
        "CreateServiceW\n"
        "IsDebuggerPresent\n"
        "CryptUnprotectData\n"
        "BitBlt\n"
        "WinHttpSendRequest\n"
        "RegSetValueExW\n"
        "LoadLibraryW\n"
        "GetProcAddress\n",
        encoding="utf-8",
    )
    (static / "floss.txt").write_text(
        "CreateProcessW\n"
        "CreateFileW\n"
        "WriteFile\n"
        "CryptGenRandom\n"
        "WSAStartup\n",
        encoding="utf-8",
    )

    out = tmp_path / "hooks"
    result = RuntimeStringHooksTool().execute(
        output_dir=str(out),
        analysis_dir=str(tmp_path / "case-a"),
    )

    assert not result.is_error
    assert result.metadata["module_name"] == "sample.exe"
    assert result.metadata["entry_offset"] == "0x770e0"
    assert "CreateProcessW" in result.metadata["api_names"]
    assert "RegSetValueExW" in result.metadata["api_names"]
    assert "CryptGenRandom" in result.metadata["api_names"]
    assert "CreateServiceW" in result.metadata["api_names"]
    assert "IsDebuggerPresent" in result.metadata["api_names"]
    assert "CryptUnprotectData" in result.metadata["api_names"]
    assert "BitBlt" in result.metadata["api_names"]
    assert "WinHttpSendRequest" in result.metadata["api_names"]
    assert result.metadata["ranked_breakpoints"][0]["kind"] == "entry"
    assert result.metadata["coverage_mode"] == "balanced"
    assert result.metadata["coverage_summary"]["by_category"]["service_persistence"] >= 1
    assert result.metadata["coverage_summary"]["by_category"]["anti_analysis"] >= 1
    assert result.metadata["inferred"]["go"]["build_id"] == "abc/def/ghi"
    assert "schtasks_persistence" in result.metadata["inferred"]["go"]["module_paths"]
    x64dbg = (out / "chatcli_string_dump.x64dbg.txt").read_text(encoding="utf-8")
    assert "bphwc sample.exe+0x770e0" in x64dbg
    assert "bp CreateProcessW" in x64dbg
    assert "bp RegSetValueExW" in x64dbg
    assert "bp CreateServiceW" in x64dbg
    assert "bp IsDebuggerPresent" in x64dbg
    assert "bp CryptUnprotectData" in x64dbg
    assert "bp BitBlt" in x64dbg
    assert "bp WinHttpSendRequest" in x64dbg
    plan = json.loads((out / "chatcli_x64dbg_plan.json").read_text(encoding="utf-8"))
    assert plan["entry_offset"] == "0x770e0"
    assert plan["coverage_mode"] == "balanced"
    assert "coverage_summary" in plan
    assert plan["ranked_breakpoints"][0]["score"] == 100
    assert (out / "chatcli_x64dbg_usage.md").is_file()
    assert "# Static Artifact Audit" in result.content
