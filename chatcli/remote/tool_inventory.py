"""Remote analysis tool discovery shared by package Guest Agent code."""

from __future__ import annotations

import importlib.util
import os
import shlex
import shutil
import sys
from pathlib import Path
from typing import Any


COLLECTOR_TOOLS = {"dumpcap", "tshark", "sysmon", "procmon"}
HEADLESS_REVERSE_TOOLS = {"ida", "ghidra"}
STATIC_EXTERNAL_TOOLS = {"diec", "yara", "exiftool", "upx"}


def resolve_ida_command() -> str:
    for env_name in ("CHATCLI_TOOL_IDA", "IDA_PATH", "IDAT64_PATH", "IDAT_PATH", "IDA64_PATH"):
        value = os.environ.get(env_name, "").strip()
        if value:
            return value

    candidates = [
        r"C:\Program Files\IDA Professional 9.0\idat64.exe",
        r"C:\Program Files\IDA Professional 9.0\idat.exe",
        r"C:\Program Files\IDA Pro 9.0\idat64.exe",
        r"C:\Program Files\IDA Pro 9.0\idat.exe",
    ]
    for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(env_name, "").strip()
        if not root:
            continue
        root_path = Path(root)
        candidates.extend(str(path / exe) for path in root_path.glob("IDA*") for exe in ("idat64.exe", "idat.exe"))
    for candidate in candidates:
        if Path(candidate).is_file():
            return candidate
    return "idat64"


def resolve_ghidra_command() -> str:
    for env_name in ("CHATCLI_TOOL_GHIDRA", "GHIDRA_HEADLESS_PATH", "GHIDRA_HOME"):
        value = os.environ.get(env_name, "").strip()
        if value:
            return value
    return "analyzeHeadless"


def resolve_tool_paths() -> dict[str, str]:
    """Return remote analysis tool commands and configured paths."""
    defaults = {
        "python": sys.executable,
        "ida": resolve_ida_command(),
        "ghidra": resolve_ghidra_command(),
        "dumpcap": "dumpcap",
        "tshark": "tshark",
        "zeek": "zeek",
        "suricata": "suricata",
        "sysmon": r"C:\Sysmon\Sysmon64.exe",
        "wevtutil": "wevtutil",
        "powershell": "powershell",
        "procmon": r"C:\Tools\Procmon64.exe",
        "diec": "diec",
        "yara": "yara",
        "exiftool": "exiftool",
        "upx": "upx",
    }
    resolved: dict[str, str] = {}
    for name, default in defaults.items():
        resolved[name] = os.environ.get(f"CHATCLI_TOOL_{name.upper()}", "").strip() or default
    return resolved


def split_command(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=False)
    except ValueError:
        return command.split()


def tool_available(command: str) -> bool:
    raw = str(command or "").strip().strip('"')
    if raw:
        raw_path = Path(raw)
        if raw_path.is_file():
            return True
        if raw_path.is_dir():
            for candidate in (
                raw_path / "support" / "analyzeHeadless.bat",
                raw_path / "support" / "analyzeHeadless",
                raw_path / "idat64.exe",
                raw_path / "idat.exe",
            ):
                if candidate.is_file():
                    return True
    argv = split_command(command)
    exe_str = argv[0].strip('"') if argv else command
    exe = Path(exe_str)
    return exe.is_file() if exe.is_absolute() else shutil.which(exe_str) is not None


def python_package_available(module_name: str) -> bool:
    return importlib.util.find_spec(module_name) is not None


def tool_kind(name: str) -> str:
    if name in COLLECTOR_TOOLS:
        return "collector"
    if name in HEADLESS_REVERSE_TOOLS:
        return "headless_reverse"
    if name in STATIC_EXTERNAL_TOOLS:
        return "static_external"
    return "external"


def tool_inventory() -> dict[str, dict[str, Any]]:
    tools: dict[str, dict[str, Any]] = {}
    for name, command in sorted(resolve_tool_paths().items()):
        tools[name] = {
            "kind": tool_kind(name),
            "path": command,
            "available": tool_available(command),
        }

    python_analyzers = {
        "capa": {
            "package": "flare-capa",
            "module": "capa",
            "command": f'"{sys.executable}" -m capa.main <sample> -j',
        },
        "floss": {
            "package": "flare-floss",
            "module": "floss",
            "command": f'"{sys.executable}" -m floss <sample>',
        },
        "yara-python": {
            "package": "yara-python",
            "module": "yara",
            "command": "import yara; yara.compile(...).match(<sample>)",
        },
    }
    for name, spec in python_analyzers.items():
        tools[name] = {
            "kind": "analysis_python",
            "package": spec["package"],
            "module": spec["module"],
            "command": spec["command"],
            "available": python_package_available(spec["module"]),
        }

    tools["binary_inspect"] = {
        "kind": "built_in_static",
        "available": True,
        "description": "Built-in hash, size, PE marker, and sampled strings metadata.",
    }
    tools["strings"] = {
        "kind": "built_in_static",
        "available": True,
        "description": "Built-in printable ASCII string extraction.",
    }
    yara_rules = os.environ.get("CHATCLI_YARA_RULES", "").strip()
    tools["yara_rules"] = {
        "kind": "analysis_config",
        "path": yara_rules,
        "available": bool(yara_rules and Path(yara_rules).is_file()),
    }
    return tools
