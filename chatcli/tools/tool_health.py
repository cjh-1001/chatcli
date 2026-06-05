"""Tool availability diagnostics."""

from __future__ import annotations

import shutil
import subprocess
import sys
from importlib import metadata as importlib_metadata
from pathlib import Path

from .base import Tool, ToolResult, coerce_bool, coerce_str_list
from ._ida_utils import _find_ida
from .ghidra import _find_ghidra


BUILT_IN_TOOLS = {
    "bash",
    "read_file",
    "write_file",
    "edit_file",
    "multi_edit",
    "glob",
    "grep",
    "list_dir",
    "web_search",
    "web_fetch",
    "ip_lookup",
    "json_extract",
    "ioc_quality_classifier",
    "detection_rule_lint",
    "git_status",
    "git_diff",
    "binary_inspect",
    "binary_find",
    "binary_hexdump",
    "binary_patch",
    "encoded_string_extract",
    "obfuscated_data_map",
    "behavior_capability_map",
    "attack_chain_builder",
    "evidence_graph",
    "behavior_claim_validator",
    "behavior_coverage_matrix",
    "command_capability_map",
    "attack_technique_mapper",
    "malware_share_package",
    "reverse_technique_map",
    "reverse_evidence_map",
    "runtime_string_hooks",
    "external_static_analyze",
    "tool_health_check",
    "chatcli_auto_request",
}

EXECUTABLE_PROBES = {
    "python": [sys.executable],
    "py": ["py"],
    "powershell": ["pwsh", "powershell"],
    "git": ["git"],
    "capa": ["capa"],
    "die": ["diec"],
    "floss": ["floss"],
    "exiftool": ["exiftool"],
    "yara": ["yara"],
    "upx": ["upx"],
    "frida": ["frida"],
    "tshark": ["tshark"],
    "tcpdump": ["tcpdump"],
    "strings": ["strings"],
    "file": ["file"],
    "objdump": ["objdump"],
    "readelf": ["readelf"],
    "radare2": ["r2", "radare2"],
    "rizin": ["rizin", "rz-bin"],
    "dotnet": ["dotnet"],
    "ilspycmd": ["ilspycmd"],
    "java": ["java"],
    "jadx": ["jadx"],
    "apktool": ["apktool"],
    "node": ["node"],
    "npm": ["npm"],
}

PYTHON_PACKAGE_PROBES = {
    "angr": "angr",
    "frida-python": "frida",
    "pefile": "pefile",
    "lief": "lief",
    "capstone": "capstone",
    "unicorn": "unicorn",
    "yara-python": "yara",
}

TOOL_DEPENDENCIES = {
    "ida_probe": ["ida"],
    "ida_analyze": ["ida"],
    "ida_focus_decompile": ["ida"],
    "ida_deobfuscate": ["ida"],
    "ghidra_probe": ["ghidra"],
    "ghidra_analyze": ["ghidra"],
    "angr_triage": ["angr"],
    "external_static_analyze": ["capa", "die", "floss", "exiftool"],
    "yara_scan": ["yara"],
    "upx_unpack": ["upx"],
    "runtime_string_hooks": ["frida"],
}

INSTALL_HINTS = {
    "capa": "Install flare-capa or use the reverse extra when available.",
    "floss": "Install flare-floss for decoded string extraction.",
    "die": "Install Detect It Easy CLI and configure die_path if it is not on PATH.",
    "exiftool": "Install ExifTool and configure exiftool_path if needed.",
    "yara": "Install YARA CLI for rule scanning.",
    "upx": "Install UPX only when UPX unpacking is needed.",
    "tshark": "Install Wireshark/tshark for packet capture triage.",
    "jadx": "Install jadx for APK and Android DEX analysis.",
    "apktool": "Install apktool for Android resource and manifest inspection.",
    "ilspycmd": "Install ilspycmd for .NET decompilation workflows.",
    "angr": "Install the reverse dependencies if symbolic execution triage is needed.",
    "frida": "Install frida-tools for local runtime instrumentation workflows.",
}


def _which_any(names: list[str]) -> str | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def _version(exe: str, timeout: float = 3.0) -> str:
    for flag in ("--version", "-version", "-V"):
        try:
            proc = subprocess.run(
                [exe, flag],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except Exception:
            continue
        output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        if output:
            return output.splitlines()[0][:160]
    return ""


def _probe_python_package(name: str, import_name: str, include_versions: bool) -> dict[str, object]:
    try:
        __import__(import_name)
    except Exception as exc:
        return {
            "name": name,
            "kind": "python-package",
            "available": False,
            "path": "",
            "error": type(exc).__name__,
        }
    row: dict[str, object] = {
        "name": name,
        "kind": "python-package",
        "available": True,
        "path": f"python import: {import_name}",
    }
    if include_versions:
        try:
            row["version"] = importlib_metadata.version(name)
        except Exception:
            row["version"] = ""
    return row


def _probe_external(name: str, include_versions: bool, config=None) -> dict[str, object]:
    if name == "ida":
        path = _find_ida(getattr(config, "ida_path", "") if config else "")
    elif name == "ghidra":
        path = _find_ghidra(getattr(config, "ghidra_path", "") if config else "")
    elif name == "angr":
        return _probe_python_package("angr", "angr", include_versions)
    elif name == "die":
        configured = getattr(config, "die_path", "") if config else ""
        path = configured if configured and Path(configured).exists() else _which_any(EXECUTABLE_PROBES.get(name, [name]))
    elif name == "exiftool":
        configured = getattr(config, "exiftool_path", "") if config else ""
        path = configured if configured and Path(configured).exists() else _which_any(EXECUTABLE_PROBES.get(name, [name]))
    elif name == "upx":
        configured = getattr(config, "upx_path", "") if config else ""
        path = configured if configured and Path(configured).exists() else _which_any(EXECUTABLE_PROBES.get(name, [name]))
    else:
        path = _which_any(EXECUTABLE_PROBES.get(name, [name]))
    row: dict[str, object] = {
        "name": name,
        "kind": "external",
        "available": bool(path),
        "path": path or "",
    }
    if include_versions and path and not str(path).startswith("python package:"):
        row["version"] = _version(path)
    return row


def _probe_tool(name: str, include_versions: bool, config=None) -> dict[str, object]:
    if name in TOOL_DEPENDENCIES:
        deps = [_probe_external(dep, include_versions, config) for dep in TOOL_DEPENDENCIES[name]]
        available = any(dep["available"] for dep in deps) if name == "external_static_analyze" else all(dep["available"] for dep in deps)
        return {
            "name": name,
            "kind": "tool",
            "available": available,
            "dependencies": deps,
        }
    if name in BUILT_IN_TOOLS:
        return {
            "name": name,
            "kind": "built-in",
            "available": True,
            "path": "chatcli",
        }
    if name in PYTHON_PACKAGE_PROBES:
        return _probe_python_package(name, PYTHON_PACKAGE_PROBES[name], include_versions)
    if name in EXECUTABLE_PROBES or name in {"ida", "ghidra", "angr"}:
        return _probe_external(name, include_versions, config)
    return {
        "name": name,
        "kind": "unknown",
        "available": False,
        "error": "unknown tool or probe name",
    }


class ToolHealthCheckTool(Tool):
    name = "tool_health_check"
    description = (
        "Check whether chatcli built-in tools and optional external dependencies "
        "are available. Useful before reverse engineering or malware triage on a "
        "new machine. Does not execute target binaries."
    )
    parameters = {
        "type": "object",
        "properties": {
            "tools": {
                "type": "array",
                "description": (
                    "Optional names to check. Examples: ida, ida_analyze, binary_hexdump, "
                    "external_static_analyze, ghidra_analyze, angr_triage, yara_scan, "
                    "upx_unpack, git, python, ilspycmd, jadx, apktool, tshark. "
                    "Default checks common reverse-analysis dependencies."
                ),
                "items": {"type": "string"},
            },
            "include_versions": {
                "type": "boolean",
                "description": "Run lightweight version commands for found external tools. Default false.",
            },
        },
    }

    def __init__(self, config=None):
        self.config = config

    def execute(self, tools: list[str] | None = None, include_versions: bool = False, **kwargs) -> ToolResult:
        include_versions = coerce_bool(include_versions, False)
        requested = coerce_str_list(tools) or [
            "python",
            "py",
            "powershell",
            "git",
            "web_fetch",
            "ip_lookup",
            "ida",
            "capa",
            "die",
            "floss",
            "exiftool",
            "binary_inspect",
            "binary_find",
            "binary_hexdump",
            "encoded_string_extract",
            "obfuscated_data_map",
            "external_static_analyze",
            "ghidra",
            "ghidra_analyze",
            "angr",
            "angr_triage",
            "yara_scan",
            "upx_unpack",
            "tshark",
            "strings",
            "file",
            "objdump",
            "readelf",
            "dotnet",
            "ilspycmd",
            "java",
            "jadx",
            "apktool",
            "frida",
            "pefile",
            "lief",
            "capstone",
            "unicorn",
        ]
        rows = [_probe_tool(str(name).strip(), include_versions, self.config) for name in requested if str(name).strip()]

        lines = ["# Tool Health Check", ""]
        available_count = sum(1 for row in rows if row.get("available"))
        lines.append(f"Available: {available_count}/{len(rows)}")
        lines.append("")
        for row in rows:
            status = "OK" if row.get("available") else "MISSING"
            lines.append(f"- {status} {row.get('name')} ({row.get('kind')})")
            if row.get("path"):
                lines.append(f"  path: {row.get('path')}")
            if row.get("version"):
                lines.append(f"  version: {row.get('version')}")
            if row.get("dependencies"):
                for dep in row["dependencies"]:
                    dep_status = "OK" if dep.get("available") else "MISSING"
                    dep_path = f" path={dep.get('path')}" if dep.get("path") else ""
                    lines.append(f"  - {dep_status} {dep.get('name')}{dep_path}")
                    if not dep.get("available") and dep.get("name") in INSTALL_HINTS:
                        lines.append(f"    hint: {INSTALL_HINTS[dep.get('name')]}")
            if row.get("error"):
                lines.append(f"  error: {row.get('error')}")
            if not row.get("available") and row.get("name") in INSTALL_HINTS:
                lines.append(f"  hint: {INSTALL_HINTS[row.get('name')]}")

        missing = [row["name"] for row in rows if not row.get("available")]
        if missing:
            lines.extend([
                "",
                "## Notes",
                "- Missing optional dependencies do not block built-in static triage.",
                "- For missing IDA, run ida_probe for detailed path diagnostics.",
                "- Continue with built-in tools when external tools are unavailable.",
            ])
        return ToolResult(
            content="\n".join(lines),
            is_error=False,
            metadata={
                "checked": len(rows),
                "available": available_count,
                "missing": missing,
            },
        )
