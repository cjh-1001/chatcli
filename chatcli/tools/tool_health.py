"""Tool availability diagnostics."""

from __future__ import annotations

import shutil
import subprocess
import sys

from .base import Tool, ToolResult
from .ida import _find_ida


BUILT_IN_TOOLS = {
    "bash",
    "read_file",
    "write_file",
    "edit_file",
    "multi_edit",
    "glob",
    "grep",
    "list_dir",
    "binary_inspect",
    "binary_find",
    "binary_hexdump",
    "binary_patch",
    "encoded_string_extract",
    "obfuscated_data_map",
    "reverse_technique_map",
    "reverse_evidence_map",
    "runtime_string_hooks",
    "external_static_analyze",
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
    "dotnet": ["dotnet"],
    "ilspycmd": ["ilspycmd"],
}

TOOL_DEPENDENCIES = {
    "ida_probe": ["ida"],
    "ida_analyze": ["ida"],
    "ida_focus_decompile": ["ida"],
    "ida_deobfuscate": ["ida"],
    "external_static_analyze": ["capa", "die", "floss", "exiftool"],
    "yara_scan": ["yara"],
    "upx_unpack": ["upx"],
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


def _probe_external(name: str, include_versions: bool) -> dict[str, object]:
    if name == "ida":
        path = _find_ida()
    else:
        path = _which_any(EXECUTABLE_PROBES.get(name, [name]))
    row: dict[str, object] = {
        "name": name,
        "kind": "external",
        "available": bool(path),
        "path": path or "",
    }
    if include_versions and path:
        row["version"] = _version(path)
    return row


def _probe_tool(name: str, include_versions: bool) -> dict[str, object]:
    if name in BUILT_IN_TOOLS:
        return {
            "name": name,
            "kind": "built-in",
            "available": True,
            "path": "chatcli",
        }
    if name in TOOL_DEPENDENCIES:
        deps = [_probe_external(dep, include_versions) for dep in TOOL_DEPENDENCIES[name]]
        available = any(dep["available"] for dep in deps) if name == "external_static_analyze" else all(dep["available"] for dep in deps)
        return {
            "name": name,
            "kind": "tool",
            "available": available,
            "dependencies": deps,
        }
    if name in EXECUTABLE_PROBES or name == "ida":
        return _probe_external(name, include_versions)
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
                    "external_static_analyze, yara_scan, upx_unpack, git, python, ilspycmd. "
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

    def execute(self, tools: list[str] | None = None, include_versions: bool = False, **kwargs) -> ToolResult:
        requested = tools or [
            "python",
            "py",
            "powershell",
            "git",
            "ida",
            "binary_inspect",
            "binary_find",
            "binary_hexdump",
            "encoded_string_extract",
            "obfuscated_data_map",
            "external_static_analyze",
            "yara_scan",
            "upx_unpack",
            "dotnet",
            "ilspycmd",
        ]
        rows = [_probe_tool(str(name).strip(), bool(include_versions)) for name in requested if str(name).strip()]

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
            if row.get("error"):
                lines.append(f"  error: {row.get('error')}")

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
