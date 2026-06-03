"""Optional external static-analysis tool integrations."""

import shutil
import subprocess
from pathlib import Path

from .base import Tool, ToolResult


SUPPORTED_ANALYZERS = {
    "capa": {
        "exe": "capa",
        "args": lambda target: ["capa", str(target)],
        "description": "Mandiant capa capability detection",
    },
    "die": {
        "exe": "diec",
        "args": lambda target: ["diec", str(target)],
        "description": "Detect It Easy file identification",
    },
    "floss": {
        "exe": "floss",
        "args": lambda target: ["floss", str(target)],
        "description": "FLOSS string extraction",
    },
    "exiftool": {
        "exe": "exiftool",
        "args": lambda target: ["exiftool", str(target)],
        "description": "ExifTool metadata extraction",
    },
}


class ExternalStaticAnalyzeTool(Tool):
    name = "external_static_analyze"
    description = (
        "Run installed external static-analysis CLIs such as capa, diec, FLOSS, "
        "and exiftool against a local binary. Does not execute the target binary."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Absolute path to the binary to analyze.",
            },
            "analyzers": {
                "type": "array",
                "description": "Optional analyzer names: capa, die, floss, exiftool. Default: all installed.",
                "items": {"type": "string"},
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout per analyzer in milliseconds. Default 180000, max 900000.",
            },
        },
        "required": ["file_path"],
    }

    def execute(
        self, file_path: str, analyzers: list[str] | None = None,
        timeout: int = 180000, **kwargs
    ) -> ToolResult:
        target = Path(file_path)
        if not target.exists():
            return ToolResult(content=f"File not found: {file_path}", is_error=True)
        if target.is_dir():
            return ToolResult(content=f"Path is a directory, not a file: {file_path}", is_error=True)

        requested = [a.lower() for a in analyzers] if analyzers else list(SUPPORTED_ANALYZERS)
        unknown = [a for a in requested if a not in SUPPORTED_ANALYZERS]
        if unknown:
            return ToolResult(content=f"Unknown analyzers: {', '.join(unknown)}", is_error=True)

        timeout_sec = min(max(int(timeout), 10000), 900000) / 1000
        results = []
        ran = 0
        missing = []
        for name in requested:
            spec = SUPPORTED_ANALYZERS[name]
            exe = shutil.which(spec["exe"])
            if not exe:
                missing.append(name)
                continue
            cmd = spec["args"](target)
            cmd[0] = exe
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout_sec,
                )
            except subprocess.TimeoutExpired:
                results.append(f"## {name}\nTimed out after {int(timeout_sec)}s.")
                continue

            ran += 1
            output = (proc.stdout or "").strip()
            if proc.stderr:
                output += ("\n[stderr]\n" + proc.stderr.strip())
            if not output:
                output = "(no output)"
            if len(output) > 50000:
                output = output[:50000] + "\n... (truncated)"
            results.append(
                f"## {name}\n"
                f"{spec['description']}\n"
                f"Exit code: {proc.returncode}\n\n"
                f"{output}"
            )

        if not ran and missing:
            return ToolResult(
                content=(
                    "No requested external analyzers were found on PATH. Missing: "
                    f"{', '.join(missing)}. Install one of: capa, diec, floss, exiftool."
                ),
                is_error=True,
                metadata={"missing": missing, "ran": 0},
            )

        header = [
            "# External Static Analysis",
            "",
            f"Target: {target}",
        ]
        if missing:
            header.append(f"Missing analyzers: {', '.join(missing)}")
        return ToolResult(
            content="\n".join(header + [""] + results),
            metadata={"path": str(target), "ran": ran, "missing": missing},
        )


class YaraScanTool(Tool):
    name = "yara_scan"
    description = (
        "Run YARA rules against a local file or directory. Requires yara on PATH. "
        "Does not execute the target binary."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target_path": {
                "type": "string",
                "description": "Absolute path to the file or directory to scan.",
            },
            "rules_path": {
                "type": "string",
                "description": "Absolute path to a YARA rule file or rules directory.",
            },
            "recursive": {
                "type": "boolean",
                "description": "Recursively scan target/rules directories. Default true.",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in milliseconds. Default 120000, max 600000.",
            },
        },
        "required": ["target_path", "rules_path"],
    }

    def execute(
        self, target_path: str, rules_path: str, recursive: bool = True,
        timeout: int = 120000, **kwargs
    ) -> ToolResult:
        yara = shutil.which("yara")
        if not yara:
            return ToolResult(content="yara executable not found on PATH.", is_error=True)
        target = Path(target_path)
        rules = Path(rules_path)
        if not target.exists():
            return ToolResult(content=f"Target not found: {target_path}", is_error=True)
        if not rules.exists():
            return ToolResult(content=f"Rules path not found: {rules_path}", is_error=True)

        cmd = [yara]
        if recursive:
            cmd.append("-r")
        cmd.extend([str(rules), str(target)])
        timeout_sec = min(max(int(timeout), 10000), 600000) / 1000
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_sec,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(content=f"YARA scan timed out after {int(timeout_sec)}s.", is_error=True)

        output = (proc.stdout or "").strip()
        if proc.stderr:
            output += ("\n[stderr]\n" + proc.stderr.strip())
        if not output:
            output = "(no matches)"
        return ToolResult(
            content=f"# YARA Scan\n\nTarget: {target}\nRules: {rules}\n\n{output}",
            is_error=proc.returncode not in (0, 1),
            metadata={"target": str(target), "rules": str(rules), "exit_code": proc.returncode},
        )


class UpxUnpackTool(Tool):
    name = "upx_unpack"
    description = (
        "Unpack a UPX-packed binary with the external upx CLI. This is for CTF, "
        "malware triage, and authorized reverse engineering. Does not execute the target binary."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Absolute path to the UPX-packed binary.",
            },
            "output_path": {
                "type": "string",
                "description": "Optional output path. Default: <stem>.unpacked<suffix> beside input.",
            },
            "upx_path": {
                "type": "string",
                "description": "Optional path to upx. Defaults to PATH lookup.",
            },
            "overwrite": {
                "type": "boolean",
                "description": "Overwrite output_path if it exists. Default false.",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in milliseconds. Default 120000, max 600000.",
            },
        },
        "required": ["file_path"],
    }

    def execute(
        self, file_path: str, output_path: str | None = None,
        upx_path: str | None = None, overwrite: bool = False,
        timeout: int = 120000, **kwargs
    ) -> ToolResult:
        target = Path(file_path)
        if not target.exists():
            return ToolResult(content=f"File not found: {file_path}", is_error=True)
        if target.is_dir():
            return ToolResult(content=f"Path is a directory, not a file: {file_path}", is_error=True)

        upx = upx_path if upx_path and Path(upx_path).exists() else shutil.which(upx_path or "upx")
        if not upx:
            return ToolResult(
                content="upx executable not found. Install UPX or pass upx_path.",
                is_error=True,
            )

        out = Path(output_path) if output_path else target.with_name(f"{target.stem}.unpacked{target.suffix}")
        if out.exists() and not overwrite:
            return ToolResult(
                content=f"Output already exists: {out}. Pass overwrite=true or choose output_path.",
                is_error=True,
            )
        out.parent.mkdir(parents=True, exist_ok=True)

        cmd = [str(upx), "-d", "-o", str(out), str(target)]
        if overwrite:
            cmd.insert(2, "-f")
        timeout_sec = min(max(int(timeout), 10000), 600000) / 1000
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_sec,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(content=f"UPX unpack timed out after {int(timeout_sec)}s.", is_error=True)

        output = (proc.stdout or "").strip()
        if proc.stderr:
            output += ("\n[stderr]\n" + proc.stderr.strip())
        if not output:
            output = "(no output)"

        ok = proc.returncode == 0 and out.exists()
        return ToolResult(
            content=(
                "# UPX Unpack\n\n"
                f"Input: {target}\n"
                f"Output: {out}\n"
                f"Exit code: {proc.returncode}\n\n"
                f"{output}"
            ),
            is_error=not ok,
            metadata={
                "input": str(target),
                "output": str(out),
                "exit_code": proc.returncode,
                "created": out.exists(),
            },
        )
