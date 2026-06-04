"""Optional external static-analysis tool integrations."""

import json
import re
import shutil
import subprocess
from pathlib import Path

from .base import Tool, ToolResult, coerce_bool, coerce_int, coerce_str_list


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

INTERESTING_STATIC_RE = re.compile(
    r"(anti|debug|vm|sandbox|inject|process|thread|service|registry|socket|http|"
    r"https|dns|connect|crypto|encrypt|decrypt|base64|xor|persistence|mutex|"
    r"credential|keylog|screenshot|clipboard|ransom|packer|upx|themida|vmprotect)",
    re.I,
)


def _short_line(text: str, limit: int = 180) -> str:
    text = str(text or "").replace("\r", " ").replace("\n", " ").strip()
    return text[:limit]


def _json_or_none(text: str):
    try:
        return json.loads(text)
    except Exception:
        return None


def _walk_json_strings(value, limit: int = 300) -> list[str]:
    out: list[str] = []

    def walk(item):
        if len(out) >= limit:
            return
        if isinstance(item, dict):
            for key, val in item.items():
                if isinstance(val, str) and key.lower() in {
                    "name", "rule", "namespace", "description", "scope", "capability",
                    "technique", "tactic", "value", "string",
                }:
                    out.append(val)
                walk(val)
        elif isinstance(item, list):
            for child in item:
                walk(child)
        elif isinstance(item, str) and INTERESTING_STATIC_RE.search(item):
            out.append(item)

    walk(value)
    seen = set()
    deduped = []
    for item in out:
        line = _short_line(item)
        if line and line not in seen:
            seen.add(line)
            deduped.append(line)
    return deduped[:limit]


def _summarize_external_output(name: str, output: str) -> list[str]:
    parsed = _json_or_none(output)
    evidence: list[str] = []
    if parsed is not None:
        evidence.extend(_walk_json_strings(parsed, 120))
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        lowered = line.lower()
        if name == "die" and any(key in lowered for key in ("packer", "compiler", "linker", "protector", "entropy")):
            evidence.append(line)
        elif name == "floss" and INTERESTING_STATIC_RE.search(line):
            evidence.append(line)
        elif name == "capa" and (
            INTERESTING_STATIC_RE.search(line)
            or line.startswith(("namespace", "ATT&CK", "MBC", "rule"))
        ):
            evidence.append(line)
        elif name == "exiftool" and any(key in lowered for key in ("file type", "machine", "subsystem", "linker", "timestamp")):
            evidence.append(line)

    seen = set()
    compact = []
    for item in evidence:
        line = _short_line(item)
        if line and line not in seen:
            seen.add(line)
            compact.append(line)
        if len(compact) >= 40:
            break

    if not compact:
        return [f"- {name}: no high-signal lines extracted; inspect raw output below."]
    return [f"- {line}" for line in compact]


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

    def __init__(self, config=None):
        self.config = config

    def _resolve_analyzer(self, name: str, spec: dict) -> str | None:
        configured = ""
        if name == "die" and self.config is not None:
            configured = getattr(self.config, "die_path", "") or ""
        elif name == "exiftool" and self.config is not None:
            configured = getattr(self.config, "exiftool_path", "") or ""
        if configured and Path(configured).exists():
            return str(Path(configured))
        return shutil.which(spec["exe"])

    def execute(
        self, file_path: str, analyzers: list[str] | None = None,
        timeout: int = 180000, **kwargs
    ) -> ToolResult:
        target = Path(file_path)
        if not target.exists():
            return ToolResult(content=f"File not found: {file_path}", is_error=True)
        if target.is_dir():
            return ToolResult(content=f"Path is a directory, not a file: {file_path}", is_error=True)

        requested = [a.lower() for a in coerce_str_list(analyzers)] if analyzers else list(SUPPORTED_ANALYZERS)
        unknown = [a for a in requested if a not in SUPPORTED_ANALYZERS]
        if unknown:
            return ToolResult(content=f"Unknown analyzers: {', '.join(unknown)}", is_error=True)

        timeout_sec = coerce_int(timeout, 180000, minimum=10000, maximum=900000) / 1000
        results = []
        ran = 0
        missing = []
        for name in requested:
            spec = SUPPORTED_ANALYZERS[name]
            exe = self._resolve_analyzer(name, spec)
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
            evidence = _summarize_external_output(name, output)
            results.append(
                f"## {name}\n"
                f"{spec['description']}\n"
                f"Exit code: {proc.returncode}\n\n"
                f"### AI Evidence Summary\n"
                + "\n".join(evidence)
                + "\n\n### Raw Output\n"
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
        recursive = coerce_bool(recursive, True)
        timeout_sec = coerce_int(timeout, 120000, minimum=10000, maximum=600000) / 1000
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

    def __init__(self, config=None):
        self.config = config

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

        configured = getattr(self.config, "upx_path", "") if self.config is not None else ""
        selected = upx_path or configured or "upx"
        upx = selected if selected and Path(selected).exists() else shutil.which(selected)
        if not upx:
            return ToolResult(
                content="upx executable not found. Install UPX or pass upx_path.",
                is_error=True,
            )

        out = Path(output_path) if output_path else target.with_name(f"{target.stem}.unpacked{target.suffix}")
        overwrite = coerce_bool(overwrite, False)
        if out.exists() and not overwrite:
            return ToolResult(
                content=f"Output already exists: {out}. Pass overwrite=true or choose output_path.",
                is_error=True,
            )
        out.parent.mkdir(parents=True, exist_ok=True)

        cmd = [str(upx), "-d", "-o", str(out), str(target)]
        if overwrite:
            cmd.insert(2, "-f")
        timeout_sec = coerce_int(timeout, 120000, minimum=10000, maximum=600000) / 1000
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
