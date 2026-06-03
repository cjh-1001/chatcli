"""IDA Pro headless static-analysis integration."""

import json
import os
import hashlib
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .base import Tool, ToolResult
from .ida_script import IDA_SCRIPT


def _safe_cache_name(value: str, fallback: str = "target") -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")
    return (name or fallback)[:80]


def _target_cache_key(target: Path, extra: str = "") -> str:
    try:
        resolved = str(target.resolve())
    except Exception:
        resolved = str(target)
    try:
        stat = target.stat()
        identity = f"{resolved}|{stat.st_size}|{stat.st_mtime_ns}|{extra}"
    except Exception:
        identity = f"{resolved}|{extra}"
    return hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest()[:16]


def _default_ida_json_path(
    target: Path,
    prefix: str,
    workspace: str | None = None,
    extra: str = "",
) -> Path:
    if workspace:
        root = Path(workspace) / ".chatcli" / "tmp" / "ida"
    else:
        root = Path(tempfile.gettempdir()) / "chatcli-ida-cache"
    key = _target_cache_key(target, extra)
    return root / f"{prefix}-{_safe_cache_name(target.stem)}-{key}.json"


def _load_reusable_json(output_path: Path, target: Path) -> dict | None:
    if not output_path.exists():
        return None
    try:
        if output_path.stat().st_mtime_ns < target.stat().st_mtime_ns:
            return None
        data = json.loads(output_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _cleanup_paths(*paths: Path) -> None:
    for path in paths:
        try:
            path.unlink()
        except Exception:
            pass


def _headless_siblings(path: Path) -> list[Path]:
    return [path / name for name in ("idat64.exe", "idat.exe", "idat64", "idat")]


def _common_ida_locations() -> list[Path]:
    roots: list[Path] = []
    for env_name in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        value = os.environ.get(env_name)
        if value:
            roots.append(Path(value))
    roots.extend([Path("C:/Program Files"), Path("C:/Program Files (x86)"), Path("C:/IDA"), Path("C:/IDA Pro")])

    candidates: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        if not root.exists():
            continue
        for pattern in ("IDA*", "Hex-Rays*", "IDA Pro*"):
            for path in root.glob(pattern):
                key = str(path).lower()
                if key in seen:
                    continue
                seen.add(key)
                candidates.extend(_headless_siblings(path))
                candidates.extend([path / "ida64.exe", path / "ida.exe"])
    return candidates


def _ida_not_found_message() -> str:
    return (
        "IDA executable not found. Install IDA Pro/Free and configure one of: "
        "IDA_PATH, IDAT64_PATH, IDAT_PATH, IDA64_PATH, PATH, or pass ida_path. "
        "ida_path may point to idat64/idat/ida64/ida or to an IDA install directory. "
        "Run ida_probe for diagnostics. Continue without IDA using binary_inspect, "
        "encoded_string_extract, obfuscated_data_map, binary_find, and binary_hexdump."
    )


def _find_ida(explicit: str | None = None) -> str | None:
    candidates = []

    def add_candidate(value: str) -> None:
        path = Path(value)
        if path.exists() and path.is_dir():
            candidates.extend(str(p) for p in _headless_siblings(path))
            candidates.extend(str(path / name) for name in ("ida64.exe", "ida.exe", "ida64", "ida"))
            return
        if path.name.lower() in {"ida.exe", "ida64.exe", "ida", "ida64"}:
            for sibling in ("idat64.exe", "idat.exe", "idat64", "idat"):
                headless = path.parent / sibling
                if headless.exists() and headless.is_file():
                    candidates.append(str(headless))
            return
        candidates.append(value)

    if explicit:
        add_candidate(explicit)
    for env_name in ("IDA_PATH", "IDAT64_PATH", "IDAT_PATH", "IDA64_PATH"):
        value = os.environ.get(env_name)
        if value:
            add_candidate(value)
    for name in ("idat64", "idat", "ida64", "ida"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    candidates.extend(str(path) for path in _common_ida_locations())

    for candidate in candidates:
        path = Path(candidate)
        if path.exists() and path.is_file():
            return str(path)
        found = shutil.which(candidate)
        if found:
            return found
    return None


class IdaProbeTool(Tool):
    name = "ida_probe"
    description = (
        "Diagnose IDA availability for headless analysis. Checks explicit ida_path, "
        "IDA-related environment variables, PATH lookup, and common Windows install "
        "directories. Does not run IDA or the target binary."
    )
    parameters = {
        "type": "object",
        "properties": {
            "ida_path": {
                "type": "string",
                "description": "Optional path to idat64/idat/ida64/ida or an IDA install directory.",
            },
        },
    }

    def __init__(self, default_ida_path: str = ""):
        self.default_ida_path = default_ida_path

    def execute(self, ida_path: str | None = None, **kwargs) -> ToolResult:
        explicit = ida_path or self.default_ida_path or ""
        resolved = _find_ida(explicit)
        lines = [
            "# IDA Probe",
            "",
            f"Resolved IDA: {resolved or '(not found)'}",
            "",
            "## Configuration",
            f"- explicit/default ida_path: {explicit or '(none)'}",
        ]
        for env_name in ("IDA_PATH", "IDAT64_PATH", "IDAT_PATH", "IDA64_PATH"):
            lines.append(f"- {env_name}: {os.environ.get(env_name) or '(unset)'}")
        lines.extend(["", "## PATH lookup"])
        for name in ("idat64", "idat", "ida64", "ida"):
            lines.append(f"- {name}: {shutil.which(name) or '(not found)'}")
        lines.extend(["", "## Common install candidates"])
        common = _common_ida_locations()
        if common:
            for path in common[:40]:
                status = "exists" if path.exists() and path.is_file() else "missing"
                lines.append(f"- {path} [{status}]")
        else:
            lines.append("- No common install directories found.")
        if not resolved:
            lines.extend(["", "## Next Steps", f"- {_ida_not_found_message()}"])
        return ToolResult(
            content="\n".join(lines),
            is_error=not bool(resolved),
            metadata={"ida_path": resolved, "found": bool(resolved)},
        )


def _format_summary(data: dict, output_path: Path) -> str:
    lines = [
        "# IDA Analysis",
        "",
        f"Input: {data.get('input', '')}",
        f"Output JSON: {output_path}",
        f"Processor: {data.get('processor', '')}",
        f"Image base: {data.get('image_base', '')}",
        f"Entry: {data.get('entry', '')}",
        "",
        f"Segments: {len(data.get('segments', []))}",
        f"Functions: {len(data.get('functions', []))}",
        f"Imports: {len(data.get('imports', []))}",
        f"Strings: {len(data.get('strings', []))}",
        f"Candidate functions: {len(data.get('candidate_functions', []))}",
        f"Entry analysis order: {len(data.get('entry_analysis_order', []))}",
        f"Pseudocode functions: {len(data.get('pseudocode', []))}",
    ]
    if data.get("partial"):
        lines.extend([
            "",
            f"[partial] IDA checkpoint reached: {data.get('last_checkpoint', 'unknown')}",
        ])
    warnings = data.get("warnings") or []
    if warnings:
        lines.extend(["", "## Warnings"])
        lines.extend(f"- {warning}" for warning in warnings[:10])
    lines.extend(["", "## Entry Analysis Order"])
    for fn in data.get("entry_analysis_order", [])[:40]:
        callees = fn.get("callees") or []
        suffix = f" callees={', '.join(callees[:5])}" if callees else ""
        lines.append(
            f"- {fn.get('start')} {fn.get('name')} score={fn.get('score')}{suffix}"
        )
    lines.extend([
        "",
        "## Candidate Functions",
    ])
    for fn in data.get("candidate_functions", [])[:40]:
        evidence = "; ".join(fn.get("evidence", [])[:3])
        suffix = f" evidence={evidence}" if evidence else ""
        lines.append(
            f"- {fn.get('start')} {fn.get('name')} score={fn.get('score')} "
            f"size={fn.get('size')}{suffix}"
        )
    lines.extend([
        "",
        "## Top Functions",
    ])
    for fn in data.get("functions", [])[:80]:
        lines.append(f"- {fn.get('start')} {fn.get('name')} size={fn.get('size')}")
    lines.extend(["", "## Imports"])
    for imp in data.get("imports", [])[:120]:
        module = imp.get("module", "")
        name = imp.get("name") or f"ordinal_{imp.get('ordinal')}"
        lines.append(f"- {module}!{name} @ {imp.get('ea')}")
    lines.extend(["", "## Strings"])
    for s in data.get("strings", [])[:120]:
        xrefs = s.get("xrefs") or []
        suffix = f" xrefs={', '.join(xrefs[:4])}" if xrefs else ""
        lines.append(f"- {s.get('ea')} {s.get('value')}{suffix}")
    if data.get("pseudocode"):
        lines.extend(["", "## Pseudocode"])
        for item in data.get("pseudocode", [])[:20]:
            text = item.get("text", "")
            first_lines = "\n".join(text.splitlines()[:40])
            lines.append(f"### {item.get('function')} @ {item.get('start')}\n```c\n{first_lines}\n```")
    return "\n".join(lines)


class IdaAnalyzeTool(Tool):
    name = "ida_analyze"
    description = (
        "Run IDA Pro/Free in headless auto-analysis mode for a local binary and "
        "export static-analysis data as JSON. Does not execute the target binary."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Absolute path to the binary to load in IDA.",
            },
            "ida_path": {
                "type": "string",
                "description": "Optional path to idat64/idat/ida64/ida or an IDA install directory. Defaults to IDA_PATH env or PATH lookup.",
            },
            "output_path": {
                "type": "string",
                "description": "Optional JSON output path. Defaults to a temp file.",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in milliseconds. Default 300000, max 900000.",
            },
            "auto_wait_timeout": {
                "type": "integer",
                "description": "Maximum seconds to wait for IDA auto-analysis before exporting partial results. Default 45; 0 skips waiting.",
            },
            "include_pseudocode": {
                "type": "boolean",
                "description": "Export Hex-Rays pseudocode when available. Default false.",
            },
            "max_pseudocode_functions": {
                "type": "integer",
                "description": "Maximum functions to decompile when include_pseudocode is true. Default 30.",
            },
            "reuse_output": {
                "type": "boolean",
                "description": "Reuse the default cached JSON when it already matches this binary and analysis mode. Default true.",
            },
        },
        "required": ["file_path"],
    }

    def __init__(self, default_ida_path: str = ""):
        self.default_ida_path = default_ida_path

    def execute(
        self, file_path: str, ida_path: str | None = None,
        output_path: str | None = None, timeout: int = 300000,
        include_pseudocode: bool = False, max_pseudocode_functions: int = 30,
        auto_wait_timeout: int = 45, reuse_output: bool = True,
        **kwargs
    ) -> ToolResult:
        progress_callback = kwargs.get("_progress_callback")
        workspace = kwargs.get("workspace")

        def emit_progress(message: str) -> None:
            if callable(progress_callback):
                progress_callback(message)
            else:
                print(f"    {message}", flush=True)

        target = Path(file_path)
        if not target.exists():
            return ToolResult(content=f"File not found: {file_path}", is_error=True)
        if target.is_dir():
            return ToolResult(content=f"Path is a directory, not a file: {file_path}", is_error=True)

        ida = _find_ida(ida_path or self.default_ida_path)
        if not ida:
            return ToolResult(
                content=_ida_not_found_message(),
                is_error=True,
            )

        cache_extra = json.dumps({
            "tool": self.name,
            "include_pseudocode": bool(include_pseudocode),
            "max_pseudocode_functions": max(1, min(int(max_pseudocode_functions), 200)),
            "auto_wait_timeout": max(0, min(int(auto_wait_timeout), 3600)),
        }, sort_keys=True)
        out = Path(output_path) if output_path else _default_ida_json_path(target, "analyze", workspace, cache_extra)
        out.parent.mkdir(parents=True, exist_ok=True)
        if reuse_output and not output_path:
            cached = _load_reusable_json(out, target)
            if cached is not None:
                emit_progress(f"ida_analyze reused cached JSON: {out}")
                return ToolResult(
                    content=_format_summary(cached, out) + "\n\n[cached] Reused existing IDA JSON.",
                    is_error=False,
                    metadata={
                        "path": str(target),
                        "output_path": str(out),
                        "ida_path": ida,
                        "cached": True,
                        "functions": len(cached.get("functions", [])),
                        "imports": len(cached.get("imports", [])),
                        "strings": len(cached.get("strings", [])),
                        "candidate_functions": len(cached.get("candidate_functions", [])),
                        "entry_analysis_order": len(cached.get("entry_analysis_order", [])),
                        "pseudocode": len(cached.get("pseudocode", [])),
                    },
                )

        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
            script_path = Path(f.name)
            progress_path = script_path.with_suffix(".progress.jsonl")
            f.write(IDA_SCRIPT % (
                str(out),
                str(progress_path),
                bool(include_pseudocode),
                max(1, min(int(max_pseudocode_functions), 200)),
                max(0, min(int(auto_wait_timeout), 3600)),
            ))

        timeout_sec = min(max(int(timeout), 10000), 900000) / 1000
        stdout_path = script_path.with_suffix(".stdout.txt")
        stderr_path = script_path.with_suffix(".stderr.txt")
        cmd = [ida, "-A", f"-S{script_path}", str(target)]
        emit_progress(f"ida_analyze started ({Path(ida).name}, timeout {int(timeout_sec)}s)")
        progress_pos = 0
        last_progress = ""

        def format_progress_event(event: dict) -> str:
            stage = event.get("stage", "")
            if stage == "auto_wait":
                return f"ida auto-analysis {event.get('status', '')}".strip()
            if stage == "metadata":
                return f"ida metadata processor={event.get('processor', '')} entry={event.get('entry', '')}"
            if stage in {"segments", "functions", "imports", "strings"}:
                status = event.get("status", "")
                tail = f" {status}" if status else ""
                return f"ida {stage} {event.get('count', 0)}{tail}"
            if stage == "candidates":
                top = ", ".join([x for x in event.get("top", []) if x][:3])
                suffix = f" top={top}" if top else ""
                return f"ida candidates {event.get('count', 0)}{suffix}"
            if stage == "entry_order":
                first = ", ".join([x for x in event.get("first", []) if x][:3])
                suffix = f" first={first}" if first else ""
                return f"ida entry-order {event.get('count', 0)}{suffix}"
            if stage == "decompile":
                return f"ida decompile {event.get('count', 0)} {event.get('function', '')}".strip()
            if stage == "pseudocode":
                return f"ida pseudocode {event.get('count', 0)} {event.get('status', '')}".strip()
            if stage == "done":
                return "ida done"
            return f"ida {stage}".strip()

        def drain_progress() -> None:
            nonlocal progress_pos, last_progress
            if not progress_path.exists():
                return
            try:
                with open(progress_path, "r", encoding="utf-8", errors="replace") as pf:
                    pf.seek(progress_pos)
                    lines = pf.readlines()
                    progress_pos = pf.tell()
            except Exception:
                return
            for line in lines:
                try:
                    event = json.loads(line)
                except Exception:
                    continue
                message = format_progress_event(event)
                if message and message != last_progress:
                    emit_progress(message)
                    last_progress = message

        try:
            with open(stdout_path, "w", encoding="utf-8", errors="replace") as stdout_f, \
                    open(stderr_path, "w", encoding="utf-8", errors="replace") as stderr_f:
                proc = subprocess.Popen(
                    cmd,
                    stdout=stdout_f,
                    stderr=stderr_f,
                    text=True,
                )
                started = time.monotonic()
                next_heartbeat = 10.0
                while proc.poll() is None:
                    elapsed = time.monotonic() - started
                    drain_progress()
                    if elapsed >= timeout_sec:
                        proc.kill()
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            pass
                        if out.exists():
                            try:
                                partial = json.loads(out.read_text(encoding="utf-8"))
                                if isinstance(partial, dict):
                                    partial["partial"] = True
                                    partial["last_checkpoint"] = (
                                        partial.get("last_checkpoint") or "timeout"
                                    )
                                    partial.setdefault("warnings", []).append(
                                        f"IDA analysis timed out after {int(timeout_sec)}s; using partial checkpoint."
                                    )
                                    out.write_text(
                                        json.dumps(partial, ensure_ascii=False, indent=2),
                                        encoding="utf-8",
                                    )
                                    _cleanup_paths(stdout_path, stderr_path, progress_path)
                                    return ToolResult(
                                        content=(
                                            _format_summary(partial, out)
                                            + "\n\n[partial] Use reverse_evidence_map on this JSON, "
                                            "then continue with targeted child tasks or ida_focus_decompile."
                                        ),
                                        is_error=False,
                                        metadata={
                                            "path": str(target),
                                            "output_path": str(out),
                                            "ida_path": ida,
                                            "timeout": int(timeout_sec),
                                            "partial": True,
                                            "functions": len(partial.get("functions", [])),
                                            "imports": len(partial.get("imports", [])),
                                            "strings": len(partial.get("strings", [])),
                                            "candidate_functions": len(partial.get("candidate_functions", [])),
                                            "entry_analysis_order": len(partial.get("entry_analysis_order", [])),
                                            "pseudocode": len(partial.get("pseudocode", [])),
                                        },
                                    )
                            except Exception:
                                pass
                        _cleanup_paths(stdout_path, stderr_path, progress_path)
                        return ToolResult(
                            content=(
                                f"IDA analysis timed out after {int(timeout_sec)}s. "
                                f"Command: {' '.join(cmd)}. No checkpoint JSON was available."
                            ),
                            is_error=True,
                            metadata={"ida_path": ida, "timeout": int(timeout_sec)},
                        )
                    if elapsed >= next_heartbeat:
                        emit_progress(f"ida_analyze running {int(elapsed)}s/{int(timeout_sec)}s")
                        next_heartbeat += 10.0
                    time.sleep(0.5)
                drain_progress()
        finally:
            _cleanup_paths(script_path)

        if not out.exists():
            stdout = stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_path.exists() else ""
            stderr = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
            details = stdout + ("\n[stderr]\n" + stderr if stderr else "")
            _cleanup_paths(stdout_path, stderr_path, progress_path)
            return ToolResult(
                content=(
                    "IDA did not produce an output JSON file. "
                    f"Exit code: {proc.returncode}\n{details[:4000]}"
                ),
                is_error=True,
                metadata={"exit_code": proc.returncode, "ida_path": ida},
            )

        try:
            data = json.loads(out.read_text(encoding="utf-8"))
        except Exception as e:
            _cleanup_paths(stdout_path, stderr_path, progress_path)
            return ToolResult(content=f"IDA output JSON could not be read: {e}", is_error=True)

        _cleanup_paths(stdout_path, stderr_path, progress_path)

        content = _format_summary(data, out)
        if proc.returncode != 0:
            content += f"\n\n[warning] IDA exited with code {proc.returncode}."

        return ToolResult(
            content=content,
            is_error=False,
            metadata={
                "path": str(target),
                "output_path": str(out),
                "ida_path": ida,
                "exit_code": proc.returncode,
                "cached": False,
                "functions": len(data.get("functions", [])),
                "imports": len(data.get("imports", [])),
                "strings": len(data.get("strings", [])),
                "candidate_functions": len(data.get("candidate_functions", [])),
                "entry_analysis_order": len(data.get("entry_analysis_order", [])),
                "pseudocode": len(data.get("pseudocode", [])),
            },
        )
