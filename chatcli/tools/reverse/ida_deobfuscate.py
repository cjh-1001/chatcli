"""IDA deobfuscation and function-map tool."""

import json
import subprocess
import tempfile
import time
from pathlib import Path

from ..base import Tool, ToolResult
from ..ida import _cleanup_paths, _default_ida_json_path, _find_ida, _ida_not_found_message, _load_reusable_json

from .ida_deobfuscate_script import IDA_DEOBFUSCATE_SCRIPT

def _render_ida_deobfuscate_script(
    out: Path,
    progress_path: Path,
    patch_database: bool,
    apply_names: bool,
    include_pseudocode: bool,
    max_functions: int,
    max_pseudocode: int,
    max_instructions_per_function: int,
    auto_wait_timeout: int,
    signatures: list[str] | None,
    plugin_modules: list[str] | None,
    plugin_scripts: list[str] | None,
) -> str:
    script = IDA_DEOBFUSCATE_SCRIPT
    replacements = {
        "__OUT_PATH__": repr(str(out)),
        "__PROGRESS_PATH__": repr(str(progress_path)),
        "__PATCH_DATABASE__": repr(bool(patch_database)),
        "__APPLY_NAMES__": repr(bool(apply_names)),
        "__INCLUDE_PSEUDOCODE__": repr(bool(include_pseudocode)),
        "__MAX_FUNCTIONS__": str(max(1, min(int(max_functions), 10000))),
        "__MAX_PSEUDOCODE__": str(max(1, min(int(max_pseudocode), 300))),
        "__MAX_INSTRUCTIONS_PER_FUNCTION__": str(max(100, min(int(max_instructions_per_function), 200000))),
        "__AUTO_WAIT_SECONDS__": str(max(0, min(int(auto_wait_timeout), 3600))),
        "__SIGNATURES__": repr([str(x) for x in (signatures or []) if str(x).strip()]),
        "__PLUGIN_MODULES__": repr([str(x) for x in (plugin_modules or []) if str(x).strip()]),
        "__PLUGIN_SCRIPTS__": repr([str(x) for x in (plugin_scripts or []) if str(x).strip()]),
    }
    for key, value in replacements.items():
        script = script.replace(key, value)
    return script


def _format_deobfuscation_summary(data: dict, output_path: Path) -> str:
    lines = [
        "# IDA Deobfuscation",
        "",
        f"Input: {data.get('input', '')}",
        f"Output JSON: {output_path}",
        f"Processor: {data.get('processor', '')}",
        f"Image base: {data.get('image_base', '')}",
        f"Patched IDA database: {data.get('patched_database', False)}",
        "",
        f"Opaque predicates: {len(data.get('opaque_predicates', []))}",
        f"Junk instructions: {len(data.get('junk_instructions', []))}",
        f"Flattened candidates: {len(data.get('flattened_candidates', []))}",
        f"PE/API function labels: {len(data.get('pe_function_labels', []))}",
        f"Function maps: {len(data.get('function_maps', []))}",
        f"Signatures: {len(data.get('signatures', []))}",
        f"External deobfuscators: {len(data.get('external_plugins', []))}",
        f"Strings: {len(data.get('strings', []))}",
        f"Pseudocode functions: {len(data.get('pseudocode', []))}",
    ]
    if data.get("warnings"):
        lines.extend(["", "## Warnings"])
        for warning in data.get("warnings", [])[:30]:
            lines.append(f"- {warning}")
    lines.extend(["", "## Flattened Switch / State-Machine Candidates"])
    for item in sorted(data.get("flattened_candidates", []), key=lambda x: x.get("score", 0), reverse=True)[:40]:
        lines.append(
            f"- {item.get('start')} {item.get('function')} score={item.get('score')} "
            f"blocks={item.get('basic_blocks')} switches={item.get('switches')} "
            f"indirect_jumps={item.get('indirect_jumps')} back_edges={item.get('back_edges')}"
        )
    lines.extend(["", "## Opaque Predicates"])
    for item in data.get("opaque_predicates", [])[:80]:
        lines.append(
            f"- {item.get('ea')} {item.get('function')} {item.get('mnem')} -> "
            f"{item.get('condition')} target={item.get('target')} reason={item.get('reason')}"
        )
    lines.extend(["", "## Junk Instructions"])
    for item in data.get("junk_instructions", [])[:80]:
        lines.append(
            f"- {item.get('ea')} {item.get('function')} {item.get('reason')}: {item.get('mnem')}"
        )
    lines.extend(["", "## PE/API Labels"])
    for item in data.get("pe_function_labels", [])[:80]:
        evidence = ", ".join(item.get("evidence", [])[:4])
        lines.append(f"- {item.get('start')} {item.get('name')} role={item.get('role')} evidence={evidence}")
    lines.extend(["", "## Function Maps"])
    for item in sorted(data.get("function_maps", []), key=lambda x: x.get("size", 0), reverse=True)[:20]:
        strings = "; ".join((s.get("value", "") for s in item.get("strings", [])[:3] if s.get("value")))
        strings_suffix = f" strings={strings}" if strings else ""
        role = item.get("api_role") or {}
        role_suffix = f" role={role.get('role')}" if role.get("role") else ""
        lines.append(
            f"- {item.get('start')} {item.get('name')} size={item.get('size')} "
            f"blocks={item.get('basic_blocks')} mapped_blocks={len(item.get('mapped_blocks', []))}"
            f"{role_suffix}{strings_suffix}"
        )
        for block in item.get("mapped_blocks", [])[:5]:
            sample = "; ".join(block.get("sampled_instructions", [])[:2])
            lines.append(
                f"  - block {block.get('start')}..{block.get('end')} size={block.get('size')} "
                f"succs={','.join(block.get('succs', [])[:3])} "
                f"calls={block.get('calls_sampled')} jumps={block.get('jumps_sampled')} "
                f"junk={block.get('junk_sampled')} sample={sample}"
            )
    if data.get("signatures"):
        lines.extend(["", "## Signatures"])
        for item in data.get("signatures", [])[:80]:
            suffix = f" error={item.get('error')}" if item.get("error") else ""
            lines.append(f"- {item.get('signature')} status={item.get('status')}{suffix}")
    if data.get("external_plugins"):
        lines.extend(["", "## External Deobfuscators"])
        for item in data.get("external_plugins", [])[:80]:
            name = item.get("name") or item.get("path")
            suffix = f" error={item.get('error')}" if item.get("error") else ""
            lines.append(f"- {item.get('kind')} {name} status={item.get('status')}{suffix}")
    if data.get("pseudocode"):
        lines.extend(["", "## Pseudocode"])
        for item in data.get("pseudocode", [])[:12]:
            text = "\n".join((item.get("text") or "").splitlines()[:50])
            lines.append(f"### {item.get('function')} @ {item.get('start')}\n```c\n{text}\n```")
    return "\n".join(lines)


class IdaDeobfuscateTool(Tool):
    name = "ida_deobfuscate"
    description = (
        "Run an IDAPython deobfuscation pass on an authorized local binary. It detects "
        "flattened switch/state-machine candidates, high-confidence constant opaque "
        "predicates, junk instructions, PE/API-based function roles, and function maps "
        "for large or high-signal functions. Optionally patches only the IDA database "
        "and exports Hex-Rays pseudocode when available."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Absolute path to the binary to load in IDA."},
            "ida_path": {"type": "string", "description": "Optional path to idat64/idat/ida64/ida or an IDA install directory."},
            "output_path": {"type": "string", "description": "Optional JSON output path. Defaults to temp file."},
            "timeout": {"type": "integer", "description": "Timeout in milliseconds. Default 180000, max 900000."},
            "patch_database": {
                "type": "boolean",
                "description": "Patch only the IDA database to NOP high-confidence junk and simplify constant branches. Default false.",
            },
            "apply_names": {
                "type": "boolean",
                "description": "Rename unnamed sub_ functions using API-role hints in the IDA database. Default true.",
            },
            "include_pseudocode": {
                "type": "boolean",
                "description": "Export Hex-Rays pseudocode for likely obfuscated/labeled functions. Default true.",
            },
            "max_functions": {"type": "integer", "description": "Maximum functions to scan. Default 3000."},
            "max_pseudocode_functions": {"type": "integer", "description": "Maximum functions to decompile. Default 40."},
            "max_instructions_per_function": {
                "type": "integer",
                "description": "Maximum instructions to scan per function for deobfuscation heuristics. Default 5000.",
            },
            "auto_wait_timeout": {
                "type": "integer",
                "description": "Maximum seconds to wait for IDA auto-analysis before continuing with partial results. Default 30; 0 skips waiting.",
            },
            "signatures": {
                "type": "array",
                "description": "Optional IDA FLIRT signature names or .sig paths to apply before API-role labeling.",
                "items": {"type": "string"},
            },
            "plugin_modules": {
                "type": "array",
                "description": "Optional installed IDAPython plugin module names to import/run, e.g. local unflatten/OLLVM/Hex-Rays deobfuscator modules.",
                "items": {"type": "string"},
            },
            "plugin_scripts": {
                "type": "array",
                "description": "Optional absolute paths to extra IDAPython scripts to run after built-in cleanup. CHATCLI_REPORT is provided in globals.",
                "items": {"type": "string"},
            },
            "reuse_output": {
                "type": "boolean",
                "description": "Reuse the default cached JSON when it matches this binary and deobfuscation options. Ignored when patch_database is true. Default true.",
            },
        },
        "required": ["file_path"],
    }

    def __init__(self, default_ida_path: str = ""):
        self.default_ida_path = default_ida_path

    def execute(
        self,
        file_path: str,
        ida_path: str | None = None,
        output_path: str | None = None,
        timeout: int = 180000,
        patch_database: bool = False,
        apply_names: bool = True,
        include_pseudocode: bool = True,
        max_functions: int = 3000,
        max_pseudocode_functions: int = 40,
        max_instructions_per_function: int = 5000,
        auto_wait_timeout: int = 30,
        signatures: list[str] | None = None,
        plugin_modules: list[str] | None = None,
        plugin_scripts: list[str] | None = None,
        reuse_output: bool = True,
        **kwargs,
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
            "patch_database": bool(patch_database),
            "apply_names": bool(apply_names),
            "include_pseudocode": bool(include_pseudocode),
            "max_functions": max(1, min(int(max_functions), 10000)),
            "max_pseudocode_functions": max(1, min(int(max_pseudocode_functions), 300)),
            "max_instructions_per_function": max(100, min(int(max_instructions_per_function), 200000)),
            "auto_wait_timeout": max(0, min(int(auto_wait_timeout), 3600)),
            "signatures": [str(x) for x in (signatures or []) if str(x).strip()],
            "plugin_modules": [str(x) for x in (plugin_modules or []) if str(x).strip()],
            "plugin_scripts": [str(x) for x in (plugin_scripts or []) if str(x).strip()],
        }, sort_keys=True)
        out = Path(output_path) if output_path else _default_ida_json_path(target, "deobf", workspace, cache_extra)
        out.parent.mkdir(parents=True, exist_ok=True)
        if reuse_output and not output_path and not patch_database:
            cached = _load_reusable_json(out, target)
            if cached is not None:
                emit_progress(f"ida_deobfuscate reused cached JSON: {out}")
                return ToolResult(
                    content=_format_deobfuscation_summary(cached, out) + "\n\n[cached] Reused existing IDA deobfuscation JSON.",
                    is_error=False,
                    metadata={
                        "path": str(target),
                        "output_path": str(out),
                        "ida_path": ida,
                        "cached": True,
                        "opaque_predicates": len(cached.get("opaque_predicates", [])),
                        "junk_instructions": len(cached.get("junk_instructions", [])),
                        "flattened_candidates": len(cached.get("flattened_candidates", [])),
                        "pe_function_labels": len(cached.get("pe_function_labels", [])),
                        "function_maps": len(cached.get("function_maps", [])),
                        "signatures": len(cached.get("signatures", [])),
                        "external_plugins": len(cached.get("external_plugins", [])),
                        "pseudocode": len(cached.get("pseudocode", [])),
                        "patched_database": False,
                    },
                )
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
            script_path = Path(f.name)
            progress_path = script_path.with_suffix(".progress.jsonl")
            f.write(_render_ida_deobfuscate_script(
                out,
                progress_path,
                bool(patch_database),
                bool(apply_names),
                bool(include_pseudocode),
                int(max_functions),
                int(max_pseudocode_functions),
                int(max_instructions_per_function),
                int(auto_wait_timeout),
                signatures,
                plugin_modules,
                plugin_scripts,
            ))

        timeout_sec = min(max(int(timeout), 10000), 900000) / 1000
        stdout_path = script_path.with_suffix(".stdout.txt")
        stderr_path = script_path.with_suffix(".stderr.txt")
        cmd = [ida, "-A", f"-S{script_path}", str(target)]
        emit_progress(f"ida_deobfuscate started ({Path(ida).name}, timeout {int(timeout_sec)}s)")
        progress_pos = 0
        last_progress = ""

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
                stage = event.get("stage", "")
                if stage == "scan":
                    msg = (
                        f"ida deobf scan {event.get('phase', '')} "
                        f"functions={event.get('functions', '')} opaque={event.get('opaque', '')} junk={event.get('junk', '')}"
                    ).strip()
                elif stage == "pseudocode":
                    msg = f"ida deobf pseudocode {event.get('count', '')} {event.get('function', event.get('status', ''))}".strip()
                elif stage == "plugins":
                    msg = f"ida deobf plugins {event.get('count', '')} {event.get('status', '')}".strip()
                elif stage == "function_maps":
                    msg = f"ida deobf function maps {event.get('count', '')} {event.get('status', '')}".strip()
                elif stage == "done":
                    msg = "ida deobf done"
                else:
                    msg = f"ida deobf {stage} {event.get('status', '')}".strip()
                if msg and msg != last_progress:
                    emit_progress(msg)
                    last_progress = msg

        try:
            with open(stdout_path, "w", encoding="utf-8", errors="replace") as stdout_f, \
                    open(stderr_path, "w", encoding="utf-8", errors="replace") as stderr_f:
                proc = subprocess.Popen(cmd, stdout=stdout_f, stderr=stderr_f, text=True)
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
                        _cleanup_paths(stdout_path, stderr_path, progress_path)
                        return ToolResult(
                            content=f"IDA deobfuscation timed out after {int(timeout_sec)}s. Command: {' '.join(cmd)}",
                            is_error=True,
                            metadata={"ida_path": ida, "timeout": int(timeout_sec)},
                        )
                    if elapsed >= next_heartbeat:
                        emit_progress(f"ida_deobfuscate running {int(elapsed)}s/{int(timeout_sec)}s")
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
                content=f"IDA did not produce deobfuscation JSON. Exit code: {proc.returncode}\n{details[:4000]}",
                is_error=True,
                metadata={"exit_code": proc.returncode, "ida_path": ida},
            )

        try:
            data = json.loads(out.read_text(encoding="utf-8"))
        except Exception as e:
            _cleanup_paths(stdout_path, stderr_path, progress_path)
            return ToolResult(content=f"IDA deobfuscation JSON could not be read: {e}", is_error=True)

        _cleanup_paths(stdout_path, stderr_path, progress_path)

        content = _format_deobfuscation_summary(data, out)
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
                "opaque_predicates": len(data.get("opaque_predicates", [])),
                "junk_instructions": len(data.get("junk_instructions", [])),
                "flattened_candidates": len(data.get("flattened_candidates", [])),
                "pe_function_labels": len(data.get("pe_function_labels", [])),
                "function_maps": len(data.get("function_maps", [])),
                "signatures": len(data.get("signatures", [])),
                "external_plugins": len(data.get("external_plugins", [])),
                "pseudocode": len(data.get("pseudocode", [])),
                "patched_database": bool(patch_database),
            },
        )


