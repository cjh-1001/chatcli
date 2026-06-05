"""Targeted IDA decompile/disassembly for selected functions."""

import json
import subprocess
import tempfile
import time
from pathlib import Path

from .base import Tool, ToolResult
from ._ida_utils import _cleanup_paths, _default_ida_json_path, _find_ida, _ida_not_found_message, _load_reusable_json
from .reverse_text import optimize_ida_text_data, persist_optimized_json, rank_text_items, short_text


IDA_FOCUS_SCRIPT = r'''
import json
import time

OUT_PATH = %r
PROGRESS_PATH = %r
TARGETS = %r
AUTO_WAIT_SECONDS = %d
MAX_INSTRUCTIONS = %d
MAX_PSEUDOCODE_LINES = %d


def progress(stage, **info):
    try:
        event = {"stage": stage}
        event.update(info)
        with open(PROGRESS_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:
        pass


def bounded_auto_wait(max_seconds):
    try:
        import ida_auto
        start = time.time()
        while True:
            try:
                if ida_auto.auto_is_ok():
                    progress("auto_wait", status="done", elapsed=int(time.time() - start))
                    return
            except Exception:
                return
            if max_seconds <= 0:
                progress("auto_wait", status="skipped")
                return
            elapsed = time.time() - start
            if elapsed >= max_seconds:
                progress("auto_wait", status="timeout", elapsed=int(elapsed))
                return
            time.sleep(0.5)
    except Exception as e:
        progress("auto_wait", status="failed", error=str(e))


def parse_target(value):
    import idaapi
    import idc
    text = str(value).strip()
    ea = idaapi.BADADDR
    try:
        ea = int(text, 16 if text.lower().startswith("0x") else 10)
    except Exception:
        ea = idc.get_name_ea_simple(text)
    if ea == idaapi.BADADDR:
        return None, "target not found"
    func = idaapi.get_func(ea)
    if not func:
        func = idaapi.get_func(idc.get_func_attr(ea, idc.FUNCATTR_START))
    if not func:
        return {"target": text, "ea": hex(ea), "error": "function not found"}, None
    return {"target": text, "ea": hex(ea), "start": hex(func.start_ea), "end": hex(func.end_ea)}, None


def collect_function(seed):
    import idaapi
    import idautils
    import idc
    start = int(seed["start"], 16)
    end = int(seed["end"], 16)
    name = idc.get_func_name(start)
    out = {
        "target": seed.get("target"),
        "ea": seed.get("ea"),
        "name": name,
        "start": seed["start"],
        "end": seed["end"],
        "size": max(0, end - start),
        "calls": [],
        "strings": [],
        "disassembly": [],
        "pseudocode": "",
        "pseudocode_error": "",
    }
    count = 0
    for ea in idautils.FuncItems(start):
        if count >= MAX_INSTRUCTIONS:
            out["disassembly"].append("... instruction limit reached ...")
            break
        try:
            mnem = idc.print_insn_mnem(ea)
            op = idc.GetDisasm(ea)
            out["disassembly"].append("{}: {}".format(hex(ea), op))
            if mnem.lower() == "call":
                target = idc.get_operand_value(ea, 0)
                if target:
                    out["calls"].append({"ea": hex(ea), "target": hex(target), "name": idc.get_func_name(target)})
            for xr in idautils.XrefsFrom(ea, 0):
                if xr.to and idc.get_str_type(xr.to) is not None:
                    value = idc.get_strlit_contents(xr.to, -1, idc.get_str_type(xr.to))
                    if value:
                        try:
                            text = value.decode("utf-8", errors="replace")
                        except Exception:
                            text = str(value)
                        out["strings"].append({"ea": hex(xr.to), "from": hex(ea), "value": text[:500]})
        except Exception:
            pass
        count += 1
    seen = set()
    dedup = []
    for s in out["strings"]:
        key = (s.get("ea"), s.get("value"))
        if key not in seen:
            dedup.append(s)
            seen.add(key)
    out["strings"] = dedup[:80]
    out["calls"] = out["calls"][:120]
    try:
        import ida_hexrays
        if ida_hexrays.init_hexrays_plugin():
            cfunc = ida_hexrays.decompile(start)
            if cfunc:
                lines = str(cfunc).splitlines()[:MAX_PSEUDOCODE_LINES]
                out["pseudocode"] = "\n".join(lines)
        else:
            out["pseudocode_error"] = "hexrays unavailable"
    except Exception as e:
        out["pseudocode_error"] = str(e)
    return out


result = {"input": "", "targets": [], "errors": []}
try:
    import idaapi
    import idc
    progress("auto_wait", status="start")
    bounded_auto_wait(AUTO_WAIT_SECONDS)
    result["input"] = idc.get_input_file_path()
    for target in TARGETS:
        seed, error = parse_target(target)
        if error:
            result["errors"].append({"target": target, "error": error})
            continue
        if seed and seed.get("error"):
            result["errors"].append(seed)
            continue
        progress("function", target=str(target), start=seed.get("start"))
        result["targets"].append(collect_function(seed))
        progress("function_done", target=str(target), collected=len(result["targets"]))
except Exception as e:
    result["fatal_error"] = str(e)
finally:
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    progress("done", targets=len(result.get("targets", [])), errors=len(result.get("errors", [])))
    try:
        import idaapi
        idaapi.qexit(0)
    except Exception:
        pass
'''


def _format_focus_summary(data: dict, output_path: Path) -> str:
    text_stats = data.get("text_processing") or {}
    lines = [
        "# IDA Focus Decompile",
        "",
        f"Input: {data.get('input', '')}",
        f"Output JSON: {output_path}",
        f"Targets: {len(data.get('targets', []))}",
        f"Errors: {len(data.get('errors', []))}",
        f"Text processing: strings={text_stats.get('strings_seen', 0)} "
        f"changed={text_stats.get('strings_changed', 0)} "
        f"low_signal={text_stats.get('low_signal_strings', 0)}",
    ]
    if data.get("fatal_error"):
        lines.append(f"Fatal error: {data.get('fatal_error')}")
    if data.get("errors"):
        lines.extend(["", "## Errors"])
        for item in data.get("errors", [])[:20]:
            lines.append(f"- {item.get('target')} {item.get('error')}")
    for item in data.get("targets", []):
        lines.extend([
            "",
            f"## {item.get('name')} @ {item.get('start')}",
            f"- Range: {item.get('start')}..{item.get('end')} size={item.get('size')}",
            f"- Calls: {len(item.get('calls', []))}",
            f"- Strings: {len(item.get('strings', []))}",
        ])
        if item.get("strings"):
            lines.append("### Strings")
            for s in rank_text_items(item.get("strings", []) or [])[:20]:
                score = f" score={s.get('text_score')}" if s.get("text_score") is not None else ""
                flags = f" flags={','.join(s.get('text_flags', []))}" if s.get("text_flags") else ""
                lines.append(
                    f"- {s.get('from')} -> {s.get('ea')}{score}{flags}: "
                    f"{short_text(s.get('value'), 220)}"
                )
        if item.get("calls"):
            lines.append("### Calls")
            for call in item.get("calls", [])[:25]:
                suffix = f" {call.get('name')}" if call.get("name") else ""
                lines.append(f"- {call.get('ea')} -> {call.get('target')}{suffix}")
        if item.get("pseudocode"):
            lines.append("### Pseudocode")
            lines.append("```c")
            lines.append(short_text(item.get("pseudocode", ""), 8000, preserve_lines=True))
            lines.append("```")
        elif item.get("pseudocode_error"):
            lines.append(f"### Pseudocode unavailable: {item.get('pseudocode_error')}")
        if item.get("disassembly"):
            lines.append("### Disassembly Sample")
            lines.append("```asm")
            lines.extend(item.get("disassembly", [])[:80])
            lines.append("```")
    return "\n".join(lines)


class IdaFocusDecompileTool(Tool):
    name = "ida_focus_decompile"
    description = (
        "Run IDA headless against selected function addresses or names and return "
        "focused pseudocode, disassembly samples, calls, and string references. Use "
        "after reverse_evidence_map identifies specific candidate functions."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Binary path to load in IDA."},
            "targets": {
                "type": "array",
                "description": "Function starts, addresses, or names to inspect, e.g. 0x140001280.",
                "items": {"type": "string"},
            },
            "ida_path": {"type": "string", "description": "Optional path to idat64/idat/ida64/ida or an IDA install directory."},
            "output_path": {"type": "string", "description": "Optional JSON output path."},
            "timeout": {"type": "integer", "description": "Timeout in milliseconds. Default 180000."},
            "auto_wait_timeout": {"type": "integer", "description": "Seconds to wait for auto-analysis. Default 15."},
            "max_instructions": {"type": "integer", "description": "Max disassembly instructions per function. Default 300."},
            "max_pseudocode_lines": {"type": "integer", "description": "Max pseudocode lines per function. Default 160."},
            "reuse_output": {
                "type": "boolean",
                "description": "Reuse the default cached JSON when it already matches this binary, targets, and limits. Default true.",
            },
        },
        "required": ["file_path", "targets"],
    }

    def __init__(self, default_ida_path: str = ""):
        self.default_ida_path = default_ida_path

    def execute(
        self,
        file_path: str,
        targets: list[str],
        ida_path: str | None = None,
        output_path: str | None = None,
        timeout: int = 180000,
        auto_wait_timeout: int = 15,
        max_instructions: int = 300,
        max_pseudocode_lines: int = 160,
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
        if not targets:
            return ToolResult(content="Error: targets cannot be empty.", is_error=True)

        ida = _find_ida(ida_path or self.default_ida_path)
        if not ida:
            return ToolResult(content=_ida_not_found_message(), is_error=True)

        normalized_targets = [str(t) for t in targets]
        cache_extra = json.dumps({
            "tool": self.name,
            "targets": normalized_targets,
            "auto_wait_timeout": max(0, min(int(auto_wait_timeout), 3600)),
            "max_instructions": max(20, min(int(max_instructions), 5000)),
            "max_pseudocode_lines": max(20, min(int(max_pseudocode_lines), 2000)),
        }, sort_keys=True)
        out = Path(output_path) if output_path else _default_ida_json_path(target, "focus", workspace, cache_extra)
        out.parent.mkdir(parents=True, exist_ok=True)
        if reuse_output and not output_path:
            cached = _load_reusable_json(out, target)
            if cached is not None:
                optimize_ida_text_data(cached)
                persist_optimized_json(out, cached)
                emit_progress(f"ida_focus_decompile reused cached JSON: {out}")
                return ToolResult(
                    content=_format_focus_summary(cached, out) + "\n\n[cached] Reused existing focused IDA JSON.",
                    metadata={
                        "path": str(target),
                        "output_path": str(out),
                        "ida_path": ida,
                        "cached": True,
                        "targets": len(cached.get("targets", [])),
                        "errors": len(cached.get("errors", [])),
                        "pseudocode": sum(1 for item in cached.get("targets", []) if item.get("pseudocode")),
                        "strings": sum(len(item.get("strings", [])) for item in cached.get("targets", [])),
                        "calls": sum(len(item.get("calls", [])) for item in cached.get("targets", [])),
                    },
                )

        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
            script_path = Path(f.name)
            progress_path = script_path.with_suffix(".progress.jsonl")
            f.write(IDA_FOCUS_SCRIPT % (
                str(out),
                str(progress_path),
                [str(t) for t in targets],
                max(0, min(int(auto_wait_timeout), 3600)),
                max(20, min(int(max_instructions), 5000)),
                max(20, min(int(max_pseudocode_lines), 2000)),
            ))

        timeout_sec = min(max(int(timeout), 10000), 900000) / 1000
        stdout_path = script_path.with_suffix(".stdout.txt")
        stderr_path = script_path.with_suffix(".stderr.txt")
        cmd = [ida, "-A", f"-S{script_path}", str(target)]
        emit_progress(f"ida_focus_decompile started ({Path(ida).name}, {len(targets)} targets)")
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
                if stage == "auto_wait":
                    msg = f"ida focus auto-analysis {event.get('status', '')}".strip()
                elif stage == "function":
                    msg = f"ida focus function {event.get('target', '')} {event.get('start', '')}".strip()
                elif stage == "function_done":
                    msg = f"ida focus collected {event.get('collected', '')}/{len(targets)}".strip()
                elif stage == "done":
                    msg = f"ida focus done targets={event.get('targets', '')} errors={event.get('errors', '')}".strip()
                else:
                    msg = f"ida focus {stage}".strip()
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
                            content=f"IDA focus decompile timed out after {int(timeout_sec)}s.",
                            is_error=True,
                            metadata={"ida_path": ida, "timeout": int(timeout_sec), "targets": len(targets)},
                        )
                    if elapsed >= next_heartbeat:
                        emit_progress(f"ida_focus_decompile running {int(elapsed)}s/{int(timeout_sec)}s")
                        next_heartbeat += 10.0
                    time.sleep(0.5)
                drain_progress()
        finally:
            _cleanup_paths(script_path)

        if not out.exists():
            stdout = stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_path.exists() else ""
            stderr = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
            _cleanup_paths(stdout_path, stderr_path, progress_path)
            return ToolResult(
                content=(
                    "IDA focus decompile did not produce JSON. "
                    f"Exit code: {proc.returncode}\n{(stdout + chr(10) + stderr)[:4000]}"
                ),
                is_error=True,
                metadata={"exit_code": proc.returncode, "ida_path": ida},
            )
        try:
            data = json.loads(out.read_text(encoding="utf-8"))
        except Exception as e:
            _cleanup_paths(stdout_path, stderr_path, progress_path)
            return ToolResult(content=f"IDA focus JSON could not be read: {e}", is_error=True)
        optimize_ida_text_data(data)
        persist_optimized_json(out, data)
        _cleanup_paths(stdout_path, stderr_path, progress_path)
        content = _format_focus_summary(data, out)
        return ToolResult(
            content=content,
            metadata={
                "path": str(target),
                "output_path": str(out),
                "ida_path": ida,
                "exit_code": proc.returncode,
                "cached": False,
                "targets": len(data.get("targets", [])),
                "errors": len(data.get("errors", [])),
                "pseudocode": sum(1 for item in data.get("targets", []) if item.get("pseudocode")),
                "strings": sum(len(item.get("strings", [])) for item in data.get("targets", [])),
                "calls": sum(len(item.get("calls", [])) for item in data.get("targets", [])),
            },
        )
