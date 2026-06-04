"""Lightweight angr static triage integration."""

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from .base import Tool, ToolResult, coerce_bool, coerce_int
from .reverse_text import short_text


ANGR_TRIAGE_SCRIPT = r'''
import json
import re
import sys

path = sys.argv[1]
run_cfg = sys.argv[2].lower() == "true"
max_functions = int(sys.argv[3])
max_strings = int(sys.argv[4])

data = {
    "input": path,
    "available": False,
    "loader": {},
    "objects": [],
    "imports": [],
    "strings": [],
    "functions": [],
    "warnings": [],
}

try:
    import angr
    data["available"] = True
except Exception as e:
    data["error"] = "angr import failed: %s" % e
    print(json.dumps(data))
    sys.exit(2)

try:
    proj = angr.Project(path, auto_load_libs=False)
    data["loader"] = {
        "arch": str(proj.arch),
        "bits": getattr(proj.arch, "bits", 0),
        "endianness": getattr(proj.arch, "memory_endness", ""),
        "entry": hex(proj.entry) if proj.entry is not None else "",
        "min_addr": hex(proj.loader.min_addr),
        "max_addr": hex(proj.loader.max_addr),
    }
    for obj in proj.loader.all_objects:
        try:
            data["objects"].append({
                "name": obj.provides,
                "path": getattr(obj, "binary", "") or "",
                "min_addr": hex(obj.min_addr),
                "max_addr": hex(obj.max_addr),
            })
        except Exception:
            pass
    main = proj.loader.main_object
    try:
        imports = getattr(main, "imports", {}) or {}
        for name, reloc in sorted(imports.items())[:2000]:
            data["imports"].append({
                "name": str(name),
                "rebased_addr": hex(getattr(reloc, "rebased_addr", 0)),
                "resolved": bool(getattr(reloc, "resolved", False)),
            })
    except Exception as e:
        data["warnings"].append("imports failed: %s" % e)
except Exception as e:
    data["error"] = "angr project load failed: %s" % e
    print(json.dumps(data))
    sys.exit(1)

try:
    raw = open(path, "rb").read()
    seen = set()
    ascii_re = re.compile(rb"[\x20-\x7e]{4,}")
    wide_re = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
    for m in ascii_re.finditer(raw):
        text = m.group(0).decode("utf-8", errors="replace")
        if text not in seen:
            seen.add(text)
            data["strings"].append({"offset": hex(m.start()), "value": text[:500]})
        if len(data["strings"]) >= max_strings:
            break
    if len(data["strings"]) < max_strings:
        for m in wide_re.finditer(raw):
            text = m.group(0).decode("utf-16le", errors="replace")
            if text not in seen:
                seen.add(text)
                data["strings"].append({"offset": hex(m.start()), "value": text[:500], "wide": True})
            if len(data["strings"]) >= max_strings:
                break
except Exception as e:
    data["warnings"].append("strings failed: %s" % e)

if run_cfg:
    try:
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        funcs = list(cfg.kb.functions.values())
        funcs.sort(key=lambda f: f.size if getattr(f, "size", None) is not None else 0, reverse=True)
        for f in funcs[:max_functions]:
            data["functions"].append({
                "name": str(f.name),
                "addr": hex(f.addr),
                "size": int(getattr(f, "size", 0) or 0),
                "block_count": len(list(f.blocks)) if hasattr(f, "blocks") else 0,
                "is_plt": bool(getattr(f, "is_plt", False)),
            })
    except Exception as e:
        data["warnings"].append("CFGFast failed: %s" % e)

print(json.dumps(data))
'''


INTERESTING_RE = re.compile(
    r"(flag|password|passwd|serial|license|auth|login|token|secret|debug|vm|"
    r"sandbox|http|https|socket|connect|cmd|powershell|encrypt|decrypt|crypto|"
    r"registry|service|mutex|inject|process)",
    re.I,
)


def _format_angr_summary(data: dict) -> str:
    loader = data.get("loader") or {}
    lines = [
        "# angr Triage",
        "",
        f"Input: {data.get('input', '')}",
        f"Arch: {loader.get('arch', '')}",
        f"Entry: {loader.get('entry', '')}",
        f"Range: {loader.get('min_addr', '')}..{loader.get('max_addr', '')}",
        "",
        f"Objects: {len(data.get('objects', []))}",
        f"Imports: {len(data.get('imports', []))}",
        f"Strings: {len(data.get('strings', []))}",
        f"Functions: {len(data.get('functions', []))}",
    ]
    if data.get("error"):
        lines.append(f"Error: {data.get('error')}")
    warnings = data.get("warnings") or []
    if warnings:
        lines.extend(["", "## Warnings"])
        lines.extend(f"- {w}" for w in warnings[:10])
    imports = [x for x in data.get("imports", []) if INTERESTING_RE.search(x.get("name", ""))]
    if imports:
        lines.extend(["", "## Interesting Imports"])
        for item in imports[:80]:
            lines.append(f"- {item.get('name')} @ {item.get('rebased_addr')} resolved={item.get('resolved')}")
    strings = [x for x in data.get("strings", []) if INTERESTING_RE.search(x.get("value", ""))]
    if strings:
        lines.extend(["", "## Interesting Strings"])
        for item in strings[:100]:
            wide = " wide" if item.get("wide") else ""
            lines.append(f"- {item.get('offset')}{wide}: {short_text(item.get('value'), 180)}")
    if data.get("functions"):
        lines.extend(["", "## Largest Functions"])
        for item in data.get("functions", [])[:60]:
            lines.append(f"- {item.get('addr')} {item.get('name')} size={item.get('size')} blocks={item.get('block_count')} plt={item.get('is_plt')}")
    lines.extend(["", "## Use"])
    lines.append("- Use this as a lightweight cross-check for loader architecture, imports, strings, and CFG candidates.")
    lines.append("- For path solving, run targeted scripts after identifying a concrete validation function.")
    return "\n".join(lines)


class AngrTriageTool(Tool):
    name = "angr_triage"
    description = (
        "Run lightweight angr static triage in a subprocess: loader metadata, imports, strings, "
        "and optional CFGFast function candidates. Does not execute the target binary."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Absolute path to the binary."},
            "run_cfg": {"type": "boolean", "description": "Run CFGFast. Default false because it can be slow."},
            "timeout": {"type": "integer", "description": "Timeout in milliseconds. Default 180000."},
            "max_functions": {"type": "integer", "description": "Maximum functions to report when run_cfg is true. Default 120."},
            "max_strings": {"type": "integer", "description": "Maximum strings to extract. Default 1000."},
            "output_path": {"type": "string", "description": "Optional JSON output path."},
        },
        "required": ["file_path"],
    }

    def execute(
        self,
        file_path: str,
        run_cfg: bool = False,
        timeout: int = 180000,
        max_functions: int = 120,
        max_strings: int = 1000,
        output_path: str | None = None,
        **kwargs,
    ) -> ToolResult:
        target = Path(file_path)
        if not target.exists():
            return ToolResult(content=f"File not found: {file_path}", is_error=True)
        if target.is_dir():
            return ToolResult(content=f"Path is a directory, not a file: {file_path}", is_error=True)

        timeout_sec = coerce_int(timeout, 180000, 10000, 900000) / 1000
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
            script_path = Path(f.name)
            f.write(ANGR_TRIAGE_SCRIPT)
        try:
            proc = subprocess.run(
                [
                    sys.executable,
                    str(script_path),
                    str(target),
                    str(coerce_bool(run_cfg, False)).lower(),
                    str(coerce_int(max_functions, 120, 10, 2000)),
                    str(coerce_int(max_strings, 1000, 50, 10000)),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_sec,
            )
        except subprocess.TimeoutExpired:
            try:
                script_path.unlink()
            except Exception:
                pass
            return ToolResult(content=f"angr triage timed out after {int(timeout_sec)}s.", is_error=True)
        finally:
            try:
                script_path.unlink()
            except Exception:
                pass

        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        if not stdout:
            return ToolResult(
                content=f"angr triage produced no JSON. Exit code: {proc.returncode}\n{stderr[:4000]}",
                is_error=True,
                metadata={"exit_code": proc.returncode},
            )
        try:
            data = json.loads(stdout.splitlines()[-1])
        except Exception as e:
            return ToolResult(
                content=f"angr triage JSON parse failed: {e}\n{stdout[:4000]}\n{stderr[:2000]}",
                is_error=True,
                metadata={"exit_code": proc.returncode},
            )
        out = Path(output_path) if output_path else None
        if out:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        content = _format_angr_summary(data)
        if out:
            content += f"\n\nOutput JSON: {out}"
        if stderr:
            content += f"\n\n[stderr]\n{stderr[:2000]}"
        return ToolResult(
            content=content,
            is_error=proc.returncode not in (0,),
            metadata={
                "path": str(target),
                "output_path": str(out) if out else "",
                "exit_code": proc.returncode,
                "available": bool(data.get("available")),
                "imports": len(data.get("imports", [])),
                "strings": len(data.get("strings", [])),
                "functions": len(data.get("functions", [])),
            },
        )
