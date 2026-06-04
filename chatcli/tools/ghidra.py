"""Ghidra headless static-analysis integration."""

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .base import Tool, ToolResult, coerce_bool, coerce_int
from .ida import _default_ida_json_path, _load_reusable_json
from .reverse_text import short_text


GHIDRA_EXPORT_SCRIPT = r'''
# chatcli Ghidra export script. Runs inside Ghidra headless Jython.
import json

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.data import StringDataInstance
from ghidra.program.model.listing import CodeUnit
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
out_path = args[0]
include_decompile = str(args[1]).lower() == "true"
max_decompile = int(args[2])
max_functions = int(args[3])
max_strings = int(args[4])

monitor = ConsoleTaskMonitor()
program = currentProgram
listing = program.getListing()
fm = program.getFunctionManager()
rm = program.getReferenceManager()
symtab = program.getSymbolTable()

def hx(addr):
    try:
        return "0x%x" % addr.getOffset()
    except:
        try:
            return "0x%x" % int(addr)
        except:
            return ""

def safe(value, limit=500):
    text = str(value or "").replace("\r", "\\r").replace("\n", "\\n")
    return text[:limit]

def entry_point():
    try:
        it = symtab.getExternalEntryPointIterator()
        if it.hasNext():
            return hx(it.next())
    except:
        pass
    return ""

data = {
    "input": program.getExecutablePath(),
    "name": program.getName(),
    "language": str(program.getLanguageID()),
    "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
    "image_base": hx(program.getImageBase()),
    "entry": entry_point(),
    "functions": [],
    "imports": [],
    "strings": [],
    "candidate_functions": [],
    "pseudocode": [],
    "warnings": [],
}

try:
    ext_iter = symtab.getExternalSymbols()
    count = 0
    while ext_iter.hasNext() and count < 2000:
        sym = ext_iter.next()
        parent = sym.getParentNamespace()
        data["imports"].append({
            "module": safe(parent.getName() if parent else "", 160),
            "name": safe(sym.getName(), 200),
            "address": hx(sym.getAddress()) if sym.getAddress() else "",
        })
        count += 1
except Exception as e:
    data["warnings"].append("imports failed: %s" % e)

try:
    count = 0
    units = listing.getDefinedData(True)
    while units.hasNext() and count < max_strings:
        item = units.next()
        try:
            sdi = StringDataInstance.getStringDataInstance(item)
            value = sdi.getStringValue()
            if value:
                refs = []
                riter = rm.getReferencesTo(item.getMinAddress())
                while riter.hasNext() and len(refs) < 12:
                    refs.append(hx(riter.next().getFromAddress()))
                data["strings"].append({
                    "ea": hx(item.getMinAddress()),
                    "value": safe(value, 500),
                    "xrefs": refs,
                })
                count += 1
        except:
            pass
except Exception as e:
    data["warnings"].append("strings failed: %s" % e)

func_rows = []
try:
    funcs = fm.getFunctions(True)
    count = 0
    while funcs.hasNext() and count < max_functions:
        f = funcs.next()
        callers = []
        callees = []
        try:
            citer = rm.getReferencesTo(f.getEntryPoint())
            while citer.hasNext() and len(callers) < 80:
                ref = citer.next()
                cf = fm.getFunctionContaining(ref.getFromAddress())
                if cf:
                    callers.append({"start": hx(cf.getEntryPoint()), "name": safe(cf.getName(), 200), "from": hx(ref.getFromAddress())})
        except:
            pass
        try:
            body = f.getBody()
            refs = rm.getReferencesFrom(f.getEntryPoint())
            it = listing.getInstructions(body, True)
            seen = set()
            insn_count = 0
            while it.hasNext() and insn_count < 3000:
                insn = it.next()
                insn_count += 1
                riter = rm.getReferencesFrom(insn.getAddress())
                while riter.hasNext() and len(callees) < 120:
                    ref = riter.next()
                    tf = fm.getFunctionAt(ref.getToAddress())
                    if tf and str(tf.getEntryPoint()) not in seen:
                        seen.add(str(tf.getEntryPoint()))
                        callees.append({"start": hx(tf.getEntryPoint()), "name": safe(tf.getName(), 200), "from": hx(insn.getAddress())})
        except:
            pass
        row = {
            "name": safe(f.getName(), 240),
            "start": hx(f.getEntryPoint()),
            "size": int(f.getBody().getNumAddresses()),
            "callers": callers,
            "callees": callees,
        }
        data["functions"].append(row)
        func_rows.append((f, row))
        count += 1
except Exception as e:
    data["warnings"].append("functions failed: %s" % e)

interesting = ("check", "valid", "verify", "auth", "login", "license", "serial", "flag", "decrypt", "hash", "config")
scores = {}
evidence = {}

def add_candidate(addr, score, reason):
    try:
        f = fm.getFunctionContaining(addr)
        if not f:
            return
        key = hx(f.getEntryPoint())
        scores[key] = scores.get(key, 0) + score
        evidence.setdefault(key, [])
        if len(evidence[key]) < 12:
            evidence[key].append(reason)
    except:
        pass

for s in data["strings"]:
    value = s.get("value", "").lower()
    score = 5 if any(x in value for x in interesting) else 1
    try:
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(s["ea"])
    except:
        addr = None
    if addr:
        riter = rm.getReferencesTo(addr)
        while riter.hasNext():
            add_candidate(riter.next().getFromAddress(), score, "string %s @ %s" % (safe(s.get("value"), 80), s.get("ea")))

for f, row in func_rows:
    name = row.get("name", "").lower()
    if any(x in name for x in interesting):
        add_candidate(f.getEntryPoint(), 3, "name %s" % row.get("name"))

lookup = dict((row["start"], row) for _, row in func_rows)
for key, score in sorted(scores.items(), key=lambda x: x[1], reverse=True)[:80]:
    row = dict(lookup.get(key, {"start": key}))
    row["score"] = int(score)
    row["evidence"] = evidence.get(key, [])
    data["candidate_functions"].append(row)

if include_decompile:
    try:
        decomp = DecompInterface()
        decomp.openProgram(program)
        done = 0
        ordered = []
        seen = set()
        for cand in data["candidate_functions"]:
            if cand.get("start") not in seen:
                ordered.append(cand.get("start"))
                seen.add(cand.get("start"))
        for _, row in func_rows:
            if row.get("start") not in seen:
                ordered.append(row.get("start"))
                seen.add(row.get("start"))
        for start in ordered:
            if done >= max_decompile:
                break
            f = None
            for func, row in func_rows:
                if row.get("start") == start:
                    f = func
                    break
            if not f:
                continue
            result = decomp.decompileFunction(f, 30, monitor)
            if result and result.decompileCompleted():
                data["pseudocode"].append({
                    "function": safe(f.getName(), 240),
                    "start": hx(f.getEntryPoint()),
                    "text": str(result.getDecompiledFunction().getC())[:12000],
                })
                done += 1
    except Exception as e:
        data["warnings"].append("decompile failed: %s" % e)

with open(out_path, "w") as f:
    json.dump(data, f, indent=2)
'''


def _headless_names() -> list[str]:
    return ["analyzeHeadless.bat", "analyzeHeadless", "analyzeHeadless.exe"]


def _find_ghidra(explicit: str | None = None) -> str | None:
    candidates: list[Path | str] = []

    def add(value: str) -> None:
        path = Path(value)
        if path.exists() and path.is_dir():
            for name in _headless_names():
                candidates.append(path / "support" / name)
                candidates.append(path / name)
        else:
            candidates.append(value)

    if explicit:
        add(explicit)
    for env_name in ("GHIDRA_HEADLESS_PATH", "GHIDRA_HOME"):
        value = os.environ.get(env_name)
        if value:
            add(value)
    for name in _headless_names():
        found = shutil.which(name)
        if found:
            candidates.append(found)
    for root in (
        Path("C:/Program Files"),
        Path("C:/Program Files (x86)"),
        Path("C:/ghidra"),
        Path("D:/ghidra"),
    ):
        if root.exists():
            for path in root.glob("ghidra*"):
                if path.is_dir():
                    add(str(path))

    for candidate in candidates:
        path = Path(candidate)
        if path.exists() and path.is_file():
            return str(path)
        found = shutil.which(str(candidate))
        if found:
            return found
    return None


def _format_ghidra_summary(data: dict, output_path: Path) -> str:
    lines = [
        "# Ghidra Analysis",
        "",
        f"Input: {data.get('input', '')}",
        f"Output JSON: {output_path}",
        f"Language: {data.get('language', '')}",
        f"Compiler: {data.get('compiler', '')}",
        f"Image base: {data.get('image_base', '')}",
        f"Entry: {data.get('entry', '')}",
        "",
        f"Functions: {len(data.get('functions', []))}",
        f"Imports: {len(data.get('imports', []))}",
        f"Strings: {len(data.get('strings', []))}",
        f"Candidate functions: {len(data.get('candidate_functions', []))}",
        f"Pseudocode functions: {len(data.get('pseudocode', []))}",
    ]
    warnings = data.get("warnings") or []
    if warnings:
        lines.extend(["", "## Warnings"])
        lines.extend(f"- {w}" for w in warnings[:10])
    lines.extend(["", "## Candidate Functions"])
    for fn in data.get("candidate_functions", [])[:40]:
        evidence = "; ".join(short_text(e, 100) for e in (fn.get("evidence") or [])[:3])
        lines.append(f"- {fn.get('start')} {fn.get('name')} score={fn.get('score')} evidence={evidence}")
    lines.extend(["", "## Imports"])
    for item in data.get("imports", [])[:80]:
        lines.append(f"- {item.get('module', '')}!{item.get('name', '')} @ {item.get('address', '')}")
    lines.extend(["", "## Strings"])
    for item in data.get("strings", [])[:80]:
        xrefs = ", ".join((item.get("xrefs") or [])[:4])
        lines.append(f"- {item.get('ea')}: {short_text(item.get('value'), 180)} xrefs=[{xrefs}]")
    if data.get("pseudocode"):
        lines.extend(["", "## Pseudocode"])
        for item in data.get("pseudocode", [])[:10]:
            text = short_text(item.get("text", ""), 4000, preserve_lines=True)
            lines.append(f"### {item.get('function')} @ {item.get('start')}\n```c\n{text}\n```")
    return "\n".join(lines)


class GhidraProbeTool(Tool):
    name = "ghidra_probe"
    description = "Diagnose Ghidra HeadlessAnalyzer availability. Does not run Ghidra or the target binary."
    parameters = {
        "type": "object",
        "properties": {
            "ghidra_path": {"type": "string", "description": "Path to analyzeHeadless or a Ghidra install directory."},
        },
    }

    def __init__(self, default_ghidra_path: str = ""):
        self.default_ghidra_path = default_ghidra_path

    def execute(self, ghidra_path: str | None = None, **kwargs) -> ToolResult:
        resolved = _find_ghidra(ghidra_path or self.default_ghidra_path)
        lines = [
            "# Ghidra Probe",
            "",
            f"Resolved Ghidra headless: {resolved or '(not found)'}",
            "",
            "Configure GHIDRA_HEADLESS_PATH, GHIDRA_HOME, PATH, or pass ghidra_path.",
        ]
        return ToolResult(content="\n".join(lines), is_error=not bool(resolved), metadata={"found": bool(resolved), "ghidra_path": resolved})


class GhidraAnalyzeTool(Tool):
    name = "ghidra_analyze"
    description = (
        "Run Ghidra HeadlessAnalyzer for a local binary and export AI-friendly static-analysis JSON. "
        "Does not execute the target binary."
    )
    parameters = {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Absolute path to the binary to analyze."},
            "ghidra_path": {"type": "string", "description": "Optional path to analyzeHeadless or a Ghidra install directory."},
            "output_path": {"type": "string", "description": "Optional JSON output path."},
            "timeout": {"type": "integer", "description": "Timeout in milliseconds. Default 600000."},
            "include_pseudocode": {"type": "boolean", "description": "Include decompiler output. Default true."},
            "max_pseudocode_functions": {"type": "integer", "description": "Maximum functions to decompile. Default 20."},
            "max_functions": {"type": "integer", "description": "Maximum functions to enumerate. Default 2000."},
            "max_strings": {"type": "integer", "description": "Maximum strings to export. Default 1000."},
            "reuse_output": {"type": "boolean", "description": "Reuse cached default JSON when available. Default true."},
        },
        "required": ["file_path"],
    }

    def __init__(self, default_ghidra_path: str = ""):
        self.default_ghidra_path = default_ghidra_path

    def execute(
        self,
        file_path: str,
        ghidra_path: str | None = None,
        output_path: str | None = None,
        timeout: int = 600000,
        include_pseudocode: bool = True,
        max_pseudocode_functions: int = 20,
        max_functions: int = 2000,
        max_strings: int = 1000,
        reuse_output: bool = True,
        **kwargs,
    ) -> ToolResult:
        target = Path(file_path)
        if not target.exists():
            return ToolResult(content=f"File not found: {file_path}", is_error=True)
        if target.is_dir():
            return ToolResult(content=f"Path is a directory, not a file: {file_path}", is_error=True)
        ghidra = _find_ghidra(ghidra_path or self.default_ghidra_path)
        if not ghidra:
            return ToolResult(
                content="Ghidra HeadlessAnalyzer not found. Configure GHIDRA_HEADLESS_PATH, GHIDRA_HOME, PATH, or pass ghidra_path.",
                is_error=True,
            )

        workspace = kwargs.get("workspace")
        cache_extra = json.dumps({
            "tool": self.name,
            "include_pseudocode": bool(include_pseudocode),
            "max_pseudocode_functions": coerce_int(max_pseudocode_functions, 20, 1, 200),
            "max_functions": coerce_int(max_functions, 2000, 100, 10000),
            "max_strings": coerce_int(max_strings, 1000, 50, 10000),
        }, sort_keys=True)
        out = Path(output_path) if output_path else _default_ida_json_path(target, "ghidra", workspace, cache_extra)
        out.parent.mkdir(parents=True, exist_ok=True)
        if reuse_output and not output_path:
            cached = _load_reusable_json(out, target)
            if cached is not None:
                return ToolResult(
                    content=_format_ghidra_summary(cached, out) + "\n\n[cached] Reused existing Ghidra JSON.",
                    metadata={"output_path": str(out), "cached": True, "ghidra_path": ghidra},
                )

        timeout_sec = coerce_int(timeout, 600000, 10000, 1800000) / 1000
        with tempfile.TemporaryDirectory(prefix="chatcli-ghidra-") as tmp:
            tmp_path = Path(tmp)
            script_dir = tmp_path / "scripts"
            project_dir = tmp_path / "project"
            script_dir.mkdir()
            project_dir.mkdir()
            script_path = script_dir / "chatcli_ghidra_export.py"
            script_path.write_text(GHIDRA_EXPORT_SCRIPT, encoding="utf-8")
            project_name = "chatcli_ghidra"
            cmd = [
                ghidra,
                str(project_dir),
                project_name,
                "-import",
                str(target),
                "-scriptPath",
                str(script_dir),
                "-postScript",
                script_path.name,
                str(out),
                str(bool(include_pseudocode)).lower(),
                str(coerce_int(max_pseudocode_functions, 20, 1, 200)),
                str(coerce_int(max_functions, 2000, 100, 10000)),
                str(coerce_int(max_strings, 1000, 50, 10000)),
                "-deleteProject",
            ]
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
                return ToolResult(content=f"Ghidra analysis timed out after {int(timeout_sec)}s.", is_error=True)

        if not out.exists():
            details = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
            if len(details) > 8000:
                details = details[:3500] + "\n\n... middle omitted ...\n\n" + details[-3500:]
            return ToolResult(
                content=f"Ghidra did not produce JSON. Exit code: {proc.returncode}\n{details}",
                is_error=True,
                metadata={"exit_code": proc.returncode, "ghidra_path": ghidra},
            )
        try:
            data = json.loads(out.read_text(encoding="utf-8", errors="replace"))
        except Exception as e:
            return ToolResult(content=f"Ghidra JSON could not be read: {e}", is_error=True)
        content = _format_ghidra_summary(data, out)
        if proc.returncode != 0:
            content += f"\n\n[warning] Ghidra exited with code {proc.returncode}."
        return ToolResult(
            content=content,
            is_error=False,
            metadata={
                "path": str(target),
                "output_path": str(out),
                "ghidra_path": ghidra,
                "exit_code": proc.returncode,
                "cached": False,
                "functions": len(data.get("functions", [])),
                "imports": len(data.get("imports", [])),
                "strings": len(data.get("strings", [])),
                "candidate_functions": len(data.get("candidate_functions", [])),
                "pseudocode": len(data.get("pseudocode", [])),
            },
        )
