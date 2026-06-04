"""Export an AI-friendly IDA context snapshot.

Run from IDA: File -> Script file... -> this file.
"""

import json
import os
import re
import time
from pathlib import Path

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_nalt
import idaapi
import idautils
import idc


INTERESTING_TEXT = re.compile(
    r"(flag|correct|wrong|invalid|valid|success|fail|password|passwd|serial|"
    r"license|key|admin|auth|login|debug|check|error|congrat|decrypt|encrypt|"
    r"http|https|socket|connect|token|secret|config|mutex|registry)",
    re.I,
)
INTERESTING_IMPORT = re.compile(
    r"(strcmp|strncmp|memcmp|strstr|scanf|gets|fgets|read|recv|send|crypt|hash|"
    r"md5|sha|aes|rc4|bcrypt|isdebuggerpresent|checkremotedebuggerpresent|"
    r"queryperformance|gettickcount|regopen|createfile|deviceiocontrol|"
    r"virtualalloc|virtualprotect|loadlibrary|getprocaddress|connect|internet)",
    re.I,
)


def env_int(name, default, minimum=0, maximum=100000):
    try:
        return max(minimum, min(int(os.environ.get(name, default)), maximum))
    except Exception:
        return default


MAX_FUNCS = env_int("CHATCLI_IDA_MAX_FUNCS", 80, 1, 500)
MAX_STRINGS = env_int("CHATCLI_IDA_MAX_STRINGS", 400, 20, 5000)
MAX_IMPORTS = env_int("CHATCLI_IDA_MAX_IMPORTS", 600, 20, 5000)
MAX_DISASM = env_int("CHATCLI_IDA_MAX_DISASM", 220, 20, 3000)
INCLUDE_PSEUDOCODE = str(os.environ.get("CHATCLI_IDA_INCLUDE_PSEUDOCODE", "1")).lower() not in {"0", "false", "no", "off"}


def hx(ea):
    try:
        return hex(int(ea))
    except Exception:
        return ""


def safe_text(value, limit=500):
    text = str(value or "").replace("\r", "\\r").replace("\n", "\\n")
    return text[:limit]


def safe_name(value):
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "ida")).strip("._-")
    return text[:80] or "ida"


def output_dir():
    configured = os.environ.get("CHATCLI_IDA_EXPORT_DIR", "").strip()
    if configured:
        path = Path(configured)
    else:
        input_path = idc.get_input_file_path() or ida_nalt.get_root_filename() or "ida"
        path = Path(input_path).parent / ".chatcli" / "ida"
    path.mkdir(parents=True, exist_ok=True)
    return path


def metadata():
    try:
        image_base = hx(idaapi.get_imagebase())
    except Exception:
        image_base = ""
    try:
        entry = hx(idc.get_inf_attr(idc.INF_START_EA))
    except Exception:
        entry = ""
    try:
        proc = idaapi.get_inf_structure().procname
    except Exception:
        proc = ""
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "input": idc.get_input_file_path(),
        "root_filename": ida_nalt.get_root_filename(),
        "database": idc.get_idb_path(),
        "processor": proc,
        "image_base": image_base,
        "entry": entry,
        "current_ea": hx(ida_kernwin.get_screen_ea()),
    }


def import_rows():
    rows = []

    def add_import(ea, name, ordinal):
        if len(rows) >= MAX_IMPORTS:
            return False
        rows.append({
            "module": current_module[0],
            "name": name or "",
            "ordinal": ordinal,
            "ea": hx(ea),
            "interesting": bool(INTERESTING_IMPORT.search(name or "")),
        })
        return True

    try:
        qty = ida_nalt.get_import_module_qty()
        for idx in range(qty):
            current_module = [ida_nalt.get_import_module_name(idx) or ""]
            ida_nalt.enum_import_names(idx, add_import)
            if len(rows) >= MAX_IMPORTS:
                break
    except Exception:
        pass
    return rows


def string_rows():
    rows = []
    try:
        strings = idautils.Strings()
        strings.setup(strtypes=[0, 1], minlen=4)
        for idx, item in enumerate(strings):
            if idx >= MAX_STRINGS:
                break
            refs = []
            try:
                for xr in idautils.XrefsTo(int(item.ea)):
                    refs.append(hx(xr.frm))
                    if len(refs) >= 12:
                        break
            except Exception:
                pass
            value = str(item)
            rows.append({
                "ea": hx(int(item.ea)),
                "value": safe_text(value),
                "xrefs": refs,
                "interesting": bool(INTERESTING_TEXT.search(value)),
            })
    except Exception:
        pass
    rows.sort(key=lambda item: (not item.get("interesting"), -len(item.get("xrefs") or []), item.get("ea", "")))
    return rows


def func_at(ea):
    func = ida_funcs.get_func(ea)
    if not func:
        start = idc.get_func_attr(ea, idc.FUNCATTR_START)
        if start != idc.BADADDR:
            func = ida_funcs.get_func(start)
    return func


def comments_in_function(func):
    out = []
    if not func:
        return out
    count = 0
    for ea in idautils.FuncItems(func.start_ea):
        if count > 3000:
            break
        count += 1
        for repeatable in (0, 1):
            cmt = idc.get_cmt(ea, repeatable)
            if cmt:
                out.append({"ea": hx(ea), "repeatable": bool(repeatable), "comment": safe_text(cmt, 1000)})
    return out


def refs_for_function(func):
    callers = []
    callees = []
    if not func:
        return callers, callees
    seen_callers = set()
    for xr in idautils.XrefsTo(func.start_ea):
        caller = idc.get_func_attr(xr.frm, idc.FUNCATTR_START)
        if caller != idc.BADADDR and caller not in seen_callers:
            seen_callers.add(caller)
            callers.append({"start": hx(caller), "name": idc.get_func_name(caller), "from": hx(xr.frm)})
    seen_callees = set()
    count = 0
    for ea in idautils.FuncItems(func.start_ea):
        count += 1
        if count > 4000:
            break
        for ref in idautils.CodeRefsFrom(ea, 0):
            callee = idc.get_func_attr(ref, idc.FUNCATTR_START)
            if callee != idc.BADADDR and callee != func.start_ea and callee not in seen_callees:
                seen_callees.add(callee)
                callees.append({"start": hx(callee), "name": idc.get_func_name(callee), "from": hx(ea)})
    return callers[:80], callees[:120]


def strings_in_function(func):
    out = []
    if not func:
        return out
    start = func.start_ea
    end = func.end_ea
    seen = set()
    count = 0
    for ea in idautils.FuncItems(start):
        count += 1
        if count > 4000:
            break
        for xr in idautils.XrefsFrom(ea, 0):
            try:
                stype = idc.get_str_type(xr.to)
                if stype is None:
                    continue
                raw = idc.get_strlit_contents(xr.to, -1, stype)
                if not raw:
                    continue
                value = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                key = (xr.to, value)
                if key in seen:
                    continue
                seen.add(key)
                out.append({"ea": hx(xr.to), "from": hx(ea), "value": safe_text(value), "interesting": bool(INTERESTING_TEXT.search(value))})
            except Exception:
                pass
        if ea >= end:
            break
    out.sort(key=lambda item: (not item.get("interesting"), item.get("ea", "")))
    return out[:120]


def disasm_function(func):
    out = []
    if not func:
        return out
    count = 0
    for ea in idautils.FuncItems(func.start_ea):
        if count >= MAX_DISASM:
            out.append("... disassembly limit reached ...")
            break
        out.append("{}: {}".format(hx(ea), idc.GetDisasm(ea)))
        count += 1
    return out


def pseudocode_function(func):
    if not INCLUDE_PSEUDOCODE or not func:
        return ""
    try:
        import ida_hexrays
        if not ida_hexrays.init_hexrays_plugin():
            return ""
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            return ""
        return str(cfunc)[:12000]
    except Exception as exc:
        return "/* pseudocode unavailable: {} */".format(exc)


def function_summary(func, include_body=True):
    if not func:
        return {}
    callers, callees = refs_for_function(func)
    item = {
        "name": idc.get_func_name(func.start_ea),
        "start": hx(func.start_ea),
        "end": hx(func.end_ea),
        "size": int(func.end_ea - func.start_ea),
        "callers": callers,
        "callees": callees,
        "strings": strings_in_function(func),
        "comments": comments_in_function(func),
    }
    if include_body:
        item["pseudocode"] = pseudocode_function(func)
        item["disassembly"] = disasm_function(func)
    return item


def score_functions(strings, imports):
    scores = {}
    evidence = {}

    def add(ea, score, reason):
        func = func_at(ea)
        if not func:
            return
        start = func.start_ea
        scores[start] = scores.get(start, 0) + score
        evidence.setdefault(start, [])
        if len(evidence[start]) < 12:
            evidence[start].append(reason)

    for row in strings:
        try:
            ea = int(row["ea"], 16)
            boost = 5 if row.get("interesting") else 1
            for xr in idautils.XrefsTo(ea):
                add(xr.frm, boost, "string {} @ {}".format(safe_text(row.get("value"), 80), row.get("ea")))
        except Exception:
            pass
    for row in imports:
        if not row.get("interesting"):
            continue
        try:
            ea = int(row["ea"], 16)
            for xr in idautils.XrefsTo(ea):
                add(xr.frm, 4, "import {}!{} @ {}".format(row.get("module"), row.get("name"), row.get("ea")))
        except Exception:
            pass
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        if re.search(r"(check|valid|verify|auth|login|license|serial|flag|decrypt|hash|parse|config)", name, re.I):
            add(ea, 3, "name {}".format(name))
    try:
        add(idc.get_inf_attr(idc.INF_START_EA), 2, "entrypoint")
    except Exception:
        pass

    out = []
    for start, score in sorted(scores.items(), key=lambda pair: pair[1], reverse=True)[:MAX_FUNCS]:
        func = ida_funcs.get_func(start)
        if not func:
            continue
        row = function_summary(func, include_body=False)
        row["score"] = int(score)
        row["evidence"] = evidence.get(start, [])
        out.append(row)
    return out


def markdown(data):
    lines = [
        "# chatcli IDA AI Context",
        "",
        "Input: {}".format(data["metadata"].get("input")),
        "Database: {}".format(data["metadata"].get("database")),
        "Processor: {}".format(data["metadata"].get("processor")),
        "Entry: {}".format(data["metadata"].get("entry")),
        "Current EA: {}".format(data["metadata"].get("current_ea")),
        "",
    ]
    cur = data.get("current_function") or {}
    if cur:
        lines.extend([
            "## Current Function",
            "",
            "- {} @ {} size={}".format(cur.get("name"), cur.get("start"), cur.get("size")),
            "- callers={} callees={} strings={} comments={}".format(
                len(cur.get("callers") or []), len(cur.get("callees") or []),
                len(cur.get("strings") or []), len(cur.get("comments") or []),
            ),
        ])
        if cur.get("strings"):
            lines.extend(["", "### Referenced Strings"])
            for item in cur.get("strings", [])[:40]:
                lines.append("- {} <- {} {}".format(item.get("ea"), item.get("from"), item.get("value")))
        if cur.get("pseudocode"):
            lines.extend(["", "### Pseudocode", "```c", cur.get("pseudocode"), "```"])
        elif cur.get("disassembly"):
            lines.extend(["", "### Disassembly", "```asm"])
            lines.extend(cur.get("disassembly", [])[:120])
            lines.append("```")
    lines.extend(["", "## Candidate Functions"])
    for item in data.get("candidate_functions", [])[:40]:
        evidence = "; ".join(item.get("evidence", [])[:3])
        lines.append("- {} @ {} score={} evidence={}".format(item.get("name"), item.get("start"), item.get("score"), evidence))
    lines.extend(["", "## Interesting Imports"])
    for item in [x for x in data.get("imports", []) if x.get("interesting")][:80]:
        lines.append("- {}!{} @ {}".format(item.get("module"), item.get("name"), item.get("ea")))
    lines.extend(["", "## Interesting Strings"])
    for item in [x for x in data.get("strings", []) if x.get("interesting")][:80]:
        lines.append("- {} {}".format(item.get("ea"), item.get("value")))
    return "\n".join(lines) + "\n"


def main():
    try:
        idaapi.auto_wait()
    except Exception:
        pass
    meta = metadata()
    imports = import_rows()
    strings = string_rows()
    current = function_summary(func_at(ida_kernwin.get_screen_ea()), include_body=True)
    data = {
        "metadata": meta,
        "current_function": current,
        "candidate_functions": score_functions(strings, imports),
        "imports": imports,
        "strings": strings,
    }
    root = safe_name(ida_nalt.get_root_filename() or "ida")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out_dir = output_dir()
    json_path = out_dir / "chatcli-ida-context-{}-{}.json".format(root, stamp)
    md_path = out_dir / "chatcli-ida-context-{}-{}.md".format(root, stamp)
    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(markdown(data), encoding="utf-8")
    ida_kernwin.msg("[chatcli] AI context JSON: {}\n".format(json_path))
    ida_kernwin.msg("[chatcli] AI context Markdown: {}\n".format(md_path))
    print("[chatcli] AI context JSON: {}".format(json_path))
    print("[chatcli] AI context Markdown: {}".format(md_path))


if __name__ == "__main__":
    main()
