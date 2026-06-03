"""IDAPython script template used by the ida_analyze tool."""

IDA_SCRIPT = r'''
import json
import os
import re
import time

OUT_PATH = %r
PROGRESS_PATH = %r
INCLUDE_PSEUDOCODE = %r
MAX_PSEUDOCODE_FUNCS = %d
AUTO_WAIT_SECONDS = %d
MAX_FUNCS = 2000
MAX_STRINGS = 1000
MAX_IMPORTS = 2000

data = {
    "input": "",
    "image_base": "",
    "entry": "",
    "processor": "",
    "segments": [],
    "functions": [],
    "imports": [],
    "strings": [],
    "candidate_functions": [],
    "entry_analysis_order": [],
    "pseudocode": [],
    "warnings": [],
    "partial": True,
    "last_checkpoint": "started",
}

def progress(stage, **info):
    try:
        event = {"stage": stage}
        event.update(info)
        with open(PROGRESS_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:
        pass

def checkpoint(stage):
    try:
        data["partial"] = True
        data["last_checkpoint"] = stage
        tmp_path = OUT_PATH + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, OUT_PATH)
    except Exception:
        pass

def bounded_auto_wait(max_seconds):
    try:
        import ida_auto
        start = time.time()
        last_heartbeat = -1
        while True:
            try:
                if ida_auto.auto_is_ok():
                    progress("auto_wait", status="done", elapsed=int(time.time() - start))
                    return True
            except Exception as e:
                progress("auto_wait", status="poll_failed", error=str(e))
                return False
            if max_seconds <= 0:
                progress("auto_wait", status="skipped")
                return False
            elapsed = time.time() - start
            if elapsed >= max_seconds:
                progress("auto_wait", status="timeout", elapsed=int(elapsed))
                return False
            now = int(elapsed)
            if now and now %% 10 == 0 and now != last_heartbeat:
                progress("auto_wait", status="running", elapsed=now)
                last_heartbeat = now
            time.sleep(0.5)
    except Exception as e:
        progress("auto_wait", status="failed", error=str(e))
        return False

try:
    import idaapi
    import idautils
    import idc
    import ida_nalt

    try:
        progress("auto_wait", status="start")
        bounded_auto_wait(AUTO_WAIT_SECONDS)
    except Exception:
        progress("auto_wait", status="failed")
        pass

    data["input"] = idc.get_input_file_path()
    try:
        data["image_base"] = hex(idaapi.get_imagebase())
    except Exception:
        data["image_base"] = ""
    try:
        data["entry"] = hex(idc.get_inf_attr(idc.INF_START_EA))
    except Exception:
        data["entry"] = ""
    try:
        data["processor"] = idaapi.get_inf_structure().procname
    except Exception:
        data["processor"] = ""
    progress("metadata", processor=data["processor"], entry=data["entry"])
    checkpoint("metadata")

    for seg_ea in idautils.Segments():
        try:
            data["segments"].append({
                "name": idc.get_segm_name(seg_ea),
                "start": hex(seg_ea),
                "end": hex(idc.get_segm_end(seg_ea)),
                "class": idc.get_segm_attr(seg_ea, idc.SEGATTR_TYPE),
            })
        except Exception:
            pass
    progress("segments", count=len(data["segments"]))
    checkpoint("segments")

    for idx, ea in enumerate(idautils.Functions()):
        if idx >= MAX_FUNCS:
            break
        try:
            end = idc.find_func_end(ea)
            data["functions"].append({
                "name": idc.get_func_name(ea),
                "start": hex(ea),
                "end": hex(end),
                "size": int(end - ea) if end and end > ea else 0,
            })
        except Exception:
            pass
        if idx and idx %% 250 == 0:
            progress("functions", count=len(data["functions"]))
    progress("functions", count=len(data["functions"]), status="done")
    checkpoint("functions")

    def add_import(ea, name, ordinal):
        if len(data["imports"]) >= MAX_IMPORTS:
            return False
        data["imports"].append({
            "ea": hex(ea),
            "name": name or "",
            "ordinal": ordinal,
            "module": current_module[0],
        })
        return True

    qty = ida_nalt.get_import_module_qty()
    for i in range(qty):
        current_module = [ida_nalt.get_import_module_name(i) or ""]
        ida_nalt.enum_import_names(i, add_import)
        if len(data["imports"]) >= MAX_IMPORTS:
            break
    progress("imports", count=len(data["imports"]))
    checkpoint("imports")

    try:
        s = idautils.Strings()
        s.setup(strtypes=[0, 1], minlen=4)
        for idx, item in enumerate(s):
            if idx >= MAX_STRINGS:
                break
            xrefs = []
            try:
                for xr in idautils.XrefsTo(int(item.ea)):
                    xrefs.append(hex(int(xr.frm)))
                    if len(xrefs) >= 12:
                        break
            except Exception:
                pass
            data["strings"].append({
                "ea": hex(int(item.ea)),
                "value": str(item)[:500],
                "xrefs": xrefs,
            })
            if idx and idx %% 200 == 0:
                progress("strings", count=len(data["strings"]))
    except Exception:
        pass
    progress("strings", count=len(data["strings"]), status="done")
    checkpoint("strings")

    candidate_scores = {}
    candidate_evidence = {}

    def add_candidate(ea, score, evidence):
        try:
            fn_start = idc.get_func_attr(ea, idc.FUNCATTR_START)
            if fn_start == idc.BADADDR:
                return
            candidate_scores[fn_start] = candidate_scores.get(fn_start, 0) + score
            candidate_evidence.setdefault(fn_start, [])
            if len(candidate_evidence[fn_start]) < 12:
                candidate_evidence[fn_start].append(evidence)
        except Exception:
            pass

    interesting_string = re.compile(
        r"(flag|correct|wrong|invalid|valid|success|fail|password|passwd|serial|"
        r"license|key|admin|auth|role|login|debug|check|error|congrat|try again)",
        re.I,
    )
    for item in data["strings"]:
        try:
            value = item.get("value", "")
            ea = int(item.get("ea", "0"), 16)
            score = 5 if interesting_string.search(value) else 1
            for xr in idautils.XrefsTo(ea):
                add_candidate(xr.frm, score, "string:%%s @ %%s" %% (value[:80], item.get("ea")))
        except Exception:
            pass

    interesting_import = re.compile(
        r"(strcmp|strncmp|memcmp|strstr|scanf|gets|fgets|read|recv|crypt|hash|md5|"
        r"sha|aes|rc4|bcrypt|isdebuggerpresent|checkremotedebuggerpresent|queryperformance|"
        r"gettickcount|getdlgitemtext|getwindowtext|regopen|createfile|deviceiocontrol)",
        re.I,
    )
    for imp in data["imports"]:
        try:
            name = imp.get("name", "")
            if not interesting_import.search(name):
                continue
            ea = int(imp.get("ea", "0"), 16)
            for xr in idautils.XrefsTo(ea):
                add_candidate(xr.frm, 4, "import:%%s!%%s @ %%s" %% (
                    imp.get("module", ""), name, imp.get("ea")
                ))
        except Exception:
            pass

    for fn in data["functions"]:
        try:
            name = fn.get("name", "")
            if re.search(r"(check|valid|verify|auth|login|license|serial|flag|decrypt|hash)", name, re.I):
                add_candidate(int(fn.get("start", "0"), 16), 3, "name:%%s" %% name)
        except Exception:
            pass

    try:
        entry = idc.get_inf_attr(idc.INF_START_EA)
        add_candidate(entry, 2, "entrypoint")
    except Exception:
        pass

    for ea, score in sorted(candidate_scores.items(), key=lambda x: x[1], reverse=True)[:80]:
        try:
            end = idc.find_func_end(ea)
            data["candidate_functions"].append({
                "name": idc.get_func_name(ea),
                "start": hex(ea),
                "end": hex(end),
                "size": int(end - ea) if end and end > ea else 0,
                "score": int(score),
                "evidence": candidate_evidence.get(ea, []),
            })
        except Exception:
            pass
    progress(
        "candidates",
        count=len(data["candidate_functions"]),
        top=[fn.get("name", "") for fn in data["candidate_functions"][:5]],
    )
    checkpoint("candidates")

    function_starts = set()
    for fn in data["functions"]:
        try:
            function_starts.add(int(fn.get("start", "0"), 16))
        except Exception:
            pass

    def function_callees(fn_start):
        out = []
        seen_out = set()
        try:
            end = idc.find_func_end(fn_start)
            count = 0
            for insn in idautils.FuncItems(fn_start):
                count += 1
                if count > 3000:
                    break
                for ref in idautils.CodeRefsFrom(insn, 0):
                    callee = idc.get_func_attr(ref, idc.FUNCATTR_START)
                    if callee != idc.BADADDR and callee in function_starts and callee not in seen_out:
                        seen_out.add(callee)
                        out.append(callee)
                if end and insn >= end:
                    break
        except Exception:
            pass
        return out

    try:
        entry = idc.get_inf_attr(idc.INF_START_EA)
        entry_fn = idc.get_func_attr(entry, idc.FUNCATTR_START)
        if entry_fn != idc.BADADDR:
            queue = [entry_fn]
            seen_entry = set()
            while queue and len(data["entry_analysis_order"]) < 80:
                fn_start = queue.pop(0)
                if fn_start in seen_entry:
                    continue
                seen_entry.add(fn_start)
                callees = function_callees(fn_start)
                data["entry_analysis_order"].append({
                    "name": idc.get_func_name(fn_start),
                    "start": hex(fn_start),
                    "score": int(candidate_scores.get(fn_start, 0)),
                    "callees": [hex(c) for c in callees[:20]],
                })
                ranked = sorted(
                    [c for c in callees if c not in seen_entry],
                    key=lambda c: candidate_scores.get(c, 0),
                    reverse=True,
                )
                queue.extend(ranked[:20])
    except Exception:
        pass
    progress(
        "entry_order",
        count=len(data["entry_analysis_order"]),
        first=[fn.get("name", "") for fn in data["entry_analysis_order"][:5]],
    )
    checkpoint("entry_order")

    if INCLUDE_PSEUDOCODE:
        try:
            import ida_hexrays
            if ida_hexrays.init_hexrays_plugin():
                ordered = []
                seen = set()
                for fn in data["entry_analysis_order"] + data["candidate_functions"]:
                    start = fn.get("start")
                    if start and start not in seen:
                        seen.add(start)
                        ordered.append(fn)
                    if len(ordered) >= MAX_PSEUDOCODE_FUNCS:
                        break
                for fn in ordered:
                    try:
                        progress(
                            "decompile",
                            count=len(data["pseudocode"]),
                            function=fn.get("name", ""),
                        )
                        ea = int(fn["start"], 16)
                        cfunc = ida_hexrays.decompile(ea)
                        if cfunc:
                            data["pseudocode"].append({
                                "function": fn["name"],
                                "start": fn["start"],
                                "text": str(cfunc)[:8000],
                            })
                    except Exception:
                        pass
        except Exception:
            pass
    progress("pseudocode", count=len(data["pseudocode"]), status="done")
    checkpoint("pseudocode")

    data["partial"] = False
    data["last_checkpoint"] = "done"
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    progress("done", output=OUT_PATH)
finally:
    try:
        import idaapi
        idaapi.qexit(0)
    except Exception:
        pass
'''

