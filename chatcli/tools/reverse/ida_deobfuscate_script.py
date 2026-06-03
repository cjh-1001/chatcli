"""Embedded IDAPython script template for deobfuscation passes."""

IDA_DEOBFUSCATE_SCRIPT = r'''
import json
import re
import struct
import time

OUT_PATH = __OUT_PATH__
PROGRESS_PATH = __PROGRESS_PATH__
PATCH_DATABASE = __PATCH_DATABASE__
APPLY_NAMES = __APPLY_NAMES__
INCLUDE_PSEUDOCODE = __INCLUDE_PSEUDOCODE__
MAX_FUNCTIONS = __MAX_FUNCTIONS__
MAX_PSEUDOCODE = __MAX_PSEUDOCODE__
MAX_INSTRUCTIONS_PER_FUNCTION = __MAX_INSTRUCTIONS_PER_FUNCTION__
AUTO_WAIT_SECONDS = __AUTO_WAIT_SECONDS__
SIGNATURES = __SIGNATURES__
PLUGIN_MODULES = __PLUGIN_MODULES__
PLUGIN_SCRIPTS = __PLUGIN_SCRIPTS__

report = {
    "input": "",
    "image_base": "",
    "processor": "",
    "patched_database": bool(PATCH_DATABASE),
    "opaque_predicates": [],
    "junk_instructions": [],
    "flattened_candidates": [],
    "pe_function_labels": [],
    "function_maps": [],
    "signatures": [],
    "external_plugins": [],
    "strings": [],
    "pseudocode": [],
    "warnings": [],
}
function_infos = []

def progress(stage, **info):
    try:
        event = {"stage": stage}
        event.update(info)
        with open(PROGRESS_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:
        pass

def hx(ea):
    try:
        return hex(int(ea))
    except Exception:
        return str(ea)

def add_warning(text):
    if len(report["warnings"]) < 80:
        report["warnings"].append(str(text))

def op_text(ea, n):
    try:
        return idc.print_operand(ea, n).strip().lower()
    except Exception:
        return ""

def item_size(ea):
    try:
        return max(1, int(idc.get_item_size(ea)))
    except Exception:
        return 1

def patch_nops(ea, size):
    for i in range(max(0, int(size))):
        ida_bytes.patch_byte(ea + i, 0x90)

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
            if now and now % 10 == 0 and now != last_heartbeat:
                progress("auto_wait", status="running", elapsed=now)
                last_heartbeat = now
            time.sleep(0.5)
    except Exception as e:
        progress("auto_wait", status="failed", error=str(e))
        return False

def patch_jcc_true(ea, target):
    size = item_size(ea)
    raw = ida_bytes.get_bytes(ea, size) or b""
    if size == 2 and raw and 0x70 <= raw[0] <= 0x7F:
        ida_bytes.patch_byte(ea, 0xEB)
        return True
    if size >= 6 and len(raw) >= 6 and raw[0] == 0x0F and 0x80 <= raw[1] <= 0x8F:
        rel = int(target) - int(ea + 5)
        ida_bytes.patch_byte(ea, 0xE9)
        ida_bytes.patch_bytes(ea + 1, struct.pack("<i", rel))
        if size > 5:
            patch_nops(ea + 5, size - 5)
        return True
    return False

def classify_constant_branch(ea):
    mnem = idc.print_insn_mnem(ea).lower()
    if mnem not in ("jz", "je", "jnz", "jne"):
        return None
    func_start = idc.get_func_attr(ea, idc.FUNCATTR_START)
    if func_start == idc.BADADDR:
        return None
    prev = idc.prev_head(ea, func_start)
    if prev == idc.BADADDR:
        return None
    pm = idc.print_insn_mnem(prev).lower()
    a = op_text(prev, 0)
    b = op_text(prev, 1)
    zf_true = None
    reason = ""
    if pm == "cmp" and a and a == b:
        zf_true = True
        reason = "cmp operand with itself"
    elif pm == "test" and (b in ("0", "0h", "0x0") or a in ("0", "0h", "0x0")):
        zf_true = True
        reason = "test with zero immediate"
    elif pm == "xor" and a and a == b:
        zf_true = True
        reason = "xor operand with itself immediately before branch"
    elif pm == "sub" and a and a == b:
        zf_true = True
        reason = "sub operand with itself immediately before branch"
    if zf_true is None:
        return None
    taken = zf_true if mnem in ("jz", "je") else not zf_true
    return {
        "ea": hx(ea),
        "function": idc.get_func_name(func_start),
        "mnem": mnem,
        "target": hx(idc.get_operand_value(ea, 0)),
        "condition": "always_taken" if taken else "never_taken",
        "reason": reason,
        "confidence": "high",
    }

def is_junk_instruction(ea):
    mnem = idc.print_insn_mnem(ea).lower()
    size = item_size(ea)
    if mnem in ("nop", "pause"):
        return "nop-equivalent"
    if mnem == "jmp":
        try:
            if int(idc.get_operand_value(ea, 0)) == int(idc.next_head(ea, ea + 32)):
                return "jump-to-next-instruction"
        except Exception:
            pass
    if mnem == "mov" and op_text(ea, 0) and op_text(ea, 0) == op_text(ea, 1):
        return "mov register to itself"
    if mnem == "lea":
        dst = op_text(ea, 0)
        src = op_text(ea, 1).replace(" ", "")
        if dst and src in ("[%s]" % dst, "[%s+0]" % dst, "[%s+0h]" % dst):
            return "lea register from itself"
    if mnem == "push":
        nxt = idc.next_head(ea, ea + 16)
        if nxt != idc.BADADDR and idc.print_insn_mnem(nxt).lower() == "pop":
            if op_text(ea, 0) == op_text(nxt, 0):
                return "push/pop same register"
    return ""

def iter_functions():
    count = 0
    for ea in idautils.Functions():
        if count >= MAX_FUNCTIONS:
            break
        count += 1
        yield ea

def analyze_flattening(fn_ea):
    try:
        func = idaapi.get_func(fn_ea)
        if not func:
            return None
        fc = idaapi.FlowChart(func)
        blocks = list(fc)
        if len(blocks) < 8:
            return None
        switch_count = 0
        indirect_jumps = 0
        cmp_count = 0
        cmov_count = 0
        back_edges = 0
        insn_count = 0
        truncated = False
        for block in blocks:
            for succ in block.succs():
                if succ.start_ea <= block.start_ea:
                    back_edges += 1
            ea = block.start_ea
            while ea < block.end_ea:
                insn_count += 1
                if insn_count > MAX_INSTRUCTIONS_PER_FUNCTION:
                    truncated = True
                    break
                m = idc.print_insn_mnem(ea).lower()
                if m == "cmp":
                    cmp_count += 1
                elif m.startswith("cmov"):
                    cmov_count += 1
                elif m == "jmp" and idc.get_operand_type(ea, 0) not in (idc.o_near, idc.o_far):
                    indirect_jumps += 1
                try:
                    if ida_nalt.get_switch_info(ea):
                        switch_count += 1
                except Exception:
                    pass
                ea = idc.next_head(ea, block.end_ea)
                if ea == idc.BADADDR:
                    break
            if truncated:
                break
        score = switch_count * 5 + indirect_jumps * 3 + back_edges * 2 + min(cmp_count // 8, 5) + cmov_count
        if score < 8:
            return None
        return {
            "function": idc.get_func_name(fn_ea),
            "start": hx(fn_ea),
            "basic_blocks": len(blocks),
            "switches": switch_count,
            "indirect_jumps": indirect_jumps,
            "back_edges": back_edges,
            "cmp_count": cmp_count,
            "cmov_count": cmov_count,
            "score": score,
            "truncated": truncated,
            "recommendation": "Likely flattened dispatcher/state-machine. Use Hex-Rays output plus switch/xref evidence to rebuild original blocks; run installed unflatten/LLVM deobf plugins here if available.",
        }
    except Exception as e:
        add_warning("flattening analysis failed at %s: %s" % (hx(fn_ea), e))
    return None

API_GROUPS = [
    ("crypto", re.compile(r"(crypt|bcrypt|hash|md5|sha|aes|des|rc4|chacha|rsa|cert)", re.I)),
    ("string", re.compile(r"(strcmp|strncmp|strstr|strlen|strcpy|sprintf|multiByte|wideChar)", re.I)),
    ("file", re.compile(r"(createfile|readfile|writefile|findfirst|findnext|getfile|setfile|mapview|createfilemapping)", re.I)),
    ("network", re.compile(r"(socket|connect|send|recv|winhttp|internet|url|http|dns|wsastartup)", re.I)),
    ("debug", re.compile(r"(isdebuggerpresent|checkremotedebugger|ntqueryinformationprocess|outputdebug|string|queryperformance|gettickcount)", re.I)),
    ("registry", re.compile(r"(regopen|regquery|regset|regcreate|regdelete)", re.I)),
    ("process", re.compile(r"(createprocess|shellexecute|virtualalloc|virtualprotect|loadlibrary|getprocaddress|createthread)", re.I)),
    ("ui", re.compile(r"(messagebox|getdlgitem|getwindowtext|dialogbox|sendmessage)", re.I)),
]

def label_import_xref_functions():
    try:
        qty = ida_nalt.get_import_module_qty()
    except Exception:
        return
    scores = {}
    evidence = {}
    def add(fn, group, api_name, module):
        if fn == idc.BADADDR:
            return
        scores.setdefault(fn, {})
        scores[fn][group] = scores[fn].get(group, 0) + 1
        evidence.setdefault(fn, [])
        if len(evidence[fn]) < 12:
            evidence[fn].append("%s!%s" % (module, api_name))
    for i in range(qty):
        module = ida_nalt.get_import_module_name(i) or ""
        def cb(ea, name, ordinal):
            api_name = name or ("ord_%s" % ordinal)
            groups = [g for g, rx in API_GROUPS if rx.search(api_name)]
            if not groups:
                return True
            try:
                for xr in idautils.XrefsTo(ea):
                    fn = idc.get_func_attr(xr.frm, idc.FUNCATTR_START)
                    for group in groups:
                        add(fn, group, api_name, module)
            except Exception:
                pass
            return True
        try:
            ida_nalt.enum_import_names(i, cb)
        except Exception:
            pass
    for fn, groups in sorted(scores.items(), key=lambda x: sum(x[1].values()), reverse=True)[:300]:
        role = sorted(groups.items(), key=lambda x: x[1], reverse=True)[0][0]
        old_name = idc.get_func_name(fn)
        suggested = "api_%s_%s" % (role, old_name)
        if APPLY_NAMES and old_name.startswith("sub_"):
            idc.set_name(fn, suggested, idc.SN_CHECK)
            old_name = idc.get_func_name(fn)
        try:
            idc.set_func_cmt(fn, "chatcli API role: %s; evidence: %s" % (role, ", ".join(evidence.get(fn, [])[:8])), 1)
        except Exception:
            pass
        report["pe_function_labels"].append({
            "start": hx(fn),
            "name": old_name,
            "role": role,
            "groups": groups,
            "evidence": evidence.get(fn, []),
        })

def apply_signatures():
    for sig in SIGNATURES:
        item = {"signature": sig, "status": "failed"}
        try:
            name = str(sig).replace("\\", "/").rsplit("/", 1)[-1]
            if name.lower().endswith(".sig"):
                name = name[:-4]
            rc = idc.apply_sig(name)
            item["status"] = "applied" if rc else "attempted"
            item["return"] = rc
        except Exception as e:
            item["error"] = str(e)
        report["signatures"].append(item)

def run_external_deobfuscators():
    import importlib
    import runpy
    for module_name in PLUGIN_MODULES:
        item = {"kind": "module", "name": module_name, "status": "failed"}
        try:
            module = importlib.import_module(module_name)
            called = False
            for entry in ("main", "run", "go", "deobfuscate", "unflatten", "start"):
                func = getattr(module, entry, None)
                if callable(func):
                    try:
                        func()
                    except TypeError:
                        func(report)
                    called = True
                    item["entry"] = entry
                    break
            item["status"] = "executed" if called else "imported"
        except Exception as e:
            item["error"] = str(e)
        report["external_plugins"].append(item)

def _function_strings(fn_start, fn_end):
    hits = []
    for item in report.get("strings", []):
        try:
            for xr in item.get("xrefs", []):
                frm = int(str(xr), 16)
                if fn_start <= frm < fn_end:
                    hits.append({
                        "ea": item.get("ea"),
                        "xref": xr,
                        "value": item.get("value", "")[:160],
                    })
                    break
        except Exception:
            pass
        if len(hits) >= 20:
            break
    return hits

def _safe_disasm(ea):
    try:
        return idc.generate_disasm_line(ea, 0) or idc.print_insn_mnem(ea)
    except Exception:
        return ""

def _block_summary(block):
    calls = 0
    jumps = 0
    cond_jumps = 0
    indirect_jumps = 0
    junk = 0
    samples = []
    ea = block.start_ea
    scanned = 0
    while ea < block.end_ea and scanned < 80:
        scanned += 1
        m = idc.print_insn_mnem(ea).lower()
        if scanned <= 3:
            samples.append("%s: %s" % (hx(ea), _safe_disasm(ea)))
        if m == "call":
            calls += 1
        elif m == "jmp":
            jumps += 1
            if idc.get_operand_type(ea, 0) not in (idc.o_near, idc.o_far):
                indirect_jumps += 1
        elif m.startswith("j") and m != "jmp":
            cond_jumps += 1
        if is_junk_instruction(ea):
            junk += 1
        ea = idc.next_head(ea, block.end_ea)
        if ea == idc.BADADDR:
            break
    try:
        succs = [hx(s.start_ea) for s in block.succs()]
    except Exception:
        succs = []
    return {
        "start": hx(block.start_ea),
        "end": hx(block.end_ea),
        "size": int(block.end_ea - block.start_ea),
        "succs": succs[:8],
        "calls_sampled": calls,
        "jumps_sampled": jumps,
        "conditional_jumps_sampled": cond_jumps,
        "indirect_jumps_sampled": indirect_jumps,
        "junk_sampled": junk,
        "sampled_instructions": samples,
        "truncated": scanned >= 80 and ea < block.end_ea,
    }

def build_function_maps():
    selected = {}
    for info in sorted(function_infos, key=lambda x: x.get("size", 0), reverse=True)[:40]:
        selected[info["start_ea"]] = info
    for item in report.get("flattened_candidates", []):
        try:
            ea = int(item.get("start", "0"), 16)
            selected.setdefault(ea, {
                "start_ea": ea,
                "end_ea": idc.find_func_end(ea),
                "name": idc.get_func_name(ea),
                "size": max(0, idc.find_func_end(ea) - ea),
            })
        except Exception:
            pass
    for item in report.get("pe_function_labels", []):
        try:
            ea = int(item.get("start", "0"), 16)
            selected.setdefault(ea, {
                "start_ea": ea,
                "end_ea": idc.find_func_end(ea),
                "name": idc.get_func_name(ea),
                "size": max(0, idc.find_func_end(ea) - ea),
            })
        except Exception:
            pass

    for _, info in sorted(selected.items(), key=lambda x: x[1].get("size", 0), reverse=True)[:80]:
        fn_start = info["start_ea"]
        fn_end = info.get("end_ea") or idc.find_func_end(fn_start)
        try:
            func = idaapi.get_func(fn_start)
            blocks = list(idaapi.FlowChart(func)) if func else []
        except Exception:
            blocks = []
        largest_blocks = sorted(blocks, key=lambda b: int(b.end_ea - b.start_ea), reverse=True)[:30]
        branch_blocks = []
        for block in blocks:
            try:
                succ_count = len(list(block.succs()))
            except Exception:
                succ_count = 0
            if succ_count >= 2:
                branch_blocks.append(block)
        branch_blocks = sorted(branch_blocks, key=lambda b: b.start_ea)[:30]
        block_items = []
        seen_blocks = set()
        for block in largest_blocks + branch_blocks:
            if block.start_ea in seen_blocks:
                continue
            seen_blocks.add(block.start_ea)
            block_items.append(_block_summary(block))
            if len(block_items) >= 50:
                break
        string_hits = _function_strings(fn_start, fn_end)
        flattened = next((x for x in report.get("flattened_candidates", []) if x.get("start") == hx(fn_start)), None)
        role = next((x for x in report.get("pe_function_labels", []) if x.get("start") == hx(fn_start)), None)
        report["function_maps"].append({
            "start": hx(fn_start),
            "end": hx(fn_end),
            "name": info.get("name") or idc.get_func_name(fn_start),
            "size": int(max(0, fn_end - fn_start)),
            "basic_blocks": len(blocks),
            "mapped_blocks": block_items,
            "strings": string_hits,
            "flattened_candidate": flattened,
            "api_role": role,
            "strategy": (
                "Start from strings/import-role blocks and high-successor branch blocks; "
                "for giant functions, analyze mapped blocks first instead of full decompile."
            ),
        })
    for script_path in PLUGIN_SCRIPTS:
        item = {"kind": "script", "path": script_path, "status": "failed"}
        try:
            runpy.run_path(script_path, init_globals={"CHATCLI_REPORT": report})
            item["status"] = "executed"
        except Exception as e:
            item["error"] = str(e)
        report["external_plugins"].append(item)

try:
    import idaapi
    import idautils
    import idc
    import ida_bytes
    import ida_nalt

    progress("auto_wait", status="start")
    try:
        bounded_auto_wait(AUTO_WAIT_SECONDS)
    except Exception:
        pass
    progress("auto_wait", status="done")

    report["input"] = idc.get_input_file_path()
    try:
        report["image_base"] = hx(idaapi.get_imagebase())
    except Exception:
        pass
    try:
        report["processor"] = idaapi.get_inf_structure().procname
    except Exception:
        pass

    progress("scan", phase="functions")
    for idx, fn_ea in enumerate(iter_functions()):
        if idx and idx % 100 == 0:
            progress("scan", functions=idx, opaque=len(report["opaque_predicates"]), junk=len(report["junk_instructions"]))
        try:
            fn_end = idc.find_func_end(fn_ea)
            function_infos.append({
                "start_ea": fn_ea,
                "end_ea": fn_end,
                "name": idc.get_func_name(fn_ea),
                "size": int(fn_end - fn_ea) if fn_end and fn_end > fn_ea else 0,
            })
        except Exception:
            pass
        flattened = analyze_flattening(fn_ea)
        if flattened:
            report["flattened_candidates"].append(flattened)
            try:
                idc.set_func_cmt(fn_ea, "chatcli: likely control-flow flattened dispatcher/state machine", 1)
            except Exception:
                pass
        try:
            for insn_idx, ea in enumerate(idautils.FuncItems(fn_ea)):
                if insn_idx >= MAX_INSTRUCTIONS_PER_FUNCTION:
                    add_warning(
                        "function scan truncated at %s after %d instructions"
                        % (hx(fn_ea), MAX_INSTRUCTIONS_PER_FUNCTION)
                    )
                    break
                if len(report["opaque_predicates"]) < 2000:
                    opaque = classify_constant_branch(ea)
                    if opaque:
                        report["opaque_predicates"].append(opaque)
                        if PATCH_DATABASE:
                            target = idc.get_operand_value(ea, 0)
                            if opaque["condition"] == "always_taken":
                                if not patch_jcc_true(ea, target):
                                    add_warning("could not rewrite always-taken branch at %s" % hx(ea))
                            else:
                                patch_nops(ea, item_size(ea))
                if len(report["junk_instructions"]) < 4000:
                    reason = is_junk_instruction(ea)
                    if reason:
                        entry = {
                            "ea": hx(ea),
                            "function": idc.get_func_name(fn_ea),
                            "mnem": idc.generate_disasm_line(ea, 0) or idc.print_insn_mnem(ea),
                            "reason": reason,
                            "size": item_size(ea),
                        }
                        report["junk_instructions"].append(entry)
                        if PATCH_DATABASE and reason in ("jump-to-next-instruction", "mov register to itself", "lea register from itself"):
                            patch_nops(ea, item_size(ea))
        except Exception as e:
            add_warning("function scan failed at %s: %s" % (hx(fn_ea), e))

    if PATCH_DATABASE:
        try:
            idaapi.auto_wait()
            for fn_ea in iter_functions():
                try:
                    idaapi.reanalyze_function(idaapi.get_func(fn_ea))
                except Exception:
                    pass
        except Exception:
            pass
    progress("scan", phase="labels")
    apply_signatures()
    label_import_xref_functions()
    progress("plugins", status="start")
    run_external_deobfuscators()
    progress("plugins", count=len(report["external_plugins"]), status="done")

    try:
        s = idautils.Strings()
        s.setup(strtypes=[0, 1], minlen=4)
        for idx, item in enumerate(s):
            if idx >= 1000:
                break
            xrefs = []
            try:
                for xr in idautils.XrefsTo(int(item.ea)):
                    xrefs.append(hx(xr.frm))
                    if len(xrefs) >= 10:
                        break
            except Exception:
                pass
            report["strings"].append({"ea": hx(int(item.ea)), "value": str(item)[:500], "xrefs": xrefs})
    except Exception:
        pass
    progress("function_maps", status="start")
    try:
        build_function_maps()
    except Exception as e:
        add_warning("function map build failed: %s" % e)
    progress("function_maps", count=len(report["function_maps"]), status="done")

    if INCLUDE_PSEUDOCODE:
        progress("pseudocode", status="start")
        try:
            import ida_hexrays
            if ida_hexrays.init_hexrays_plugin():
                ordered = []
                seen = set()
                for item in sorted(report["flattened_candidates"], key=lambda x: x.get("score", 0), reverse=True):
                    start = int(item["start"], 16)
                    if start not in seen:
                        seen.add(start)
                        ordered.append((start, item["function"]))
                for item in report["pe_function_labels"]:
                    start = int(item["start"], 16)
                    if start not in seen:
                        seen.add(start)
                        ordered.append((start, item["name"]))
                    if len(ordered) >= MAX_PSEUDOCODE:
                        break
                for idx, (ea, name) in enumerate(ordered[:MAX_PSEUDOCODE]):
                    progress("pseudocode", count=idx, function=name)
                    try:
                        cfunc = ida_hexrays.decompile(ea)
                        if cfunc:
                            report["pseudocode"].append({"function": name, "start": hx(ea), "text": str(cfunc)[:12000]})
                    except Exception as e:
                        add_warning("decompile failed at %s: %s" % (hx(ea), e))
        except Exception as e:
            add_warning("Hex-Rays pseudocode unavailable: %s" % e)
        progress("pseudocode", count=len(report["pseudocode"]), status="done")

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    progress("done", output=OUT_PATH)
finally:
    try:
        import idaapi
        idaapi.qexit(0)
    except Exception:
        pass
'''


