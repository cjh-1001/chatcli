"""Apply reviewed AI rename/comment/color suggestions inside IDA.

Run from IDA: File -> Script file... -> this file.
"""

import json
import re

import ida_kernwin
import ida_name
import idaapi
import idc


NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_@$?]{0,127}$")


def parse_ea(value):
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    if not text:
        return idaapi.BADADDR
    try:
        return int(text, 16 if text.lower().startswith("0x") else 10)
    except Exception:
        return idaapi.BADADDR


def parse_color(value):
    if isinstance(value, int):
        return value & 0xFFFFFF
    text = str(value or "").strip().lower().replace("#", "0x")
    try:
        return int(text, 16 if text.startswith("0x") else 10) & 0xFFFFFF
    except Exception:
        return None


def valid_ea(ea):
    return ea != idaapi.BADADDR and idc.get_segm_name(ea) != ""


def load_json_path():
    path = ida_kernwin.ask_file(False, "*.json", "Select chatcli AI suggestion JSON")
    if not path:
        return None, None
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("top-level JSON must be an object")
    return path, data


def summarize(data):
    renames = data.get("renames") or []
    comments = data.get("comments") or []
    colors = data.get("colors") or []
    return (
        "Apply chatcli AI suggestions?\n\n"
        "Renames: {}\nComments: {}\nColors: {}\n\n"
        "Only reviewed suggestions should be applied."
    ).format(len(renames), len(comments), len(colors))


def apply_renames(items, force):
    applied = []
    skipped = []
    for item in items:
        if not isinstance(item, dict):
            skipped.append({"item": item, "reason": "not an object"})
            continue
        ea = parse_ea(item.get("ea"))
        name = str(item.get("name") or "").strip()
        if not valid_ea(ea):
            skipped.append({"item": item, "reason": "invalid ea"})
            continue
        if not NAME_RE.match(name):
            skipped.append({"item": item, "reason": "invalid name"})
            continue
        flags = ida_name.SN_CHECK | ida_name.SN_NOWARN
        if force:
            flags |= ida_name.SN_FORCE
        ok = ida_name.set_name(ea, name, flags)
        if ok:
            applied.append({"ea": hex(ea), "name": name})
        else:
            skipped.append({"item": item, "reason": "set_name failed"})
    return applied, skipped


def apply_comments(items):
    applied = []
    skipped = []
    for item in items:
        if not isinstance(item, dict):
            skipped.append({"item": item, "reason": "not an object"})
            continue
        ea = parse_ea(item.get("ea"))
        comment = str(item.get("comment") or "").strip()
        repeatable = bool(item.get("repeatable", False))
        if not valid_ea(ea):
            skipped.append({"item": item, "reason": "invalid ea"})
            continue
        if not comment:
            skipped.append({"item": item, "reason": "empty comment"})
            continue
        idc.set_cmt(ea, comment[:2048], int(repeatable))
        applied.append({"ea": hex(ea), "repeatable": repeatable})
    return applied, skipped


def apply_colors(items):
    applied = []
    skipped = []
    for item in items:
        if not isinstance(item, dict):
            skipped.append({"item": item, "reason": "not an object"})
            continue
        ea = parse_ea(item.get("ea"))
        color = parse_color(item.get("color"))
        if not valid_ea(ea):
            skipped.append({"item": item, "reason": "invalid ea"})
            continue
        if color is None:
            skipped.append({"item": item, "reason": "invalid color"})
            continue
        idc.set_color(ea, idc.CIC_ITEM, color)
        applied.append({"ea": hex(ea), "color": hex(color)})
    return applied, skipped


def main():
    try:
        path, data = load_json_path()
        if not path:
            return
        answer = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, summarize(data))
        if answer != ida_kernwin.ASKBTN_YES:
            print("[chatcli] apply cancelled")
            return
        force = bool(data.get("force", False))
        rename_ok, rename_skip = apply_renames(data.get("renames") or [], force)
        comment_ok, comment_skip = apply_comments(data.get("comments") or [])
        color_ok, color_skip = apply_colors(data.get("colors") or [])
        result = {
            "source": path,
            "renames_applied": rename_ok,
            "comments_applied": comment_ok,
            "colors_applied": color_ok,
            "skipped": rename_skip + comment_skip + color_skip,
        }
        print("[chatcli] apply result:")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        ida_kernwin.msg("[chatcli] applied: renames={} comments={} colors={} skipped={}\n".format(
            len(rename_ok), len(comment_ok), len(color_ok), len(result["skipped"])
        ))
    except Exception as exc:
        ida_kernwin.warning("chatcli AI apply failed: {}".format(exc))
        raise


if __name__ == "__main__":
    main()

