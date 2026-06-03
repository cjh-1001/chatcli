"""Runtime string hook script generators."""

import json
from pathlib import Path

from ..base import Tool, ToolResult

FRIDA_TEMPLATE = r'''/*
chatcli runtime string hook template.
Scope: attach only to an authorized local lab/CTF/owned target.

Usage examples:
  frida -f ./target.exe -l chatcli_string_dump.frida.js --no-pause
  frida -p <pid> -l chatcli_string_dump.frida.js
*/

const moduleName = "__MODULE_NAME__";
const decryptOffset = "__DECRYPT_OFFSET__";
const apiNames = __API_NAMES__;
const argIndexes = __ARG_INDEXES__;
const maxLen = __MAX_LEN__;

function readStringAt(ptrValue) {
  if (ptrValue.isNull()) return null;
  try {
    const s = Memory.readCString(ptrValue, maxLen);
    if (s && s.length > 0) return { kind: "ascii", value: s };
  } catch (_) {}
  try {
    const s = Memory.readUtf16String(ptrValue, maxLen / 2);
    if (s && s.length > 0) return { kind: "utf16", value: s };
  } catch (_) {}
  return null;
}

function emitString(source, where, ptrValue) {
  const s = readStringAt(ptrValue);
  if (!s) return;
  send({
    type: "string",
    source,
    where,
    pointer: ptrValue.toString(),
    kind: s.kind,
    value: s.value
  });
}

function hookAddress(label, address) {
  Interceptor.attach(address, {
    onEnter(args) {
      this.args = [];
      for (const idx of argIndexes) {
        this.args.push({ index: idx, value: args[idx] });
        emitString(label, "arg" + idx + "_enter", args[idx]);
      }
    },
    onLeave(retval) {
      emitString(label, "retval", retval);
      for (const item of this.args) {
        emitString(label, "arg" + item.index + "_leave", item.value);
      }
    }
  });
  send({ type: "hooked", label, address: address.toString() });
}

if (moduleName && decryptOffset) {
  const base = Module.findBaseAddress(moduleName);
  if (base === null) {
    send({ type: "error", message: "module not loaded: " + moduleName });
  } else {
    hookAddress(moduleName + "+" + decryptOffset, base.add(ptr(decryptOffset)));
  }
}

for (const name of apiNames) {
  const addr = Module.findExportByName(null, name);
  if (addr !== null) hookAddress(name, addr);
  else send({ type: "missing_export", name });
}
'''


FRIDA_COLLECTOR_TEMPLATE = r'''"""
chatcli Frida string dump collector.
Scope: run only against an authorized local lab/CTF/owned target.

Examples:
  python chatcli_frida_collect.py --spawn ./target.exe
  python chatcli_frida_collect.py --attach 1234
"""

import argparse
import json
from pathlib import Path

import frida


SCRIPT_PATH = Path(__file__).with_name("chatcli_string_dump.frida.js")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spawn", help="Executable path to spawn under Frida.")
    parser.add_argument("--attach", help="PID or process name to attach to.")
    parser.add_argument("--jsonl", default="chatcli_strings.jsonl")
    parser.add_argument("--txt", default="chatcli_strings.txt")
    args = parser.parse_args()
    if not args.spawn and not args.attach:
        parser.error("provide --spawn or --attach")

    seen = set()
    jsonl_path = Path(args.jsonl)
    txt_path = Path(args.txt)

    def on_message(message, data):
        if message.get("type") != "send":
            print(message)
            return
        payload = message.get("payload", {})
        if payload.get("type") != "string":
            print(json.dumps(payload, ensure_ascii=False))
            return
        value = payload.get("value") or ""
        key = (payload.get("source"), payload.get("where"), value)
        if value in seen:
            return
        seen.add(value)
        with jsonl_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        with txt_path.open("a", encoding="utf-8") as f:
            f.write(value.replace("\r", "\\r").replace("\n", "\\n") + "\n")
        print(json.dumps(payload, ensure_ascii=False))

    device = frida.get_local_device()
    pid = None
    if args.spawn:
        pid = device.spawn([args.spawn])
        session = device.attach(pid)
    else:
        target = int(args.attach) if str(args.attach).isdigit() else args.attach
        session = device.attach(target)
    script = session.create_script(SCRIPT_PATH.read_text(encoding="utf-8"))
    script.on("message", on_message)
    script.load()
    if pid is not None:
        device.resume(pid)
    print("collector running; press Ctrl+C to stop")
    try:
        import sys
        sys.stdin.read()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
'''


X64DBG_TEMPLATE = r'''; chatcli x64dbg string hook template
; Scope: use only with an authorized local lab/CTF/owned target.
; Set breakpoints on the decrypt function/API and inspect return value + buffer args.

log "chatcli string hook script loaded"
__BREAKPOINT_LINES__

; At each breakpoint:
;   x64: RCX/RDX/R8/R9 are the first four integer/pointer args; RAX is return value after stepping out.
;   x86 stdcall/cdecl args are at [ESP+4], [ESP+8], ...
; Suggested manual commands:
;   log "decrypt hit: rip={rip} rcx={rcx} rdx={rdx} r8={r8} r9={r9}"
;   rtr
;   log "decrypt return: rax={rax}"
;   dump rax
;   dump rcx
;   dump rdx
'''


class RuntimeStringHooksTool(Tool):
    name = "runtime_string_hooks"
    description = (
        "Generate Frida and x64dbg scripts for authorized local runtime string extraction. "
        "The scripts hook a decrypt function address or exported APIs and dump plaintext "
        "strings from return values and selected buffer arguments. A Frida collector is "
        "also generated to bulk-export unique strings to JSONL/TXT."
    )
    parameters = {
        "type": "object",
        "properties": {
            "output_dir": {"type": "string", "description": "Directory where scripts will be written. Default .chatcli/tmp/hooks."},
            "module_name": {"type": "string", "description": "Module name for a module+offset decrypt hook, e.g. target.exe."},
            "decrypt_offset": {"type": "string", "description": "Hex offset from module base for the decrypt function, e.g. 0x1234."},
            "api_names": {
                "type": "array",
                "description": "Optional exported API names to hook, e.g. CryptStringToBinaryA or custom exported decrypt.",
                "items": {"type": "string"},
            },
            "arg_indexes": {
                "type": "array",
                "description": "Argument indexes to read before and after the call. Default [0, 1, 2].",
                "items": {"type": "integer"},
            },
            "max_string_length": {"type": "integer", "description": "Max chars to read per pointer. Default 4096."},
        },
        "required": [],
    }

    def execute(
        self,
        output_dir: str = ".chatcli/tmp/hooks",
        module_name: str = "",
        decrypt_offset: str = "",
        api_names: list[str] | None = None,
        arg_indexes: list[int] | None = None,
        max_string_length: int = 4096,
        **kwargs,
    ) -> ToolResult:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        api_names = [str(x) for x in (api_names or []) if str(x).strip()]
        arg_indexes = [int(x) for x in (arg_indexes if arg_indexes is not None else [0, 1, 2])]
        arg_indexes = [x for x in arg_indexes if 0 <= x <= 15]
        max_string_length = max(16, min(int(max_string_length or 4096), 65536))

        frida = FRIDA_TEMPLATE
        frida = frida.replace("__MODULE_NAME__", module_name.replace("\\", "\\\\").replace('"', '\\"'))
        frida = frida.replace("__DECRYPT_OFFSET__", decrypt_offset.replace('"', '\\"'))
        frida = frida.replace("__API_NAMES__", json.dumps(api_names))
        frida = frida.replace("__ARG_INDEXES__", json.dumps(arg_indexes))
        frida = frida.replace("__MAX_LEN__", str(max_string_length))

        breakpoints = []
        if module_name and decrypt_offset:
            breakpoints.append(f'bphwc {module_name}+{decrypt_offset}')
        for name in api_names:
            breakpoints.append(f'bp {name}')
        x64dbg = X64DBG_TEMPLATE.replace("__BREAKPOINT_LINES__", "\n".join(breakpoints) if breakpoints else '; Add bp/bphwc commands here after resolving the decrypt address.')

        frida_path = out_dir / "chatcli_string_dump.frida.js"
        collector_path = out_dir / "chatcli_frida_collect.py"
        x64dbg_path = out_dir / "chatcli_string_dump.x64dbg.txt"
        frida_path.write_text(frida, encoding="utf-8")
        collector_path.write_text(FRIDA_COLLECTOR_TEMPLATE, encoding="utf-8")
        x64dbg_path.write_text(x64dbg, encoding="utf-8")

        lines = [
            "# Runtime String Hook Scripts",
            "",
            f"Frida script: {frida_path}",
            f"Frida collector: {collector_path}",
            f"x64dbg script: {x64dbg_path}",
            f"Module: {module_name or '(not set)'}",
            f"Decrypt offset: {decrypt_offset or '(not set)'}",
            f"API hooks: {', '.join(api_names) if api_names else '(none)'}",
            f"Argument indexes: {arg_indexes}",
            "",
            "Run only against an authorized local target. The scripts do not execute here; they are generated for debugger/instrumentation use.",
        ]
        return ToolResult(
            content="\n".join(lines),
            metadata={
                "frida_script": str(frida_path),
                "frida_collector": str(collector_path),
                "x64dbg_script": str(x64dbg_path),
                "module_name": module_name,
                "decrypt_offset": decrypt_offset,
                "api_names": api_names,
                "arg_indexes": arg_indexes,
            },
        )
