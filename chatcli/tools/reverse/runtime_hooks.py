"""Runtime string hook script generators."""

import json
import re
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


API_HOOK_CANDIDATES: tuple[str, ...] = (
    "CreateProcessW",
    "CreateProcessA",
    "CreateProcessAsUserW",
    "ShellExecuteW",
    "WinExec",
    "CoCreateInstance",
    "CoInitializeEx",
    "CreateServiceW",
    "StartServiceW",
    "OpenSCManagerW",
    "OpenServiceW",
    "ChangeServiceConfigW",
    "DeleteService",
    "RegCreateKeyExW",
    "RegSetValueExW",
    "RegOpenKeyExW",
    "RegQueryValueExW",
    "RegDeleteKeyW",
    "RegDeleteValueW",
    "CreateFileW",
    "WriteFile",
    "DeleteFileW",
    "MoveFileW",
    "MoveFileExW",
    "CopyFileW",
    "FindFirstFileW",
    "FindNextFileW",
    "ReadFile",
    "LoadLibraryW",
    "LoadLibraryExW",
    "GetProcAddress",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "FindWindowW",
    "GetTickCount",
    "GetTickCount64",
    "QueryPerformanceCounter",
    "Sleep",
    "VirtualAlloc",
    "VirtualProtect",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtWriteVirtualMemory",
    "NtOpenProcess",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
    "NtResumeThread",
    "NtDelayExecution",
    "NtSetInformationProcess",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "QueueUserAPC",
    "SetWindowsHookExW",
    "AmsiScanBuffer",
    "EtwEventWrite",
    "OpenProcess",
    "CreateToolhelp32Snapshot",
    "Process32FirstW",
    "Process32NextW",
    "Module32FirstW",
    "Module32NextW",
    "OpenProcessToken",
    "AdjustTokenPrivileges",
    "LookupPrivilegeValueW",
    "ImpersonateLoggedOnUser",
    "RevertToSelf",
    "CryptUnprotectData",
    "CryptAcquireContextW",
    "CryptGenRandom",
    "CryptDecrypt",
    "CryptEncrypt",
    "CryptStringToBinaryW",
    "CryptBinaryToStringW",
    "CryptReleaseContext",
    "BCryptGenRandom",
    "BCryptDecrypt",
    "BCryptEncrypt",
    "GetUserNameW",
    "GetComputerNameW",
    "GetComputerNameExW",
    "NetUserEnum",
    "NetUserGetInfo",
    "NetShareEnum",
    "GetAdaptersInfo",
    "GetAdaptersAddresses",
    "DnsQuery_W",
    "OpenClipboard",
    "GetClipboardData",
    "CloseClipboard",
    "GetDC",
    "CreateCompatibleDC",
    "CreateCompatibleBitmap",
    "BitBlt",
    "GetDIBits",
    "WSAStartup",
    "WSASocketW",
    "connect",
    "recv",
    "WSASend",
    "WSARecv",
    "send",
    "InternetOpenW",
    "InternetConnectW",
    "HttpOpenRequestW",
    "HttpSendRequestW",
    "InternetReadFile",
    "WinHttpOpen",
    "WinHttpConnect",
    "WinHttpOpenRequest",
    "WinHttpSendRequest",
    "WinHttpReceiveResponse",
    "WinHttpReadData",
    "URLDownloadToFileW",
)


KEYWORD_API_HINTS: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("schtasks", "cmd.exe", "powershell", "os/exec", "exec:"), ("CreateProcessW", "CreateProcessAsUserW")),
    (("schedule", "task scheduler", "itaskservice", "clsid", "cocreateinstance"), ("CoInitializeEx", "CoCreateInstance", "CreateProcessW")),
    (("service", "openscmanager", "createservice", "startservice"), ("OpenSCManagerW", "CreateServiceW", "OpenServiceW", "StartServiceW", "ChangeServiceConfigW")),
    (("registry", "regset", "regcreate", "hkcu", "hklm", "currentversion"), ("RegCreateKeyExW", "RegSetValueExW", "RegOpenKeyExW", "RegQueryValueExW")),
    (("createfile", "writefile", "deletefile", "movefile", "copyfile", "findfirstfile"), ("CreateFileW", "ReadFile", "WriteFile", "DeleteFileW", "MoveFileW", "CopyFileW", "FindFirstFileW", "FindNextFileW")),
    (("loadlibrary", "getprocaddress"), ("LoadLibraryW", "LoadLibraryExW", "GetProcAddress")),
    (("debugger", "isdebuggerpresent", "checkremotedebugger", "ntqueryinformationprocess", "findwindow", "sleep", "queryperformance", "ntdelayexecution"), ("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "FindWindowW", "GetTickCount", "QueryPerformanceCounter", "Sleep", "NtDelayExecution")),
    (("amsi", "etw", "eventwrite"), ("AmsiScanBuffer", "EtwEventWrite")),
    (("virtualalloc", "virtualprotect", "writeprocessmemory", "createremotethread", "openprocess", "ntcreatethreadex", "ntwritevirtualmemory", "ntallocatevirtualmemory", "ntprotectvirtualmemory", "queueuserapc", "setwindowshook"), ("VirtualAlloc", "VirtualProtect", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx", "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory", "NtOpenProcess", "QueueUserAPC", "SetWindowsHookExW", "OpenProcess")),
    (("mapviewofsection", "process hollow", "hollowing", "resumethread"), ("NtMapViewOfSection", "NtUnmapViewOfSection", "NtResumeThread", "NtSetInformationProcess")),
    (("toolhelp", "process32", "module32", "snapshot", "lsass"), ("CreateToolhelp32Snapshot", "Process32FirstW", "Process32NextW", "Module32FirstW", "Module32NextW", "OpenProcess")),
    (("token", "privilege", "impersonate", "sedebugprivilege"), ("OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValueW", "ImpersonateLoggedOnUser", "RevertToSelf")),
    (("credential", "cred", "dpapi", "cryptunprotect", "lsa", "browser", "wallet"), ("CryptUnprotectData", "OpenProcess", "ReadFile")),
    (("crypt", "bcrypt", "base64", "decrypt", "encrypt"), ("CryptAcquireContextW", "CryptGenRandom", "CryptDecrypt", "CryptEncrypt", "CryptStringToBinaryW", "CryptBinaryToStringW", "CryptReleaseContext", "BCryptGenRandom", "BCryptDecrypt", "BCryptEncrypt")),
    (("username", "computername", "netuser", "netshare", "adapter", "ipconfig", "systeminfo"), ("GetUserNameW", "GetComputerNameW", "GetComputerNameExW", "NetUserEnum", "NetUserGetInfo", "NetShareEnum", "GetAdaptersInfo", "GetAdaptersAddresses")),
    (("clipboard", "screenshot", "bitblt", "getdibits"), ("OpenClipboard", "GetClipboardData", "CloseClipboard", "GetDC", "CreateCompatibleDC", "CreateCompatibleBitmap", "BitBlt", "GetDIBits")),
    (("wsastartup", "connect", "wsasend", "wsarecv", "recv", "dnsquery", "net/http", "http://", "https://"), ("WSAStartup", "WSASocketW", "connect", "WSASend", "WSARecv", "send", "recv", "DnsQuery_W")),
    (("winhttp",), ("WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest")),
    (("wininet", "internetopen", "internetconnect", "httpopenrequest", "urldownload"), ("InternetOpenW", "InternetConnectW", "HttpOpenRequestW", "HttpSendRequestW", "InternetReadFile", "URLDownloadToFileW")),
)


API_CATEGORIES: dict[str, str] = {
    "CreateProcessW": "process_creation",
    "CreateProcessA": "process_creation",
    "CreateProcessAsUserW": "process_creation",
    "ShellExecuteW": "process_creation",
    "WinExec": "process_creation",
    "CoCreateInstance": "com_wmi_task",
    "CoInitializeEx": "com_wmi_task",
    "CreateServiceW": "service_persistence",
    "StartServiceW": "service_persistence",
    "OpenSCManagerW": "service_persistence",
    "OpenServiceW": "service_persistence",
    "ChangeServiceConfigW": "service_persistence",
    "DeleteService": "service_persistence",
    "RegCreateKeyExW": "registry",
    "RegSetValueExW": "registry",
    "RegOpenKeyExW": "registry",
    "RegQueryValueExW": "registry",
    "RegDeleteKeyW": "registry",
    "RegDeleteValueW": "registry",
    "CreateFileW": "file",
    "WriteFile": "file",
    "DeleteFileW": "file",
    "MoveFileW": "file",
    "MoveFileExW": "file",
    "CopyFileW": "file",
    "FindFirstFileW": "file_discovery",
    "FindNextFileW": "file_discovery",
    "ReadFile": "file",
    "LoadLibraryW": "dynamic_import",
    "LoadLibraryExW": "dynamic_import",
    "GetProcAddress": "dynamic_import",
    "IsDebuggerPresent": "anti_analysis",
    "CheckRemoteDebuggerPresent": "anti_analysis",
    "NtQueryInformationProcess": "anti_analysis",
    "FindWindowW": "anti_analysis",
    "GetTickCount": "anti_analysis",
    "GetTickCount64": "anti_analysis",
    "QueryPerformanceCounter": "anti_analysis",
    "Sleep": "anti_analysis",
    "VirtualAlloc": "memory",
    "VirtualProtect": "memory",
    "NtAllocateVirtualMemory": "injection",
    "NtProtectVirtualMemory": "injection",
    "NtWriteVirtualMemory": "injection",
    "NtOpenProcess": "injection",
    "NtMapViewOfSection": "injection",
    "NtUnmapViewOfSection": "injection",
    "NtResumeThread": "injection",
    "NtDelayExecution": "anti_analysis",
    "NtSetInformationProcess": "anti_analysis",
    "VirtualAllocEx": "injection",
    "WriteProcessMemory": "injection",
    "CreateRemoteThread": "injection",
    "NtCreateThreadEx": "injection",
    "QueueUserAPC": "injection",
    "SetWindowsHookExW": "injection",
    "AmsiScanBuffer": "defense_evasion_observation",
    "EtwEventWrite": "defense_evasion_observation",
    "OpenProcess": "injection",
    "CreateToolhelp32Snapshot": "process_discovery",
    "Process32FirstW": "process_discovery",
    "Process32NextW": "process_discovery",
    "Module32FirstW": "process_discovery",
    "Module32NextW": "process_discovery",
    "OpenProcessToken": "privilege",
    "AdjustTokenPrivileges": "privilege",
    "LookupPrivilegeValueW": "privilege",
    "ImpersonateLoggedOnUser": "privilege",
    "RevertToSelf": "privilege",
    "CryptUnprotectData": "credential_access",
    "CryptAcquireContextW": "crypto",
    "CryptGenRandom": "crypto",
    "CryptDecrypt": "crypto",
    "CryptEncrypt": "crypto",
    "CryptStringToBinaryW": "crypto",
    "CryptBinaryToStringW": "crypto",
    "CryptReleaseContext": "crypto",
    "BCryptGenRandom": "crypto",
    "BCryptDecrypt": "crypto",
    "BCryptEncrypt": "crypto",
    "GetUserNameW": "discovery",
    "GetComputerNameW": "discovery",
    "GetComputerNameExW": "discovery",
    "NetUserEnum": "discovery",
    "NetUserGetInfo": "discovery",
    "NetShareEnum": "discovery",
    "GetAdaptersInfo": "discovery",
    "GetAdaptersAddresses": "discovery",
    "DnsQuery_W": "network",
    "OpenClipboard": "collection",
    "GetClipboardData": "collection",
    "CloseClipboard": "collection",
    "GetDC": "collection",
    "CreateCompatibleDC": "collection",
    "CreateCompatibleBitmap": "collection",
    "BitBlt": "collection",
    "GetDIBits": "collection",
    "WSAStartup": "network",
    "WSASocketW": "network",
    "connect": "network",
    "recv": "network",
    "WSASend": "network",
    "WSARecv": "network",
    "send": "network",
    "InternetOpenW": "network",
    "InternetConnectW": "network",
    "HttpOpenRequestW": "network",
    "HttpSendRequestW": "network",
    "InternetReadFile": "network",
    "WinHttpOpen": "network",
    "WinHttpConnect": "network",
    "WinHttpOpenRequest": "network",
    "WinHttpSendRequest": "network",
    "WinHttpReceiveResponse": "network",
    "WinHttpReadData": "network",
    "URLDownloadToFileW": "network",
}


CATEGORY_WEIGHTS: dict[str, int] = {
    "process_creation": 95,
    "registry": 90,
    "injection": 88,
    "service_persistence": 88,
    "com_wmi_task": 86,
    "network": 85,
    "dynamic_import": 80,
    "credential_access": 80,
    "privilege": 78,
    "crypto": 75,
    "process_discovery": 74,
    "discovery": 72,
    "collection": 72,
    "file": 70,
    "file_discovery": 68,
    "memory": 65,
    "anti_analysis": 70,
    "defense_evasion_observation": 70,
}


COVERAGE_THRESHOLDS: dict[str, tuple[int, int]] = {
    "focused": (85, 32),
    "balanced": (70, 64),
    "comprehensive": (0, 0),
}


def _append_unique(items: list[str], values: list[str] | tuple[str, ...]) -> None:
    seen = {item.lower() for item in items}
    for value in values:
        name = str(value).strip()
        if name and name.lower() not in seen:
            items.append(name)
            seen.add(name.lower())


def _find_first(root: Path, filename: str) -> Path | None:
    if root.is_file() and root.name == filename:
        return root
    if root.is_file():
        return None
    direct = root / filename
    if direct.is_file():
        return direct
    for path in root.rglob(filename):
        if path.is_file():
            return path
    return None


def _read_text(path: Path | None, limit: int = 2_000_000) -> str:
    if not path or not path.is_file():
        return ""
    data = path.read_bytes()[:limit]
    return data.decode("utf-8", errors="ignore")


def _parse_entry_point(text: str) -> str:
    match = re.search(r"Entry Point\s*:\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+)", text)
    if not match:
        return ""
    value = match.group(1)
    return value if value.lower().startswith("0x") else f"0x{value}"


def _parse_binary_inspect(path: Path | None) -> dict:
    if not path or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _go_clues(corpus: str) -> dict:
    build_match = re.search(r'Go build ID:\s*"([^"]+)"', corpus)
    module_matches = re.findall(r"(?:^|\n)path\\t([^\r\n]+)", corpus)
    symbol_matches = re.findall(
        r"\b(?:main|syscall|internal/syscall/windows|os|net/http|crypto/[A-Za-z0-9_/]+)"
        r"(?:[./][A-Za-z0-9_*$<>-]+)+",
        corpus,
    )
    symbols: list[str] = []
    _append_unique(symbols, tuple(symbol_matches[:200]))
    return {
        "build_id": build_match.group(1) if build_match else "",
        "module_paths": sorted(set(module_matches))[:20],
        "symbols": symbols[:50],
    }


def _select_api_names(
    api_names: list[str],
    inferred_breakpoints: list[dict],
    coverage_mode: str,
    max_api_hooks: int,
) -> list[str]:
    mode = (coverage_mode or "balanced").strip().lower()
    min_score, default_limit = COVERAGE_THRESHOLDS.get(mode, COVERAGE_THRESHOLDS["balanced"])
    limit = int(max_api_hooks or 0) or default_limit
    scores = {item.get("name"): int(item.get("score", 0)) for item in inferred_breakpoints}
    order = {item.get("name"): idx for idx, item in enumerate(inferred_breakpoints)}

    selected = [
        name for name in api_names
        if scores.get(name, 100 if not inferred_breakpoints else 0) >= min_score
    ]
    selected.sort(key=lambda name: (-scores.get(name, 50), order.get(name, 9999), name.lower()))
    if limit > 0:
        selected = selected[:limit]
    return selected


def _coverage_summary(ranked_breakpoints: list[dict]) -> dict:
    by_category: dict[str, int] = {}
    for item in ranked_breakpoints:
        category = str(item.get("category") or "unknown")
        by_category[category] = by_category.get(category, 0) + 1
    return {
        "total_breakpoints": len(ranked_breakpoints),
        "api_breakpoints": sum(1 for item in ranked_breakpoints if item.get("kind") == "api"),
        "entry_breakpoints": sum(1 for item in ranked_breakpoints if item.get("kind") == "entry"),
        "by_category": dict(sorted(by_category.items())),
        "gaps": [
            "direct syscalls may bypass user-mode API breakpoints",
            "custom protocol/config parsing may need function-level reversing",
            "trigger-gated behavior may not hit until conditions are satisfied",
            "x64dbg breakpoints do not replace Procmon/Sysmon/PCAP telemetry",
        ],
    }


def _infer_from_analysis_dir(analysis_dir: str) -> dict:
    root = Path(analysis_dir)
    if not analysis_dir or not root.exists():
        return {}

    binary_path = _find_first(root, "binary_inspect.json")
    exif_path = _find_first(root, "exiftool.txt")
    strings_path = _find_first(root, "strings.txt")
    floss_path = _find_first(root, "floss.txt")
    status_path = _find_first(root, "status.json")

    binary = _parse_binary_inspect(binary_path)
    exif_text = _read_text(exif_path)
    corpus = "\n".join(
        text
        for text in (
            json.dumps(binary, ensure_ascii=False),
            exif_text,
            _read_text(strings_path),
            _read_text(floss_path),
            _read_text(status_path),
        )
        if text
    )
    lowered = corpus.lower()

    inferred_apis: list[str] = []
    breakpoints: dict[str, dict] = {}

    def add_breakpoint(api: str, reason: str, evidence: str, score_bonus: int = 0) -> None:
        category = API_CATEGORIES.get(api, "api")
        score = CATEGORY_WEIGHTS.get(category, 50) + score_bonus
        current = breakpoints.get(api)
        if current and current["score"] >= score:
            current["reasons"].append(reason)
            return
        breakpoints[api] = {
            "kind": "api",
            "name": api,
            "category": category,
            "score": min(100, score),
            "confidence": "high" if evidence == "direct" else "medium",
            "evidence": evidence,
            "reasons": [reason],
        }
        _append_unique(inferred_apis, (api,))

    for api in API_HOOK_CANDIDATES:
        if api.lower() in lowered:
            add_breakpoint(api, f"static artifacts mention {api}", "direct", 8)
    for keywords, apis in KEYWORD_API_HINTS:
        if any(keyword in lowered for keyword in keywords):
            matched = [keyword for keyword in keywords if keyword in lowered]
            for api in apis:
                add_breakpoint(api, f"matched behavior keywords: {', '.join(matched[:4])}", "keyword")

    sample_path = str(binary.get("path") or "")
    module_name = Path(sample_path).name if sample_path else ""
    entry_offset = _parse_entry_point(exif_text)

    evidence = []
    if binary_path:
        evidence.append(str(binary_path))
    if exif_path:
        evidence.append(str(exif_path))
    if strings_path:
        evidence.append(str(strings_path))
    if floss_path:
        evidence.append(str(floss_path))

    return {
        "analysis_dir": str(root),
        "sample_path": sample_path,
        "module_name": module_name,
        "entry_offset": entry_offset,
        "api_names": inferred_apis,
        "breakpoints": sorted(breakpoints.values(), key=lambda item: item["score"], reverse=True),
        "go": _go_clues(corpus),
        "evidence_files": evidence,
    }


def _build_usage_markdown(plan: dict) -> str:
    sample = plan.get("sample_path") or "(unknown sample)"
    x64dbg_script = plan.get("x64dbg_script") or "chatcli_string_dump.x64dbg.txt"
    ranked = plan.get("ranked_breakpoints", [])
    summary = plan.get("coverage_summary", {})
    lines = [
        "# x64dbg Runtime Plan",
        "",
        f"Sample: `{sample}`",
        f"x64dbg script: `{x64dbg_script}`",
        f"Coverage mode: `{plan.get('coverage_mode', 'balanced')}`",
        f"Total breakpoints: `{summary.get('total_breakpoints', len(ranked))}`",
        "",
        "## Load And Observe",
        "",
        "1. Open the sample in x64dbg inside the isolated lab VM.",
        "2. Load the generated x64dbg script.",
        "3. Keep execution paused at entry until the breakpoint list is loaded.",
        "4. Run until the highest-ranked API breakpoint hits.",
        "5. Inspect x64 arguments: RCX, RDX, R8, R9; return value is RAX after stepping out.",
        "6. Record command lines, registry value names/data, file paths, network endpoints, and loaded DLL/API names.",
        "",
        "## Ranked Breakpoints",
        "",
    ]
    for item in ranked[:25]:
        reasons = "; ".join(item.get("reasons", [])[:2])
        lines.append(
            f"- {item.get('score', 0):03d} `{item.get('name')}` "
            f"({item.get('category')}, {item.get('confidence')}): {reasons}"
        )
    lines.extend([
        "",
        "## Coverage Gaps",
        "",
    ])
    for gap in summary.get("gaps", []):
        lines.append(f"- {gap}")
    return "\n".join(lines) + "\n"


def _ps_single_quoted(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _normalize_remote_windows_path(path: str) -> str:
    value = path.replace("/", "\\").strip()
    if value.startswith("\\\\"):
        prefix = "\\\\"
        rest = value[2:]
    else:
        prefix = ""
        rest = value
    while "\\\\" in rest:
        rest = rest.replace("\\\\", "\\")
    return prefix + rest


def _remote_write_file(client, remote_path: str, content: str) -> dict:
    import base64

    remote_path = _normalize_remote_windows_path(remote_path)
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    remote = _ps_single_quoted(remote_path)
    if len(encoded) > 3500:
        temp = _ps_single_quoted(remote_path + ".b64")
        init_command = (
            "powershell -NoProfile -ExecutionPolicy Bypass -Command "
            f"\"$p={remote}; $t={temp}; "
            "$d=[System.IO.Path]::GetDirectoryName($p); "
            "New-Item -ItemType Directory -Force -Path $d | Out-Null; "
            "if (Test-Path -LiteralPath $t) { Remove-Item -LiteralPath $t -Force }; "
            "Write-Output $p\""
        )
        init_result = client.exec_command(init_command, timeout=60)
        if init_result.get("exit_code") != 0:
            return init_result
        for start in range(0, len(encoded), 3000):
            chunk = encoded[start:start + 3000]
            append_command = (
                "powershell -NoProfile -ExecutionPolicy Bypass -Command "
                f"\"Add-Content -LiteralPath {temp} -Value '{chunk}' -NoNewline\""
            )
            append_result = client.exec_command(append_command, timeout=60)
            if append_result.get("exit_code") != 0:
                return append_result
        finalize_command = (
            "powershell -NoProfile -ExecutionPolicy Bypass -Command "
            f"\"$p={remote}; $t={temp}; "
            "$s=Get-Content -LiteralPath $t -Raw; "
            "$b=[Convert]::FromBase64String($s); "
            "[System.IO.File]::WriteAllBytes($p,$b); "
            "Remove-Item -LiteralPath $t -Force -ErrorAction SilentlyContinue; "
            "Write-Output $p\""
        )
        return client.exec_command(finalize_command, timeout=60)

    command = (
        "powershell -NoProfile -ExecutionPolicy Bypass -Command "
        f"\"$p={remote}; "
        "$d=[System.IO.Path]::GetDirectoryName($p); "
        "New-Item -ItemType Directory -Force -Path $d | Out-Null; "
        f"$b=[Convert]::FromBase64String('{encoded}'); "
        "[System.IO.File]::WriteAllBytes($p,$b); "
        "Write-Output $p\""
    )
    return client.exec_command(command, timeout=60)


class RuntimeStringHooksTool(Tool):
    name = "runtime_string_hooks"
    description = (
        "Generate Frida and x64dbg scripts for authorized local runtime string extraction. "
        "The scripts hook a decrypt function address or exported APIs and dump plaintext "
        "strings from return values and selected buffer arguments. It can also audit a "
        "ChatCLI static-analysis result directory and infer x64dbg API breakpoints from "
        "binary_inspect/exiftool/strings/floss artifacts. A Frida collector is generated "
        "to bulk-export unique strings to JSONL/TXT."
    )
    parameters = {
        "type": "object",
        "properties": {
            "output_dir": {"type": "string", "description": "Directory where scripts will be written. Default .chatcli/tmp/hooks."},
            "module_name": {"type": "string", "description": "Module name for a module+offset decrypt hook, e.g. target.exe."},
            "decrypt_offset": {"type": "string", "description": "Hex offset from module base for the decrypt function, e.g. 0x1234."},
            "analysis_dir": {"type": "string", "description": "Optional ChatCLI static result directory. When set, infer module name, entry point, and API hooks from binary_inspect.json, exiftool.txt, strings.txt, and floss.txt."},
            "entry_offset": {"type": "string", "description": "Optional module-relative entry or code offset to add as an x64dbg hardware breakpoint without treating it as a decrypt hook."},
            "include_entry_breakpoint": {"type": "boolean", "description": "Add an x64dbg module+entry_offset breakpoint when an entry offset is available. Default true."},
            "sync_to_remote": {"type": "boolean", "description": "If true, copy generated scripts and plan to the configured remote Guest Agent server. This does not execute the sample."},
            "remote_output_dir": {"type": "string", "description": "Remote directory for sync_to_remote, e.g. C:\\analysis\\hooks\\case-id. Default uses C:\\analysis\\hooks\\<output folder name>."},
            "coverage_mode": {"type": "string", "description": "Breakpoint coverage mode: focused, balanced, or comprehensive. Default balanced.", "enum": ["focused", "balanced", "comprehensive"]},
            "max_api_hooks": {"type": "integer", "description": "Maximum API breakpoints after ranking. 0 uses the mode default; comprehensive default is unlimited."},
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

    def __init__(self, config=None) -> None:
        self._config = config

    def execute(
        self,
        output_dir: str = ".chatcli/tmp/hooks",
        module_name: str = "",
        decrypt_offset: str = "",
        analysis_dir: str = "",
        entry_offset: str = "",
        include_entry_breakpoint: bool = True,
        sync_to_remote: bool = False,
        remote_output_dir: str = "",
        coverage_mode: str = "balanced",
        max_api_hooks: int = 0,
        api_names: list[str] | None = None,
        arg_indexes: list[int] | None = None,
        max_string_length: int = 4096,
        **kwargs,
    ) -> ToolResult:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        inferred = _infer_from_analysis_dir(analysis_dir)
        if inferred:
            module_name = module_name or inferred.get("module_name", "")
            entry_offset = entry_offset or inferred.get("entry_offset", "")
        api_names = [str(x) for x in (api_names or []) if str(x).strip()]
        _append_unique(api_names, tuple(inferred.get("api_names", ())))
        inferred_breakpoints = list(inferred.get("breakpoints", []))
        api_names = _select_api_names(api_names, inferred_breakpoints, coverage_mode, max_api_hooks)
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
        if include_entry_breakpoint and module_name and entry_offset and entry_offset != decrypt_offset:
            breakpoints.append(f'; Entry/code breakpoint inferred from static artifacts')
            breakpoints.append(f'bphwc {module_name}+{entry_offset}')
        if inferred.get("analysis_dir"):
            breakpoints.append(f'; API breakpoints inferred from {inferred["analysis_dir"]}')
        for name in api_names:
            breakpoints.append(f'bp {name}')
        x64dbg = X64DBG_TEMPLATE.replace("__BREAKPOINT_LINES__", "\n".join(breakpoints) if breakpoints else '; Add bp/bphwc commands here after resolving the decrypt address.')

        frida_path = out_dir / "chatcli_string_dump.frida.js"
        collector_path = out_dir / "chatcli_frida_collect.py"
        x64dbg_path = out_dir / "chatcli_string_dump.x64dbg.txt"
        plan_path = out_dir / "chatcli_x64dbg_plan.json"
        usage_path = out_dir / "chatcli_x64dbg_usage.md"
        frida_path.write_text(frida, encoding="utf-8")
        collector_path.write_text(FRIDA_COLLECTOR_TEMPLATE, encoding="utf-8")
        x64dbg_path.write_text(x64dbg, encoding="utf-8")

        ranked_breakpoints = []
        if entry_offset and module_name:
            ranked_breakpoints.append({
                "kind": "entry",
                "name": f"{module_name}+{entry_offset}",
                "category": "entry",
                "score": 100,
                "confidence": "high",
                "evidence": "exiftool",
                "reasons": ["entry point from static artifact"],
            })
        ranked_breakpoints.extend(
            item for item in inferred_breakpoints
            if item.get("name") in set(api_names)
        )
        if not inferred_breakpoints:
            ranked_breakpoints.extend(
                {
                    "kind": "api",
                    "name": name,
                    "category": API_CATEGORIES.get(name, "api"),
                    "score": CATEGORY_WEIGHTS.get(API_CATEGORIES.get(name, "api"), 50),
                    "confidence": "manual",
                    "evidence": "user_provided",
                    "reasons": ["provided by caller"],
                }
                for name in api_names
            )

        plan = {
            "sample_path": inferred.get("sample_path", ""),
            "analysis_dir": inferred.get("analysis_dir", ""),
            "module_name": module_name,
            "decrypt_offset": decrypt_offset,
            "entry_offset": entry_offset,
            "api_names": api_names,
            "arg_indexes": arg_indexes,
            "coverage_mode": coverage_mode,
            "ranked_breakpoints": ranked_breakpoints,
            "coverage_summary": _coverage_summary(ranked_breakpoints),
            "go": inferred.get("go", {}),
            "evidence_files": inferred.get("evidence_files", []),
            "x64dbg_script": str(x64dbg_path),
            "frida_script": str(frida_path),
            "frida_collector": str(collector_path),
        }
        plan_path.write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
        usage_path.write_text(_build_usage_markdown(plan), encoding="utf-8")

        remote_sync: dict = {}
        if sync_to_remote:
            remote = getattr(self._config, "remote", None) if self._config else None
            if remote is None or not getattr(remote, "enabled", False):
                remote_sync = {"status": "skipped", "reason": "remote is not configured"}
            elif not getattr(remote, "base_url", "") or not getattr(remote, "guest_agent_token", ""):
                remote_sync = {"status": "skipped", "reason": "Guest Agent base_url/token missing"}
            else:
                from chatcli.remote.guest_client import GuestAgentClient

                client = GuestAgentClient(remote.base_url, remote.guest_agent_token, timeout=120, verify=False)
                target_dir = remote_output_dir.strip() or rf"C:\analysis\hooks\{out_dir.name}"
                uploaded = []
                for local_path in (x64dbg_path, frida_path, collector_path, plan_path, usage_path):
                    remote_path = target_dir.rstrip("\\/") + "\\" + local_path.name
                    result = _remote_write_file(client, remote_path, local_path.read_text(encoding="utf-8"))
                    uploaded.append({
                        "local": str(local_path),
                        "remote": remote_path,
                        "exit_code": result.get("exit_code"),
                    })
                remote_sync = {"status": "uploaded", "remote_output_dir": target_dir, "files": uploaded}

        lines = [
            "# Runtime String Hook Scripts",
            "",
            f"Frida script: {frida_path}",
            f"Frida collector: {collector_path}",
            f"x64dbg script: {x64dbg_path}",
            f"x64dbg plan: {plan_path}",
            f"x64dbg usage: {usage_path}",
            f"Module: {module_name or '(not set)'}",
            f"Decrypt offset: {decrypt_offset or '(not set)'}",
            f"Entry offset: {entry_offset or '(not set)'}",
            f"API hooks: {', '.join(api_names) if api_names else '(none)'}",
            f"Coverage mode: {coverage_mode}",
            f"Ranked breakpoints: {len(ranked_breakpoints)}",
            f"Argument indexes: {arg_indexes}",
            "",
            "Run only against an authorized local target. The scripts do not execute here; they are generated for debugger/instrumentation use.",
        ]
        if inferred:
            lines.extend([
                "",
                "# Static Artifact Audit",
                f"Analysis dir: {inferred.get('analysis_dir')}",
                f"Sample path: {inferred.get('sample_path') or '(not found)'}",
                f"Evidence files: {', '.join(inferred.get('evidence_files', [])) or '(none)'}",
            ])
        if remote_sync:
            lines.extend([
                "",
                "# Remote Sync",
                json.dumps(remote_sync, ensure_ascii=False),
            ])
        return ToolResult(
            content="\n".join(lines),
            metadata={
                "frida_script": str(frida_path),
                "frida_collector": str(collector_path),
                "x64dbg_script": str(x64dbg_path),
                "x64dbg_plan": str(plan_path),
                "x64dbg_usage": str(usage_path),
                "module_name": module_name,
                "decrypt_offset": decrypt_offset,
                "entry_offset": entry_offset,
                "api_names": api_names,
                "arg_indexes": arg_indexes,
                "inferred": inferred,
                "coverage_mode": coverage_mode,
                "coverage_summary": _coverage_summary(ranked_breakpoints),
                "ranked_breakpoints": ranked_breakpoints,
                "remote_sync": remote_sync,
            },
        )
