"""Technique routing helper for reverse-engineering workflows."""

from ..base import Tool, ToolResult, coerce_int, coerce_str_list


ROUTES = [
    {
        "keys": ("ida", "auto_wait", "timeout", "stall", "卡", "超时"),
        "title": "IDA stalls or times out",
        "tools": "binary_inspect -> background ida_analyze(auto_wait_timeout) -> ida_deobfuscate(function_maps)",
        "next": "Use partial IDA results and data maps; do not block the main loop on full auto-analysis.",
        "child": "Run IDA/deobfuscation in a child window; main continues static triage.",
    },
    {
        "keys": ("high entropy", "高熵", "encrypted", "packed", "unusual section", "异常节", "blob"),
        "title": "High-entropy or suspicious data",
        "tools": "obfuscated_data_map -> encoded_string_extract -> binary_find/binary_hexdump",
        "next": "Map blobs, identify magic/constants/xrefs, then choose static decode or runtime dump.",
        "child": "Delegate blob-xref or decoder-function analysis to child windows.",
    },
    {
        "keys": ("sparse strings", "少字符串", "encrypted strings", "runtime string", "字符串加密",
                "stack string", "push imm", "mov byte ptr"),
        "title": "Encrypted, stack-built, or runtime-only strings",
        "tools": "encoded_string_extract -> check for push-imm stack strings -> obfuscated_data_map -> runtime_string_hooks",
        "next": "Try FLOSS tight-string mode for stack strings. Find decrypt routine/API, dump return values and output buffers, then extract strings from dump.",
        "child": "Child prepares hook scripts or analyzes one decrypt function.",
    },
    {
        "keys": ("giant function", "大函数", "huge function", "sub_140009000", "generated"),
        "title": "Giant generated function",
        "tools": "ida_deobfuscate(include_pseudocode=false, function_maps) -> child function/block analysis",
        "next": "Use basic-block maps and high-signal blocks; avoid full decompile first.",
        "child": "One child per function/range/block cluster; main keeps summaries only.",
    },
    {
        "keys": ("flatten", "扁平", "state machine", "switch", "dispatcher", "indirect jump"),
        "title": "Control-flow flattening / dispatcher",
        "tools": "ida_deobfuscate -> function_maps -> narrow Hex-Rays after cleanup",
        "next": "Identify dispatcher, state updates, transition predicates, and payload blocks.",
        "child": "Child reconstructs transition table for one dispatcher function.",
    },
    {
        "keys": ("opaque", "不透明谓词", "恒真", "恒假", "junk", "花指令", "jmp $+5",
                "dead code", "unused computation", "useless block"),
        "title": "Opaque predicates, junk instructions, or dead code",
        "tools": "ida_deobfuscate(patch_database=false first; true only after evidence)",
        "next": "Report high-confidence branches/junk/dead blocks; patch only IDA database and compare CFG.",
        "child": "Child validates one noisy function or region.",
    },
    {
        "keys": ("driver", "sys", "ioctl", "deviceiocontrol", "ntoskrnl", "驱动"),
        "title": "User-mode + driver protocol",
        "tools": "binary_inspect -> ida_analyze child -> function_maps -> binary_find constants",
        "next": "Map device names, IOCTL codes, dispatch table, shared events, and buffer formats.",
        "child": "Split app protocol and driver dispatch into separate child tasks.",
    },
    {
        "keys": ("crypto", "aes", "crc", "hash", "checksum", "key", "sbox", "加密"),
        "title": "Crypto/hash/checksum routine",
        "tools": "obfuscated_data_map -> binary_find constants -> ida_deobfuscate function map",
        "next": "Identify algorithm and key source before writing a decoder/solver.",
        "child": "Child analyzes one candidate decrypt/hash routine.",
    },
    {
        "keys": ("stripped", "no symbols", "无符号", "standard library", "flirt"),
        "title": "Stripped PE / library noise",
        "tools": "ida_deobfuscate(signatures, API-role labels) -> external_static_analyze(capa/floss)",
        "next": "Apply signatures, label functions by API role, prioritize reachable high-score routines.",
        "child": "Child labels and summarizes one role group.",
    },
    # ── New routes for anti-debug, anti-VM, SMC, API hashing, custom packers ──
    {
        "keys": ("anti-debug", "isdebuggerpresent", "peb", "beingdebugged", "ntglobalflag",
                "ntqueryinformation", "debugport", "getthreadcontext", "dr register",
                "hardware breakpoint", "int3 scan", "0xcc", "repne scasb",
                "rdtsc", "queryperformancecounter", "timing", "gettickcount",
                "closehandle invalid", "int 2d", "seh", "veh", "exception handler",
                "unhandledexceptionfilter", "outputdebugstring",
                "findwindow", "enumwindows", "debugger window",
                "parent process", "createtoolhelp32snapshot", "sedebugprivilege",
                "createthread", "tls callback", ".tls",
                "反调试", "调试检测", "检测调试器"),
        "title": "Anti-debug / anti-analysis detection",
        "tools": "binary_find -> imports + IDA xrefs -> binary_hexdump around check offsets",
        "next": "Catalog all checks. Classify each gate (PEB, HW BP, INT3 scan, timing, exception, window, parent process, privilege, thread, TLS). Map dependencies — some checks protect others via integrity guards. Patch decision branches in dependency order.",
        "child": "Child catalogs anti-debug check sites and maps one detection chain.",
    },
    {
        "keys": ("anti-vm", "virtual machine", "vmware", "virtualbox", "vbox", "qemu",
                "hyper-v", "parallels", "xen", "cpuid", "sidt", "sgdt", "sldt",
                "red pill", "mac address", "mac oui", "00:0c:29", "00:50:56",
                "wmi", "win32_computersystem", "acpi", "io port", "vmtoolsd",
                "vboxservice", "regopenkey", "虚拟机", "反虚拟机"),
        "title": "Anti-VM / sandbox detection",
        "tools": "binary_find for VM strings -> IDA xrefs -> classify detection type (registry/process/CPUID/MAC/WMI/filesystem)",
        "next": "For each VM check, NOP the conditional branch after detection. If checks are chained, find the earliest exit and patch there first to bypass all downstream checks at once.",
        "child": "Child catalogs VM detection sites and maps the detection chain.",
    },
    {
        "keys": ("self-modifying", "smc", "virtualprotect", "virtualalloc", "flushinstructioncache",
                "execute_readwrite", "decrypt code", "decrypt .text", "writable code",
                "自修改", "代码解密"),
        "title": "Self-modifying code (SMC)",
        "tools": "binary_inspect -> IDA xrefs to VirtualProtect/VirtualAlloc -> identify decrypt loop",
        "next": "Break on VirtualProtect targeting code regions. Trace write/decrypt loop. For XOR-SMC: extract key, decode in scratch. For nested SMC: repeat per layer. Dump post-decrypt code and re-run analysis. If execution not allowed: reconstruct decrypt algorithm statically.",
        "child": "Child traces one SMC decrypt layer.",
    },
    {
        "keys": ("api hash", "api hashing", "hash resolve", "peb walk", "export table walk",
                "ror13", "crc32 api", "fnv-1a", "djb2", "getprocaddress loop",
                "loadlibrary getprocaddress", "dynamic import", "no imports",
                "fs:[0x30]", "gs:[0x60]", "inmemoryordermodulelist",
                "hash 解析", "动态导入", "API哈希"),
        "title": "API hashing / dynamic import resolution",
        "tools": "binary_find for hash constants -> IDA for PEB walk + export-table parse -> reconstruct hash function in scratch",
        "next": "Extract target hash constants. Reverse the hash function. Precompute hashes for all DLL exports and match to found constants. Label resolved APIs. Use ida_deobfuscate API-role labels to propagate resolved names.",
        "child": "Child reconstructs hash function and builds lookup table for one DLL.",
    },
    {
        "keys": ("custom packer", "tail jump", "oep", "original entry point", "stolen bytes",
                "import rebuild", "iat rebuild", "non-upx", "packed not upx",
                ".vmp0", ".vmp1", ".themida", ".enigma1", ".enigma2",
                "iat encryption", "process hollowing", "runpe", "createsuspended",
                "ntunmapviewofsection", "resumethread",
                "resource encrypt", "findresource", "lockresource",
                "延迟导入", "delayed import", "自定义壳"),
        "title": "Custom packer / advanced packing",
        "tools": "binary_inspect -> identify packer family by section names/.tls/entropy -> locate OEP via tail jump or stack pivot",
        "next": "Find the OEP (look for tail jump/stack pivot at end of unpacking stub). Dump process at OEP. Rebuild imports (identify IAT region, match addresses to DLL exports). Handle stolen bytes (OEP corruption). Fix PE entry point and sections. Verify unpacked binary with new binary_inspect + ida_analyze.",
        "child": "Child handles one stage: OEP finding, dump, import rebuild, or stolen bytes.",
    },
    {
        "keys": ("integrity guard", "code checksum", "crc .text", "checksum guard",
                "patch protection", "patch detected", "anti-tamper",
                "完整性保护", "校验和", "防篡改"),
        "title": "Integrity guard / anti-tamper checksum",
        "tools": "IDA for checksum/hash loops over code regions -> binary_find for checksum constants -> identify comparison branch",
        "next": "Determine protected region (start/end addresses). Determine checksum algorithm. Handle the guard BEFORE patching validation logic: patch comparison to always match, or recompute checksum after patches. For nested guards, solve outermost first. Do not patch validation branches until integrity checks are understood.",
        "child": "Child maps one integrity check routine (algorithm, protected range, comparison site).",
    },
    {
        "keys": ("indirect call", "call [reg", "jmp [reg", "call dword ptr", "call table",
                "dynamic dispatch", "iat-like table", "obfuscated call",
                "间接调用"),
        "title": "Indirect call / call-table obfuscation",
        "tools": "IDA disasm around indirect call sites -> trace reg value source -> hexdump call table region",
        "next": "Identify the dispatch table. Trace how table entries are populated (runtime fill, static array, encrypted). Map resolved call targets by function role. If runtime-filled: break after fill loop and dump resolved table addresses.",
        "child": "Child maps one call-table cluster or resolves indirect targets.",
    },
    {
        "keys": ("mba", "mixed boolean arithmetic", "instruction substitution", "obfuscated math",
                "complex expression", "constant unfolding", "anti-constant-folding",
                "obfuscated arithmetic", "xor换成", "指令替换", "混淆表达式"),
        "title": "MBA / instruction substitution / constant unfolding",
        "tools": "IDA pseudocode review -> identify seed constants in .data -> flag as obfuscated",
        "next": "Flag the function as MBA-obfuscated. Do not manually decompile every expression. Identify pattern families (XOR-from-AND-OR, multiply-from-shift-add). If expression blocks solver: escalate to symbolic simplification (Z3, Triton). Identify seed constants and their derivations. For constant unfolding: find XOR key or volatile barriers.",
        "child": "Child simplifies one expression cluster or reverses one constant unfolding mechanism.",
    },
]


class ReverseTechniqueMapTool(Tool):
    name = "reverse_technique_map"
    description = (
        "Recommend reverse-engineering techniques and tools from observed signals. "
        "Use as a routing map before spending context on large IDA/function details."
    )
    parameters = {
        "type": "object",
        "properties": {
            "signals": {
                "type": "array",
                "description": "Observed signals, symptoms, imports, section clues, or blockers.",
                "items": {"type": "string"},
            },
            "goal": {
                "type": "string",
                "description": "Current objective, e.g. recover strings, map IOCTLs, deobfuscate giant function, build solver.",
            },
            "max_routes": {
                "type": "integer",
                "description": "Maximum recommended routes. Default 5.",
            },
        },
        "required": [],
    }

    def execute(
        self,
        signals: list[str] | None = None,
        goal: str = "",
        max_routes: int = 5,
        **kwargs,
    ) -> ToolResult:
        signals = coerce_str_list(signals)
        text = " ".join([goal or ""] + signals).lower()
        max_routes = coerce_int(max_routes, 5, minimum=1, maximum=len(ROUTES))
        scored = []
        for route in ROUTES:
            score = 0
            for key in route["keys"]:
                if key.lower() in text:
                    score += 1
            if score:
                scored.append((score, route))
        if not scored:
            scored = [(0, route) for route in ROUTES[:max_routes]]
        scored.sort(key=lambda x: x[0], reverse=True)

        lines = [
            "# Reverse Technique Map",
            "",
            f"Goal: {goal or '(not specified)'}",
            f"Signals: {', '.join(signals or []) if signals else '(none)'}",
            "",
            "## Recommended Routes",
        ]
        selected = []
        for score, route in scored[:max_routes]:
            selected.append(route["title"])
            lines.extend([
                f"### {route['title']}",
                f"- Match score: {score}",
                f"- Tools: {route['tools']}",
                f"- Next: {route['next']}",
                f"- Child strategy: {route['child']}",
            ])
        lines.extend([
            "",
            "## Main-Window Rule",
            "- Keep only decisions, evidence, child summaries, and record paths in the main context.",
            "- Put long IDA output, pseudocode, block dumps, and function details in child records or JSON files.",
        ])
        return ToolResult(
            content="\n".join(lines),
            metadata={"recommended": selected, "signals": signals or [], "goal": goal},
        )
