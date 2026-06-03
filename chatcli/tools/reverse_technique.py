"""Technique routing helper for reverse-engineering workflows."""

from .base import Tool, ToolResult


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
        "keys": ("sparse strings", "少字符串", "encrypted strings", "runtime string", "字符串加密"),
        "title": "Encrypted or runtime-only strings",
        "tools": "encoded_string_extract -> obfuscated_data_map -> runtime_string_hooks",
        "next": "Find decrypt routine/API, dump return values and output buffers, then extract strings from dump.",
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
        "keys": ("opaque", "不透明谓词", "恒真", "恒假", "junk", "花指令", "jmp $+5"),
        "title": "Opaque predicates or junk instructions",
        "tools": "ida_deobfuscate(patch_database=false first; true only after evidence)",
        "next": "Report high-confidence branches/junk; patch only IDA database and compare CFG.",
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
        text = " ".join([goal or ""] + [str(s) for s in (signals or [])]).lower()
        max_routes = max(1, min(int(max_routes or 5), len(ROUTES)))
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
