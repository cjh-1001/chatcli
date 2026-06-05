"""Build a defensive attack-chain draft from static capability candidates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ._json_utils import load_json
from ._text_utils import short_text
from .base import Tool, ToolResult, coerce_int, coerce_str_list

STAGE_ORDER = {
    "initial_access_artifact": (10, "入口投递/初始执行"),
    "loader_staging": (20, "加载/解包/多阶段执行"),
    "command_execution": (25, "命令执行"),
    "lotl_abuse": (27, "系统工具滥用"),
    "api_hashing_obfuscation": (28, "导入隐藏/解析"),
    "dll_sideload_hijack": (29, "DLL 侧载/搜索劫持"),
    "process_injection": (32, "进程注入/进程内执行"),
    "defense_evasion": (30, "反分析/防御规避"),
    "security_tool_tampering": (35, "安全工具对抗"),
    "persistence": (40, "持久化"),
    "privilege_escalation": (50, "提权/权限操纵"),
    "rootkit_driver": (55, "驱动/rootkit"),
    "bootkit_uefi": (56, "启动链/Bootkit/UEFI"),
    "discovery": (60, "主机/网络发现"),
    "ad_discovery": (65, "AD/域环境发现"),
    "credential_access": (70, "凭据访问"),
    "browser_cloud_credentials": (72, "浏览器/云凭据访问"),
    "keylogging_capture": (74, "键盘/屏幕/剪贴板捕获"),
    "wallet_clipboard_hijack": (76, "钱包/剪贴板劫持"),
    "collection": (80, "信息/文件收集"),
    "cloud_container": (85, "云/容器环境访问"),
    "mobile_iot": (88, "移动/IoT 平台行为"),
    "c2_network": (90, "C2/网络通信"),
    "c2_variants": (92, "C2 变种/隐蔽通道"),
    "rat_backdoor_control": (94, "RAT/后门命令控制"),
    "lateral_movement": (100, "横向移动"),
    "worm_propagation": (105, "蠕虫/自传播"),
    "exfiltration": (110, "数据外传"),
    "ddos_bot_proxy": (112, "Botnet/DDoS/代理滥用"),
    "miner": (114, "资源滥用/挖矿"),
    "file_infector": (116, "文件感染/病毒式修改"),
    "supply_chain_update_abuse": (118, "供应链/更新通道滥用"),
    "ransomware_anti_recovery": (119, "勒索/反恢复"),
    "impact": (120, "影响/破坏"),
}

IMPACT_HINTS = {
    "initial_access_artifact": "可能说明样本入口或投递载体；需确认真实启动路径。",
    "loader_staging": "可能说明样本存在解包、解密或多阶段载荷加载。",
    "command_execution": "可能支持本地命令、脚本或子进程执行。",
    "lotl_abuse": "可能滥用系统自带工具完成下载、执行、注册或横向动作，增加检测难度。",
    "api_hashing_obfuscation": "可能隐藏真实导入，降低静态 API 视图完整性。",
    "dll_sideload_hijack": "可能借合法宿主加载恶意 DLL，影响溯源和信任边界判断。",
    "process_injection": "可能将代码放入其他进程上下文运行，影响检测和溯源可见性。",
    "defense_evasion": "可能降低分析和检测可见性。",
    "security_tool_tampering": "可能削弱终端防护、日志和响应能力。",
    "persistence": "可能支持重启后继续驻留。",
    "privilege_escalation": "可能扩大执行权限和后续行为影响面。",
    "rootkit_driver": "可能涉及内核级持久化、隐藏或安全工具对抗风险。",
    "bootkit_uefi": "可能影响启动链或固件/引导配置，增加恢复和取证复杂度。",
    "discovery": "可能为后续 C2、横向移动或数据收集选择目标。",
    "ad_discovery": "可能用于域内目标定位、权限路径分析或横向移动准备。",
    "credential_access": "可能导致账号、密钥或会话材料泄露。",
    "browser_cloud_credentials": "可能导致浏览器会话、云账号或容器环境凭据泄露。",
    "keylogging_capture": "可能捕获键盘、屏幕、剪贴板或窗口内容，造成隐私和凭据泄露。",
    "wallet_clipboard_hijack": "可能窃取或替换钱包/剪贴板内容，造成资产转移风险。",
    "collection": "可能导致本机文件、屏幕、剪贴板或敏感信息被收集。",
    "cloud_container": "可能扩大到云资源、容器集群或 CI/CD 环境。",
    "mobile_iot": "可能影响移动设备、IoT 设备或嵌入式网络环境。",
    "c2_network": "可能支持远程指令、数据交换或后续载荷控制。",
    "c2_variants": "可能使用隐蔽或第三方平台通道维持通信。",
    "rat_backdoor_control": "可能支持远程命令调度、插件执行、文件/进程/屏幕操作等后门能力。",
    "lateral_movement": "可能扩散到内网其他主机或服务。",
    "worm_propagation": "可能自传播到可达主机、共享目录、移动介质或联系人。",
    "exfiltration": "可能导致收集数据离开受害环境。",
    "ddos_bot_proxy": "可能将主机用于 DDoS、代理、垃圾邮件或其他第三方滥用。",
    "miner": "可能消耗 CPU/GPU/云资源并造成性能、成本和稳定性影响。",
    "file_infector": "可能修改可执行文件，造成扩散、破坏和清理复杂度上升。",
    "supply_chain_update_abuse": "可能借受信更新、插件或包管理路径传播或加载载荷。",
    "ransomware_anti_recovery": "可能加密文件或破坏恢复能力，造成可用性和恢复成本风险。",
    "impact": "可能造成数据破坏、加密勒索、恢复能力下降或可用性损失。",
}




def _find_capabilities(value: Any, out: list[dict[str, Any]]) -> None:
    if isinstance(value, dict):
        caps = value.get("capabilities")
        if isinstance(caps, list):
            for item in caps:
                if isinstance(item, dict) and (item.get("category") or item.get("label")):
                    out.append(item)
        hints = value.get("report_hints")
        if isinstance(hints, dict):
            candidates = hints.get("key_capability_candidates")
            if isinstance(candidates, list):
                for item in candidates:
                    if isinstance(item, dict):
                        out.append({
                            "category": "unknown",
                            "label": item.get("category", "能力候选"),
                            "matched_terms": [item.get("technique", "")],
                            "evidence": [item.get("evidence", "")],
                            "confidence": item.get("confidence", "low"),
                            "claim_level": "static capability",
                            "required_validation": ["Validate the supporting code path before using this in conclusions."],
                        })
        for child in value.values():
            _find_capabilities(child, out)
    elif isinstance(value, list):
        for child in value:
            _find_capabilities(child, out)


def _normalize_capability(item: dict[str, Any]) -> dict[str, Any]:
    category = str(item.get("category") or "unknown")
    label = str(item.get("label") or item.get("category") or "能力候选")
    matched_terms = item.get("matched_terms") or item.get("signals") or []
    if isinstance(matched_terms, str):
        matched_terms = [matched_terms]
    evidence = item.get("evidence") or []
    if isinstance(evidence, str):
        evidence = [evidence]
    validation = item.get("required_validation") or item.get("validation") or []
    if isinstance(validation, str):
        validation = [validation]
    claim_gate = item.get("claim_gate") or []
    if isinstance(claim_gate, str):
        claim_gate = [claim_gate]
    confidence = str(item.get("confidence") or "low")
    claim_level = str(item.get("claim_level") or "static capability")
    return {
        "category": category,
        "label": label,
        "matched_terms": [str(x) for x in matched_terms if str(x).strip()],
        "evidence": [str(x) for x in evidence if str(x).strip()],
        "required_validation": [str(x) for x in validation if str(x).strip()],
        "claim_gate": [str(x) for x in claim_gate if str(x).strip()],
        "confidence": confidence,
        "claim_level": claim_level,
    }


def _rank_confidence(value: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(value.lower(), 0)


def _downgrade_confidence(value: str) -> str:
    value = value.lower()
    if value == "high":
        return "medium"
    if value == "medium":
        return "low"
    return value


def _merge_step_group(group: list[dict[str, Any]]) -> dict[str, Any]:
    first = group[0]
    behaviors = [item["behavior"] for item in group]
    techniques = []
    evidence = []
    gaps = []
    gates = []
    source_categories = []
    confidence = "low"
    claim_level = "hypothesis"
    impact_bits = []
    for item in group:
        source_categories.append(str(item.get("source_category", "")))
        techniques.extend([x.strip() for x in str(item.get("technique", "")).split(",") if x.strip()])
        evidence.extend([line[2:].strip() if line.startswith("- ") else line.strip() for line in str(item.get("evidence", "")).splitlines() if line.strip()])
        gaps.extend([line[2:].strip() if line.startswith("- ") else line.strip() for line in str(item.get("gaps", "")).splitlines() if line.strip()])
        gates.extend(item.get("claim_gate", []) if isinstance(item.get("claim_gate"), list) else [])
        cat = str(item.get("source_category", ""))
        impact_bits.append(IMPACT_HINTS.get(cat, "静态能力候选；影响需结合上下文确认。"))
        if _rank_confidence(item["confidence"]) > _rank_confidence(confidence):
            confidence = item["confidence"]
        if item.get("claim_level") == "static capability":
            claim_level = "static capability"
    seen = set()
    unique_techniques = []
    for term in techniques:
        if term not in seen:
            seen.add(term)
            unique_techniques.append(term)
    seen.clear()
    unique_evidence = []
    for line in evidence:
        if line not in seen:
            seen.add(line)
            unique_evidence.append(line)
    seen.clear()
    unique_gaps = []
    for line in gaps:
        if line not in seen:
            seen.add(line)
            unique_gaps.append(line)
    return {
        "stage_order": first["stage_order"],
        "stage": first["stage"],
        "behavior": " / ".join(behaviors),
        "technique": ", ".join(unique_techniques[:12]) or first["behavior"],
        "evidence": "\n".join(f"- {short_text(ev)}" for ev in unique_evidence[:8]) or "No direct evidence snippet provided.",
        "target": "受害主机/环境",
        "impact": "；".join(dict.fromkeys(impact_bits)),
        "confidence": confidence,
        "claim_level": claim_level,
        "gaps": "\n".join(f"- {short_text(v)}" for v in unique_gaps[:8]),
        "claim_gate": [x for x in dict.fromkeys(gates) if x],
        "gate_status": "needs_validation" if gates else "not_required",
        "source_category": " + ".join(dict.fromkeys(cat for cat in source_categories if cat)),
    }


def _merge_same_stage(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    current_order: int | None = None
    for step in steps:
        if current and step["stage_order"] == current_order:
            current.append(step)
        else:
            if current:
                grouped.append(current)
            current = [step]
            current_order = step["stage_order"]
    if current:
        grouped.append(current)
    return [_merge_step_group(group) for group in grouped]


def _apply_dependency_checks(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    adjusted: list[dict[str, Any]] = []
    for step in steps:
        item = dict(step)
        cat_raw = str(item.get("source_category", ""))
        cats = {part.strip() for part in cat_raw.split("+") if part.strip()}
        gaps = item.get("gaps", "")
        gap_lines = [line for line in gaps.splitlines() if line.strip()]
        if "exfiltration" in cats and not ({"collection", "c2_network", "c2_variants"} & seen):
            gap_lines.append("- Dependency gap: exfiltration appears without prior collection or network channel evidence.")
            item["confidence"] = _downgrade_confidence(item["confidence"])
        if "lateral_movement" in cats and not ({"credential_access", "browser_cloud_credentials", "discovery", "ad_discovery"} & seen):
            gap_lines.append("- Dependency gap: lateral movement appears without prior discovery or credential access evidence.")
            item["confidence"] = _downgrade_confidence(item["confidence"])
        if "c2_variants" in cats and not ({"c2_network", "c2_variants"} & seen):
            gap_lines.append("- Dependency gap: alternate C2 channel appears without standard C2 evidence.")
            item["confidence"] = _downgrade_confidence(item["confidence"])
        if "rat_backdoor_control" in cats and not ({"c2_network", "c2_variants"} & seen):
            gap_lines.append("- Dependency gap: RAT/backdoor command handling appears without prior C2 or IPC channel evidence.")
            item["confidence"] = _downgrade_confidence(item["confidence"])
        if "ddos_bot_proxy" in cats and not ({"c2_network", "c2_variants", "rat_backdoor_control"} & seen):
            gap_lines.append("- Dependency gap: bot/proxy/DDoS abuse appears without command channel or configuration evidence.")
            item["confidence"] = _downgrade_confidence(item["confidence"])
        if "miner" in cats:
            terms = str(item.get("technique", "")).lower()
            if not ("stratum" in terms and ("wallet" in terms or "worker" in terms or "pool" in terms)):
                gap_lines.append("- Dependency gap: miner clue appears without a complete pool plus wallet/worker configuration.")
                item["confidence"] = _downgrade_confidence(item["confidence"])
        if "worm_propagation" in cats and not ({"discovery", "ad_discovery", "lateral_movement", "credential_access"} & seen):
            gap_lines.append("- Dependency gap: propagation appears without prior target discovery, credential, or remote access evidence.")
            item["confidence"] = _downgrade_confidence(item["confidence"])
        if "wallet_clipboard_hijack" in cats and not ({"keylogging_capture", "collection", "credential_access", "browser_cloud_credentials"} & seen):
            gap_lines.append("- Dependency gap: wallet/clipboard hijack clue appears without prior capture, collection, or credential-access evidence.")
            item["confidence"] = _downgrade_confidence(item["confidence"])
        if "supply_chain_update_abuse" in cats and not ({"initial_access_artifact", "loader_staging", "dll_sideload_hijack"} & seen):
            gap_lines.append("- Dependency gap: supply-chain/update abuse appears without an update/plugin loading path or payload boundary.")
            item["confidence"] = _downgrade_confidence(item["confidence"])
        item["gaps"] = "\n".join(gap_lines)
        if item.get("claim_gate"):
            item["gate_status"] = "needs_validation"
        seen.update(cats)
        adjusted.append(item)
    return adjusted


def _build_steps(capabilities: list[dict[str, Any]], max_steps: int) -> list[dict[str, Any]]:
    normalized = [_normalize_capability(item) for item in capabilities]
    normalized.sort(key=lambda item: STAGE_ORDER.get(item["category"], (999, ""))[0])
    steps = []
    for item in normalized[:max_steps]:
        order, stage = STAGE_ORDER.get(item["category"], (999, "未归类能力"))
        terms = ", ".join(item["matched_terms"][:8]) or item["label"]
        evidence = "\n".join(f"- {short_text(ev)}" for ev in item["evidence"][:6]) or "No direct evidence snippet provided."
        gaps = "\n".join(f"- {short_text(v)}" for v in item["required_validation"][:5])
        claim_gate = [f"Claim gate: {short_text(v)}" for v in item.get("claim_gate", [])[:5]]
        if claim_gate:
            gaps = "\n".join([part for part in [gaps, *[f"- {gate}" for gate in claim_gate]] if part])
        steps.append({
            "step": len(steps) + 1,
            "stage_order": order,
            "stage": stage,
            "behavior": item["label"],
            "technique": terms,
            "evidence": evidence,
            "target": "受害主机/环境",
            "impact": IMPACT_HINTS.get(item["category"], "静态能力候选；影响需结合上下文确认。"),
            "confidence": item["confidence"],
            "claim_level": item["claim_level"],
            "gaps": gaps,
            "claim_gate": item.get("claim_gate", []),
            "gate_status": "needs_validation" if item.get("claim_gate") else "not_required",
            "source_category": item["category"],
        })
    steps.sort(key=lambda item: item["stage_order"])
    steps = _merge_same_stage(steps)
    steps = _apply_dependency_checks(steps)
    for idx, step in enumerate(steps, 1):
        step["step"] = idx
    return steps


class AttackChainBuilderTool(Tool):
    name = "attack_chain_builder"
    description = (
        "Build an ordered defensive attack-chain draft from behavior capability "
        "candidates. Does not execute samples. Produces report-ready steps with "
        "evidence, confidence, claim level, impact, and validation gaps."
    )
    parameters = {
        "type": "object",
        "properties": {
            "capabilities": {
                "type": "array",
                "description": "Capability candidate objects, usually from behavior_capability_map metadata.",
                "items": {"type": "object"},
            },
            "json_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional JSON files to mine for capability candidates.",
            },
            "max_steps": {
                "type": "integer",
                "description": "Maximum chain steps to return. Default 20.",
            },
        },
    }

    def execute(
        self,
        capabilities: list[dict[str, Any]] | None = None,
        json_paths: list[str] | str | None = None,
        max_steps: int = 20,
        **kwargs,
    ) -> ToolResult:
        max_steps = coerce_int(max_steps, 20, minimum=1, maximum=80)
        collected = [item for item in (capabilities or []) if isinstance(item, dict)]
        warnings = []

        for raw_path in coerce_str_list(json_paths):
            data, error = load_json(Path(raw_path), label="attack chain")
            if error:
                warnings.append(error)
                continue
            _find_capabilities(data, collected)

        if not collected:
            return ToolResult(
                content="Error: provide capabilities or json_paths containing capability candidates.",
                is_error=True,
                metadata={"warnings": warnings},
            )

        steps = _build_steps(collected, max_steps)
        lines = [
            "# Attack Chain Draft",
            "",
            f"Capabilities scanned: {len(collected)}",
            f"Steps returned: {len(steps)}",
        ]
        if warnings:
            lines.extend(["", "## Warnings"])
            lines.extend(f"- {warning}" for warning in warnings)
        lines.extend(["", "## Ordered Steps"])
        for step in steps:
            lines.extend([
                "",
                f"### {step['step']}. {step['stage']} - {step['behavior']}",
                f"- Source category: {step['source_category']}",
                f"- Technique/signals: {step['technique']}",
                f"- Confidence: {step['confidence']}",
                f"- Claim level: {step['claim_level']}",
                f"- Gate status: {step.get('gate_status', 'not_required')}",
                f"- Expected impact: {step['impact']}",
                "- Evidence:",
                step["evidence"],
            ])
            if step["gaps"]:
                lines.extend(["- Required validation:", step["gaps"]])

        report_chain = [
            {
                "step": step["step"],
                "behavior": f"{step['stage']} - {step['behavior']}",
                "technique": step["technique"],
                "evidence": step["evidence"],
                "target": step["target"],
                "impact": step["impact"],
                "confidence": step["confidence"],
                "gate_status": step.get("gate_status", "not_required"),
                "gaps": step["gaps"],
            }
            for step in steps
        ]

        return ToolResult(
            content="\n".join(lines),
            metadata={
                "warnings": warnings,
                "capabilities_scanned": len(collected),
                "steps": steps,
                "report_hints": {
                    "attack_chain": report_chain,
                },
            },
        )
