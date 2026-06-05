"""Hierarchical planning and conservative noise reduction for behavior candidates."""

from __future__ import annotations

from typing import Any

from .behavior_confidence import downgrade_confidence, has_shared_evidence, rank_confidence


BEHAVIOR_FAMILIES: dict[str, dict[str, Any]] = {
    "entry_execution": {
        "label": "入口/执行/载荷链",
        "description": "先确认样本如何进入、落地、下载、释放或启动后续载荷。",
        "validation": [
            "Identify the initial artifact, command line, child process, dropped file, or execution transfer.",
            "Separate delivery, download, dropper, loader, and command execution before drawing a chain conclusion.",
        ],
        "categories": {
            "initial_access_artifact", "silent_downloader", "payload_dropper",
            "loader_staging", "command_execution", "lotl_abuse",
            "api_hashing_obfuscation", "dll_sideload_hijack",
            "supply_chain_update_abuse",
        },
    },
    "evasion_injection": {
        "label": "规避/注入/内核对抗",
        "description": "先判断是否在降低分析、检测、进程归因或内核可见性。",
        "validation": [
            "Confirm the anti-analysis check, telemetry bypass, injection sequence, masquerade, driver, or boot artifact.",
            "Treat isolated imports or environment strings as leads until a reachable behavior-changing branch is found.",
        ],
        "categories": {
            "process_injection", "process_masquerading", "defense_evasion",
            "anti_debug", "anti_vm_sandbox", "execution_delay",
            "telemetry_bypass", "security_tool_tampering",
            "rootkit_driver", "byovd_abuse", "bootkit_uefi",
            "file_infector",
        },
    },
    "persistence_privilege": {
        "label": "持久化/提权/驻留",
        "description": "先确认重启、登录、事件触发、账户、服务或权限提升路径。",
        "validation": [
            "Identify the exact autostart location, service/task/account/extension artifact, or privilege trigger.",
            "Confirm the payload path and creation or modification action before calling persistence or elevation confirmed.",
        ],
        "categories": {
            "persistence", "scheduled_task_persistence", "startup_folder_persistence",
            "service_persistence", "wmi_persistence",
            "registry_autostart_extension_persistence", "ifeo_debugger_persistence",
            "accessibility_hijack_persistence", "bits_jobs_persistence",
            "account_persistence", "privilege_escalation", "uac_bypass",
            "browser_extension_toolbar",
        },
    },
    "discovery_lateral": {
        "label": "发现/横向/传播",
        "description": "先确认主机、域、网络、共享目录或远程目标选择逻辑。",
        "validation": [
            "Tie discovery output to later credential use, remote execution, copy/drop, or propagation behavior.",
            "Do not infer lateral movement from network or share strings without target selection and execution evidence.",
        ],
        "categories": {
            "discovery", "ad_discovery", "lateral_movement", "worm_propagation",
        },
    },
    "credential_collection": {
        "label": "凭据/采集/隐私窃取",
        "description": "先确认被访问的数据源，再验证解析、暂存、捕获或外传路径。",
        "validation": [
            "Identify the credential store, browser/session artifact, capture API, local file set, or staged archive.",
            "Require parsing, decryption, staging, or transmission evidence before confirmed theft conclusions.",
        ],
        "categories": {
            "credential_access", "banking_credential_theft", "lsass_dumping",
            "silent_process_exit_dump", "ssp_credential_capture",
            "registry_credential_dumping", "ntds_dumping", "dcsync_replication",
            "kerberos_ticket_access", "dpapi_credential_access",
            "ssh_private_key_access", "unix_shadow_access",
            "browser_cloud_credentials", "keylogging_capture",
            "wallet_clipboard_hijack", "collection", "archive_staging",
            "adware_browser_manipulation", "user_deception_fraud",
            "cloud_container", "mobile_iot",
        },
    },
    "command_control_exfil": {
        "label": "C2/远控/外传",
        "description": "先确认通信或本地控制通道，再验证命令调度、协议字段和数据流向。",
        "validation": [
            "Identify endpoint, transport, identity/config fields, command parser, IPC channel, or upload destination.",
            "Keep C2 and exfiltration separate unless collected data is tied to a send/upload path.",
        ],
        "categories": {
            "c2_network", "c2_config_protocol", "named_pipe_ipc",
            "c2_variants", "remote_access_tool_abuse",
            "rat_backdoor_control", "exfiltration",
        },
    },
    "impact_abuse": {
        "label": "影响/资源滥用",
        "description": "先确认加密、破坏、反恢复、挖矿、DDoS、代理或垃圾流量模块。",
        "validation": [
            "Identify the destructive, resource-use, proxy, DDoS, spam, or anti-recovery code path.",
            "Require target selection, command/config, or file/volume modification evidence before impact conclusions.",
        ],
        "categories": {
            "ddos_bot_proxy", "miner", "ransomware_anti_recovery", "impact",
        },
    },
}

CATEGORY_TO_FAMILY = {
    category: family
    for family, data in BEHAVIOR_FAMILIES.items()
    for category in data["categories"]
}

GENERAL_FAMILY_CATEGORIES = {
    "persistence",
    "defense_evasion",
    "credential_access",
    "collection",
    "impact",
}


def _family_specifics(category: str, family: str) -> list[str]:
    categories = sorted(BEHAVIOR_FAMILIES.get(family, {}).get("categories", set()))
    return [item for item in categories if item != category]


def annotate_hierarchy(capabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for item in capabilities:
        category = str(item.get("category") or "")
        family = CATEGORY_TO_FAMILY.get(category, "uncategorized")
        data = BEHAVIOR_FAMILIES.get(family, {})
        item["analysis_family"] = family
        item["family_label"] = str(data.get("label") or "未归类")
        item["family_description"] = str(data.get("description") or "No hierarchy family is configured for this category.")
        item["family_validation"] = [str(x) for x in data.get("validation", [])]
        item["refinement_candidates"] = _family_specifics(category, family)[:12]
    return capabilities


def apply_family_noise_reduction(capabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_category = {str(item.get("category") or ""): item for item in capabilities}
    for category in GENERAL_FAMILY_CATEGORIES:
        general = by_category.get(category)
        if not general:
            continue
        family = CATEGORY_TO_FAMILY.get(category)
        if not family:
            continue
        suppressors = []
        for other_category in BEHAVIOR_FAMILIES[family]["categories"]:
            if other_category == category:
                continue
            specific = by_category.get(other_category)
            if not specific:
                continue
            if rank_confidence(str(specific.get("confidence") or "")) < rank_confidence("medium"):
                continue
            if has_shared_evidence(general, specific):
                suppressors.append(other_category)
        if not suppressors:
            continue
        general["family_suppressed_by"] = sorted(suppressors)
        overlap_suppressors = set(general.get("overlap_suppressed_by") or [])
        if set(suppressors) <= overlap_suppressors:
            continue

        old_confidence = str(general.get("confidence") or "low")
        new_confidence = downgrade_confidence(old_confidence)
        general["confidence"] = new_confidence
        reason = (
            f"downgraded because more specific categories in the same family matched shared evidence: "
            f"{', '.join(sorted(suppressors))}"
        )
        general["noise_reduction_reason"] = reason
        general["confidence_reason"] = (str(general.get("confidence_reason") or "") + "; " + reason).strip("; ")
        validation = list(general.get("required_validation") or [])
        validation.append(
            "Hierarchy note: start from the family-level hypothesis, then prefer the more specific matched category for conclusions."
        )
        general["required_validation"] = validation
        if new_confidence == "low":
            general["claim_level"] = "hypothesis"
    return capabilities


def build_family_plan(capabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in capabilities:
        grouped.setdefault(str(item.get("analysis_family") or "uncategorized"), []).append(item)

    plan = []
    for family, items in grouped.items():
        data = BEHAVIOR_FAMILIES.get(family, {})
        plan.append({
            "family": family,
            "label": str(data.get("label") or "未归类"),
            "description": str(data.get("description") or ""),
            "validation": [str(x) for x in data.get("validation", [])],
            "matched_categories": [str(item.get("category") or "") for item in items],
            "top_labels": [str(item.get("label") or item.get("category") or "") for item in items[:6]],
        })
    plan.sort(key=lambda item: item["family"])
    return plan
