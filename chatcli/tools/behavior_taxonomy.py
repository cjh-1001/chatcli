"""Taxonomy helpers for behavior capability post-processing."""

from __future__ import annotations

from typing import Any

from .behavior_confidence import downgrade_confidence, has_shared_evidence, rank_confidence


SPECIFIC_CATEGORY_OVERRIDES = {
    "persistence": {
        "service_persistence",
        "scheduled_task_persistence",
        "wmi_persistence",
        "startup_folder_persistence",
        "account_persistence",
        "accessibility_hijack_persistence",
        "registry_autostart_extension_persistence",
        "ifeo_debugger_persistence",
        "bits_jobs_persistence",
        "browser_extension_toolbar",
    },
    "defense_evasion": {
        "anti_debug",
        "anti_vm_sandbox",
        "execution_delay",
        "telemetry_bypass",
        "process_masquerading",
    },
    "credential_access": {
        "banking_credential_theft",
        "lsass_dumping",
        "silent_process_exit_dump",
        "ssp_credential_capture",
        "registry_credential_dumping",
        "ntds_dumping",
        "dcsync_replication",
        "kerberos_ticket_access",
        "dpapi_credential_access",
        "ssh_private_key_access",
        "unix_shadow_access",
        "browser_cloud_credentials",
    },
    "collection": {
        "archive_staging",
        "keylogging_capture",
        "wallet_clipboard_hijack",
        "adware_browser_manipulation",
        "browser_extension_toolbar",
        "user_deception_fraud",
    },
    "c2_network": {
        "c2_config_protocol",
        "named_pipe_ipc",
        "remote_access_tool_abuse",
    },
}


def apply_overlap_suppression(capabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_category = {str(item.get("category") or ""): item for item in capabilities}
    for general, specifics in SPECIFIC_CATEGORY_OVERRIDES.items():
        general_item = by_category.get(general)
        if not general_item:
            continue
        suppressors = []
        for specific in specifics:
            specific_item = by_category.get(specific)
            if not specific_item:
                continue
            if rank_confidence(str(specific_item.get("confidence") or "")) < rank_confidence("medium"):
                continue
            if has_shared_evidence(general_item, specific_item):
                suppressors.append(specific)
        if not suppressors:
            continue
        old_confidence = str(general_item.get("confidence") or "low")
        new_confidence = downgrade_confidence(old_confidence)
        general_item["confidence"] = new_confidence
        general_item["overlap_suppressed_by"] = sorted(suppressors)
        general_item["confidence_reason"] = (
            str(general_item.get("confidence_reason") or "")
            + "; downgraded because more specific behavior category matched shared evidence: "
            + ", ".join(sorted(suppressors))
        ).strip("; ")
        validation = list(general_item.get("required_validation") or [])
        validation.append(
            "Overlap note: prefer the more specific matched behavior category for reporting conclusions."
        )
        general_item["required_validation"] = validation
    return capabilities
