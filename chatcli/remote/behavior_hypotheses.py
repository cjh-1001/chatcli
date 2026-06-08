"""Rule-based static behavior hypotheses for remote malware analysis."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class BehaviorRule:
    rule_id: str
    analysis_family: str
    behavior: str
    match_any: tuple[str, ...]
    evidence_terms: tuple[str, ...]
    targets: dict[str, Any] | Callable[[str], dict[str, Any]]
    min_matches: int = 1


def read_text_file(path: Path, limit: int = 500_000) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")[:limit]


def matching_lines(text: str, terms: list[str] | tuple[str, ...], limit: int = 8) -> list[str]:
    lowered = [term.lower() for term in terms if term]
    lines: list[str] = []
    for line in text.splitlines():
        low = line.lower()
        if lowered and not any(term in low for term in lowered):
            continue
        clean = line.strip()
        if clean and clean not in lines:
            lines.append(clean[:500])
        if len(lines) >= limit:
            break
    return lines


def extract_urls(text: str, limit: int = 20) -> list[str]:
    urls: list[str] = []
    for match in re.findall(r"https?://[^\s\"'<>]+", text, flags=re.IGNORECASE):
        value = match.rstrip(").,;]")
        if value not in urls:
            urls.append(value)
        if len(urls) >= limit:
            break
    return urls


def extract_ips(text: str, limit: int = 20) -> list[str]:
    ips: list[str] = []
    for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        parts = [int(part) for part in match.split(".") if part.isdigit()]
        if len(parts) != 4 or any(part > 255 for part in parts):
            continue
        if match not in ips:
            ips.append(match)
        if len(ips) >= limit:
            break
    return ips


def extract_domains(text: str, limit: int = 20) -> list[str]:
    allowed_tlds = {
        "com", "net", "org", "cn", "io", "co", "info", "biz", "top", "xyz",
        "dev", "app", "ru", "hk", "tw", "cc", "me", "site", "online", "shop",
    }
    noise_domains = {"godebugs.info", "eq.io"}
    domains: list[str] = []
    for match in re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text):
        low = match.lower().strip(".")
        if low in noise_domains:
            continue
        tld = low.rsplit(".", 1)[-1]
        if tld not in allowed_tlds:
            continue
        if low.endswith((".dll", ".exe", ".pdb", ".local")):
            continue
        if low not in domains:
            domains.append(low)
        if len(domains) >= limit:
            break
    return domains


def merge_list(target: dict[str, Any], key: str, values: list[str]) -> None:
    existing = [str(item) for item in target.get(key, []) if str(item)]
    for value in values:
        if value and value not in existing:
            existing.append(value)
    if existing:
        target[key] = existing


def merge_network_indicators(targets: dict[str, Any], indicators: dict[str, list[str]]) -> None:
    current = targets.get("network_indicators")
    if not isinstance(current, dict):
        current = {}
    for key, values in indicators.items():
        merge_list(current, key, values)
    if current:
        targets["network_indicators"] = current


def merge_validation_targets(targets: dict[str, Any], new_targets: dict[str, Any]) -> dict[str, Any]:
    merged = dict(targets or {})
    for key, values in (new_targets or {}).items():
        if key == "network_indicators" and isinstance(values, dict):
            merge_network_indicators(merged, values)
        elif isinstance(values, list):
            merge_list(merged, key, [str(item) for item in values])
        elif values:
            merge_list(merged, key, [str(values)])
    return merged


def merge_dynamic_config(base: dict[str, Any] | None, derived: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base or {})
    merged_targets = merge_validation_targets(
        dict(merged.get("validation_targets") or {}),
        dict(derived.get("validation_targets") or {}),
    )
    if merged_targets:
        merged["validation_targets"] = merged_targets
    if derived.get("static_hypotheses"):
        merged["static_hypotheses"] = derived["static_hypotheses"]
    return merged


def _scheduled_task_targets(text: str) -> dict[str, Any]:
    task_names = [
        (double_quoted or single_quoted or bare).strip()
        for double_quoted, single_quoted, bare in re.findall(
            r"(?:/tn|-tn)\s+(?:\"([^\"]+)\"|'([^']+)'|([^\s\"']+))",
            text,
            flags=re.IGNORECASE,
        )
    ]
    return {
        "watch_processes": ["schtasks.exe"],
        "watch_services_tasks": task_names or ["schtasks"],
        "watch_registry": [
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache",
        ],
    }


def _service_targets(text: str) -> dict[str, Any]:
    service_names = [
        match.strip()
        for match in re.findall(r"\bsc(?:\.exe)?\s+create\s+([^\s\"']+)", text, flags=re.IGNORECASE)
    ]
    service_names.extend(
        match.strip()
        for match in re.findall(r"\bNew-Service\s+-Name\s+([^\s\"']+)", text, flags=re.IGNORECASE)
    )
    return {
        "watch_processes": ["sc.exe", "powershell.exe"],
        "watch_registry": [r"HKLM\System\CurrentControlSet\Services"],
        "watch_services_tasks": service_names or ["services"],
    }


def _startup_folder_targets(_text: str) -> dict[str, Any]:
    return {
        "watch_paths": [
            r"\Microsoft\Windows\Start Menu\Programs\Startup",
            r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
            r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
        ],
    }


def _wmi_targets(_text: str) -> dict[str, Any]:
    return {
        "watch_processes": ["wmic.exe", "powershell.exe"],
        "watch_paths": [r"C:\Windows\System32\wbem"],
        "watch_services_tasks": ["WMI", "Winmgmt"],
    }


def _uac_bypass_targets(_text: str) -> dict[str, Any]:
    return {
        "watch_processes": ["fodhelper.exe", "computerdefaults.exe", "eventvwr.exe", "sdclt.exe"],
        "watch_registry": [
            r"HKCU\Software\Classes\ms-settings\Shell\Open\command",
            r"HKCU\Software\Classes\mscfile\Shell\Open\command",
            r"DelegateExecute",
        ],
    }


def _file_dropper_targets(_text: str) -> dict[str, Any]:
    return {
        "watch_paths": [
            r"%TEMP%",
            r"%APPDATA%",
            r"%PROGRAMDATA%",
            r"C:\Users\Public",
        ],
    }


def _defense_evasion_targets(_text: str) -> dict[str, Any]:
    return {
        "watch_processes": ["powershell.exe", "netsh.exe", "sc.exe", "reg.exe"],
        "watch_registry": [
            r"HKLM\Software\Microsoft\Windows Defender",
            r"HKLM\System\CurrentControlSet\Services\WinDefend",
            r"HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy",
        ],
        "watch_services_tasks": ["WinDefend", "SecurityHealthService", "firewall"],
    }


def _credential_targets(_text: str) -> dict[str, Any]:
    return {
        "watch_processes": ["rundll32.exe", "procdump.exe", "taskmgr.exe"],
        "watch_paths": [r"C:\Windows\Temp", r"C:\Users\Public", r"%TEMP%"],
    }


def _network_targets(text: str) -> dict[str, Any]:
    return {
        "network_indicators": {
            "urls": extract_urls(text),
            "domains": extract_domains(text),
            "ips": extract_ips(text),
        }
    }


BEHAVIOR_RULES: tuple[BehaviorRule, ...] = (
    BehaviorRule(
        rule_id="scheduled_task_persistence",
        analysis_family="persistence_privilege",
        behavior="计划任务持久化",
        match_any=("schtasks", "taskscheduler", "\\taskcache\\"),
        evidence_terms=("schtasks", "/create", "/query", "TaskCache", "SecurityScript"),
        targets=_scheduled_task_targets,
    ),
    BehaviorRule(
        rule_id="run_key_persistence",
        analysis_family="persistence_privilege",
        behavior="Run/RunOnce 注册表自启动",
        match_any=("currentversion\\run", "\\runonce"),
        evidence_terms=("CurrentVersion\\Run", "RunOnce", "RegSetValue"),
        targets={
            "watch_registry": [
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            ],
        },
    ),
    BehaviorRule(
        rule_id="service_persistence",
        analysis_family="persistence_privilege",
        behavior="服务创建/服务持久化",
        match_any=("createservice", "sc create", "sc.exe create", "new-service"),
        evidence_terms=("CreateService", "sc create", "sc.exe create", "New-Service", "\\Services\\"),
        targets=_service_targets,
    ),
    BehaviorRule(
        rule_id="startup_folder_persistence",
        analysis_family="persistence_privilege",
        behavior="启动目录持久化",
        match_any=("startup", "start menu\\programs\\startup", "shell:startup"),
        evidence_terms=("Startup", "Start Menu\\Programs\\Startup", "shell:startup"),
        targets=_startup_folder_targets,
        min_matches=2,
    ),
    BehaviorRule(
        rule_id="wmi_persistence",
        analysis_family="persistence_privilege",
        behavior="WMI 事件订阅持久化",
        match_any=("__eventfilter", "commandlineeventconsumer", "__filtertoconsumerbinding", "wmic /namespace", "root\\subscription"),
        evidence_terms=("__EventFilter", "CommandLineEventConsumer", "__FilterToConsumerBinding", "root\\subscription"),
        targets=_wmi_targets,
    ),
    BehaviorRule(
        rule_id="living_off_the_land_execution",
        analysis_family="entry_execution",
        behavior="系统工具/脚本解释器执行",
        match_any=("powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32"),
        evidence_terms=("powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32"),
        targets={
            "watch_processes": [
                "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                "mshta.exe", "rundll32.exe", "regsvr32.exe",
            ],
        },
    ),
    BehaviorRule(
        rule_id="payload_dropper",
        analysis_family="entry_execution",
        behavior="文件投放/二阶段载荷落地",
        match_any=("writefile", "createfile", "findresource", "loadresource", "appdata", "programdata", "%temp%", "payload", "dropper"),
        evidence_terms=("WriteFile", "CreateFile", "FindResource", "LoadResource", "AppData", "ProgramData", "%TEMP%", "payload", "dropper"),
        targets=_file_dropper_targets,
        min_matches=2,
    ),
    BehaviorRule(
        rule_id="process_injection",
        analysis_family="defense_evasion_execution",
        behavior="进程注入/远程线程执行",
        match_any=("virtualallocex", "writeprocessmemory", "createremotethread", "ntcreatethreadex", "queueuserapc", "setwindowshookex", "process hollowing"),
        evidence_terms=("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC", "SetWindowsHookEx", "process hollowing"),
        targets={},
        min_matches=2,
    ),
    BehaviorRule(
        rule_id="credential_access",
        analysis_family="credential_access",
        behavior="凭据访问/LSASS 转储候选",
        match_any=("lsass", "minidumpwritedump", "sekurlsa", "comsvcs.dll", "procdump"),
        evidence_terms=("lsass", "MiniDumpWriteDump", "sekurlsa", "comsvcs.dll", "procdump"),
        targets=_credential_targets,
    ),
    BehaviorRule(
        rule_id="uac_bypass",
        analysis_family="persistence_privilege",
        behavior="UAC 绕过候选",
        match_any=("fodhelper", "computerdefaults", "eventvwr", "sdclt", "delegateexecute", "ms-settings\\shell\\open\\command"),
        evidence_terms=("fodhelper", "computerdefaults", "eventvwr", "sdclt", "DelegateExecute", "ms-settings\\Shell\\Open\\command"),
        targets=_uac_bypass_targets,
        min_matches=2,
    ),
    BehaviorRule(
        rule_id="defense_evasion_security_tool_tampering",
        analysis_family="defense_evasion_execution",
        behavior="安全工具/防火墙禁用或规避",
        match_any=("set-mppreference", "disableantispyware", "disablerealtimemonitoring", "add-mppreference", "exclusionpath", "netsh advfirewall", "windefend"),
        evidence_terms=("Set-MpPreference", "DisableAntiSpyware", "DisableRealtimeMonitoring", "Add-MpPreference", "ExclusionPath", "netsh advfirewall", "WinDefend"),
        targets=_defense_evasion_targets,
    ),
    BehaviorRule(
        rule_id="network_or_c2_activity",
        analysis_family="command_control_exfil",
        behavior="网络连接/C2 候选",
        match_any=("http://", "https://", "winhttp", "internetopen", "internetconnect", "http_send", "httpopenrequest"),
        evidence_terms=("http://", "https://", "WinHttp", "InternetOpen", "InternetConnect", "HttpOpenRequest"),
        targets=_network_targets,
    ),
)


def derive_static_behavior_targets(outbox_or_static_dir: Path, sample_name: str) -> dict[str, Any]:
    static_dir = outbox_or_static_dir / "static" if (outbox_or_static_dir / "static").is_dir() else outbox_or_static_dir
    text = "\n".join(
        read_text_file(static_dir / name)
        for name in ("floss.txt", "strings.txt", "capa.json", "diec.txt", "exiftool.txt")
    )
    low = text.lower()
    hypotheses: list[dict[str, Any]] = []
    targets: dict[str, Any] = {
        "watch_processes": [sample_name],
        "watch_paths": [],
        "watch_registry": [],
        "watch_services_tasks": [],
    }

    for rule in BEHAVIOR_RULES:
        matched_terms = tuple(term for term in rule.match_any if term in low)
        if len(matched_terms) < rule.min_matches:
            continue
        dynamic_targets = rule.targets(text) if callable(rule.targets) else dict(rule.targets)
        evidence = matching_lines(text, rule.evidence_terms, limit=8)
        if not evidence:
            evidence = [f"static terms matched: {', '.join(matched_terms)}"]
        hypotheses.append(
            {
                "id": rule.rule_id,
                "analysis_family": rule.analysis_family,
                "behavior": rule.behavior,
                "confidence": "hypothesis",
                "static_evidence": evidence,
                "dynamic_targets": dynamic_targets,
            }
        )
        targets = merge_validation_targets(targets, dynamic_targets)

    payload = {
        "sample_name": sample_name,
        "hypotheses": hypotheses,
        "dynamic_config": {"validation_targets": targets},
        "static_hypotheses": hypotheses,
    }
    static_dir.mkdir(parents=True, exist_ok=True)
    (static_dir / "behavior_hypotheses.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return payload
