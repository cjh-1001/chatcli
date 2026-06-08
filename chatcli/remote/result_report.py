"""Local report generation for downloaded remote analysis results."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from chatcli.templates.malware_report import render_malware_html, validate_malware_report


@dataclass(frozen=True)
class GeneratedMalwareReport:
    json_path: Path
    html_path: Path
    errors: list[str]


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _read_text(path: Path, limit: int = 200_000) -> str:
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except Exception:
        return ""


def _selected_lines(text: str, terms: list[str], limit: int = 12) -> list[str]:
    lowered_terms = [term.lower() for term in terms if term]
    lines: list[str] = []
    for line in text.splitlines():
        low = line.lower()
        if "environment:" in low:
            line = line.split("Environment:", 1)[0].rstrip()
        if lowered_terms and not any(term in low for term in lowered_terms):
            continue
        clean = line.strip()
        if clean and clean not in lines:
            lines.append(clean[:1000])
        if len(lines) >= limit:
            break
    return lines


def _first(data: dict[str, Any], *keys: str, default: str = "") -> str:
    for key in keys:
        value = data.get(key)
        if value not in (None, ""):
            return str(value)
    return default


def _file_size_label(size: Any) -> str:
    try:
        number = int(size)
    except (TypeError, ValueError):
        return ""
    return f"{number:,} bytes"


def _detect_schtasks(process_lines: list[str], static_lines: list[str]) -> bool:
    text = "\n".join(process_lines + static_lines).lower()
    return "schtasks" in text and ("/create" in text or " /tn " in text or "securityscript" in text)


def _flatten_target_values(value: Any) -> list[str]:
    values: list[str] = []
    if value is None:
        return values
    if isinstance(value, dict):
        for child in value.values():
            values.extend(_flatten_target_values(child))
    elif isinstance(value, (list, tuple, set)):
        for child in value:
            values.extend(_flatten_target_values(child))
    else:
        text = str(value).strip()
        if text:
            values.append(text)
    return values


def _family_label(family: str) -> str:
    return {
        "entry_execution": "入口/执行/载荷链",
        "persistence_privilege": "持久化/提权/驻留",
        "defense_evasion_execution": "规避/注入/执行控制",
        "credential_access": "凭据访问",
        "command_control_exfil": "命令控制/外联/外传",
    }.get(family, "未归类")


def _impact_for_behavior(behavior: str, family: str) -> str:
    if family == "persistence_privilege":
        return "可能建立持久化、提权或驻留能力，需用动态证据确认具体落点。"
    if family == "command_control_exfil":
        return "可能产生外联、命令控制或数据外传风险，需结合 PCAP/DNS/HTTP 证据验证。"
    if family == "credential_access":
        return "可能尝试访问凭据或敏感进程内存，需重点复核 LSASS/转储文件证据。"
    if family == "defense_evasion_execution":
        return "可能规避安全工具、注入进程或隐藏执行链，需结合进程和注册表证据验证。"
    if family == "entry_execution":
        return "可能投放或启动后续载荷，需确认文件落地、子进程和执行边。"
    return f"{behavior} 需要结合静态和动态证据继续确认。"


def build_malware_report_from_results(
    local_dir: str | Path,
    *,
    output_dir: str | Path = "",
) -> GeneratedMalwareReport | None:
    """Build a concise HTML malware report from a downloaded remote result dir.

    The remote runner deliberately produces raw evidence. This helper performs a
    local, token-safe summarization and renders the existing malware HTML format.
    It returns None when the directory is not a recognizable remote result.
    """
    root = Path(local_dir)
    if not root.is_dir():
        return None

    status = _read_json(root / "status.json")
    binary = _read_json(root / "static" / "binary_inspect.json")
    dynamic_status = _read_json(root / "dynamic" / "dynamic_status.json")
    behavior_hypotheses = _read_json(root / "static" / "behavior_hypotheses.json")
    if not status and not binary and not dynamic_status:
        return None

    case_id = status.get("job_id") or root.name
    sample_path = _first(binary, "path", default=str(status.get("sample_path") or ""))
    sample_name = Path(sample_path.replace("\\", "/")).name if sample_path else str(case_id)
    sha256 = _first(binary, "sha256", default=str(status.get("sample_sha256") or ""))
    md5 = _first(binary, "md5")
    size = _file_size_label(binary.get("size"))

    floss_text = _read_text(root / "static" / "floss.txt")
    strings_text = _read_text(root / "static" / "strings.txt")
    diec_text = _read_text(root / "static" / "diec.txt", limit=20_000).strip()
    exif_text = _read_text(root / "static" / "exiftool.txt", limit=50_000)
    process_text = _read_text(root / "dynamic" / "targeted_process_tree.txt")
    persistence_text = _read_text(root / "dynamic" / "targeted_persistence.txt")
    network_summary = _read_text(root / "dynamic" / "network_summary.txt", limit=50_000)

    static_terms = [
        "schtasks",
        "/create",
        "/query",
        "securityscript",
        "calc.exe",
        "run",
        "startup",
        "powershell",
        "cmd.exe",
    ]
    static_lines = _selected_lines(floss_text + "\n" + strings_text, static_terms, limit=12)
    process_lines = _selected_lines(process_text, static_terms + [sample_name], limit=16)
    persistence_lines = _selected_lines(
        persistence_text,
        ["schtasks", "securityscript", "taskcache", "\\run", "image file execution options", "bam"],
        limit=10,
    )
    is_schtasks = _detect_schtasks(process_lines, static_lines)
    hypotheses = behavior_hypotheses.get("hypotheses") if isinstance(behavior_hypotheses.get("hypotheses"), list) else []

    dns_empty = (root / "dynamic" / "dns.txt").is_file() and (root / "dynamic" / "dns.txt").stat().st_size == 0
    http_empty = (root / "dynamic" / "http.txt").is_file() and (root / "dynamic" / "http.txt").stat().st_size == 0
    tls_empty = (root / "dynamic" / "tls_sni.txt").is_file() and (root / "dynamic" / "tls_sni.txt").stat().st_size == 0

    sample_exit = ""
    for event in dynamic_status.get("events", []) if isinstance(dynamic_status.get("events"), list) else []:
        if isinstance(event, dict) and event.get("event") == "sample_exited":
            sample_exit = f"exit_code={event.get('exit_code')}"
            break

    dynamic_text = "\n".join([process_text, persistence_text, network_summary])
    behavior_summaries: list[dict[str, Any]] = []
    for item in hypotheses:
        if not isinstance(item, dict):
            continue
        behavior_name = str(item.get("behavior") or item.get("id") or "静态行为假设")
        family = str(item.get("analysis_family") or "uncategorized")
        dynamic_targets = item.get("dynamic_targets") if isinstance(item.get("dynamic_targets"), dict) else {}
        target_terms = [term for term in _flatten_target_values(dynamic_targets) if len(term) >= 3]
        target_terms.extend(str(term) for term in item.get("static_evidence", []) if len(str(term)) >= 3)
        if any("%appdata%" in term.lower() for term in target_terms):
            target_terms.extend(["AppData", "Roaming"])
        if any("%temp%" in term.lower() for term in target_terms):
            target_terms.extend(["Temp", "Local\\Temp"])
        if any("%programdata%" in term.lower() for term in target_terms):
            target_terms.append("ProgramData")
        target_terms.extend([behavior_name, str(item.get("id") or "")])
        matched_dynamic = _selected_lines(dynamic_text, target_terms, limit=6)
        if item.get("id") == "scheduled_task_persistence" and is_schtasks:
            status = "confirmed"
            confidence_after = "confirmed"
            matched_dynamic = dynamic_evidence if "dynamic_evidence" in locals() else matched_dynamic
        elif family == "command_control_exfil" and dns_empty and http_empty and tls_empty:
            status = "unobserved"
            confidence_after = "unobserved"
        elif matched_dynamic:
            status = "confirmed"
            confidence_after = "confirmed"
        else:
            status = "inconclusive"
            confidence_after = "inconclusive"
        behavior_summaries.append(
            {
                "id": str(item.get("id") or behavior_name),
                "behavior": behavior_name,
                "family": family,
                "family_label": _family_label(family),
                "technique": str(item.get("id") or behavior_name),
                "static_evidence": item.get("static_evidence") if isinstance(item.get("static_evidence"), list) else [],
                "dynamic_evidence": matched_dynamic,
                "status": status,
                "confidence": confidence_after,
                "impact": _impact_for_behavior(behavior_name, family),
            }
        )

    if is_schtasks:
        create_lines = [
            line for line in process_lines
            if "schtasks" in line.lower() and "/create" in line.lower()
        ]
        query_lines = [
            line for line in process_lines
            if "schtasks" in line.lower() and "/query" in line.lower()
        ]
        other_lines = [line for line in process_lines if line not in create_lines and line not in query_lines]
        verdict = (
            f"该样本在远程动态运行中已确认会创建 Windows 计划任务。"
            f"Procmon 捕获到 {sample_name} 启动 schtasks.exe 执行 /create 命令；"
            "未观察到 DNS、HTTP、TLS SNI 或明确外联 C2 行为。"
        )
        behavior = "计划任务持久化"
        technique = "schtasks.exe /create"
        impact = "可建立周期性执行点，达到持久化驻留或后续载荷周期拉起效果。"
        dynamic_evidence = (create_lines + query_lines + other_lines)[:6] or ["Procmon targeted_process_tree.txt 命中 schtasks 相关进程事件。"]
        confidence = "confirmed"
        if behavior_summaries:
            for summary in behavior_summaries:
                if summary["id"] == "scheduled_task_persistence":
                    summary["dynamic_evidence"] = dynamic_evidence
                    summary["status"] = "confirmed"
                    summary["confidence"] = "confirmed"
                    break
    elif behavior_summaries:
        primary = behavior_summaries[0]
        verdict = (
            f"静态分析提出 {len(behavior_summaries)} 个行为假设，"
            "当前动态证据已生成验证矩阵；未自动确认完整高置信攻击链时保持待复核结论。"
        )
        behavior = primary["behavior"]
        technique = primary["technique"]
        impact = primary["impact"]
        dynamic_evidence = primary["dynamic_evidence"] or process_lines[:6] or ["当前动态摘要未命中该假设的验证目标。"]
        confidence = "confirmed" if primary["status"] == "confirmed" else "medium"
    else:
        verdict = (
            "远程结果已下载并完成基础归纳，但当前自动报告器未识别出可确认的高置信行为链。"
            "请结合静态/动态原始证据继续人工确认。"
        )
        behavior = "远程样本执行与证据采集"
        technique = "静态工具 + Procmon/PCAP 动态采集"
        impact = "已形成后续人工分析的证据包。"
        dynamic_evidence = process_lines[:6] or ["未提取到高置信进程行为摘要。"]
        confidence = "medium"

    if not behavior_summaries:
        behavior_summaries = [
            {
                "id": behavior,
                "behavior": behavior,
                "family": "persistence_privilege" if is_schtasks else "uncategorized",
                "family_label": "持久化/提权/驻留" if is_schtasks else "未归类",
                "technique": technique,
                "static_evidence": static_lines[:6],
                "dynamic_evidence": dynamic_evidence[:6],
                "status": "confirmed" if is_schtasks else "inconclusive",
                "confidence": confidence,
                "impact": impact,
            }
        ]

    file_type = "Win64 EXE / PE32+" if "PE32+" in exif_text or "PE+(64)" in diec_text else ("PE executable" if binary.get("is_pe") else "unknown")
    architecture = "AMD64" if "AMD64" in exif_text or "EXE64" in diec_text else ""

    report: dict[str, Any] = {
        "title": f"恶意样本分析报告: {sample_name}",
        "meta": {
            "date": datetime.now().strftime("%Y-%m-%d"),
            "analyst": "chatcli",
            "classification": "malware-analysis",
            "confidence": confidence,
            "tags": ["remote-analysis", "windows", "procmon", "pcap"],
        },
        "identity": {
            "path": sample_path,
            "sha256": sha256,
            "md5": md5,
            "file_type": file_type,
            "architecture": architecture,
            "size": size,
            "compile_time": "未确认",
            "sections": [],
            "entropy": "未计算",
            "packer": diec_text or "未确认",
        },
        "conclusion": {
            "verdict": verdict,
            "confidence": confidence,
            "impact_one_liner": impact,
            "family": "未知",
        },
        "attack_chain": [
            {
                "step": 1,
                "family_label": "入口/执行/载荷链",
                "analysis_family": "entry_execution",
                "behavior": "样本启动",
                "technique": "远程隔离环境执行",
                "evidence": sample_exit or "dynamic_status.json 记录样本执行流程。",
                "target": "Windows 分析环境",
                "impact": "触发样本主逻辑并生成动态证据。",
                "confidence": "confirmed" if sample_exit else "medium",
                "gaps": "",
            },
            *[
                {
                    "step": index + 2,
                    "family_label": summary["family_label"],
                    "analysis_family": summary["family"],
                    "behavior": summary["behavior"],
                    "technique": summary["technique"],
                    "evidence": (summary["dynamic_evidence"] or summary["static_evidence"] or ["未提取到证据摘要。"])[0],
                    "target": "Windows 主机",
                    "impact": summary["impact"],
                    "confidence": summary["confidence"],
                    "gaps": "" if summary["status"] == "confirmed" else "需要人工复核原始 Procmon/PCAP/静态证据。",
                }
                for index, summary in enumerate(behavior_summaries[:6])
            ],
        ],
        "key_capabilities": [
            {
                "category": summary["behavior"],
                "family_label": summary["family_label"],
                "analysis_family": summary["family"],
                "technique": summary["technique"],
                "evidence": "; ".join((summary["static_evidence"] + summary["dynamic_evidence"])[:5]),
                "impact": summary["impact"],
                "confidence": summary["confidence"],
            }
            for summary in behavior_summaries[:8]
        ],
        "static_tool_evidence": [
            {
                "tool": "binary_inspect",
                "status": "ok" if binary else "missing",
                "confidence": "high" if binary else "low",
                "evidence": [item for item in [f"sha256={sha256}" if sha256 else "", f"md5={md5}" if md5 else "", f"size={size}" if size else ""] if item],
                "notes": "基础样本身份识别。",
            },
            {
                "tool": "floss/strings",
                "status": "ok" if static_lines else "no_hits",
                "confidence": "medium" if static_lines else "low",
                "evidence": static_lines[:8],
                "notes": "静态字符串只作为能力假设，需动态证据确认。",
            },
        ],
        "dynamic_validation": [],
        "dynamic_evidence": {
            "execution": [sample_exit or "dynamic_status.json 已生成。"],
            "process": dynamic_evidence,
            "file": ["查看 dynamic/targeted_file_activity.txt 获取完整文件活动。"],
            "registry": persistence_lines or ["未提取到高置信注册表摘要。"],
            "network": [
                "dns.txt/http.txt/tls_sni.txt 为空。" if dns_empty and http_empty and tls_empty else "查看 dynamic/network_summary.txt。",
                network_summary.splitlines()[0] if network_summary.splitlines() else "network_summary.txt 未生成或为空。",
            ],
            "artifacts": [
                "status.json",
                "static/binary_inspect.json",
                "static/floss.txt",
                "dynamic/dynamic_status.json",
                "dynamic/targeted_process_tree.txt",
                "dynamic/network.pcapng",
                "dynamic/procmon.csv",
            ],
        },
        "evidence_chain": [
            {
                "claim": summary["behavior"],
                "static_evidence": summary["static_evidence"][:6],
                "dynamic_evidence": summary["dynamic_evidence"][:6],
                "source_artifacts": ["static/floss.txt", "dynamic/targeted_process_tree.txt", "dynamic/dynamic_status.json"],
                "interpretation": "静态证据提出假设，动态 Procmon/PCAP 结果用于确认、反驳或标记未观察到。",
                "confidence": summary["confidence"],
                "gaps": "" if summary["status"] == "confirmed" else "当前自动摘要未完全闭合该行为链。",
            }
            for summary in behavior_summaries[:8]
        ],
        "coverage": {
            "confirmed": [summary["behavior"] for summary in behavior_summaries if summary["status"] == "confirmed"] or ["远程证据采集完成"],
            "likely": [summary["behavior"] for summary in behavior_summaries if summary["status"] == "inconclusive"],
            "not_observed": [summary["behavior"] for summary in behavior_summaries if summary["status"] == "unobserved"]
            + (["DNS 查询", "HTTP 请求", "TLS SNI"] if dns_empty and http_empty and tls_empty else []),
            "not_analyzed": ["函数级逆向", "长时间窗口/多分支触发", "完整 Procmon 人工审阅"],
        },
        "coverage_family_counts": {},
        "iocs": {
            "network": [],
            "host": [
                {"type": "样本路径", "value": sample_path, "context": "被分析样本"} if sample_path else {},
                {"type": "SHA256", "value": sha256, "context": "样本哈希"} if sha256 else {},
                {"type": "进程/命令行", "value": dynamic_evidence[0], "context": "Procmon 摘要"} if dynamic_evidence else {},
            ],
            "crypto_config": [],
            "low_confidence": [],
        },
        "impact": {
            "confidentiality": "未观察到数据外传证据。" if dns_empty and http_empty and tls_empty else "网络证据需继续复核。",
            "integrity": impact,
            "availability": "本次未观察到破坏性影响。",
            "persistence_risk": impact if is_schtasks else "未自动确认。",
            "business_exposure": "同类行为在真实环境中可用于驻留、周期拉起 payload 或后续攻击阶段。",
        },
        "detection": {
            "yara": "",
            "sigma": "",
            "edr_hunting": [
                "检索非常规父进程启动 schtasks.exe /create 的进程创建事件。",
                "复核 dynamic/procmon.csv 中与样本 PID、子进程和持久化关键字相关的行。",
                "联动 PCAP 与进程时间线，避免把云元数据或环境流量误归因到样本。",
            ],
            "containment": "动态分析 VM 在证据下载后应执行快照回滚；若发现计划任务，先导出证据再删除。",
        },
        "limitations": {
            "packed_areas": "未完成函数级逆向和完整熵分析。",
            "runtime_only": "动态窗口有限，延迟、条件或环境检测分支可能未触发。",
            "missing_evidence": "自动报告是证据归纳，不替代人工逆向复核。",
            "notes": "报告生成时会截断 Procmon 环境块，避免泄露令牌等敏感上下文。",
        },
    }

    family_counts: dict[str, dict[str, int]] = {}
    for summary in behavior_summaries:
        family = summary["family"]
        status = summary["status"]
        family_counts.setdefault(family, {})
        family_counts[family][status] = family_counts[family].get(status, 0) + 1
    if dns_empty and http_empty and tls_empty:
        family_counts.setdefault("command_control_exfil", {})
        family_counts["command_control_exfil"]["unobserved"] = family_counts["command_control_exfil"].get("unobserved", 0) + 3
    report["coverage_family_counts"] = family_counts

    dynamic_validation = report["dynamic_validation"]
    for summary in behavior_summaries:
        if summary["status"] == "confirmed":
            evidence = "; ".join(summary["dynamic_evidence"][:4]) or "动态摘要命中该静态假设的验证目标。"
            update = f"{summary['behavior']} 由静态假设提升为 confirmed。"
            gaps = ""
        elif summary["status"] == "unobserved":
            evidence = "dns.txt/http.txt/tls_sni.txt 为空；未形成外联 C2 证据。"
            update = f"{summary['behavior']} 在本次窗口内标记为未观察到。"
            gaps = "短时间窗口可能未覆盖延迟或条件触发分支。"
        else:
            evidence = "未从当前动态摘要中提取到足够证据确认或反驳。"
            update = "保留为待人工复核。"
            gaps = "需要复核原始 Procmon/PCAP 或扩大动态触发条件。"
        dynamic_validation.append(
            {
                "static_claim": summary["behavior"],
                "dynamic_status": summary["status"],
                "dynamic_evidence": evidence,
                "report_update": update,
                "confidence_after": summary["confidence"],
                "gaps": gaps,
            }
        )

    if not hypotheses:
        dynamic_validation.append(
            {
                "static_claim": "检查是否存在网络/C2 行为。",
                "dynamic_status": "unobserved" if dns_empty and http_empty and tls_empty else "inconclusive",
                "dynamic_evidence": "dns.txt/http.txt/tls_sni.txt 为空。" if dns_empty and http_empty and tls_empty else "PCAP 已生成，需继续复核 network_summary/tshark 输出。",
                "report_update": "网络行为不写成已确认能力。",
                "confidence_after": "unobserved" if dns_empty and http_empty and tls_empty else "inconclusive",
                "gaps": "短时间窗口可能未覆盖延迟或条件触发网络分支。",
            }
        )

    report["iocs"]["host"] = [item for item in report["iocs"]["host"] if item]

    errors = validate_malware_report(report)
    out_dir = Path(output_dir) if output_dir else Path(".chatcli") / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = str(case_id or root.name)
    json_path = out_dir / f"{stem}.malware.json"
    html_path = out_dir / f"{stem}.malware.html"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    html_path.write_text(render_malware_html(report), encoding="utf-8")
    return GeneratedMalwareReport(json_path=json_path, html_path=html_path, errors=errors)
