"""Streaming Procmon CSV screening for targeted dynamic validation."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any


def target_values(dynamic_config: dict[str, Any], sample_name: str = "") -> list[str]:
    targets = dynamic_config.get("validation_targets") if isinstance(dynamic_config, dict) else {}
    values: list[str] = []

    def add(value: Any) -> None:
        if value is None:
            return
        if isinstance(value, dict):
            for item in value.values():
                add(item)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                add(item)
            return
        text = str(value).strip()
        if text:
            values.append(text)

    if isinstance(targets, dict):
        for key in (
            "network_indicators",
            "watch_processes",
            "watch_paths",
            "watch_registry",
            "watch_services_tasks",
            "behaviors",
        ):
            add(targets.get(key))
    add(sample_name)

    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        key = value.lower()
        if key and key not in seen:
            seen.add(key)
            out.append(value)
    return out


def tshark_target_filter(dynamic_config: dict[str, Any]) -> str:
    targets = dynamic_config.get("validation_targets") if isinstance(dynamic_config, dict) else {}
    if not isinstance(targets, dict):
        return ""
    indicators = targets.get("network_indicators") or {}
    if not isinstance(indicators, dict):
        return ""

    def quote(value: Any) -> str:
        return str(value).replace("\\", "\\\\").replace('"', '\\"')

    terms: list[str] = []
    for domain in indicators.get("domains") or []:
        value = quote(domain)
        terms.extend([
            f'dns.qry.name contains "{value}"',
            f'http.host contains "{value}"',
            f'tls.handshake.extensions_server_name contains "{value}"',
        ])
    for ip in indicators.get("ips") or []:
        if re.fullmatch(r"[0-9a-fA-F:.]+", str(ip).strip()):
            terms.append(f"ip.addr == {ip}")
    for port in indicators.get("ports") or []:
        if str(port).strip().isdigit():
            terms.append(f"tcp.port == {int(port)} || udp.port == {int(port)}")
    for path in indicators.get("uri_paths") or []:
        terms.append(f'http.request.uri contains "{quote(path)}"')
    for user_agent in indicators.get("user_agents") or []:
        terms.append(f'http.user_agent contains "{quote(user_agent)}"')
    for url in indicators.get("urls") or []:
        value = quote(url)
        terms.extend([
            f'http.request.full_uri contains "{value}"',
            f'http.request.uri contains "{value}"',
        ])
    return " || ".join(f"({term})" for term in terms if term)


def screen_procmon_csv(csv_path: Path, dynamic_dir: Path, dynamic_config: dict[str, Any], sample_name: str) -> list[Path]:
    if not csv_path.is_file():
        return []
    target_terms = [value.lower() for value in target_values(dynamic_config, sample_name) if len(value.strip()) >= 3]
    targets = dynamic_config.get("validation_targets") if isinstance(dynamic_config, dict) else {}
    watch_processes = set()
    if isinstance(targets, dict):
        for value in targets.get("watch_processes") or []:
            watch_processes.add(str(value).strip().lower())
    sample_key = sample_name.lower()
    seed_processes = {sample_key}
    high_signal_processes = {
        sample_key,
        "schtasks.exe",
        "sc.exe",
        "reg.exe",
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "mshta.exe",
        "certutil.exe",
        "bitsadmin.exe",
        *watch_processes,
    }
    file_write_ops = (
        "writefile",
        "setrenameinformationfile",
        "setdispositioninformationfile",
        "setendoffileinformationfile",
    )
    registry_write_ops = ("regsetvalue", "regcreatekey", "regdeletekey", "regdeletevalue")
    process_ops = ("process create", "process start", "process exit")
    persistence_keywords = (
        "\\run",
        "\\runonce",
        "\\services",
        "\\taskcache\\",
        "\\tasks\\",
        "startup",
        "scheduled task",
        "schtasks",
        "winlogon",
        "image file execution options",
    )
    suspicious_file_keywords = (
        "\\startup\\",
        "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup",
        "\\windows\\tasks\\",
        "\\system32\\tasks\\",
        "\\temp\\",
        "\\appdata\\",
        "\\programdata\\",
    )
    registry_noise_keywords = (
        "\\muicache\\",
        "\\userassist\\",
        "\\shellbags\\",
        "\\bagmru\\",
        "\\recentdocs\\",
        "\\typedpaths",
    )
    try:
        max_lines = int(dynamic_config.get("max_procmon_lines_per_file", 200))
    except Exception:
        max_lines = 200
    max_lines = max(25, min(max_lines, 1000))
    rows: dict[str, list[str]] = {
        "targeted_host_timeline.txt": [],
        "targeted_file_activity.txt": [],
        "targeted_registry_activity.txt": [],
        "targeted_process_tree.txt": [],
        "targeted_persistence.txt": [],
    }
    seen: dict[str, set[str]] = {name: set() for name in rows}
    dropped: dict[str, int] = {name: 0 for name in rows}
    relevant_pids: set[str] = set()
    rows_scanned = 0

    def clean_detail(detail: str) -> str:
        return detail.split("Environment:", 1)[0].strip()

    def line_for(row: dict[str, str]) -> str:
        detail = clean_detail(str(row.get("Detail", "") or ""))
        values = [
            str(row.get("Time of Day", "") or ""),
            str(row.get("Process Name", "") or ""),
            str(row.get("PID", "") or ""),
            str(row.get("Operation", "") or ""),
            str(row.get("Path", "") or ""),
            str(row.get("Result", "") or ""),
            detail,
        ]
        return "\t".join(values).strip()[:1200]

    def add(name: str, line: str) -> None:
        if not line or line in seen[name]:
            return
        seen[name].add(line)
        if len(rows[name]) < max_lines:
            rows[name].append(line)
        else:
            dropped[name] += 1

    def term_match(text: str) -> bool:
        return not target_terms or any(term in text for term in target_terms)

    def process_match(process_name: str) -> bool:
        return process_name in high_signal_processes or process_name == sample_key

    def seed_process_match(process_name: str) -> bool:
        return process_name in seed_processes

    with csv_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rows_scanned += 1
            process_name = str(row.get("Process Name", "") or "").strip().lower()
            pid = str(row.get("PID", "") or "").strip()
            operation = str(row.get("Operation", "") or "").strip().lower()
            path = str(row.get("Path", "") or "")
            detail = clean_detail(str(row.get("Detail", "") or ""))
            text = " ".join((process_name, operation, path, detail, str(row.get("Result", "") or "")))
            low = text.lower()
            if seed_process_match(process_name) and pid:
                relevant_pids.add(pid)
            matched = pid in relevant_pids or term_match(low) or process_match(process_name)
            if not matched and not (operation == "process create" and any(name in low for name in high_signal_processes if name)):
                continue

            if operation == "process create":
                child = re.search(r"\bPID:\s*(\d+)", detail)
                if child and (pid in relevant_pids or sample_key in low or seed_process_match(process_name)):
                    relevant_pids.add(child.group(1))

            line = line_for(row)
            relevant_actor = pid in relevant_pids or seed_process_match(process_name)
            process_signal = operation in process_ops and (relevant_actor or sample_key in low)
            is_registry_noise = any(key in low for key in registry_noise_keywords)
            is_registry_write = relevant_actor and any(op in operation for op in registry_write_ops) and not is_registry_noise
            is_file_write = relevant_actor and any(op in operation for op in file_write_ops)
            is_createfile_signal = (
                relevant_actor
                and operation == "createfile"
                and any(key in low for key in suspicious_file_keywords)
                and "name not found" not in low
            )
            is_persistence = (
                relevant_actor
                and any(key in low for key in persistence_keywords)
                and (process_signal or is_registry_write or is_file_write or is_createfile_signal)
            )
            high_signal = process_signal or is_registry_write or is_file_write or is_createfile_signal or is_persistence

            if high_signal:
                add("targeted_host_timeline.txt", line)
            if is_file_write or is_createfile_signal:
                add("targeted_file_activity.txt", line)
            if is_registry_write:
                add("targeted_registry_activity.txt", line)
            if process_signal:
                add("targeted_process_tree.txt", line)
            if is_persistence:
                add("targeted_persistence.txt", line)

    written: list[Path] = []
    for name, lines in rows.items():
        output = dynamic_dir / name
        if not lines:
            output.write_text("No matching Procmon rows for configured validation targets.\n", encoding="utf-8")
        else:
            header = (
                f"# Procmon targeted screening: {len(lines)} line(s)"
                + (f", {dropped[name]} omitted by cap" if dropped[name] else "")
                + "\n"
            )
            output.write_text(header + "\n".join(lines) + "\n", encoding="utf-8", errors="replace")
        written.append(output)
    summary = dynamic_dir / "targeted_procmon_summary.json"
    summary.write_text(
        json.dumps(
            {
                "rows_scanned": rows_scanned,
                "target_terms": target_terms,
                "relevant_pids": sorted(relevant_pids),
                "max_lines_per_file": max_lines,
                "output_counts": {name: len(lines) for name, lines in rows.items()},
                "omitted_by_cap": dropped,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    written.append(summary)
    return written
