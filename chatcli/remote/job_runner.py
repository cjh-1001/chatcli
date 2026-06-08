"""Job Runner — analysis orchestration engine deployed on Tencent Cloud.

Reads a job directory (sample + job.json from inbox), executes the analysis plan
step by step, writes structured results to outbox, and creates _DONE or _FAILED
marker files as completion signals.

This file is deployed to and runs on the remote analysis server. It is NOT
imported by chatcli — it's a standalone script invoked by watcher.py or
manually via SSH.

Usage (on Tencent Cloud server):
    python job_runner.py C:\\analysis\\inbox\\job-001 [--mode dry_run]
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from chatcli.remote.behavior_hypotheses import (
    derive_static_behavior_targets as _derive_static_behavior_targets,
    merge_dynamic_config as _merge_dynamic_config_shared,
)
from chatcli.remote.procmon_screen import (
    screen_procmon_csv as _screen_procmon_csv_shared,
    target_values as _target_values_shared,
    tshark_target_filter as _tshark_target_filter_shared,
)


# ── Constants ────────────────────────────────────────────────────

DEFAULT_OUTBOX = Path("C:/analysis/outbox")
DEFAULT_TOOLS = Path("C:/tools")
DEFAULT_PYTHON = "python"


def _write_command_output(output_path: Path, result: subprocess.CompletedProcess[str]) -> None:
    output_path.write_text(
        (result.stdout or "") + (("\n[stderr]\n" + result.stderr) if result.stderr else ""),
        encoding="utf-8",
        errors="replace",
    )


def _target_values(dynamic_config: dict[str, Any], sample_name: str = "") -> list[str]:
    return _target_values_shared(dynamic_config, sample_name)


def _read_text_file(path: Path, limit: int = 500_000) -> str:
    from chatcli.remote.behavior_hypotheses import read_text_file

    return read_text_file(path, limit)


def _matching_lines(text: str, terms: list[str], limit: int = 8) -> list[str]:
    from chatcli.remote.behavior_hypotheses import matching_lines

    return matching_lines(text, terms, limit)


def _extract_domains(text: str, limit: int = 20) -> list[str]:
    from chatcli.remote.behavior_hypotheses import extract_domains

    return extract_domains(text, limit)


def _extract_ips(text: str, limit: int = 20) -> list[str]:
    from chatcli.remote.behavior_hypotheses import extract_ips

    return extract_ips(text, limit)


def _extract_urls(text: str, limit: int = 20) -> list[str]:
    from chatcli.remote.behavior_hypotheses import extract_urls

    return extract_urls(text, limit)


def _merge_list(target: dict[str, Any], key: str, values: list[str]) -> None:
    from chatcli.remote.behavior_hypotheses import merge_list

    merge_list(target, key, values)


def _merge_network_indicators(targets: dict[str, Any], indicators: dict[str, list[str]]) -> None:
    from chatcli.remote.behavior_hypotheses import merge_network_indicators

    merge_network_indicators(targets, indicators)


def _merge_dynamic_config(base: dict[str, Any] | None, derived: dict[str, Any]) -> dict[str, Any]:
    return _merge_dynamic_config_shared(base, derived)


def derive_static_behavior_targets(outbox_dir: Path, sample_name: str) -> dict[str, Any]:
    return _derive_static_behavior_targets(outbox_dir, sample_name)


def _tshark_target_filter(dynamic_config: dict[str, Any]) -> str:
    return _tshark_target_filter_shared(dynamic_config)


def _screen_procmon_csv(csv_path: Path, dynamic_dir: Path, dynamic_config: dict[str, Any], sample_name: str) -> list[Path]:
    return _screen_procmon_csv_shared(csv_path, dynamic_dir, dynamic_config, sample_name)

# Available static analysis tools (checked in order)
STATIC_TOOLS = [
    {
        "name": "binary_inspect",
        "command": "binary_inspect",
        "output": "binary_inspect.json",
        "args": lambda target: ["binary_inspect", str(target), "--json"],
    },
    {
        "name": "capa",
        "command": "capa",
        "output": "capa.json",
        "args": lambda target: ["capa", str(target), "-j"],
    },
    {
        "name": "floss",
        "command": "floss",
        "output": "floss.txt",
        "args": lambda target: ["floss", str(target)],
    },
    {
        "name": "yara",
        "command": "yara",
        "output": "yara.json",
        "args": lambda target: ["yara", str(target)],
    },
    {
        "name": "diec",
        "command": "diec",
        "output": "diec.txt",
        "args": lambda target: ["diec", str(target)],
    },
    {
        "name": "strings",
        "command": "python",
        "output": "strings.txt",
        "args": lambda target: [
            "python", "-c",
            "import re, sys; data=open(sys.argv[1],'rb').read(); "
            "strings=[b.decode('ascii','replace') for b in "
            "re.findall(rb'[\\x20-\\x7e]{4,}', data)]; "
            "print('\\n'.join(strings[:2000]))",
            str(target),
        ],
    },
]

# Available reverse engineering tools
REVERSE_TOOLS = [
    {
        "name": "angr_triage",
        "command": "python",
        "output": "angr_triage.json",
        "args": lambda target: [
            "python", "-c",
            "from chatcli.tools.angr_triage import AngrTriageTool; "
            "import json, sys; "
            "t = AngrTriageTool(); "
            "r = t.execute(target_path=sys.argv[1], run_cfg=False); "
            "print(json.dumps({'content': r.content, 'metadata': r.metadata}))",
            str(target),
        ],
    },
]


# ── Job state ────────────────────────────────────────────────────


@dataclass
class JobState:
    """Mutable state tracking a job's progress."""

    job_id: str
    sample_path: Path
    sample_sha256: str
    outbox_dir: Path
    plan: dict[str, bool]   # {static, reverse, dynamic, network}
    status: str = "pending"  # pending | running | done | failed
    steps_completed: list[str] = field(default_factory=list)
    steps_failed: list[str] = field(default_factory=list)
    started_at: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "sample_sha256": self.sample_sha256,
            "status": self.status,
            "steps_completed": self.steps_completed,
            "steps_failed": self.steps_failed,
            "started_at": self.started_at,
            "error": self.error,
            "duration_seconds": (
                time.time() - self.started_at if self.started_at else 0
            ),
        }

    def write_status(self):
        """Atomic write of status.json to outbox."""
        path = self.outbox_dir / "status.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        tmp.replace(path)

    def mark_done(self):
        """Write _DONE marker — this IS the completion signal."""
        self.status = "done"
        self.write_status()
        (self.outbox_dir / "_DONE").touch()
        self._cleanup_marker("_FAILED")

    def mark_failed(self, error: str):
        """Write _FAILED marker with error detail."""
        self.status = "failed"
        self.error = error
        self.write_status()
        (self.outbox_dir / "_FAILED").write_text(error, encoding="utf-8")
        self._cleanup_marker("_DONE")

    def _cleanup_marker(self, name: str):
        marker = self.outbox_dir / name
        if marker.exists():
            marker.unlink()


# ── Tool execution ───────────────────────────────────────────────


def run_step(
    state: JobState,
    step_name: str,
    command: list[str],
    output_file: str,
    timeout: float = 300.0,
) -> bool:
    """Run a single analysis step, capture output, record result.

    Returns True on success (exit code 0), False on failure.
    """
    output_path = state.outbox_dir / output_file
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(state.sample_path.parent.parent),  # job root
        )
        # Write output regardless of exit code — model can analyze partial results
        output_path.write_text(
            result.stdout or result.stderr or "",
            encoding="utf-8",
            errors="replace",
        )
        if result.returncode == 0:
            state.steps_completed.append(step_name)
            return True
        else:
            # Non-zero exit — record but don't fail the whole job
            state.steps_failed.append(f"{step_name} (exit={result.returncode})")
            return False
    except subprocess.TimeoutExpired:
        output_path.write_text(
            f"[timeout after {timeout}s]", encoding="utf-8"
        )
        state.steps_failed.append(f"{step_name} (timeout)")
        return False
    except Exception as exc:
        output_path.write_text(f"[error: {exc}]", encoding="utf-8")
        state.steps_failed.append(f"{step_name} (error: {exc})")
        return False


def run_static_analysis(state: JobState, mode: str = "real") -> None:
    """Execute all available static analysis tools."""
    static_dir = state.outbox_dir / "static"
    static_dir.mkdir(parents=True, exist_ok=True)

    # Verify sample exists
    sample = state.sample_path
    if not sample.is_file():
        state.mark_failed(f"Sample not found: {sample}")
        return

    for tool in STATIC_TOOLS:
        step_name = f"static.{tool['name']}"
        if mode == "dry_run":
            state.steps_completed.append(f"{step_name} (dry_run)")
            continue

        output_file = f"static/{tool['output']}"
        run_step(state, step_name, tool["args"](sample), output_file)


def run_reverse_analysis(state: JobState, mode: str = "real") -> None:
    """Execute reverse engineering tools (angr triage, etc.)."""
    reverse_dir = state.outbox_dir / "reverse"
    reverse_dir.mkdir(parents=True, exist_ok=True)

    sample = state.sample_path
    for tool in REVERSE_TOOLS:
        step_name = f"reverse.{tool['name']}"
        if mode == "dry_run":
            state.steps_completed.append(f"{step_name} (dry_run)")
            continue

        output_file = f"reverse/{tool['output']}"
        run_step(state, step_name, tool["args"](sample), output_file)


def run_dynamic_analysis(
    state: JobState,
    vm_config: dict[str, Any] | None = None,
    mode: str = "real",
) -> None:
    """Execute dynamic analysis with collectors started before the sample."""
    dynamic_dir = state.outbox_dir / "dynamic"
    dynamic_dir.mkdir(parents=True, exist_ok=True)
    status_path = dynamic_dir / "dynamic_status.json"
    network_pcap = dynamic_dir / "network.pcapng"
    procmon_pml = dynamic_dir / "procmon.pml"
    procmon_csv = dynamic_dir / "procmon.csv"
    vm = vm_config or {}
    timeout_seconds = int(vm.get("timeout_seconds") or 60)
    collectors = set(vm.get("collectors") or ["procmon", "pcap", "tshark"])
    interface = str(vm.get("network_interface") or vm.get("interface") or "1")
    validation_targets = vm.get("validation_targets")
    if validation_targets:
        plan_payload = json.dumps(
            {
                "validation_targets": validation_targets,
                "static_hypotheses": vm.get("static_hypotheses", []),
            },
            indent=2,
            ensure_ascii=False,
        )
        (dynamic_dir / "targeting_plan.json").write_text(plan_payload, encoding="utf-8")
        (dynamic_dir / "dynamic_targeting_plan.json").write_text(plan_payload, encoding="utf-8")

    tools = {
        "procmon": os.environ.get("CHATCLI_TOOL_PROCMON", r"C:\Tools\Procmon64.exe"),
        "dumpcap": os.environ.get("CHATCLI_TOOL_DUMPCAP", "dumpcap"),
        "tshark": os.environ.get("CHATCLI_TOOL_TSHARK", "tshark"),
        "zeek": os.environ.get("CHATCLI_TOOL_ZEEK", "zeek"),
        "suricata": os.environ.get("CHATCLI_TOOL_SURICATA", "suricata"),
        "wevtutil": os.environ.get("CHATCLI_TOOL_WEVTUTIL", "wevtutil"),
        "sysmon": os.environ.get("CHATCLI_TOOL_SYSMON", r"C:\Program Files\reverseTools\Sysmon.exe"),
    }
    availability = {name: _command_available(command) for name, command in tools.items()}
    events: list[dict[str, Any]] = []

    def record(event: str, **kwargs: Any) -> None:
        item = {"event": event, "timestamp": time.time()}
        item.update(kwargs)
        events.append(item)

    def write_status(status: str, **kwargs: Any) -> None:
        payload = {
            "status": status,
            "mode": mode,
            "sample_path": str(state.sample_path),
            "sample_sha256": state.sample_sha256,
            "timeout_seconds": timeout_seconds,
            "collectors": collectors and sorted(collectors),
            "tool_availability": availability,
            "events": events,
            "outputs": {
                "procmon_pml": str(procmon_pml),
                "procmon_csv": str(procmon_csv),
                "network_pcap": str(network_pcap),
                "network_summary": str(dynamic_dir / "network_summary.txt"),
                "dns": str(dynamic_dir / "dns.txt"),
                "http": str(dynamic_dir / "http.txt"),
                "conversations": str(dynamic_dir / "conversations.txt"),
                "tls_sni": str(dynamic_dir / "tls_sni.txt"),
                "tcp_syn": str(dynamic_dir / "tcp_syn.txt"),
                "targeted_network_iocs": str(dynamic_dir / "targeted_network_iocs.txt"),
                "sysmon_evtx": str(dynamic_dir / "sysmon.evtx"),
                "sysmon_text": str(dynamic_dir / "sysmon.txt"),
                "zeek_dir": str(dynamic_dir / "zeek"),
                "suricata_dir": str(dynamic_dir / "suricata"),
                "targeting_plan": str(dynamic_dir / "targeting_plan.json"),
                "dynamic_targeting_plan": str(dynamic_dir / "dynamic_targeting_plan.json"),
            },
        }
        payload.update(kwargs)
        status_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    if mode == "dry_run":
        state.steps_completed.append("dynamic.sandbox (dry_run)")
        record("would_start_packet_capture", before_sample=True, tool=tools["dumpcap"], interface=interface)
        record("would_start_procmon", before_sample=True, tool=tools["procmon"])
        if "sysmon" in collectors:
            record("would_export_sysmon", after_sample=True, tool=tools["wevtutil"])
        record("would_execute_sample", sample=str(state.sample_path), timeout_seconds=timeout_seconds)
        record("would_stop_collectors", after_sample=True)
        record("would_parse_pcap", tool=tools["tshark"])
        if "zeek" in collectors:
            record("would_run_zeek", tool=tools["zeek"])
        if "suricata" in collectors:
            record("would_run_suricata", tool=tools["suricata"])
        if "procmon" in collectors:
            record("would_export_procmon_csv", tool=tools["procmon"], output=str(procmon_csv))
        if validation_targets:
            record("would_screen_dynamic_targets", target_count=len(_target_values(vm, state.sample_path.name)))
        write_status("dry_run")
        return

    capture_enabled = "pcap" in collectors and availability["dumpcap"]
    procmon_enabled = "procmon" in collectors and availability["procmon"]
    sysmon_enabled = "sysmon" in collectors and availability["wevtutil"]
    if not capture_enabled and not procmon_enabled and not sysmon_enabled:
        note = "Dynamic analysis skipped: no configured collector is available."
        (dynamic_dir / "_SKIPPED").write_text(note, encoding="utf-8")
        record("skipped_no_collectors", reason=note)
        write_status("skipped", reason=note)
        return

    dumpcap_proc: subprocess.Popen | None = None
    procmon_proc: subprocess.Popen | None = None
    sample_proc: subprocess.Popen | None = None
    try:
        if capture_enabled:
            dumpcap_cmd = [tools["dumpcap"], "-i", interface, "-w", str(network_pcap)]
            dumpcap_proc = subprocess.Popen(
                dumpcap_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            record("packet_capture_started", before_sample=True, command=dumpcap_cmd, pid=dumpcap_proc.pid)
            write_status("collecting")
            time.sleep(2.0)

        if procmon_enabled:
            procmon_cmd = [
                tools["procmon"],
                "/AcceptEula",
                "/Quiet",
                "/Minimized",
                "/BackingFile",
                str(procmon_pml),
            ]
            procmon_proc = subprocess.Popen(
                procmon_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            time.sleep(2.0)
            record(
                "procmon_started",
                before_sample=True,
                command=procmon_cmd,
                pid=procmon_proc.pid,
                still_running=procmon_proc.poll() is None,
            )
            write_status("collecting")
            time.sleep(1.0)

        sample_proc = subprocess.Popen(
            [str(state.sample_path)],
            cwd=str(state.sample_path.parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
        )
        record("sample_started", pid=sample_proc.pid, timeout_seconds=timeout_seconds)
        write_status("collecting")
        try:
            sample_proc.wait(timeout=max(1, timeout_seconds))
            record("sample_exited", exit_code=sample_proc.returncode)
        except subprocess.TimeoutExpired:
            sample_proc.terminate()
            try:
                sample_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                sample_proc.kill()
                sample_proc.wait(timeout=5)
            record("sample_timeout_terminated", exit_code=sample_proc.returncode)

    finally:
        if procmon_enabled:
            try:
                stop_cmd = [tools["procmon"], "/Terminate"]
                completed = subprocess.run(stop_cmd, capture_output=True, text=True, timeout=30)
                record(
                    "procmon_stopped",
                    after_sample=True,
                    command=stop_cmd,
                    exit_code=completed.returncode,
                    stderr=(completed.stderr or "")[:1000],
                )
            except Exception as exc:
                record("procmon_stop_failed", error=f"{type(exc).__name__}: {exc}")

        if dumpcap_proc is not None:
            dumpcap_proc.terminate()
            try:
                _, stderr = dumpcap_proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                dumpcap_proc.kill()
                _, stderr = dumpcap_proc.communicate(timeout=10)
            record(
                "packet_capture_stopped",
                after_sample=True,
                exit_code=dumpcap_proc.returncode,
                stderr=(stderr or "")[:1000],
            )
        write_status("collecting")

    if "tshark" in collectors and availability["tshark"] and network_pcap.exists():
        tshark_jobs = [
            ("network_summary.txt", [tools["tshark"], "-r", str(network_pcap), "-q", "-z", "conv,ip"]),
            ("dns.txt", [tools["tshark"], "-r", str(network_pcap), "-Y", "dns"]),
            ("http.txt", [tools["tshark"], "-r", str(network_pcap), "-Y", "http"]),
            ("conversations.txt", [tools["tshark"], "-r", str(network_pcap), "-q", "-z", "conv,tcp"]),
            ("tls_sni.txt", [tools["tshark"], "-r", str(network_pcap), "-Y", "tls.handshake.extensions_server_name", "-T", "fields", "-e", "frame.time", "-e", "ip.src", "-e", "ip.dst", "-e", "tls.handshake.extensions_server_name"]),
            ("tcp_syn.txt", [tools["tshark"], "-r", str(network_pcap), "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0", "-T", "fields", "-e", "frame.time", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.dstport"]),
        ]
        target_filter = _tshark_target_filter(vm)
        if target_filter:
            tshark_jobs.append((
                "targeted_network_iocs.txt",
                [
                    tools["tshark"],
                    "-r",
                    str(network_pcap),
                    "-Y",
                    target_filter,
                    "-T",
                    "fields",
                    "-e",
                    "frame.time",
                    "-e",
                    "ip.src",
                    "-e",
                    "ip.dst",
                    "-e",
                    "dns.qry.name",
                    "-e",
                    "http.host",
                    "-e",
                    "http.request.uri",
                    "-e",
                    "tls.handshake.extensions_server_name",
                ],
            ))
        for output_name, command in tshark_jobs:
            output_path = dynamic_dir / output_name
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            _write_command_output(output_path, result)
            record("pcap_parsed", command=command, output=str(output_path), exit_code=result.returncode)

    if procmon_enabled and procmon_pml.exists():
        command = [tools["procmon"], "/AcceptEula", "/OpenLog", str(procmon_pml), "/SaveAs", str(procmon_csv)]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=90)
            record("procmon_exported", command=command, output=str(procmon_csv), exit_code=result.returncode, stderr=(result.stderr or "")[:1000])
            for output in _screen_procmon_csv_shared(procmon_csv, dynamic_dir, vm, state.sample_path.name):
                record("procmon_screened", output=str(output))
        except Exception as exc:
            record("procmon_export_failed", command=command, error=f"{type(exc).__name__}: {exc}")

    if sysmon_enabled:
        evtx_path = dynamic_dir / "sysmon.evtx"
        text_path = dynamic_dir / "sysmon.txt"
        export_cmd = [tools["wevtutil"], "epl", "Microsoft-Windows-Sysmon/Operational", str(evtx_path), "/ow:true"]
        text_cmd = [tools["wevtutil"], "qe", "Microsoft-Windows-Sysmon/Operational", "/f:text", "/c:2000", "/rd:true"]
        for output_path, command in ((evtx_path, export_cmd), (text_path, text_cmd)):
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=60)
                if output_path == text_path:
                    _write_command_output(output_path, result)
                record("sysmon_exported", command=command, output=str(output_path), exit_code=result.returncode, stderr=(result.stderr or "")[:1000])
            except Exception as exc:
                record("sysmon_export_failed", command=command, output=str(output_path), error=f"{type(exc).__name__}: {exc}")

    if "zeek" in collectors and availability["zeek"] and network_pcap.exists():
        zeek_dir = dynamic_dir / "zeek"
        zeek_dir.mkdir(parents=True, exist_ok=True)
        command = [tools["zeek"], "-r", str(network_pcap)]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=120, cwd=str(zeek_dir))
            _write_command_output(zeek_dir / "_zeek_run.txt", result)
            record("zeek_parsed", command=command, output=str(zeek_dir), exit_code=result.returncode)
        except Exception as exc:
            record("zeek_failed", command=command, output=str(zeek_dir), error=f"{type(exc).__name__}: {exc}")

    if "suricata" in collectors and availability["suricata"] and network_pcap.exists():
        suricata_dir = dynamic_dir / "suricata"
        suricata_dir.mkdir(parents=True, exist_ok=True)
        command = [tools["suricata"], "-r", str(network_pcap), "-l", str(suricata_dir), "-k", "none"]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=180)
            _write_command_output(suricata_dir / "_suricata_run.txt", result)
            record("suricata_parsed", command=command, output=str(suricata_dir), exit_code=result.returncode)
        except Exception as exc:
            record("suricata_failed", command=command, output=str(suricata_dir), error=f"{type(exc).__name__}: {exc}")

    state.steps_completed.append("dynamic.collectors")
    write_status("collected")


def _command_available(command: str) -> bool:
    raw = str(command or "").strip().strip('"')
    if not raw:
        return False
    path = Path(raw)
    if path.is_file():
        return True
    return shutil.which(raw) is not None


def run_network_analysis(state: JobState, mode: str = "real") -> None:
    """Network capture placeholders — implemented with dynamic analysis."""
    network_dir = state.outbox_dir / "dynamic"
    network_dir.mkdir(parents=True, exist_ok=True)

    if mode == "dry_run":
        state.steps_completed.append("network.capture (dry_run)")
        return

    # Network capture is triggered as part of dynamic VM execution
    (network_dir / "_NETWORK_NOTE").write_text(
        "Network capture runs as part of dynamic VM execution.",
        encoding="utf-8",
    )


def _run_verify_probe(command: str, timeout: int = 10) -> dict[str, Any]:
    started = time.time()
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(1, min(timeout, 30)),
        )
        return {
            "command": command,
            "exit_code": result.returncode,
            "stdout": (result.stdout or "")[:12000],
            "stderr": (result.stderr or "")[:4000],
            "elapsed_ms": int((time.time() - started) * 1000),
        }
    except subprocess.TimeoutExpired:
        return {
            "command": command,
            "exit_code": -1,
            "stdout": "",
            "stderr": f"timeout after {timeout}s",
            "elapsed_ms": int((time.time() - started) * 1000),
        }
    except Exception as exc:
        return {
            "command": command,
            "exit_code": -2,
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}",
            "elapsed_ms": int((time.time() - started) * 1000),
        }


def run_server_verification(state: JobState, mode: str = "real") -> None:
    """Collect post-analysis server indicators for compromise review."""
    verify_dir = state.outbox_dir / "verify"
    verify_dir.mkdir(parents=True, exist_ok=True)

    snapshot: dict[str, Any] = {
        "job_id": state.job_id,
        "sample_sha256": state.sample_sha256,
        "sample_path": str(state.sample_path),
        "timestamp": time.time(),
        "hostname": platform.node(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "mode": mode,
        "status": "dry_run" if mode == "dry_run" else "collected",
        "probes": {},
    }

    if mode == "dry_run":
        state.steps_completed.append("verify.server_status (dry_run)")
    else:
        probes = {
            "network_connections": "netstat -ano" if os.name == "nt" else "ss -tunap",
            "processes": "tasklist" if os.name == "nt" else "ps aux",
        }
        if os.name == "nt":
            probes.update({
                "services": "sc query state= all",
                "scheduled_tasks": "schtasks /query /fo LIST",
                "recent_system_events": "wevtutil qe System /c:30 /f:text",
            })
        else:
            probes.update({
                "services": "systemctl --no-pager --type=service --state=running",
                "cron": "crontab -l",
                "recent_logs": "journalctl -n 50 --no-pager",
            })
        snapshot["probes"] = {
            name: _run_verify_probe(command)
            for name, command in probes.items()
        }
        state.steps_completed.append("verify.server_status")

    (verify_dir / "server_status_after.json").write_text(
        json.dumps(snapshot, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


# ── Main entry ───────────────────────────────────────────────────


def run_job(
    job_dir: str | Path,
    mode: str = "real",
    outbox_root: str | Path | None = None,
) -> JobState:
    """Execute a complete analysis job from inbox directory.

    Args:
        job_dir: Path to job directory (contains sample/ + job.json)
        mode: "real" | "dry_run"
        outbox_root: Output root (default C:\\analysis\\outbox)

    Returns JobState with final status.
    """
    job_dir = Path(job_dir)
    outbox_root = Path(outbox_root) if outbox_root else DEFAULT_OUTBOX

    # Load job config
    job_file = job_dir / "job.json"
    if not job_file.is_file():
        raise FileNotFoundError(f"job.json not found in {job_dir}")

    job = json.loads(job_file.read_text(encoding="utf-8"))
    job_id = job.get("job_id", job_dir.name)
    plan = job.get("analysis_plan", {"static": True})
    vm_config = job.get("dynamic_config", {})

    # Find sample. Newer Guest Agent jobs may point at a file that already
    # exists on the remote server; uploaded samples still use sample/.
    configured_sample = str(job.get("sample_path", "") or "").strip()
    if configured_sample:
        candidate = Path(configured_sample).expanduser()
        sample_path = candidate if candidate.is_absolute() else job_dir / candidate
        if not sample_path.is_file():
            raise FileNotFoundError(f"Configured sample_path not found: {sample_path}")
    else:
        sample_dir = job_dir / "sample"
        samples = list(sample_dir.glob("*")) if sample_dir.is_dir() else []
        if not samples:
            raise FileNotFoundError(
                f"No sample found in {sample_dir}; provide sample_path in job.json "
                "or upload a sample before running."
            )
        sample_path = samples[0]  # Take the first file

    # Compute hash
    sha256 = hashlib.sha256()
    with open(sample_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    sample_sha256 = sha256.hexdigest()

    # Setup outbox
    outbox_dir = outbox_root / job_id
    outbox_dir.mkdir(parents=True, exist_ok=True)

    state = JobState(
        job_id=job_id,
        sample_path=sample_path,
        sample_sha256=sample_sha256,
        outbox_dir=outbox_dir,
        plan=plan,
        status="running",
        started_at=time.time(),
    )
    state.write_status()

    try:
        # ── Static analysis ──────────────────────────────────
        if plan.get("static", True):
            run_static_analysis(state, mode)
            if plan.get("dynamic", False):
                derived = _derive_static_behavior_targets(state.outbox_dir, state.sample_path.name)
                vm_config = _merge_dynamic_config_shared(vm_config, derived.get("dynamic_config", {}))
                if derived.get("static_hypotheses"):
                    vm_config["static_hypotheses"] = derived["static_hypotheses"]
            state.write_status()

        # ── Reverse engineering ──────────────────────────────
        if plan.get("reverse", False):
            run_reverse_analysis(state, mode)
            state.write_status()

        # ── Dynamic analysis ─────────────────────────────────
        if plan.get("dynamic", False):
            run_dynamic_analysis(state, vm_config, mode)
            state.write_status()

        # ── Network capture ──────────────────────────────────
        if plan.get("network", False):
            run_network_analysis(state, mode)
            state.write_status()

        # ── Server compromise/attack-state verification ─────────
        if plan.get("verify", False):
            run_server_verification(state, mode)
            state.write_status()

        state.mark_done()
    except Exception as exc:
        state.mark_failed(str(exc))

    return state


# ── CLI ──────────────────────────────────────────────────────────


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="chatcli Job Runner — execute analysis job"
    )
    parser.add_argument(
        "job_dir",
        help="Path to job directory (inbox/<job_id>/)",
    )
    parser.add_argument(
        "--mode",
        choices=["real", "dry_run"],
        default="real",
        help="Execution mode (default: real)",
    )
    parser.add_argument(
        "--outbox",
        default=str(DEFAULT_OUTBOX),
        help=f"Output root (default: {DEFAULT_OUTBOX})",
    )
    args = parser.parse_args()

    try:
        state = run_job(args.job_dir, mode=args.mode, outbox_root=args.outbox)
        print(f"Job {state.job_id}: {state.status}")
        if state.status == "done":
            print(f"  Steps: {', '.join(state.steps_completed)}")
        if state.steps_failed:
            print(f"  Failed: {', '.join(state.steps_failed)}")
        duration = time.time() - state.started_at if state.started_at else 0
        print(f"  Duration: {duration:.1f}s")
        sys.exit(0 if state.status == "done" else 1)
    except Exception as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
