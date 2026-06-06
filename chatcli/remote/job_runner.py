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


# ── Constants ────────────────────────────────────────────────────

DEFAULT_OUTBOX = Path("C:/analysis/outbox")
DEFAULT_TOOLS = Path("C:/tools")
DEFAULT_PYTHON = "python"

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
    """Execute dynamic analysis in Hyper-V sandbox VM.

    Placeholder — Hyper-V VM management is complex and will be
    implemented once the Tencent Cloud server with Hyper-V is ready.
    """
    dynamic_dir = state.outbox_dir / "dynamic"
    dynamic_dir.mkdir(parents=True, exist_ok=True)

    if mode == "dry_run":
        state.steps_completed.append("dynamic.sandbox (dry_run)")
        return

    vm = vm_config or {}
    vm_enabled = vm.get("enabled", False)

    if not vm_enabled:
        note = (
            "Dynamic analysis not configured. "
            "Set dynamic.enabled=true in job.json and ensure Hyper-V "
            "VM 'malware-sandbox' is set up with clean snapshot."
        )
        (dynamic_dir / "_SKIPPED").write_text(note, encoding="utf-8")
        return

    # TODO: Full VM execution flow (Phase 3 in plan)
    # 1. Restore VM snapshot
    # 2. Start VM
    # 3. Copy sample into VM
    # 4. Start Frida hooks + tshark capture
    # 5. Execute sample with timeout
    # 6. Stop VM, collect results
    # 7. Parse outputs into structured JSON
    (dynamic_dir / "_NOT_IMPLEMENTED").write_text(
        "Dynamic VM execution not yet implemented. "
        "Will integrate Hyper-V + Frida + tshark.",
        encoding="utf-8",
    )


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
