"""Inbox Watcher — monitors C:\\analysis\\inbox for new analysis jobs.

Deployed on the Tencent Cloud analysis server. When a new job directory
appears (containing sample/ + job.json), the watcher triggers job_runner
to execute the analysis. Results are written to outbox/<job_id>/ with
_DONE or _FAILED markers.

Runs as a long-lived daemon process. Use Windows Task Scheduler or NSSM
to register as a Windows Service for auto-start.

Usage (on Tencent Cloud server):
    python watcher.py [--interval 5] [--once] [--job-id JOB_ID]

    --interval N    Polling interval in seconds (default 5)
    --once          Process pending jobs and exit
    --job-id ID     Process a specific job and exit
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("chatcli.remote.watcher")

DEFAULT_INBOX = Path("C:/analysis/inbox")
DEFAULT_OUTBOX = Path("C:/analysis/outbox")
DEFAULT_INTERVAL = 5  # seconds between inbox scans


# ── Watcher ──────────────────────────────────────────────────────


@dataclass
class WatcherState:
    """Tracks processed and skipped jobs across polling cycles."""

    inbox: Path
    outbox: Path
    interval: float = DEFAULT_INTERVAL
    processed: set[str] = None  # type: ignore

    def __post_init__(self):
        if self.processed is None:
            self.processed = set()

    @property
    def processed_file(self) -> Path:
        return self.outbox / ".watcher_processed.json"

    def load_state(self) -> None:
        """Restore previously processed job IDs from disk."""
        if self.processed_file.exists():
            try:
                data = json.loads(
                    self.processed_file.read_text(encoding="utf-8")
                )
                self.processed = set(data.get("processed", []))
                logger.info(
                    "Loaded %d processed job IDs from %s",
                    len(self.processed),
                    self.processed_file,
                )
            except Exception:
                logger.warning("Could not load watcher state, starting fresh")
                self.processed = set()

    def save_state(self) -> None:
        """Persist processed job IDs to disk."""
        self.outbox.mkdir(parents=True, exist_ok=True)
        self.processed_file.write_text(
            json.dumps(
                {"processed": sorted(self.processed), "updated": time.time()},
                indent=2,
            ),
            encoding="utf-8",
        )

    def is_done(self, job_id: str) -> bool:
        """Check if a job has already been processed or completed."""
        outbox_dir = self.outbox / job_id
        return (
            job_id in self.processed
            or (outbox_dir / "_DONE").exists()
            or (outbox_dir / "_FAILED").exists()
        )

    def mark_processed(self, job_id: str) -> None:
        self.processed.add(job_id)

    def find_pending_jobs(self) -> list[Path]:
        """Scan inbox for job directories that haven't been processed."""
        if not self.inbox.is_dir():
            return []

        pending = []
        for entry in sorted(self.inbox.iterdir()):
            if not entry.is_dir():
                continue
            job_id = entry.name
            if self.is_done(job_id):
                continue

            job_file = entry / "job.json"
            sample_dir = entry / "sample"
            if job_file.is_file() and sample_dir.is_dir():
                pending.append(entry)
            else:
                logger.debug(
                    "Skipping %s: missing job.json or sample/", job_id
                )

        return pending

    def process_job(self, job_dir: Path) -> bool:
        """Run job_runner for a single job directory.

        Returns True on success (_DONE created), False otherwise.
        """
        job_id = job_dir.name
        logger.info("Processing job: %s", job_id)

        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "chatcli.remote.job_runner",
                    str(job_dir),
                    "--outbox",
                    str(self.outbox),
                ],
                capture_output=True,
                text=True,
                timeout=1800,  # 30 min max per job
            )
            logger.info(
                "job_runner exit=%d stdout=%s stderr=%s",
                result.returncode,
                result.stdout.strip()[:500] if result.stdout else "",
                result.stderr.strip()[:500] if result.stderr else "",
            )

            done_marker = self.outbox / job_id / "_DONE"
            failed_marker = self.outbox / job_id / "_FAILED"

            if done_marker.exists():
                logger.info("Job %s completed successfully", job_id)
                self.mark_processed(job_id)
                return True
            elif failed_marker.exists():
                error = failed_marker.read_text(encoding="utf-8")[:200]
                logger.error("Job %s failed: %s", job_id, error)
                self.mark_processed(job_id)
                return False
            else:
                logger.error(
                    "Job %s finished but no _DONE or _FAILED marker", job_id
                )
                # Write a _FAILED marker ourselves
                (self.outbox / job_id / "_FAILED").write_text(
                    f"job_runner exited {result.returncode} "
                    "without marking completion",
                    encoding="utf-8",
                )
                self.mark_processed(job_id)
                return False

        except subprocess.TimeoutExpired:
            logger.error("Job %s timed out", job_id)
            outbox_dir = self.outbox / job_id
            outbox_dir.mkdir(parents=True, exist_ok=True)
            (outbox_dir / "_FAILED").write_text(
                "Job timed out after 30 minutes", encoding="utf-8"
            )
            self.mark_processed(job_id)
            return False
        except Exception as exc:
            logger.exception("Job %s crashed: %s", job_id, exc)
            self.mark_processed(job_id)
            return False


# ── Main loop ────────────────────────────────────────────────────


def run_watcher(
    inbox: str | Path = DEFAULT_INBOX,
    outbox: str | Path = DEFAULT_OUTBOX,
    interval: float = DEFAULT_INTERVAL,
    once: bool = False,
    job_id: str = "",
) -> None:
    """Main watcher loop."""
    state = WatcherState(
        inbox=Path(inbox),
        outbox=Path(outbox),
        interval=interval,
    )
    state.load_state()

    # Ensure directories exist
    state.inbox.mkdir(parents=True, exist_ok=True)
    state.outbox.mkdir(parents=True, exist_ok=True)

    logger.info(
        "Watcher started: inbox=%s outbox=%s interval=%.1fs mode=%s",
        state.inbox,
        state.outbox,
        interval,
        "once" if once or job_id else "continuous",
    )

    if job_id:
        # Process a specific job
        job_dir = state.inbox / job_id
        if not job_dir.is_dir():
            print(f"Job directory not found: {job_dir}", file=sys.stderr)
            sys.exit(1)
        ok = state.process_job(job_dir)
        state.save_state()
        sys.exit(0 if ok else 1)

    while True:
        pending = state.find_pending_jobs()

        if pending:
            logger.info(
                "Found %d pending job(s): %s",
                len(pending),
                ", ".join(d.name for d in pending),
            )
            for job_dir in pending:
                state.process_job(job_dir)
            state.save_state()
        else:
            logger.debug("No pending jobs")

        if once:
            logger.info("--once mode: exiting after processing batch")
            break

        time.sleep(interval)


# ── CLI ──────────────────────────────────────────────────────────


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="chatcli Inbox Watcher — monitors for new analysis jobs"
    )
    parser.add_argument(
        "--inbox",
        default=str(DEFAULT_INBOX),
        help=f"Inbox directory (default: {DEFAULT_INBOX})",
    )
    parser.add_argument(
        "--outbox",
        default=str(DEFAULT_OUTBOX),
        help=f"Outbox directory (default: {DEFAULT_OUTBOX})",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help=f"Polling interval in seconds (default: {DEFAULT_INTERVAL})",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process pending jobs once and exit",
    )
    parser.add_argument(
        "--job-id",
        default="",
        help="Process a specific job ID and exit",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )

    run_watcher(
        inbox=args.inbox,
        outbox=args.outbox,
        interval=args.interval,
        once=args.once,
        job_id=args.job_id,
    )


if __name__ == "__main__":
    main()
