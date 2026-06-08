"""SSH client for remote command execution and file transfer.

Uses paramiko for a pure-Python SSH implementation.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

logger = logging.getLogger("chatcli.remote.ssh")

MAX_STDOUT_BYTES = 1_000_000
MAX_STDERR_BYTES = 200_000


class SSHClient:
    """SSH client wrapping paramiko for remote execution + file transfer."""

    def __init__(
        self,
        host: str,
        user: str = "Administrator",
        port: int = 22,
        key_file: str = "",
        password: str = "",
        timeout: float = 30.0,
    ) -> None:
        self.host = host
        self.user = user
        self.port = port
        self.key_file = key_file
        self.password = password
        self.timeout = timeout
        self._client = None

    def _connect(self):
        """Lazy-connect to the remote host."""
        if self._client is not None:
            return
        import paramiko

        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict = {
            "hostname": self.host,
            "port": self.port,
            "username": self.user,
            "timeout": self.timeout,
            "look_for_keys": False,
            "allow_agent": False,
        }

        if self.key_file:
            key_path = Path(self.key_file).expanduser()
            if key_path.exists():
                connect_kwargs["key_filename"] = str(key_path)
            else:
                # Try loading as a raw key string
                connect_kwargs["pkey"] = paramiko.RSAKey.from_private_key(
                    paramiko.StringIO(self.key_file)
                )
        elif self.password:
            connect_kwargs["password"] = self.password
        else:
            # Fallback to default key lookup
            connect_kwargs["look_for_keys"] = True

        self._client.connect(**connect_kwargs)
        logger.info("SSH connected to %s@%s:%d", self.user, self.host, self.port)

    def exec(
        self,
        command: str,
        timeout: float = 300.0,
        workdir: str = "",
        max_stdout_bytes: int = MAX_STDOUT_BYTES,
        max_stderr_bytes: int = MAX_STDERR_BYTES,
    ) -> tuple[int, str, str]:
        """Execute a command on the remote host.

        Returns (exit_code, stdout, stderr).
        """
        self._connect()
        assert self._client is not None

        if workdir:
            command = f"cd {_quote_cmd(workdir)} && {command}"

        logger.info("SSH exec: %s", command[:200])
        started = time.monotonic()
        chan = self._client.get_transport().open_session()
        chan.settimeout(timeout)
        chan.exec_command(command)

        stdout = bytearray()
        stderr = bytearray()
        stdout_seen = 0
        stderr_seen = 0
        stdout_truncated = False
        stderr_truncated = False

        def collect(target: bytearray, chunk: bytes, seen: int, limit: int) -> tuple[int, bool]:
            if not chunk:
                return seen, seen > limit
            remaining = max(0, limit - len(target))
            if remaining:
                target.extend(chunk[:remaining])
            seen += len(chunk)
            return seen, seen > limit

        while not chan.exit_status_ready():
            if chan.recv_ready():
                stdout_seen, stdout_truncated = collect(
                    stdout,
                    chan.recv(65536),
                    stdout_seen,
                    max_stdout_bytes,
                )
            if chan.recv_stderr_ready():
                stderr_seen, stderr_truncated = collect(
                    stderr,
                    chan.recv_stderr(65536),
                    stderr_seen,
                    max_stderr_bytes,
                )
            if time.monotonic() - started > timeout:
                chan.close()
                return (
                    -1,
                    _decode_output(bytes(stdout), stdout_truncated, stdout_seen, max_stdout_bytes),
                    f"timeout after {timeout:.0f}s",
                )

        # Drain remaining
        while chan.recv_ready():
            stdout_seen, stdout_truncated = collect(
                stdout,
                chan.recv(65536),
                stdout_seen,
                max_stdout_bytes,
            )
        while chan.recv_stderr_ready():
            stderr_seen, stderr_truncated = collect(
                stderr,
                chan.recv_stderr(65536),
                stderr_seen,
                max_stderr_bytes,
            )

        exit_code = chan.recv_exit_status()
        elapsed = time.monotonic() - started
        logger.info(
            "SSH exec done: exit=%d, stdout=%d bytes, stderr=%d bytes, %.1fs",
            exit_code, stdout_seen, stderr_seen, elapsed,
        )
        return (
            exit_code,
            _decode_output(bytes(stdout), stdout_truncated, stdout_seen, max_stdout_bytes),
            _decode_output(bytes(stderr), stderr_truncated, stderr_seen, max_stderr_bytes),
        )

    def put_file(self, local_path: str, remote_path: str) -> bool:
        """Upload a file to the remote host via SFTP."""
        self._connect()
        assert self._client is not None

        local = Path(local_path).expanduser()
        if not local.is_file():
            logger.error("local file not found: %s", local)
            return False

        sftp = self._client.open_sftp()
        try:
            sftp.put(str(local), remote_path)
            logger.info("SFTP put: %s -> %s", local, remote_path)
            return True
        except Exception as exc:
            logger.error("SFTP put failed: %s", exc)
            return False
        finally:
            sftp.close()

    def get_file(self, remote_path: str, local_path: str) -> bool:
        """Download a file from the remote host via SFTP."""
        self._connect()
        assert self._client is not None

        local = Path(local_path).expanduser()
        local.parent.mkdir(parents=True, exist_ok=True)

        sftp = self._client.open_sftp()
        try:
            sftp.get(remote_path, str(local))
            logger.info("SFTP get: %s -> %s", remote_path, local)
            return True
        except Exception as exc:
            logger.error("SFTP get failed: %s", exc)
            return False
        finally:
            sftp.close()

    def list_dir(self, remote_path: str) -> list[dict]:
        """List directory contents on remote host."""
        self._connect()
        assert self._client is not None

        sftp = self._client.open_sftp()
        try:
            items = []
            for entry in sftp.listdir_attr(remote_path):
                items.append({
                    "name": entry.filename,
                    "size": entry.st_size,
                    "is_dir": entry.st_mode & 0o40000 != 0,
                    "mtime": entry.st_mtime,
                })
            return items
        except Exception as exc:
            logger.error("SFTP list_dir failed: %s", exc)
            return []
        finally:
            sftp.close()

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None


def _quote_cmd(s: str) -> str:
    """Minimal shell quoting for cd paths."""
    if '"' in s:
        return "'" + s.replace("'", "\\'") + "'"
    if " " in s:
        return '"' + s + '"'
    return s


def _decode_output(data: bytes, truncated: bool, seen: int, limit: int) -> str:
    text = data.decode("utf-8", errors="replace")
    if not truncated:
        return text
    return text + f"\n[TRUNCATED: remote stream was {seen} bytes, kept first {limit}]"
