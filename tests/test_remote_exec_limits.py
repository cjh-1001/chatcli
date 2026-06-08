from types import SimpleNamespace
from unittest.mock import patch

from chatcli.remote.ssh_client import _decode_output
from chatcli.tools.remote_exec import RemoteExecTool


def test_remote_exec_truncates_tool_output_and_metadata():
    class FakeSSHClient:
        def __init__(self, **_kwargs):
            pass

        def exec(self, command, timeout=300, workdir=""):
            return 0, "A" * 70000, "B" * 13000

        def close(self):
            pass

    config = SimpleNamespace(
        remote=SimpleNamespace(
            enabled=True,
            host="remote",
            user="Administrator",
            port=22,
            key_file="",
            password="",
            remote_analysis_dir="C:\\analysis",
        )
    )

    with patch("chatcli.remote.ssh_client.SSHClient", FakeSSHClient):
        result = RemoteExecTool(config).execute(command="big-output")

    assert not result.is_error
    assert "[TRUNCATED: remote output was 70000 chars" in result.content
    assert result.metadata["stdout_truncated"]
    assert result.metadata["stderr_truncated"]
    assert result.metadata["stdout_chars"] == 70000
    assert result.metadata["stderr_chars"] == 13000
    assert len(result.metadata["stdout"]) < 61000
    assert len(result.metadata["stderr"]) < 13000


def test_ssh_decode_output_marks_stream_truncation():
    output = _decode_output(b"abc", truncated=True, seen=1000001, limit=3)

    assert output == "abc\n[TRUNCATED: remote stream was 1000001 bytes, kept first 3]"
