import subprocess
from unittest.mock import patch

from chatcli.tools.bash import BashTool


def test_bash_tool_truncates_large_output_and_metadata():
    completed = subprocess.CompletedProcess(
        args="big-output",
        returncode=0,
        stdout="A" * 70000,
        stderr="B" * 13000,
    )

    with patch("chatcli.tools.bash.subprocess.run", return_value=completed):
        result = BashTool().execute(command="big-output", workspace=".")

    assert not result.is_error
    assert "[TRUNCATED: command output was 70000 chars" in result.content
    assert result.metadata["stdout_truncated"]
    assert result.metadata["stderr_truncated"]
    assert result.metadata["stdout_chars"] == 70000
    assert result.metadata["stderr_chars"] == 13000
