"""chatcli — Give any chat LLM local CLI superpowers."""

import sys

if sys.version_info < (3, 10):
    sys.exit(
        f"chatcli requires Python 3.10 or later. "
        f"You are running Python {sys.version_info.major}.{sys.version_info.minor}.\n"
        f"Please upgrade: https://www.python.org/downloads/"
    )

__version__ = "0.1.0"
