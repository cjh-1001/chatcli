"""Compatibility exports for reverse-engineering deobfuscation tools.

The implementation is split under ``chatcli.tools.reverse`` to keep modules
small and easier to maintain. Import these names from this module only for
backward compatibility.
"""

from .reverse.ida_deobfuscate import IdaDeobfuscateTool
from .reverse.encoded_strings import EncodedStringExtractTool
from .reverse.runtime_hooks import RuntimeStringHooksTool

__all__ = [
    "IdaDeobfuscateTool",
    "EncodedStringExtractTool",
    "RuntimeStringHooksTool",
]
