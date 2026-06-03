"""Tools registry."""

from .base import Tool, ToolResult, ToolRegistry
from .bash import BashTool
from .read import ReadTool
from .write import WriteTool
from .edit import EditTool
from .multi_edit import MultiEditTool
from .glob import GlobTool
from .grep import GrepTool
from .list_dir import ListDirTool
from .web_search import WebSearchTool
from .web_fetch import WebFetchTool
from .git_tools import GitStatusTool, GitDiffTool
from .binary_inspect import BinaryInspectTool
from .binary_search import BinaryFindTool, BinaryHexdumpTool
from .binary_patch import BinaryPatchTool
from .ida import IdaAnalyzeTool, IdaProbeTool
from .ida_focus import IdaFocusDecompileTool
from .external_static import ExternalStaticAnalyzeTool, YaraScanTool, UpxUnpackTool
from .reverse import (
    IdaDeobfuscateTool,
    EncodedStringExtractTool,
    RuntimeStringHooksTool,
)
from .data_obfuscation import ObfuscatedDataMapTool
from .reverse_technique import ReverseTechniqueMapTool
from .reverse_evidence import ReverseEvidenceMapTool
from .internal import ChatcliAutoRequestTool
from .tool_health import ToolHealthCheckTool


def create_registry(config=None) -> ToolRegistry:
    registry = ToolRegistry()
    tools = [
        BashTool(),
        ReadTool(),
        WriteTool(config),
        EditTool(),
        MultiEditTool(),
        GlobTool(),
        GrepTool(config),
        ListDirTool(),
        WebSearchTool(),
        WebFetchTool(),
        GitStatusTool(),
        GitDiffTool(),
        BinaryInspectTool(),
        BinaryFindTool(),
        BinaryHexdumpTool(),
        BinaryPatchTool(),
        IdaProbeTool(getattr(config, "ida_path", "") if config else ""),
        IdaAnalyzeTool(getattr(config, "ida_path", "") if config else ""),
        IdaFocusDecompileTool(getattr(config, "ida_path", "") if config else ""),
        IdaDeobfuscateTool(getattr(config, "ida_path", "") if config else ""),
        EncodedStringExtractTool(),
        ObfuscatedDataMapTool(),
        ReverseTechniqueMapTool(),
        ReverseEvidenceMapTool(),
        RuntimeStringHooksTool(),
        ExternalStaticAnalyzeTool(),
        YaraScanTool(),
        UpxUnpackTool(),
        ToolHealthCheckTool(),
        ChatcliAutoRequestTool(),
    ]
    for tool in tools:
        registry.register(tool)
    return registry


__all__ = [
    "Tool", "ToolResult", "ToolRegistry",
    "BashTool", "ReadTool", "WriteTool", "EditTool",
    "MultiEditTool", "GlobTool", "GrepTool", "ListDirTool",
    "WebSearchTool", "WebFetchTool", "GitStatusTool", "GitDiffTool",
    "BinaryInspectTool", "BinaryFindTool", "BinaryHexdumpTool", "BinaryPatchTool",
    "IdaProbeTool", "IdaAnalyzeTool", "IdaFocusDecompileTool", "ExternalStaticAnalyzeTool", "YaraScanTool",
    "IdaDeobfuscateTool", "EncodedStringExtractTool", "RuntimeStringHooksTool",
    "ObfuscatedDataMapTool", "ReverseTechniqueMapTool", "ReverseEvidenceMapTool",
    "UpxUnpackTool", "ToolHealthCheckTool", "ChatcliAutoRequestTool",
    "create_registry",
]
