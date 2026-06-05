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
from .ip_lookup import IPLookupTool
from .json_extract import JsonExtractTool
from .ioc_quality import IocQualityClassifierTool
from .detection_lint import DetectionRuleLintTool
from .git_tools import GitStatusTool, GitDiffTool
from .binary_inspect import BinaryInspectTool
from .binary_search import BinaryFindTool, BinaryHexdumpTool
from .binary_patch import BinaryPatchTool
from .ida import IdaAnalyzeTool, IdaProbeTool
from .ida_focus import IdaFocusDecompileTool
from .ida_mcp import IdaMcpCallTool, IdaMcpEnsureTool, IdaMcpListToolsTool, IdaMcpProbeTool
from .ghidra import GhidraAnalyzeTool, GhidraProbeTool
from .angr_triage import AngrTriageTool
from .external_static import ExternalStaticAnalyzeTool, YaraScanTool, UpxUnpackTool
from .reverse import (
    EncodedStringExtractTool,
    IdaDeobfuscateTool,
    ReverseEvidenceMapTool,
    ReverseTechniqueMapTool,
    RuntimeStringHooksTool,
)
from .data_obfuscation import ObfuscatedDataMapTool
from .behavior_capability import BehaviorCapabilityMapTool
from .attack_chain import AttackChainBuilderTool
from .evidence_graph import EvidenceGraphTool
from .behavior_validator import BehaviorClaimValidatorTool, BehaviorCoverageMatrixTool
from .command_capability import CommandCapabilityMapTool
from .attack_technique import AttackTechniqueMapperTool
from .attack_technique_plan import AttackTechniquePlannerTool
from .malware_share import MalwareSharePackageTool
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
        IPLookupTool(),
        JsonExtractTool(),
        IocQualityClassifierTool(),
        DetectionRuleLintTool(),
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
        IdaMcpEnsureTool(
            getattr(config, "ida_mcp_url", "") if config else "",
            getattr(config, "ida_mcp_start_command", "") if config else "",
        ),
        IdaMcpProbeTool(getattr(config, "ida_mcp_url", "") if config else ""),
        IdaMcpListToolsTool(getattr(config, "ida_mcp_url", "") if config else ""),
        IdaMcpCallTool(getattr(config, "ida_mcp_url", "") if config else ""),
        GhidraProbeTool(getattr(config, "ghidra_path", "") if config else ""),
        GhidraAnalyzeTool(getattr(config, "ghidra_path", "") if config else ""),
        AngrTriageTool(),
        EncodedStringExtractTool(),
        ObfuscatedDataMapTool(),
        BehaviorCapabilityMapTool(),
        AttackChainBuilderTool(),
        EvidenceGraphTool(),
        BehaviorClaimValidatorTool(),
        BehaviorCoverageMatrixTool(),
        CommandCapabilityMapTool(),
        AttackTechniquePlannerTool(),
        AttackTechniqueMapperTool(),
        MalwareSharePackageTool(),
        ReverseTechniqueMapTool(),
        ReverseEvidenceMapTool(),
        RuntimeStringHooksTool(),
        ExternalStaticAnalyzeTool(config),
        YaraScanTool(config),
        UpxUnpackTool(config),
        ToolHealthCheckTool(config),
        ChatcliAutoRequestTool(),
    ]
    for tool in tools:
        registry.register(tool)
    return registry


__all__ = [
    "Tool", "ToolResult", "ToolRegistry",
    "BashTool", "ReadTool", "WriteTool", "EditTool",
    "MultiEditTool", "GlobTool", "GrepTool", "ListDirTool",
    "WebSearchTool", "WebFetchTool", "IPLookupTool", "JsonExtractTool",
    "IocQualityClassifierTool", "DetectionRuleLintTool",
    "GitStatusTool", "GitDiffTool",
    "BinaryInspectTool", "BinaryFindTool", "BinaryHexdumpTool", "BinaryPatchTool",
    "IdaProbeTool", "IdaAnalyzeTool", "IdaFocusDecompileTool",
    "IdaMcpEnsureTool", "IdaMcpProbeTool", "IdaMcpListToolsTool", "IdaMcpCallTool",
    "GhidraProbeTool", "GhidraAnalyzeTool", "AngrTriageTool",
    "ExternalStaticAnalyzeTool", "YaraScanTool",
    "IdaDeobfuscateTool", "EncodedStringExtractTool", "RuntimeStringHooksTool",
    "ObfuscatedDataMapTool", "BehaviorCapabilityMapTool",
    "AttackChainBuilderTool", "EvidenceGraphTool",
    "BehaviorClaimValidatorTool", "BehaviorCoverageMatrixTool",
    "CommandCapabilityMapTool", "AttackTechniqueMapperTool",
    "AttackTechniquePlannerTool",
    "MalwareSharePackageTool",
    "ReverseTechniqueMapTool", "ReverseEvidenceMapTool",
    "UpxUnpackTool", "ToolHealthCheckTool", "ChatcliAutoRequestTool",
    "create_registry",
]
