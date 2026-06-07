"""Multi-agent orchestration for remote analysis results.

Defines observer roles that each analyze one dimension of analysis output,
then a correlator that merges findings into a unified report.

Reuses the existing ChildWindow system — each observer is a child agent
with a restricted tool set matching its role.
"""

from __future__ import annotations

from typing import Any

# ── Role definitions ──────────────────────────────────────────────

ANALYSIS_ROLES: dict[str, dict[str, Any]] = {
    "static_observer": {
        "name": "static_observer",
        "description": (
            "Analyze static scan output: binary_inspect, capa, yara, strings, "
            "FLOSS, DIE — form initial behavior hypotheses with confidence labels."
        ),
        "input_patterns": ["static/*.json", "static/*.txt"],
        "allowed_tools": [
            "read_file", "glob", "grep", "json_extract",
            "binary_inspect", "binary_find", "binary_hexdump",
            "behavior_capability_map", "attack_technique_planner",
            "attack_technique_mapper", "command_capability_map",
            "obfuscated_data_map", "encoded_string_extract",
        ],
        "prompt": (
            "You are a static analysis observer. Your task is to analyze the "
            "static scan results from a remote malware analysis job.\n\n"
            "Read all files under static/ in the result directory. Extract:\n"
            "1. File identity: format, architecture, compiler, packer clues\n"
            "2. Imports of interest: network, crypto, process, registry APIs\n"
            "3. Strings: IPs, URLs, commands, registry paths, encoded data\n"
            "4. Capabilities (use behavior_capability_map): what can the binary do?\n"
            "5. Obfuscation: packer, entropy, encoded strings\n\n"
            "Form initial behavior hypotheses. Each hypothesis must have a "
            "confidence label (high/medium/low) and the EXACT evidence that "
            "supports it. Output format:\n"
            "## Static Analysis Summary\n"
            "### Identity\n...\n"
            "### Behavioral Hypotheses\n"
            "- [confidence] hypothesis — evidence: <concrete>\n"
            "### Unresolved Questions\n...\n\n"
            "End with: STATIC OBSERVER COMPLETE"
        ),
    },

    "dynamic_observer": {
        "name": "dynamic_observer",
        "description": (
            "Analyze dynamic execution output: VM execution log, API trace, "
            "process tree, file/registry changes — confirm or refute static hypotheses."
        ),
        "input_patterns": ["dynamic/*.json", "dynamic/*.txt"],
        "allowed_tools": [
            "read_file", "glob", "grep", "json_extract",
            "behavior_capability_map", "attack_chain_builder",
            "behavior_claim_validator", "behavior_coverage_matrix",
            "command_capability_map",
        ],
        "prompt": (
            "You are a dynamic analysis observer. Your task is to analyze the "
            "dynamic execution output from a remote malware analysis job.\n\n"
            "Read all files under dynamic/ in the result directory. Extract:\n"
            "1. Execution summary: did the sample run? exit code, duration\n"
            "2. API call trace: which APIs were actually called? sequence?\n"
            "3. Process behavior: child processes, injection, persistence\n"
            "4. File system changes: created/modified/deleted files\n"
            "5. Registry changes: new keys, modified values, persistence\n\n"
            "CRITICAL: Compare with static hypotheses. For each static hypothesis:\n"
            "- CONFIRMED: dynamic evidence matches — cite exact API call / file path\n"
            "- REFUTED: static suggested X but dynamic shows Y\n"
            "- UNOBSERVED: static hypothesis had no dynamic counterpart\n\n"
            "Output format:\n"
            "## Dynamic Analysis Summary\n"
            "### Execution Facts\n...\n"
            "### Hypothesis Validation\n"
            "- [static hypothesis] → CONFIRMED/REFUTED/UNOBSERVED — reason\n"
            "### New Observations\n...\n\n"
            "End with: DYNAMIC OBSERVER COMPLETE"
        ),
    },

    "network_observer": {
        "name": "network_observer",
        "description": (
            "Analyze network traffic: PCAP parsing, DNS/HTTP/TLS extraction, "
            "C2 communication patterns, network IOC extraction."
        ),
        "input_patterns": ["dynamic/network*.*", "dynamic/*.pcap"],
        "allowed_tools": [
            "read_file", "glob", "grep", "json_extract",
            "ioc_quality_classifier", "ip_lookup",
        ],
        "prompt": (
            "You are a network analysis observer. Your task is to analyze the "
            "network traffic captured during dynamic analysis.\n\n"
            "Read network-related files under dynamic/ in the result directory.\n"
            "Extract:\n"
            "1. DNS queries: domains, timing, responses\n"
            "2. HTTP/HTTPS: URLs, User-Agent, request/response patterns\n"
            "3. TLS: SNI, certificate fingerprints\n"
            "4. Connection summary: unique IPs, ports, protocols\n"
            "5. C2 patterns: beaconing intervals, data exfiltration indicators\n"
            "6. Network IOCs with quality ratings\n\n"
            "Output format:\n"
            "## Network Analysis Summary\n"
            "### Connection Summary\n...\n"
            "### DNS Activity\n...\n"
            "### HTTP/HTTPS\n...\n"
            "### Network IOCs\n"
            "- [type] value — quality: high/medium/low — reason\n"
            "### C2 Assessment\n...\n\n"
            "End with: NETWORK OBSERVER COMPLETE"
        ),
    },

    "correlator": {
        "name": "correlator",
        "description": (
            "Cross-correlate all observer outputs: static hypotheses vs dynamic "
            "evidence vs network data. Find contradictions, fill gaps, produce "
            "unified analysis report."
        ),
        "depends_on": ["static_observer", "dynamic_observer", "network_observer"],
        "allowed_tools": [
            "read_file", "glob", "grep", "json_extract",
            "attack_chain_builder", "evidence_graph",
            "behavior_claim_validator", "behavior_coverage_matrix",
            "ioc_quality_classifier", "attack_technique_mapper",
        ],
        "prompt": (
            "You are the correlation analyst. Your task is to read the outputs "
            "of static_observer, dynamic_observer, and network_observer (check "
            ".chatcli/children/ for their records) and produce a final-report "
            "grade unified malware analysis, not a process summary.\n\n"
            "Your job:\n"
            "1. Cross-reference: for each static hypothesis, check dynamic "
            "   validation result. Mark as confirmed/refuted/unresolved.\n"
            "2. Find contradictions: static says X, dynamic says Y — explain.\n"
            "3. Update the original static behavior chain and capability "
            "   confidence from dynamic evidence. Confirmed runtime behavior "
            "   should be promoted; refuted behavior should be removed or "
            "   demoted; unobserved behavior should remain a gap unless static "
            "   reachability is independently strong.\n"
            "4. Fill gaps: did any observer miss something? Note it.\n"
            "5. Build attack chain: use attack_chain_builder to sequence events.\n"
            "6. Complete behavior coverage matrix: confirm all dimensions checked.\n"
            "7. Extract final IOCs: network + host + behavioral, all quality-rated.\n"
            "8. Assign ATT&CK techniques: map confirmed behaviors to techniques.\n"
            "9. Build a complete evidence-chain table that maps each final "
            "   conclusion to static evidence, dynamic evidence, source "
            "   artifacts, analyst interpretation, confidence, and gaps.\n"
            "10. Produce impact assessment and detection recommendations.\n\n"
            "Output format:\n"
            "## Unified Analysis Report\n"
            "### Executive Summary\n"
            "### Static-Dynamic Validation Matrix\n"
            "### Attack Chain\n"
            "### Confirmed Behaviors (with evidence)\n"
            "### Evidence Chain\n"
            "### Unresolved / Gaps\n"
            "### IOC Summary\n"
            "### ATT&CK Mapping\n"
            "### Detection Recommendations\n"
            "### Confidence Assessment\n\n"
            "The final report must be suitable for the structured malware_report.py "
            "JSON renderer: include conclusion, identity, attack_chain, "
            "key_capabilities, static_tool_evidence, dynamic_validation, "
            "dynamic_evidence, evidence_chain, coverage, iocs, impact, "
            "detection, and limitations when data exists. The final report "
            "visible headings and narrative must be Simplified Chinese. Do not "
            "output only a quality gate checklist, English final-deliverables "
            "section, or TASK COMPLETE note.\n\n"
            "End with: CORRELATOR COMPLETE"
        ),
    },
}


# ── Orchestration helpers ─────────────────────────────────────────


def get_role_order() -> list[str]:
    """Return role names in dependency order (observers first, correlator last)."""
    return ["static_observer", "dynamic_observer", "network_observer", "correlator"]


def get_observer_roles() -> list[str]:
    """Return only the observer roles (no correlator)."""
    return ["static_observer", "dynamic_observer", "network_observer"]


def get_role_allowed_tools(role_name: str) -> list[str]:
    """Get allowed tool names for a role."""
    role = ANALYSIS_ROLES.get(role_name, {})
    return role.get("allowed_tools", [])


def get_role_prompt(role_name: str) -> str:
    """Get the role-specific prompt prefix."""
    role = ANALYSIS_ROLES.get(role_name, {})
    return role.get("prompt", "")
