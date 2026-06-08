from pathlib import Path

import yaml

from chatcli.skills import rank_skills


ROOT = Path(__file__).resolve().parents[1]
DYNAMIC_SCOPE_QUESTION = (
    "是否需要包含动态分析？如果需要，请指定隔离环境（VM/沙箱/远程一次性环境）"
    "和回滚方式（快照/销毁重建/还原点）；我不会在宿主机执行样本。"
    "如果不需要，我将按静态分析处理。"
)
DYNAMIC_SCOPE_ONE_LINER = f"USER CHOICE REQUIRED: {DYNAMIC_SCOPE_QUESTION}"


def test_all_project_skill_frontmatter_is_valid_and_minimal():
    skill_dirs = [
        path
        for path in (ROOT / "chatcli" / "skills").iterdir()
        if path.is_dir() and (path / "SKILL.md").exists()
    ]

    assert skill_dirs
    for skill_dir in skill_dirs:
        path = skill_dir / "SKILL.md"
        text = path.read_text(encoding="utf-8")
        assert text.startswith("---\n"), f"missing frontmatter in {path}"
        parts = text.split("---", 2)
        assert len(parts) == 3, f"malformed frontmatter in {path}"
        meta = yaml.safe_load(parts[1])
        assert isinstance(meta, dict), f"frontmatter is not a mapping in {path}"
        assert meta.get("name") == skill_dir.name
        assert isinstance(meta.get("description"), str) and meta["description"].strip()
        assert "aliases" not in meta, f"aliases belong in description, not frontmatter: {path}"
        assert "triggers" not in meta, f"triggers belong in description, not frontmatter: {path}"


def test_all_project_skills_have_openai_agent_metadata():
    skill_dirs = [
        path
        for path in (ROOT / "chatcli" / "skills").iterdir()
        if path.is_dir() and (path / "SKILL.md").exists()
    ]

    assert skill_dirs
    for skill_dir in skill_dirs:
        agent = skill_dir / "agents" / "openai.yaml"
        assert agent.exists(), f"missing agents/openai.yaml for {skill_dir.name}"
        meta = yaml.safe_load(agent.read_text(encoding="utf-8"))
        interface = meta.get("interface") if isinstance(meta, dict) else None
        assert isinstance(interface, dict), f"missing interface mapping in {agent}"
        assert interface.get("display_name"), f"missing display_name in {agent}"
        assert interface.get("short_description"), f"missing short_description in {agent}"
        prompt = interface.get("default_prompt")
        assert isinstance(prompt, str) and f"${skill_dir.name}" in prompt


def test_tencent_remote_analysis_skill_matches_remote_dynamic_requests():
    workspace = str(ROOT)

    matches = rank_skills("腾讯云 remote_guest 动态分析 网络流量 tshark", workspace)

    assert matches
    names = [skill.name for _, skill in matches]
    assert "tencent-remote-analysis" in names


def test_tencent_remote_analysis_skill_matches_sequential_batch_requests():
    workspace = str(ROOT)

    matches = rank_skills("把腾讯云服务器 C:\\samples 文件夹里的恶意样本依次分析", workspace)

    assert matches
    names = [skill.name for _, skill in matches]
    assert "tencent-remote-analysis" in names


def test_tencent_remote_dynamic_skill_documents_procmon_and_pcap_interface():
    text = (
        ROOT
        / "chatcli"
        / "skills"
        / "tencent-remote-analysis"
        / "references"
        / "dynamic-invocation.md"
    ).read_text(encoding="utf-8")

    assert "There is no separate `remote_guest action=procmon` endpoint" in text
    assert '"collectors": ["pcap", "procmon", "tshark"]' in text
    assert "dumpcap -> Procmon -> sample" in text
    assert "CHATCLI_TOOL_PROCMON" in text


def test_malware_behavior_validation_skill_matches_static_to_dynamic_requests():
    workspace = str(ROOT)

    matches = rank_skills("根据静态分析发现的 C2 和持久化迹象，用 Wireshark tshark 抓包验证恶意行为", workspace)

    assert matches
    names = [skill.name for _, skill in matches]
    assert "malware-behavior-validation" in names


def test_dynamic_behavior_targeting_skill_matches_targeted_screening_requests():
    workspace = str(ROOT)

    matches = rank_skills(
        "根据静态分析检出的 C2 域名 持久化注册表和进程名，定向筛查 Procmon 和 tshark 数据包",
        workspace,
    )

    assert matches
    names = [skill.name for _, skill in matches]
    assert "dynamic-behavior-targeting" in names


def test_dynamic_behavior_targeting_documents_validation_targets_and_outputs():
    skill = (
        ROOT / "chatcli" / "skills" / "dynamic-behavior-targeting" / "SKILL.md"
    ).read_text(encoding="utf-8")
    playbook = (
        ROOT
        / "chatcli"
        / "skills"
        / "dynamic-behavior-targeting"
        / "references"
        / "targeting-playbook.md"
    ).read_text(encoding="utf-8")

    assert "dynamic_config.validation_targets" in skill
    assert "dynamic_targeting_plan.json" in skill
    assert "Target Plan Schema" in playbook
    assert "network_indicators" in playbook
    assert "watch_processes" in playbook
    assert "tshark -r dynamic/network.pcapng -Y dns" in playbook
    assert "dynamic/targeted_process_tree.txt" in playbook


def test_x64dbg_runtime_analysis_skill_matches_debugger_requests():
    workspace = str(ROOT)

    matches = rank_skills("用 x64dbg 给 decrypt 函数下断点提取运行时字符串", workspace)

    assert matches
    names = [skill.name for _, skill in matches]
    assert "x64dbg-runtime-analysis" in names


def test_x64dbg_runtime_analysis_documents_tool_boundary_and_handoffs():
    skill = (
        ROOT / "chatcli" / "skills" / "x64dbg-runtime-analysis" / "SKILL.md"
    ).read_text(encoding="utf-8")
    malware = (
        ROOT / "chatcli" / "skills" / "malware-triage" / "SKILL.md"
    ).read_text(encoding="utf-8")
    reverse = (
        ROOT / "chatcli" / "skills" / "reverse-audit" / "SKILL.md"
    ).read_text(encoding="utf-8")

    assert "runtime_string_hooks" in skill
    assert "x64dbg` itself is an external debugger" in skill
    assert "not part of that baseline dynamic collector stack" in skill
    assert "Behavior Coverage Matrix" in skill
    assert "Process injection" in skill
    assert "Credential access" in skill
    assert "Anti-analysis" in skill
    assert "Autonomous Generation Decision" in skill
    assert "runtime_string_hooks analysis_dir=<result-dir>" in skill
    assert "Choose Coverage Mode" in skill
    assert "Required Final Summary" in skill
    assert "chatcli_x64dbg_plan.json" in skill
    assert "../x64dbg-runtime-analysis/SKILL.md" in malware
    assert "../x64dbg-runtime-analysis/SKILL.md" in reverse


def test_malware_behavior_validation_documents_hypothesis_testing():
    skill = (
        ROOT / "chatcli" / "skills" / "malware-behavior-validation" / "SKILL.md"
    ).read_text(encoding="utf-8")
    matrix = (
        ROOT
        / "chatcli"
        / "skills"
        / "malware-behavior-validation"
        / "references"
        / "behavior-validation-matrix.md"
    ).read_text(encoding="utf-8")

    assert "static-dynamic validation matrix" in skill
    assert "confirmed, refuted, unobserved, or inconclusive" in skill
    assert "C2 beacon or downloader" in matrix
    assert "tshark -r dynamic/network.pcapng -Y dns" in matrix
    assert "Procmon/Sysmon" in matrix


def test_malware_and_tencent_skills_link_behavior_validation_and_targeting_skills():
    malware = (
        ROOT / "chatcli" / "skills" / "malware-triage" / "SKILL.md"
    ).read_text(encoding="utf-8")
    tencent = (
        ROOT / "chatcli" / "skills" / "tencent-remote-analysis" / "SKILL.md"
    ).read_text(encoding="utf-8")
    behavior_validation = (
        ROOT / "chatcli" / "skills" / "malware-behavior-validation" / "SKILL.md"
    ).read_text(encoding="utf-8")
    dynamic_invocation = (
        ROOT
        / "chatcli"
        / "skills"
        / "tencent-remote-analysis"
        / "references"
        / "dynamic-invocation.md"
    ).read_text(encoding="utf-8")

    assert "../malware-behavior-validation/SKILL.md" in malware
    assert "../malware-behavior-validation/SKILL.md" in tencent
    assert "../dynamic-behavior-targeting/SKILL.md" in malware
    assert "../dynamic-behavior-targeting/SKILL.md" in tencent
    assert "../dynamic-behavior-targeting/SKILL.md" in behavior_validation
    assert "../dynamic-behavior-targeting/SKILL.md" in dynamic_invocation
    assert "Do not run a generic sandbox pass" in malware
    assert "not just a collector toggle" in tencent
    assert "validation_targets" in dynamic_invocation


def test_malware_triage_prefers_current_remote_guest_tools():
    files = [
        ROOT / "chatcli" / "skills" / "malware-triage" / "SKILL.md",
        ROOT / "chatcli" / "skills" / "malware-triage" / "references" / "tool-playbook.md",
        ROOT / "chatcli" / "skills" / "malware-triage" / "references" / "malware-triage-safety.md",
    ]

    for path in files:
        text = path.read_text(encoding="utf-8")
        assert "remote_guest" in text, f"missing remote_guest preference in {path}"
        assert "remote_batch_analyze" in text, f"missing batch remote tool in {path}"
        assert "remote_vm_control" in text, f"missing VM lifecycle tool in {path}"

    playbook = (
        ROOT / "chatcli" / "skills" / "malware-triage" / "references" / "tool-playbook.md"
    ).read_text(encoding="utf-8")
    assert "| 8     | Dynamic analysis          | `remote_guest`, `remote_batch_analyze`, `remote_vm_control` |" in playbook
    assert "Treat `remote_submit`, `remote_watch`, and `remote_consume` as legacy" in (
        ROOT / "chatcli" / "skills" / "malware-triage" / "SKILL.md"
    ).read_text(encoding="utf-8")


def test_reverse_skill_tool_names_use_registered_names():
    files = [
        ROOT / "chatcli" / "skills" / "malware-triage" / "references" / "tool-playbook.md",
        ROOT / "chatcli" / "skills" / "reverse-audit" / "SKILL.md",
    ]
    forbidden_aliases = [
        "binary_formats",
        "external_static",
        "reverse_text",
        "data_obfuscation",
        "behavior_capability",
        "command_capability",
        "behavior_validator",
        "behavior_confidence",
        "behavior_taxonomy",
        "behavior_hierarchy",
        "behavior_requirements",
        "behavior_rules",
        "attack_chain",
        "attack_technique",
        "ioc_quality",
        "detection_lint",
        "malware_share",
        "tool_health",
        "ida",
        "ghidra",
    ]
    malware_required_names = [
        "external_static_analyze",
        "encoded_string_extract",
        "obfuscated_data_map",
        "behavior_capability_map",
        "command_capability_map",
        "behavior_claim_validator",
        "behavior_coverage_matrix",
        "attack_chain_builder",
        "attack_technique_mapper",
        "ioc_quality_classifier",
        "detection_rule_lint",
        "malware_share_package",
        "ida_analyze",
        "ghidra_analyze",
    ]
    reverse_required_names = [
        "external_static_analyze",
        "encoded_string_extract",
        "obfuscated_data_map",
        "behavior_capability_map",
        "command_capability_map",
        "behavior_claim_validator",
        "behavior_coverage_matrix",
        "attack_chain_builder",
        "attack_technique_mapper",
        "ioc_quality_classifier",
        "detection_rule_lint",
        "ida_analyze",
        "ida_focus_decompile",
        "ghidra_analyze",
    ]

    for path in files:
        text = path.read_text(encoding="utf-8")
        for alias in forbidden_aliases:
            assert f"`{alias}`" not in text, f"stale tool alias `{alias}` in {path}"
    text = (
        ROOT / "chatcli" / "skills" / "malware-triage" / "references" / "tool-playbook.md"
    ).read_text(encoding="utf-8")
    for name in malware_required_names:
        assert f"`{name}`" in text, f"missing registered tool `{name}` in malware playbook"

    text = (ROOT / "chatcli" / "skills" / "reverse-audit" / "SKILL.md").read_text(encoding="utf-8")
    for name in reverse_required_names:
        assert f"`{name}`" in text, f"missing registered tool `{name}` in reverse audit skill"


def test_common_tool_registry_reference_is_linked_and_current():
    registry = (
        ROOT / "chatcli" / "skills" / "common" / "references" / "tool-registry.md"
    ).read_text(encoding="utf-8")
    required_names = [
        "read_file",
        "external_static_analyze",
        "encoded_string_extract",
        "behavior_capability_map",
        "behavior_claim_validator",
        "attack_chain_builder",
        "ioc_quality_classifier",
        "detection_rule_lint",
        "remote_guest",
        "remote_batch_analyze",
        "remote_vm_control",
    ]
    for name in required_names:
        assert f"`{name}`" in registry

    linked_files = [
        ROOT / "chatcli" / "skills" / "malware-triage" / "SKILL.md",
        ROOT / "chatcli" / "skills" / "reverse-audit" / "SKILL.md",
        ROOT / "chatcli" / "skills" / "tencent-remote-analysis" / "SKILL.md",
    ]
    for path in linked_files:
        assert "../common/references/tool-registry.md" in path.read_text(encoding="utf-8")


def test_common_tool_registry_documents_functional_chains():
    text = (
        ROOT / "chatcli" / "skills" / "common" / "references" / "tool-registry.md"
    ).read_text(encoding="utf-8")

    assert "## Functional Tool Chains" in text
    assert "Success artifact" in text
    assert "`binary_inspect` -> `external_static_analyze`" in text
    assert "`encoded_string_extract` -> `obfuscated_data_map` -> `ioc_quality_classifier`" in text
    assert "`remote_guest health` -> `tools` -> `prepare` -> `run`" in text
    assert "Do not skip the success artifact check" in text

    playbook = (
        ROOT / "chatcli" / "skills" / "malware-triage" / "references" / "tool-playbook.md"
    ).read_text(encoding="utf-8")
    technique_map = (
        ROOT / "chatcli" / "skills" / "reverse-audit" / "references" / "technique-map.md"
    ).read_text(encoding="utf-8")
    assert "../../common/references/tool-registry.md#functional-tool-chains" in playbook
    assert "../../common/references/tool-registry.md#functional-tool-chains" in technique_map


def test_tencent_remote_result_handling_uses_actual_dynamic_output_names():
    text = (
        ROOT
        / "chatcli"
        / "skills"
        / "tencent-remote-analysis"
        / "references"
        / "result-handling.md"
    ).read_text(encoding="utf-8")

    assert "dynamic/network_summary.txt" in text
    assert "dynamic/network_summary.json" not in text


def test_tencent_remote_tool_inventory_documents_interface_selection():
    text = (
        ROOT
        / "chatcli"
        / "skills"
        / "tencent-remote-analysis"
        / "references"
        / "tool-inventory.md"
    ).read_text(encoding="utf-8")

    assert "## Interface Selection" in text
    assert "remote_guest action=tools" in text
    assert "remote_batch_analyze" in text
    assert "Do not use local `/tools check` for remote availability" in text


def test_reverse_audit_skill_matches_chinese_reverse_analysis_requests():
    workspace = str(ROOT)

    matches = rank_skills("帮我做这个二进制的逆向分析，审计 IDA 结论和 patch 偏移", workspace)

    assert matches
    names = [skill.name for _, skill in matches]
    assert "reverse-audit" in names


def test_malware_triage_prompts_require_dynamic_scope_question_before_triage():
    files = [
        ROOT / "chatcli" / "work_prompts.py",
        ROOT / "chatcli" / "skills" / "malware-triage" / "SKILL.md",
        ROOT / "chatcli" / "skills" / "malware-triage" / "references" / "pre-analysis-checklist.md",
        ROOT / "chatcli" / "skills" / "malware-triage" / "references" / "tool-playbook.md",
    ]

    for path in files:
        text = path.read_text(encoding="utf-8")
        assert DYNAMIC_SCOPE_QUESTION in text, f"missing dynamic scope question in {path}"
        assert DYNAMIC_SCOPE_ONE_LINER in text, f"missing one-line pause question in {path}"

    prompt = (ROOT / "chatcli" / "work_prompts.py").read_text(encoding="utf-8")
    assert "stop before sample triage until the" in prompt
    assert "exception to autonomous work mode" in prompt
    assert "one-line format" in prompt


def test_malware_triage_prompts_do_not_default_unspecified_dynamic_scope_to_static():
    files = [
        ROOT / "chatcli" / "skills" / "malware-triage" / "SKILL.md",
        ROOT / "chatcli" / "skills" / "malware-triage" / "references" / "pre-analysis-checklist.md",
        ROOT / "chatcli" / "skills" / "malware-triage" / "references" / "tool-playbook.md",
        ROOT / "chatcli" / "skills" / "malware-triage" / "references" / "safety-boundaries.md",
    ]
    forbidden = [
        "Default static-only",
        "default static-only",
        "Default to static",
        "assume **static-only**",
        "assume static",
        "infer static-only",
        "stay static-only",
        "If explicit approval is missing",
        "当前默认按静态分析处理",
    ]

    for path in files:
        text = path.read_text(encoding="utf-8")
        for phrase in forbidden:
            assert phrase not in text, f"forbidden phrase {phrase!r} in {path}"


def test_malware_triage_dynamic_scope_question_can_pause_work_loop():
    ui_work = (ROOT / "chatcli" / "ui_work.py").read_text(encoding="utf-8")
    agent = (ROOT / "chatcli" / "agent.py").read_text(encoding="utf-8")

    assert "_run_work_loop(MALWARE_TRIAGE_PROMPT, allow_pauses=True" in ui_work
    assert "max_cycles=max(60" not in ui_work
    assert "Work-mode pause markers must return control to the REPL" in agent
    assert '"USER CHOICE REQUIRED" in upper_text' in agent
    assert '"TASK COMPLETE" in upper_text' in agent
    assert "PHASE_COMPLETE_MARKER" in ui_work
    assert "_needs_phase_pause" in ui_work


def test_malware_triage_prompt_has_clear_phase_and_completion_markers():
    prompt = (ROOT / "chatcli" / "work_prompts.py").read_text(encoding="utf-8")

    assert "PHASE COMPLETE" in prompt
    assert "TASK COMPLETE" in prompt
    assert "Say `TASK COMPLETE` only when the final report is genuinely" in prompt


def test_tencent_remote_dynamic_analysis_requires_post_run_rollback():
    files = [
        ROOT / "chatcli" / "skills" / "tencent-remote-analysis" / "SKILL.md",
        ROOT / "chatcli" / "skills" / "tencent-remote-analysis" / "references" / "dynamic-invocation.md",
        ROOT / "chatcli" / "skills" / "tencent-remote-analysis" / "references" / "result-handling.md",
        ROOT / "chatcli" / "work_prompts.py",
        ROOT / "chatcli" / "skills" / "malware-triage" / "SKILL.md",
    ]

    for path in files:
        text = path.read_text(encoding="utf-8")
        assert "remote_vm_control" in text, f"missing VM rollback tool in {path}"
        assert "restore_snapshot" in text, f"missing snapshot restore in {path}"

    result_handling = (
        ROOT / "chatcli" / "skills" / "tencent-remote-analysis" /
        "references" / "result-handling.md"
    ).read_text(encoding="utf-8")
    assert "Do not restore before downloading results" in result_handling
    assert "post-rollback status check succeeds" in result_handling


def test_dynamic_results_must_revise_final_report_not_process_summary():
    files = [
        ROOT / "chatcli" / "work_prompts.py",
        ROOT / "chatcli" / "skills" / "malware-triage" / "references" / "report-template.md",
        ROOT / "chatcli" / "skills" / "tencent-remote-analysis" / "references" / "result-handling.md",
    ]

    for path in files:
        text = path.read_text(encoding="utf-8")
        assert "静态-动态验证矩阵" in text or "dynamic_validation" in text
        assert "证据链" in text or "evidence_chain" in text
        assert "process report" in text or "process note" in text

    prompt = (ROOT / "chatcli" / "work_prompts.py").read_text(encoding="utf-8")
    assert "`dynamic_validation`, `dynamic_evidence`, and `evidence_chain`" in prompt
    assert "恶意样本静态分析报告" in prompt
    assert "Quality Gate Checklist" in prompt
