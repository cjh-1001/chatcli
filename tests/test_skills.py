from pathlib import Path

from chatcli.skills import rank_skills


ROOT = Path(__file__).resolve().parents[1]
DYNAMIC_SCOPE_QUESTION = (
    "是否需要包含动态分析？如果需要，请指定隔离环境（VM/沙箱/远程一次性环境）"
    "和回滚方式（快照/销毁重建/还原点）；我不会在宿主机执行样本。"
    "如果不需要，我将按静态分析处理。"
)
DYNAMIC_SCOPE_ONE_LINER = f"USER CHOICE REQUIRED: {DYNAMIC_SCOPE_QUESTION}"


def test_tencent_remote_analysis_skill_matches_remote_dynamic_requests():
    workspace = str(ROOT)

    matches = rank_skills("腾讯云 remote_guest 动态分析 网络流量 tshark", workspace)

    assert matches
    names = [skill.name for _, skill in matches]
    assert "tencent-remote-analysis" in names


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
