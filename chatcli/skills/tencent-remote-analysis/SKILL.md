---
name: tencent-remote-analysis
description: Tencent Cloud Guest Agent workflow for authorized remote malware/sample analysis. Use when a sample is already on a Tencent Cloud server, when remote_guest is configured, when checking server-side analysis tools, or when planning remote static/dynamic analysis with IDA, Ghidra, YARA, Procmon, dumpcap, or tshark.
metadata:
  aliases:
    - tencent-remote
    - remote-malware
    - remote_guest
    - 腾讯云分析
  triggers:
    - Tencent Cloud
    - remote_guest
    - remote sample
    - remote analysis
    - guest agent
    - dumpcap
    - tshark
    - procmon
    - 腾讯云
    - 远端分析
    - 远程样本
    - 服务器工具
    - 动态分析
    - 网络流量
---

# Tencent Remote Analysis Skill

Use this skill for authorized malware/sample analysis through a Tencent Cloud
Windows Guest Agent. This skill describes the overall situation and routing. The
concrete tool invocation details are split into reference files for
maintainability.

## Core Rules

1. Tencent Cloud tool status must be checked with `remote_guest tools`.
   Do not use local `/tools check` to judge server-side tools.
2. If the sample already exists on the server, use `sample_path`; do not upload
   unless the user explicitly asks to upload.
3. Before analysis, determine dynamic scope:
   - If the user explicitly asks for dynamic/sandbox/runtime/network/PCAP/
     Procmon/Sysmon analysis, proceed with dynamic workflow without asking again.
   - If the user explicitly asks for static-only/no execution/no dynamic, run
     static-only.
   - If dynamic scope is not stated, ask once whether dynamic analysis is needed.
     If not included, interpret the task as static analysis only.
4. Never call heavyweight tools directly with unsafe/no-argument commands. In
   particular, do not call Ghidra `analyzeHeadless` directly with no arguments
   through `remote_guest exec`; use `analysis_plan.ghidra=true`.
5. Do not claim observed runtime behavior unless actual dynamic artifacts exist,
   such as PCAP, Procmon/Sysmon logs, or parsed network summaries.

## Reference Map

Read only the files needed for the current task:

- `references/overview.md`: end-to-end remote workflow and decision points.
- `references/tool-inventory.md`: server-side tool expectations and environment
  variables.
- `references/analysis-plans.md`: static, IDA, Ghidra, dynamic, and dry-run plan
  templates.
- `references/static-invocation.md`: static tools and expected output files.
- `references/dynamic-invocation.md`: Procmon, dumpcap, tshark, and dynamic
  collector usage.
- `references/result-handling.md`: status/download, output interpretation, and
  reporting rules.
- `references/recovery.md`: safe recovery commands when the agent or port 8443
  is stuck.

## Minimal Invocation Skeleton

For a server-side sample:

```text
remote_guest action=health
remote_guest action=tools
remote_guest action=prepare sample_path=<server-path> analysis_plan=<plan>
remote_guest action=run case_id=<case-id> mode=real
remote_guest action=status case_id=<case-id>
remote_guest action=download case_id=<case-id>
```

After download, inspect `.chatcli/remote_results/<case-id>/` and base the report
on actual result files.
