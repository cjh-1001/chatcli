---
name: tencent-remote-analysis
description: Tencent Cloud Guest Agent workflow for authorized remote malware/sample analysis. Use when a sample or sample directory is already on a Tencent Cloud server; when remote_guest or remote_batch_analyze is configured; when checking server-side analysis tools; or when planning remote static, dynamic, batch, sequential, 依次分析, 逐个分析, 腾讯云分析, 远端分析, 远程样本, 样本目录, server-tool, Guest Agent, IDA, Ghidra, YARA, Procmon, dumpcap, tshark, PCAP, 网络流量, or remote malware workflows.
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
3. If the user asks to analyze a remote directory, batch, queue, or samples
   "one by one" / "依次" / "逐个", use `remote_batch_analyze` instead of
   manually looping through `remote_guest`. If the remote path is missing, ask
   one concise question for the server-side directory or sample path; do not
   ask the user to rewrite the request as flags or JSON.
4. Before analysis, determine dynamic scope:
   - If the user explicitly asks for dynamic/sandbox/runtime/network/PCAP/
     Procmon/Sysmon analysis, proceed with dynamic workflow without asking again.
   - If the user explicitly asks for static-only/no execution/no dynamic, run
     static-only.
   - If dynamic scope is not stated, ask once whether dynamic analysis is needed.
     If not included, interpret the task as static analysis only.
   - If dynamic analysis is included, require a configured rollback method.
     For Tencent Cloud rollback, use `remote.tencent_snapshot_id`.
   - For multiple dynamic samples, do not assume one server state is valid for
     all samples. `remote_batch_analyze` does not restore VM snapshots between
     samples; for strong isolation, process one sample, download results,
     restore snapshot, then continue.
5. Never call heavyweight tools directly with unsafe/no-argument commands. In
   particular, do not call Ghidra `analyzeHeadless` directly with no arguments
   through `remote_guest exec`; use `analysis_plan.ghidra=true`.
6. Do not claim observed runtime behavior unless actual dynamic artifacts exist,
   such as PCAP, Procmon/Sysmon logs, or parsed network summaries.
7. For dynamic validation, read
   `../malware-behavior-validation/SKILL.md` and map each static hypothesis to
   expected PCAP/Procmon/Sysmon/verify artifacts before running the case. The
   dynamic job is a validation plan, not just a collector toggle. If static
   findings contain endpoints, process names, paths, registry keys, service or
   task names, also read `../dynamic-behavior-targeting/SKILL.md` and create a
   targeted screening plan before `remote_guest action=run`.
8. After any remote dynamic analysis, download results first, then restore the
   Tencent Cloud server to the configured rollback snapshot before saying
   `TASK COMPLETE`. If rollback is unavailable or fails, report the blocker and
   do not mark the task complete.
9. During dynamic analysis, use `remote_guest action=monitor case_id=<case-id>`
   as the live telemetry dashboard source for process, network, registry,
   scheduled-task, service, file-activity, and observer-agent status.

## Reference Map

Read only the files needed for the current task:

- `references/overview.md`: end-to-end remote workflow and decision points.
- `references/tool-inventory.md`: server-side tool expectations and environment
  variables.
- `../common/references/tool-registry.md`: registered local ChatCLI tool names;
  use only when the workflow crosses from remote result handling into local
  analysis tools.
- `../malware-behavior-validation/SKILL.md`: static-to-dynamic behavior
  validation planning and PCAP/host telemetry interpretation.
- `../dynamic-behavior-targeting/SKILL.md`: converts static findings into
  targeted PCAP/TShark, Procmon/Sysmon, process, file, registry, and IOC
  screening plans before a dynamic run.
- `references/analysis-plans.md`: static, IDA, Ghidra, dynamic, and dry-run plan
  templates, including batch `remote_batch_analyze` usage.
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
remote_guest action=monitor case_id=<case-id>
remote_guest action=status case_id=<case-id>
remote_guest action=download case_id=<case-id>
remote_vm_control action=stop dry_run=false
remote_vm_control action=restore_snapshot dry_run=false
remote_vm_control action=status
```

After download, inspect `.chatcli/remote_results/<case-id>/` and base the report
on actual result files.

For a server-side sample directory or conversational batch request:

```text
remote_batch_analyze sample_dir=<server-dir> pattern=*.exe analysis_plan=<plan>
```

Use `sample_paths=[...]` instead of `sample_dir` when the user names individual
remote files. Let `remote_batch_analyze` handle sequential execution, waiting,
and downloading.
