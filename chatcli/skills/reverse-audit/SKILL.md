---
name: reverse-audit
description: >-
  Use this skill for authorized defensive reverse engineering and reverse-analysis review:
  逆向分析, 逆向审计, IDA/Ghidra/angr/frida output review, CTF/crackme/local
  challenge analysis, validation-logic reconstruction, solver or patch audit for
  owned/local binaries, malware report evidence validation, ATT&CK/IOC/detection-rule
  audit, static-vs-dynamic consistency checks, and evidence-backed correction of
  reverse-engineering conclusions. Prefer malware-triage for first-pass malware
  behavior triage from only a sample path; use reverse-audit for /reverse tasks,
  function-level analysis, crackme-style reasoning, patch validation, or auditing
  existing findings.
---

# Reverse Audit Skill

Audit and perform authorized reverse analysis with evidence discipline. Use the smallest technique that can prove or disprove the current claim, record durable state, and avoid turning local analysis into real-world offensive capability.

## Scope Decision

Use this skill when the task is any of:

- Review or strengthen an existing reverse-engineering or malware-analysis conclusion.
- Analyze an authorized local binary, CTF/crackme, validation gate, local challenge, patch candidate, or solver target.
- Interpret IDA, Ghidra, angr, Frida, capa, FLOSS, YARA, sandbox, PCAP, or decompiler output.
- Validate behavior claims, IOC quality, ATT&CK mappings, static/dynamic consistency, or detection rules.
- Continue a `/reverse` workflow that needs function-level evidence, obfuscation handling, unpacking plans, or patch audit.

Prefer `malware-triage` when the user only provides a suspicious sample and asks for broad malware behavior triage, IOC extraction, or a final malware report. Hand off back to `malware-triage` when the reverse work has produced enough function-level evidence for behavior reporting.

## Progressive Reference Loading

Read only the reference needed for the current route:

- `references/audit-checklist.md`: use for report review, claim validation, confidence correction, ATT&CK/IOC/detection audit, or static-vs-dynamic consistency.
- `references/rewrite-templates.md`: use before rewriting overclaimed report language or producing final safer wording.
- `references/technique-map.md`: use when choosing the next reverse technique from file/code/data/API/packer signals.
- `references/competition-playbook.md`: use for authorized local CTF/crackme, validation logic, patch audit, solver, anti-debug, anti-VM, custom packer, API hashing, or local instrumentation routes.
- `references/github-reverse-patterns.md`: use when common routes stall or the sample shows advanced patterns such as custom VM, MBA, TLS init, direct syscall, IAT encryption, layered integrity guards, or runtime-only values.

Do not load all references by default.

## Hard Rules

1. Tie every conclusion to evidence: source, offset/function/log entry, and confidence.
2. Separate raw evidence, interpretation, capability, and observed behavior.
3. Never accept strings, imports, AV labels, capa/YARA matches, or ATT&CK tags as confirmed behavior by themselves.
4. Downgrade confidence when reachability, xrefs, API arguments, data flow, or runtime observation are missing.
5. Do not execute unknown samples on the analyst host. Treat dynamic work as sandbox/remote/local-lab only and only when explicitly in scope.
6. For CTF/crackme/local owned binaries, keep patching, hooking, solvers, and instrumentation scoped to the provided artifact.
7. Do not provide persistence, stealth, EDR/AV bypass, credential theft, live C2 operation, destructive behavior, piracy, unauthorized access, or real third-party exploitation guidance.
8. Prefer defensive next steps: validation, containment, hunting, detection, remediation, and safe lab plans.

If the user asks for unsafe improvement, say:

> 我不能帮助增强恶意样本的隐蔽性、持久化、绕过、窃密或破坏能力。但我可以帮你审计它当前是否具备这些能力、指出证据强弱，并生成防御检测建议。

## State And Work Management

For `/reverse` or long-running work:

1. Read `.chatcli/task.md` first.
2. If it contains `## Reverse Analysis State`, treat it as the source of truth.
3. Update the state after meaningful phases with analyzed functions, verified evidence, solver notes, patch offsets, blockers, and child summaries.
4. Do not repeat completed `[x]` entries unless new evidence invalidates them.
5. For large IDA/Ghidra/function work, delegate focused child tasks and keep the main context to decisions, evidence maps, and summaries.
6. Do not claim completion while required child findings are still pending unless they are explicitly non-blocking.

Use this compact state shape when creating or repairing state:

```markdown
## Reverse Analysis State

### Scope
- Target:
- Authorized boundary:
- Dynamic execution:

### Completed Phases
- [ ] Identity and static triage
- [ ] Candidate function map
- [ ] Focused function analysis
- [ ] Claim/confidence audit
- [ ] Patch/solver verification

### Verified Evidence
- source:
- offset/function:
- evidence:
- supports:
- confidence:

### Analyzed Functions
- [ ] address/name:
  role:
  evidence:
  conclusion:
  next:

### Open Questions
- 
```

## Default Workflow

### 1. Classify The Task

Decide the route before tool use:

| Route | Use when | First reference |
| --- | --- | --- |
| Claim/report audit | User gives conclusions, report, IOC list, ATT&CK table, tool output | `audit-checklist.md` |
| Local reverse analysis | User gives binary/function/path and asks how it works | `technique-map.md` |
| CTF/crackme/solver | User asks for flag, password, validation logic, local patch, or challenge solve | `competition-playbook.md` |
| Patch audit | User asks whether bytes/branches/offsets are safe to patch | `competition-playbook.md` |
| Advanced blocker | Packing, custom VM, SMC, API hashing, direct syscall, MBA, integrity guard | `github-reverse-patterns.md` |

If the route is ambiguous, start with static identity and evidence mapping. Ask for scope only when authorization, dynamic execution, or target boundaries are materially unclear.

### 2. Collect Fast Evidence

Start with lightweight static evidence before deep decompilation:

- File identity: path, SHA256 when available, size, format, architecture, entry point.
- Sections, entropy, imports, resources, overlays, TLS/delayed-import clues.
- Strings and encoded strings; always check xrefs before treating them as behavior.
- Packer/protector signs.
- Candidate functions from entry order, xrefs, imports, strings, or existing IDA/Ghidra JSON.

Use broad tools only once per artifact unless the previous output is stale or empty. Prefer focused follow-up tools over repeating broad IDA/Ghidra passes.

### 3. Build The Evidence Queue

Normalize findings into claims or work items:

- claim or question
- evidence source
- offset/function/log
- evidence type
- missing proof
- next smallest technique

Evidence types:

```text
dynamic_observation, decompiled_logic, disassembly, api_cluster, string_xref,
string_only, import_only, config, network_log, file_event, registry_event,
heuristic, analyst_inference, unsupported
```

Confidence levels:

```text
confirmed, high, medium, low, unsupported, contradicted
```

Use `confirmed` only for dynamic observation or directly proven execution/data flow. Static-only evidence is usually `high` at best.

### 4. Choose The Next Technique

Pick the smallest action that can change confidence:

- Need xref? Inspect string/import xrefs.
- Need arguments? Focused decompile or disassembly at the call site.
- Need reachability? Trace caller chain from entry or observed function.
- Need local validation? Reconstruct a bounded scratch solver.
- Need patch audit? Verify exact offset, original bytes, branch semantics, integrity guard risk, and rollback.
- Need unpacking? Map loader/decrypt/OEP first; do not trust packed pseudocode.
- Need runtime-only values? Provide a local-lab hook/dump plan unless execution is explicitly in scope.

### 5. Validate Or Correct Claims

For each claim, decide:

```text
supported, partially_supported, overstated, unsupported, contradicted,
needs_more_evidence
```

Common downgrades:

- URL string only -> possible endpoint, not confirmed C2.
- Run key string only -> possible persistence, not confirmed persistence.
- Browser path only -> possible credential-access targeting, not confirmed theft.
- `VirtualAlloc` only -> memory allocation, not process injection.
- Crypto imports only -> crypto capability, not ransomware.
- AV/family label only -> weak attribution, not family confirmation.

### 6. Produce A Task-Fit Output

Use Chinese when the user writes Chinese.

For report/claim audit, include:

- **审计结论**
- **主要问题**
- **逐条行为审计**
- **证据质量评估**
- **IOC 审计** when IOCs exist
- **ATT&CK 映射审计** when mappings exist
- **检测规则审计** when rules exist
- **静态 / 动态一致性** when both evidence types exist
- **缺失证据**
- **建议改写**
- **安全补充分析建议**

For local reverse/CTF/crackme work, include:

- target identity
- fast-path decision
- key functions/offsets
- validation logic or behavior reconstruction
- solver/patch plan only when evidence supports it
- exact offsets/bytes and rollback for patch audit
- verification status and blockers

## Required Tables When Applicable

Behavior audit:

| 原始结论 | 证据 | 审计结果 | 建议置信度 | 建议改写 |
| --- | --- | --- | --- | --- |

Evidence quality:

| 证据 | 类型 | 强度 | 支持的结论 | 问题 |
| --- | --- | --- | --- | --- |

IOC audit:

| IOC | 类型 | 价值 | 风险 | 建议 |
| --- | --- | --- | --- | --- |

ATT&CK audit:

| ATT&CK 技术 | 原始映射 | 证据 | 审计结果 | 建议 |
| --- | --- | --- | --- | --- |

Patch audit:

| 位置 | 原始字节 | 建议字节 | 语义 | 风险 | 回滚 |
| --- | --- | --- | --- | --- | --- |

Gap table:

| 缺口 | 影响 | 建议补充分析 |
| --- | --- | --- |

## Tool Preferences

Use ChatCLI tools when available:

- Identity/static triage: `binary_inspect`, `external_static`, `reverse_text`.
- Search/verification: `binary_search`, `binary_formats`, focused `read`.
- Obfuscation/data: `data_obfuscation`, `encoded_strings`, reverse data tools.
- IDA/Ghidra: `ida`, `ida_focus`, `ida_script`, `ghidra`, `angr_triage`.
- Claim validation: `behavior_validator`, `behavior_confidence`, `behavior_requirements`, `evidence_graph`, `attack_chain`, `attack_technique`.
- IOC/rule quality: `ioc_quality`, `detection_lint`.
- Patching: `binary_patch` only for authorized local copied artifacts with verified old bytes.

If a tool output is unavailable or inconclusive, continue with the next best evidence and state the limitation.

## Completion Checklist

Before finalizing, verify:

- Evidence and interpretation are separated.
- Unsupported or overbroad claims are downgraded.
- Strings/imports/tool labels are not treated as confirmed behavior.
- Function reachability, xrefs, arguments, and data flow are addressed where relevant.
- IOC quality and shared-infrastructure risk are checked when IOCs exist.
- ATT&CK mappings are tied to behavior evidence when mappings exist.
- Patch/solver claims include exact evidence and verification status.
- Missing evidence and safe next steps are explicit.
- Unsafe malware-improvement or unauthorized-access guidance is excluded.
