---
name: reverse-audit
description: Use this skill when the user asks to audit reverse-engineering work, validate malware-analysis conclusions, review IDA/Ghidra/angr/frida output, check whether behavior claims are supported by evidence, compare static and dynamic findings, or identify missing evidence in a suspicious binary analysis. This skill does not perform primary triage; it reviews and strengthens existing reverse-analysis results by checking evidence quality, confidence, gaps, unsafe assumptions, IOC quality, ATT&CK mappings, and report correctness.
---

# Reverse Audit Skill

## Primary goal

Audit reverse-engineering and malware-analysis conclusions for correctness, evidence quality, and safety.

This skill should answer:

1. Which conclusions are well supported?
2. Which conclusions are overstated?
3. Which claims need more evidence?
4. Which tool outputs may be misleading?
5. Which IOCs are high value versus noisy?
6. Which ATT&CK mappings are justified?
7. What safe follow-up analysis should be done?

This skill is a review layer. It should not replace `malware-triage` when the user wants a first-pass sample analysis.

Use `malware-triage` for primary sample triage.  
Use `reverse-audit` for validating, correcting, or strengthening an existing analysis.

---

## When to use this skill

Use this skill when the user asks:

- 帮我审一下这个逆向分析结论
- 这个恶意行为判断有没有证据
- 这个报告哪里不严谨
- 这个 IDA/Ghidra 分析是否可信
- capa/floss/yara/angr/frida 的输出怎么验证
- 这个 ATT&CK 映射是否合理
- IOC 有没有误报风险
- 哪些行为是 confirmed，哪些只是 guessed
- 静态分析和动态分析是否矛盾
- 哪些地方需要补充分析
- 帮我把报告改得更专业
- review this malware report
- audit this reverse engineering result
- validate these behavior claims

---

## Difference from malware-triage

| Skill            | Purpose                                                      |
| ---------------- | ------------------------------------------------------------ |
| `malware-triage` | Analyze a suspicious sample and produce behavior findings    |
| `reverse-audit`  | Review existing findings and check whether they are evidence-backed |

If the user provides only a sample path and asks for analysis, use `malware-triage`.

If the user provides analysis results, tool output, report text, behavior claims, or reverse notes and asks whether they are correct, use `reverse-audit`.

---

## Hard rules

1. Never accept a behavior claim only because a tool reported it.
2. Separate raw evidence, analyst interpretation, and unsupported speculation.
3. Downgrade confidence when code reachability, runtime observation, or data flow is missing.
4. Do not treat strings alone as confirmed behavior.
5. Do not treat imports alone as confirmed behavior.
6. Do not treat ATT&CK mappings as valid unless behavior evidence exists.
7. Do not recommend blind blocking of shared infrastructure.
8. Do not give instructions that improve malware persistence, stealth, evasion, credential theft, exfiltration, or destructive capability.
9. If evidence is insufficient, say so directly.
10. Prefer defensive next steps.

---

## Input types

The user may provide:

- Malware report text
- Tool output
- IDA notes
- Ghidra decompiler output
- capa results
- FLOSS string output
- YARA match output
- Sandbox logs
- PCAP summary
- IOC list
- ATT&CK mapping table
- Decompiled functions
- Disassembly snippets
- Behavior claim table
- A path to existing analysis files

Accept partial input. Do not require a perfect report.

---

## Default audit workflow

### Phase 1: Identify claims

Extract explicit and implicit claims from the provided material.

Claims may include:

- The sample is malware.
- The sample is packed.
- The sample is a loader.
- The sample contacts C2.
- The sample persists.
- The sample injects into another process.
- The sample steals credentials.
- The sample encrypts files.
- The sample exfiltrates data.
- The sample evades analysis.
- The sample belongs to a malware family.
- The sample maps to a specific ATT&CK technique.
- An IOC should be blocked.

For each claim, identify:

- Claim text
- Claimed behavior
- Evidence cited by the original analysis
- Evidence actually present
- Confidence level
- Missing proof

---

### Phase 2: Classify evidence

Classify each evidence item as one of:

| Evidence type       | Meaning                                           |
| ------------------- | ------------------------------------------------- |
| dynamic_observation | Runtime telemetry observed behavior               |
| decompiled_logic    | Decompiled code supports behavior                 |
| disassembly         | Instruction-level support                         |
| api_cluster         | API sequence supports capability                  |
| string_xref         | String is referenced by relevant code             |
| string_only         | String exists but usage is unknown                |
| import_only         | Import exists but usage is unknown                |
| config              | Extracted configuration                           |
| network_log         | DNS, HTTP, TLS, socket, or PCAP evidence          |
| file_event          | Runtime or static file artifact                   |
| registry_event      | Runtime or static registry artifact               |
| heuristic           | Tool inference without direct supporting evidence |
| analyst_inference   | Analyst interpretation                            |
| unsupported         | No evidence found                                 |

Prefer stronger evidence.

Evidence strength order:

1. Dynamic observation
2. Reachable decompiled logic
3. Disassembly with clear call/data flow
4. API cluster in same function or reachable path
5. String with relevant xref
6. Extracted config
7. Tool heuristic with supporting details
8. String only
9. Import only
10. Unsupported assertion

---

### Phase 3: Assign confidence

Use these confidence levels:

| Confidence   | Meaning                                                |
| ------------ | ------------------------------------------------------ |
| confirmed    | Behavior was observed dynamically or directly proven   |
| high         | Strong static evidence with clear code relationship    |
| medium       | Plausible evidence but incomplete proof                |
| low          | Weak evidence such as isolated string/import/heuristic |
| unsupported  | No adequate evidence                                   |
| contradicted | Evidence conflicts with the claim                      |

Do not use `confirmed` for static-only evidence unless the code path and data flow are directly proven.

---

### Phase 4: Detect overclaiming

Flag overclaiming patterns.

| Overclaim                                          | Safer wording                                                |
| -------------------------------------------------- | ------------------------------------------------------------ |
| "This is a stealer" from browser path strings only | "The sample contains possible credential-access indicators"  |
| "This contacts C2" from URL string only            | "The sample contains a possible C2 URL, but runtime communication is unconfirmed" |
| "This is ransomware" from crypto imports only      | "The sample imports crypto APIs; ransomware behavior is not proven" |
| "This injects code" from `VirtualAlloc` only       | "The sample may allocate executable memory; injection is not proven" |
| "This persists" from Run key string only           | "Possible persistence indicator; no registry write confirmed" |
| "This evades EDR" from obfuscation only            | "The sample contains obfuscation or defense-evasion indicators" |
| "This belongs to family X" from one string         | "Family attribution is insufficiently supported"             |

When overclaiming is found, provide corrected wording.

---

### Phase 5: Validate ATT&CK mapping

For each ATT&CK mapping, check:

- Is the mapped behavior actually present?
- Is the evidence strong enough?
- Is the technique too broad?
- Is a more specific technique appropriate?
- Is the mapping based only on a tool heuristic?
- Does the report confuse capability with execution?

Use this table:

| ATT&CK 技术 | 原始映射 | 证据 | 审计结果 | 建议 |
| ----------- | -------- | ---- | -------- | ---- |

Audit result values:

- valid
- valid_but_lower_confidence
- too_broad
- weak_evidence
- unsupported
- wrong_mapping

If evidence is weak, write:

> 当前证据不足以支持该 ATT&CK 映射。

---

### Phase 6: Validate IOC quality

For each IOC, classify:

| IOC value            | Meaning                                                      |
| -------------------- | ------------------------------------------------------------ |
| high_value           | Unique or strongly tied to malicious behavior                |
| medium_value         | Useful but not fully confirmed or not unique                 |
| low_value            | Noisy, generic, local, or weak                               |
| do_not_block_blindly | Shared, public, cloud, CDN, resolver, localhost, private, or risky to block |

Check for:

- Public DNS resolvers
- CDNs
- Cloud provider infrastructure
- GitHub, Microsoft, Google, Cloudflare, AWS, Azure, or similar shared platforms
- RFC1918 private IPs
- Localhost
- Sandbox artifacts
- Sinkholes
- Generic filenames
- Generic registry paths
- Common user agents
- Analyst machine paths
- Victim-specific internal hostnames

Do not recommend blocking shared infrastructure unless the report has strong context and risk acceptance.

Use this table:

| IOC  | 类型 | 原始建议 | 质量评级 | 审计意见 |
| ---- | ---- | -------- | -------- | -------- |

---

### Phase 7: Check static versus dynamic consistency

If both static and dynamic evidence are provided, compare them.

Look for:

- Static C2 string but no dynamic network
- Dynamic network to endpoint not found in static strings
- Static persistence code but no runtime registry write
- Dynamic child process not explained by static code
- Static injection APIs but no injection telemetry
- Sandbox exits early due to anti-analysis
- Dynamic behavior depends on command-line arguments
- Missing trigger condition
- Packed outer loader hides payload behavior

Use this table:

| 项目 | 静态证据 | 动态证据 | 是否一致 | 解释 |
| ---- | -------- | -------- | -------- | ---- |

Consistency values:

- consistent
- partially_consistent
- inconsistent
- not_observed
- insufficient_data

Do not treat absent dynamic behavior as proof of absence.

---

### Phase 8: Identify missing evidence

Common missing evidence:

- Function reachability not proven
- String xref missing
- API call site not reviewed
- Data flow not traced
- Dynamic execution not performed
- Sandbox did not trigger payload
- Network unavailable or sinkholed
- Packed payload not recovered
- Dropped files not collected
- Memory dump missing
- Child payload not separately analyzed
- Config not decoded
- ATT&CK mapping too generic
- IOC not quality-scored
- Report does not separate static and dynamic evidence

Output missing evidence clearly.

---

## Recommended tool usage

Use available ChatCLI tools only when needed.

### For report or claim audit

Recommended tools:

- `behavior_validator`
- `behavior_confidence`
- `behavior_requirements`
- `behavior_taxonomy`
- `evidence_graph`
- `attack_chain`
- `attack_technique`
- `ioc_quality`

### For validating static evidence

Recommended tools:

- `binary_inspect`
- `external_static`
- `reverse_text`
- `data_obfuscation`
- `behavior_capability`
- `command_capability`
- `ida`
- `ghidra`
- `angr_triage`

### For validating dynamic evidence

Only if dynamic logs or sandbox results are already available, or user approved dynamic analysis:

- `remote_consume`
- `remote_watch`
- `remote_vm`
- `ioc_quality`
- `evidence_graph`

Do not execute a sample merely to audit a report unless the user explicitly requests dynamic validation and a safe isolated environment is available.

---

## Output format

Use Chinese when the user writes Chinese.

Default final structure:

1. **审计结论**
2. **主要问题**
3. **逐条行为审计**
4. **证据强度评估**
5. **IOC 审计**
6. **ATT&CK 映射审计**
7. **静态 / 动态一致性**
8. **缺失证据**
9. **建议修改后的报告表述**
10. **下一步安全验证建议**

---

## Required tables

### Behavior audit table

| 原始结论 | 证据 | 审计结果 | 建议置信度 | 建议改写 |
| -------- | ---- | -------- | ---------- | -------- |
|          |      |          |            |          |

Audit result values:

- supported
- partially_supported
- overstated
- unsupported
- contradicted
- needs_more_evidence

---

### Evidence quality table

| 证据 | 类型 | 强度 | 支持的结论 | 问题 |
| ---- | ---- | ---- | ---------- | ---- |
|      |      |      |            |      |

Strength values:

- strong
- moderate
- weak
- misleading
- irrelevant

---

### IOC audit table

| IOC  | 类型 | 价值 | 风险 | 建议 |
| ---- | ---- | ---- | ---- | ---- |
|      |      |      |      |      |

---

### Gap table

| 缺口 | 影响 | 建议补充分析 |
| ---- | ---- | ------------ |
|      |      |              |

---

## Corrective language examples

Use these rewrites when the original report overstates evidence.

### C2

Original:

> 样本连接 C2。

Rewrite if only URL string exists:

> 样本包含疑似 C2 URL 字符串，但当前证据仅证明该字符串存在，尚未确认其被网络 API 使用或在运行时连接。

Rewrite if URL is passed to network API:

> 静态证据高置信度支持样本构造到该 URL 的网络请求，但尚未通过动态流量确认实际连接。

Rewrite if PCAP confirms connection:

> 动态分析确认样本向该 endpoint 发起网络请求。

---

### Persistence

Original:

> 样本会持久化。

Rewrite if only Run key string exists:

> 样本包含 Run key 路径字符串，提示可能存在持久化逻辑，但尚未确认写注册表 API 或运行时写入事件。

Rewrite if write API and xref exist:

> 静态证据高置信度支持样本通过 Run key 实现登录持久化。

Rewrite if sandbox confirms write:

> 动态分析确认样本写入 Run key，实现登录持久化。

---

### Credential access

Original:

> 样本窃取浏览器密码。

Rewrite if only paths exist:

> 样本包含浏览器凭据数据库路径，提示可能针对凭据存储，但尚未确认文件读取、DPAPI 解密或外传逻辑。

Rewrite if path plus SQLite and DPAPI logic exist:

> 静态证据高置信度支持样本尝试访问浏览器凭据数据库并调用 DPAPI 相关逻辑。

Rewrite if dynamic file read is observed:

> 动态分析确认样本访问浏览器凭据数据库。是否成功解密或外传仍需结合后续证据判断。

---

### Injection

Original:

> 样本进程注入。

Rewrite if only one API exists:

> 样本包含注入相关 API，但单个 API 不足以证明进程注入。

Rewrite if API cluster exists:

> 静态证据高置信度支持远程线程注入行为，因为相关 API 组合出现在同一可疑流程中。

Rewrite if dynamic telemetry confirms:

> 动态分析确认样本向目标进程写入内存并创建远程线程。

---

### Ransomware

Original:

> 样本是勒索病毒。

Rewrite if only crypto imports exist:

> 样本导入加密相关 API，但未发现文件遍历、文件重写、勒索说明或备份删除逻辑，因此不足以证明勒索行为。

Rewrite if encryption workflow exists:

> 静态证据支持 ransomware-like 文件加密逻辑，但尚未通过动态分析确认实际加密文件。

Rewrite if dynamic encryption observed:

> 动态分析确认样本加密文件并生成勒索说明。

---

## Family attribution audit

Family attribution requires stronger evidence than behavior mapping.

Do not accept family attribution based only on:

- One string
- One domain
- Similar filename
- Similar packer
- Similar import table
- Generic capability overlap
- AV label

Better evidence includes:

- Shared config format
- Shared protocol
- Shared encryption routine
- Shared unique mutex or campaign structure
- Shared code structure
- Shared builder artifact
- Multiple independent intelligence sources
- High-confidence YARA family rule with unique logic

Use this wording when evidence is weak:

> 当前证据不足以确认样本属于该家族。更稳妥的表述是：该样本与该家族在若干行为或配置特征上相似。

---

## Detection rule audit

When reviewing YARA, Sigma, Suricata, EDR, or SIEM rules, check:

1. Does the rule match evidence-backed behavior?
2. Are strings unique enough?
3. Does the condition require multiple indicators?
4. Are generic library strings excluded?
5. Is file type constrained when appropriate?
6. Are false positives discussed?
7. Is shared infrastructure avoided?
8. Are hashes used only when hash-only hunting is intended?
9. Is the rule syntactically valid?
10. Does the rule align with available telemetry?

Use `detection_lint` if available.

Output:

| 规则 | 问题 | 风险 | 建议修改 |
| ---- | ---- | ---- | -------- |
|      |      |      |          |

---

## Safety boundaries

This skill may discuss:

- Whether evasion exists
- Whether persistence exists
- Whether credential targeting exists
- Whether exfiltration exists
- Whether destructive behavior exists
- How to detect or contain these behaviors

This skill must not help:

- Improve evasion
- Improve persistence
- Improve credential theft
- Improve exfiltration
- Improve destructive behavior
- Operate C2
- Deploy malware
- Bypass EDR or AV in real environments

If the user asks for unsafe changes, say:

> 我不能帮助增强恶意样本的隐蔽性、持久化、绕过、窃密或破坏能力。但我可以帮你审计它当前是否具备这些能力、指出证据强弱，并生成防御检测建议。

---

## Minimum final answer standard

Every reverse audit answer must include:

- Overall audit conclusion
- At least one behavior audit table
- Evidence quality discussion
- Confidence corrections
- Missing evidence
- Safer rewritten claims
- Defensive next steps

If the provided material is too limited, say:

> 当前材料不足以完成完整审计。

Then still provide:

- What can be checked
- What cannot be checked
- What evidence is missing
- What the user should provide next

---

## Final checklist

Before answering, verify:

- Did I distinguish evidence from interpretation?
- Did I downgrade unsupported claims?
- Did I avoid accepting tool output blindly?
- Did I check IOC quality?
- Did I check ATT&CK mapping quality?
- Did I identify missing evidence?
- Did I provide safer rewritten wording?
- Did I avoid unsafe malware-improvement guidance?
- Did I provide defensive next steps?
