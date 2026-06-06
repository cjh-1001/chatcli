# Reverse Analysis Audit Checklist

This reference defines the detailed audit checklist for the `reverse-audit` skill.

Use this file when reviewing:

- malware analysis reports
- reverse-engineering notes
- IDA or Ghidra findings
- capa / FLOSS / YARA output
- sandbox logs
- IOC lists
- ATT&CK mappings
- detection rules
- behavior claims
- analyst conclusions

The purpose is to identify unsupported claims, improve confidence scoring, and produce safer, more accurate defensive analysis.

---

## 1. Core audit principles

A reverse-analysis conclusion is only as strong as its evidence.

Do not accept a conclusion because:

- a tool said it
- an AV label said it
- the sample looks suspicious
- a string exists
- an import exists
- a known malware family has similar behavior
- the analyst used confident language

Every audited claim should be evaluated by:

- evidence type
- evidence strength
- code reachability
- data-flow support
- dynamic confirmation
- contradiction or absence of evidence
- confidence level
- missing proof

---

## 2. Standard audit object

Use this conceptual schema for each audited claim:

```json
{
  "original_claim": "Claim from the report or analyst",
  "normalized_claim": "Plain behavior statement",
  "category": "execution | persistence | privilege_escalation | defense_evasion | anti_analysis | unpacking | injection | discovery | credential_access | collection | c2 | exfiltration | impact | attribution | detection | unknown",
  "audit_result": "supported | partially_supported | overstated | unsupported | contradicted | needs_more_evidence",
  "recommended_confidence": "confirmed | high | medium | low | unknown",
  "evidence": [
    {
      "type": "dynamic_observation | decompiled_logic | disassembly | api_cluster | string_xref | string_only | import_only | config | network_log | file_event | registry_event | heuristic | analyst_inference | unsupported",
      "value": "Evidence summary",
      "source": "Tool, report section, function, log, or file",
      "strength": "strong | moderate | weak | misleading | irrelevant"
    }
  ],
  "problems": [
    "Overclaiming, missing evidence, ambiguity, or contradiction"
  ],
  "suggested_rewrite": "Safer wording for the report",
  "next_steps": [
    "Safe validation steps"
  ]
}
```

---

## 3. Audit result values

Use exactly one of these values.

### supported

Use when the claim is backed by strong evidence.

Examples:

- Dynamic log confirms registry Run key write.
- Decompiled code clearly passes decoded URL to network API.
- PCAP confirms HTTP request to reported C2 endpoint.
- API cluster and data flow support process injection.
- Ransom note creation and file encryption are dynamically observed.

Wording:

> 该结论有充分证据支持。

---

### partially_supported

Use when part of the claim is supported, but the original wording is too broad.

Examples:

- Report says "steals credentials", but evidence only shows browser credential paths.
- Report says "C2 communication", but evidence only shows URL construction.
- Report says "ransomware", but evidence shows file enumeration and crypto APIs without actual encryption.
- Report says "process injection", but only part of the injection API chain exists.

Wording:

> 该结论部分成立，但原始表述过宽，需要降低置信度或缩小范围。

---

### overstated

Use when the evidence exists but the conclusion is stronger than justified.

Examples:

- String-only evidence is described as confirmed runtime behavior.
- Import-only evidence is described as active behavior.
- Static-only evidence is described as dynamically confirmed.
- Capability is described as executed behavior.
- Possible C2 is described as confirmed C2.

Wording:

> 原始结论存在过度推断，应改为更保守的表述。

---

### unsupported

Use when no adequate evidence is provided.

Examples:

- Claim has no cited evidence.
- Tool label is given without details.
- Family attribution is asserted without code or config similarity.
- IOC is marked malicious without context.
- ATT&CK technique is assigned without behavior evidence.

Wording:

> 当前材料不足以支持该结论。

---

### contradicted

Use when evidence conflicts with the claim.

Examples:

- Report says no network behavior, but sandbox log shows outbound DNS and HTTP.
- Report says persistence exists, but cited registry event is from benign software.
- Report says PE executable, but file type is a script.
- Report says x64, but metadata shows x86.
- Report says no packing, but entropy and import profile strongly suggest packing.

Wording:

> 当前证据与原始结论存在冲突，需要修正。

---

### needs_more_evidence

Use when the claim is plausible but cannot be audited with the provided data.

Examples:

- Decompiled function is missing.
- Sandbox logs are summarized but not included.
- IOC list lacks source context.
- ATT&CK mapping lacks evidence.
- Sample is packed and inner payload was not recovered.
- Dynamic run did not trigger payload path.

Wording:

> 该结论可能成立，但需要补充证据才能确认。

---

## 4. Evidence strength scale

### strong

Use for evidence that directly supports a claim.

Examples:

- Sandbox event showing exact behavior.
- PCAP showing exact network request.
- Decompiled code showing API call and argument.
- Disassembly showing control transfer to decoded payload.
- Extracted config referenced by code.
- File or registry event with timestamp and process context.

### moderate

Use for evidence that supports a claim but lacks one important piece.

Examples:

- API cluster without dynamic confirmation.
- String xref near relevant API.
- Tool finding with function offset and supporting details.
- Decoded config without observed runtime use.
- Command string with likely execution path.

### weak

Use for evidence that suggests capability but not behavior.

Examples:

- String only.
- Import only.
- Generic API name.
- Generic filename.
- Heuristic rule match.
- Suspicious but unreferenced URL.

### misleading

Use for evidence that may point to a wrong conclusion.

Examples:

- Benign library string treated as malware indicator.
- Public DNS resolver treated as C2.
- Test fixture treated as active malware logic.
- Security research code treated as live malicious intent.
- Packer signature treated as family attribution.

### irrelevant

Use for evidence that does not support the claim.

Examples:

- File hash cited to prove persistence.
- URL cited to prove credential theft.
- Crypto import cited to prove exfiltration.
- ATT&CK tag cited as behavior evidence.

---

## 5. Claim audit checklist

For every behavior claim, ask:

1. What exactly is being claimed?
2. Is it a capability, an attempted behavior, or observed execution?
3. Is the evidence static, dynamic, or inferred?
4. Does the evidence prove the claim or only suggest it?
5. Is the relevant code reachable?
6. Are API arguments known?
7. Are strings cross-referenced to code?
8. Is there data flow from source to sink?
9. Was the behavior observed at runtime?
10. Are there contradictions?
11. What confidence is appropriate?
12. What evidence is missing?

---

## 6. Static evidence audit

Static evidence includes:

- imports
- strings
- decoded strings
- sections
- resources
- entropy
- PE/ELF/Mach-O metadata
- decompiled code
- disassembly
- control flow
- data flow
- YARA matches
- capa results
- FLOSS output

Audit questions:

| Question                                        | Why it matters                               |
| ----------------------------------------------- | -------------------------------------------- |
| Is the string referenced by code?               | Unreferenced strings may be decoys or unused |
| Is the import actually called?                  | Imported APIs may be unused                  |
| Are API arguments resolved?                     | API names alone do not prove behavior        |
| Is the function reachable?                      | Dead code should not be treated as behavior  |
| Is the sample packed?                           | Static view may only show loader             |
| Are decoded strings complete?                   | Partial decode can mislead                   |
| Is the tool output mapped to offsets/functions? | Generic findings are weaker                  |
| Is the code path conditional?                   | Behavior may require trigger                 |
| Is there an inner payload?                      | Outer behavior may not represent final stage |

Static-only findings should usually be phrased as:

- "static evidence suggests"
- "the binary contains"
- "the code appears to"
- "this likely indicates"
- "runtime behavior is not confirmed"

---

## 7. Dynamic evidence audit

Dynamic evidence includes:

- process tree
- command lines
- file events
- registry events
- service creation
- scheduled tasks
- network logs
- DNS queries
- HTTP requests
- TLS SNI
- PCAP
- memory dumps
- dropped files
- sandbox reports

Audit questions:

| Question                                            | Why it matters                          |
| --------------------------------------------------- | --------------------------------------- |
| Was the sample executed in an isolated environment? | Host execution is unsafe                |
| Was the correct sample run?                         | Hash mismatch invalidates results       |
| Was the run long enough?                            | Sleep delays can hide behavior          |
| Was networking available or simulated?              | Lack of traffic may be environmental    |
| Were command-line arguments needed?                 | Behavior may require trigger            |
| Did anti-analysis checks fire?                      | Sandbox may miss payload                |
| Are dropped files collected?                        | Child payload may contain main behavior |
| Is process context available?                       | Events need attribution                 |
| Are timestamps correlated?                          | Sequence matters                        |
| Are logs raw or summarized?                         | Summaries may omit evidence             |

Dynamic absence is not proof of absence.

Use wording:

> 动态分析未观察到该行为，但这并不能证明样本不具备该能力；可能存在触发条件、反沙箱或执行路径未覆盖。

---

## 8. Common overclaim patterns

### C2 overclaim

Weak evidence:

- URL string exists
- domain appears in resource
- IP appears in decoded blob
- network import exists

Stronger evidence:

- URL is passed to network API
- decoded config contains endpoint
- dynamic DNS/HTTP/TLS observed
- beacon loop identified
- tasking protocol parsed

Safe rewrite:

> 样本包含疑似 C2 指标，但当前证据尚未确认运行时通信。

---

### Persistence overclaim

Weak evidence:

- Run key string exists
- service name string exists
- `RegSetValueEx` import exists

Stronger evidence:

- Run key path passed to registry write API
- service creation logic confirmed
- scheduled task command built
- dynamic registry/service/task event observed

Safe rewrite:

> 样本包含持久化相关迹象，但尚未确认实际写入或创建持久化项。

---

### Credential theft overclaim

Weak evidence:

- browser path strings
- `CryptUnprotectData` import
- `Login Data` string

Stronger evidence:

- code reads browser database
- code calls DPAPI on extracted values
- dynamic file access observed
- collected credentials are staged or uploaded

Safe rewrite:

> 当前证据支持可能的凭据访问目标，但不足以确认凭据窃取已发生。

---

### Process injection overclaim

Weak evidence:

- `VirtualAlloc` import
- executable memory allocation
- `OpenProcess` string

Stronger evidence:

- complete injection API chain
- target process identified
- memory write to remote process
- remote thread or context manipulation
- dynamic injection telemetry

Safe rewrite:

> 当前证据提示可能存在注入能力，但尚未证明完整进程注入流程。

---

### Ransomware overclaim

Weak evidence:

- crypto imports
- ransom-like words
- file extension strings

Stronger evidence:

- recursive file traversal
- file write/encryption loop
- extension rewrite
- ransom note creation
- shadow copy deletion
- dynamic encrypted files observed

Safe rewrite:

> 样本包含 ransomware-like 指标，但现有证据不足以确认完整勒索行为。

---

### Family attribution overclaim

Weak evidence:

- AV label
- one string
- one domain
- same packer
- similar filename
- generic behavior overlap

Stronger evidence:

- shared config format
- shared protocol
- shared code
- shared encryption routine
- unique mutex/campaign structure
- multiple independent sources
- high-specificity YARA hit

Safe rewrite:

> 当前证据只能说明与该家族存在相似特征，不能确认归属。

---

## 9. Confidence correction guide

Use this table to adjust original report confidence.

| Original evidence                              | Correct confidence     |
| ---------------------------------------------- | ---------------------- |
| Dynamic event directly observed                | confirmed              |
| Decompiled reachable code with clear arguments | high                   |
| API cluster in likely path                     | high or medium         |
| String xref near relevant API                  | medium                 |
| Decoded config without runtime use             | medium                 |
| Tool heuristic with offset details             | medium                 |
| String only                                    | low                    |
| Import only                                    | low                    |
| AV label only                                  | low                    |
| No evidence                                    | unknown or unsupported |
| Contradictory evidence                         | contradicted           |

---

## 10. IOC audit checklist

For each IOC, ask:

1. What is the IOC type?
2. Where did it come from?
3. Is it static, dynamic, or third-party?
4. Is it unique to the sample or generic?
5. Is it shared infrastructure?
6. Is it internal or victim-specific?
7. Is it safe to block?
8. Should it be used for hunting only?
9. Is it redacted if sensitive?
10. Does the report explain context?

IOC quality values:

```text
high_value
medium_value
low_value
do_not_block_blindly
```

### High-value IOC examples

- Sample SHA256
- Dropped payload hash
- Unique mutex
- Unique malware config key
- Unique URI path
- Unique ransom note filename
- Confirmed C2 endpoint
- Campaign-specific user agent

### Do-not-block-blindly examples

- Public DNS resolvers
- CDN domains
- Cloud provider infrastructure
- GitHub, Microsoft, Google, AWS, Azure, Cloudflare shared services
- RFC1918 private IPs
- Localhost
- Sinkhole infrastructure
- Common software update endpoints

---

## 11. ATT&CK mapping audit checklist

For every ATT&CK mapping, ask:

1. What behavior supports this mapping?
2. Is the behavior confirmed or inferred?
3. Is the technique too broad?
4. Is there a more precise technique?
5. Is this a capability or observed use?
6. Is the mapping based only on tool output?
7. Does the report include evidence?
8. Should confidence be lowered?

Audit results:

```text
valid
valid_but_lower_confidence
too_broad
weak_evidence
unsupported
wrong_mapping
```

Example corrections:

| Weak mapping                       | Better approach                                   |
| ---------------------------------- | ------------------------------------------------- |
| `T1059` from `cmd.exe` string only | Do not map unless command execution is shown      |
| `T1055` from `VirtualAlloc` only   | Mark injection unsupported                        |
| `T1486` from crypto import only    | Do not map ransomware impact                      |
| `T1071` from URL string only       | Mark possible C2, not confirmed protocol use      |
| `T1027` from high entropy only     | Map only if obfuscation/packing evidence is clear |

---

## 12. Detection rule audit checklist

When reviewing YARA, Sigma, Suricata, EDR, or SIEM rules, check:

1. Is the rule based on evidence?
2. Is the rule type appropriate?
3. Are strings or conditions specific enough?
4. Does the rule avoid generic library strings?
5. Does it avoid shared infrastructure as a standalone indicator?
6. Is the condition too broad?
7. Is the condition too narrow?
8. Is required telemetry stated?
9. Are false positives listed?
10. Is confidence stated?
11. Is it marked hunting, alerting, or blocking?
12. Has syntax been linted if a linter is available?

Rule audit result values:

```text
acceptable
needs_tuning
too_broad
too_narrow
weak_evidence
syntax_issue
unsupported
```

---

## 13. Standard audit output

Use this table for behavior claims:

| 原始结论    | 证据       | 审计结果   | 建议置信度 | 建议改写                                |
| ----------- | ---------- | ---------- | ---------- | --------------------------------------- |
| 样本连接 C2 | URL 字符串 | overstated | low        | 样本包含疑似 C2 URL，但运行时通信未确认 |

Use this table for evidence quality:

| 证据                        | 类型        | 强度 | 支持的结论 | 问题                       |
| --------------------------- | ----------- | ---- | ---------- | -------------------------- |
| `CreateRemoteThread` import | import_only | weak | 进程注入   | 单独 import 不足以证明注入 |

Use this table for ATT&CK mappings:

| ATT&CK 技术 | 原始映射          | 证据                | 审计结果    | 建议                          |
| ----------- | ----------------- | ------------------- | ----------- | ----------------------------- |
| T1055       | Process Injection | `VirtualAlloc` only | unsupported | 需要完整注入 API 链或动态证据 |

Use this table for IOCs:

| IOC       | 类型 | 价值                 | 风险     | 建议                     |
| --------- | ---- | -------------------- | -------- | ------------------------ |
| `8.8.8.8` | IP   | do_not_block_blindly | 公共 DNS | 不建议阻断，可作为上下文 |

Use this table for gaps:

| 缺口              | 影响                 | 建议补充分析                 |
| ----------------- | -------------------- | ---------------------------- |
| 未确认字符串 xref | 不能证明字符串被使用 | 在 IDA/Ghidra 中检查交叉引用 |

---

## 14. Suggested final structure

Use this structure for reverse-audit answers:

1. **审计结论**
2. **主要风险：哪些结论被高估**
3. **逐条行为审计**
4. **证据质量评估**
5. **IOC 审计**
6. **ATT&CK 映射审计**
7. **检测规则审计** if applicable
8. **静态 / 动态一致性**
9. **缺失证据**
10. **建议改写**
11. **安全补充分析建议**

---

## 15. Safe validation suggestions

Recommended safe next steps:

- Check string cross-references in IDA/Ghidra.
- Verify API arguments in decompiled code.
- Confirm whether suspicious functions are reachable.
- Extract and analyze decoded configuration.
- Re-run static triage on unpacked payload.
- Use isolated sandbox to confirm runtime behavior.
- Collect PCAP, process tree, registry, and file logs.
- Analyze dropped files as separate samples.
- Lint detection rules.
- Score IOCs before blocking.

Avoid suggesting:

- Running sample on host.
- Contacting live C2 from production network.
- Testing stolen credentials.
- Improving evasion, persistence, or payload reliability.
- Deploying or modifying malware.

---

## 16. Final validation checklist

Before answering, verify:

- Did every audited claim get an audit result?
- Did unsupported claims get downgraded?
- Did I separate static, dynamic, and inference?
- Did I identify string-only and import-only overclaims?
- Did I check ATT&CK mappings?
- Did I check IOC quality?
- Did I mention shared infrastructure risk?
- Did I include missing evidence?
- Did I provide safer rewritten wording?
- Did I avoid unsafe malware-improvement guidance?
- Did I provide defensive next steps?