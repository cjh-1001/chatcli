# Common Finding Schema

This reference defines a shared finding schema for all security, repository, file-search, malware-triage, and reverse-audit skills.

Use this schema when converting raw tool output, file matches, repository findings, malware behavior claims, IOC results, or audit notes into structured findings.

The goal is to make findings consistent across skills so they can be passed between workflows.

Example flow:

```text
file-search finds a suspicious executable
  -> repo checks whether it was introduced by a risky commit
  -> malware-triage analyzes the artifact
  -> reverse-audit validates the final behavior claims
```

---

## 1. Core principle

Every finding must be:

- evidence-backed
- risk-scored
- confidence-scored
- tied to a source
- reproducible
- clear about gaps
- safe to report

Do not report a finding as confirmed unless the evidence supports that confidence.

---

## 2. Standard finding object

Use this conceptual schema:

```json
{
  "title": "Short finding title",
  "category": "secret | credential | key_material | suspicious_script | binary_artifact | unsafe_config | dependency_risk | ci_cd_risk | malware_behavior | malware_indicator | ioc | detection_rule | report_quality | evidence_gap | unknown",
  "risk": "critical | high | medium | low | informational | unknown",
  "confidence": "confirmed | high | medium | low | unknown",
  "source_skill": "repo | file-search | malware-triage | reverse-audit | common | unknown",
  "source_tool": "Tool name or null",
  "source_type": "file | commit | diff | static_analysis | dynamic_analysis | report_text | tool_output | manual_review | unknown",
  "path": "File path or null",
  "line": "Line number or null",
  "offset": "Byte offset or null",
  "commit": "Commit hash or null",
  "branch": "Branch name or null",
  "artifact_hash": {
    "md5": "optional",
    "sha1": "optional",
    "sha256": "optional"
  },
  "evidence": [
    {
      "type": "string | regex | import | api | decompile | disassembly | dynamic | config | network | registry | file | commit | heuristic | analyst_inference | unsupported",
      "value": "Redacted evidence value",
      "location": "Where the evidence was found",
      "interpretation": "Why the evidence matters"
    }
  ],
  "impact": "Why this finding matters",
  "recommendation": "Safe defensive next step",
  "gaps": [
    "What is not proven or not checked"
  ],
  "redaction": {
    "redacted": true,
    "reason": "secret | credential | internal_host | private_ip | customer_data | none"
  }
}
```

---

## 3. Required fields

Every finding should include at least:

```text
title
category
risk
confidence
source_skill
source_type
evidence
impact
recommendation
gaps
```

If a field is unavailable, use `null`, `unknown`, or an empty list rather than inventing data.

---

## 4. Risk values

Risk describes potential impact.

Use exactly one of:

```text
critical
high
medium
low
informational
unknown
```

### critical

Use for confirmed severe exposure or dangerous behavior.

Examples:

- production cloud secret committed
- private signing key committed
- CI/CD pipeline exfiltrates secrets
- confirmed destructive malware behavior
- confirmed credential theft behavior
- live production credential exposed

### high

Use for strong evidence of serious risk.

Examples:

- token-like secret in active branch
- suspicious binary executed by CI
- high-confidence process injection behavior
- high-confidence persistence behavior
- sandbox-confirmed C2 traffic
- obfuscated downloader in install script

### medium

Use for plausible but incomplete risk.

Examples:

- suspicious URL in script
- unknown binary in source tree
- credential path strings without confirmed access
- C2-like domain without runtime confirmation
- broad CI/CD permissions
- dependency source changed to unknown Git repository

### low

Use for weak or low-impact findings.

Examples:

- placeholder secret
- generic suspicious keyword
- documentation example
- generic import only
- low-value IOC
- common file path

### informational

Use for context or hygiene observations.

Examples:

- repository has generated files
- file skipped due to size
- sample is packed
- dynamic analysis not performed
- full history not available

### unknown

Use when impact cannot be assessed.

Examples:

- unreadable file
- encrypted archive
- missing commit context
- corrupted sample
- incomplete report

---

## 5. Confidence values

Confidence describes certainty.

Use exactly one of:

```text
confirmed
high
medium
low
unknown
```

### confirmed

Use when direct evidence proves the finding.

Examples:

- sandbox log shows registry write
- private key block is present
- CI workflow clearly sends environment variables externally
- PCAP shows network request
- decompiled reachable code confirms API arguments

### high

Use when evidence strongly supports the finding.

Examples:

- decoded C2 URL is passed to network API
- secret-like token has valid structure and high entropy
- injection API cluster appears in one reachable routine
- binary is referenced by install script
- Run key path is passed to registry write API

### medium

Use when plausible but incomplete.

Examples:

- suspicious URL string without xref
- secret-like value with unknown validity
- browser credential path without confirmed file read
- obfuscated script with unclear trigger
- binary artifact without metadata

### low

Use for weak evidence.

Examples:

- string only
- import only
- generic keyword
- heuristic only
- broad pattern match

### unknown

Use when confidence cannot be assessed.

Examples:

- insufficient data
- tool output missing details
- file unreadable
- contradictory evidence
- analysis incomplete

---

## 6. Category values

Use one primary category per finding.

If a result spans multiple categories, split it into multiple findings.

### secret

Hardcoded API keys, passwords, tokens, database URLs, cloud secrets.

### credential

Session cookies, JWTs, OAuth tokens, refresh tokens, auth headers, password-like values.

### key_material

Private keys, signing keys, certificates with private components, kubeconfigs.

### suspicious_script

PowerShell, shell, batch, macro, or scripting behavior that may download, execute, persist, or exfiltrate.

### binary_artifact

Executable, DLL, driver, archive, macro document, unknown binary blob, or dropped payload.

### unsafe_config

Dangerous settings, broad permissions, insecure deployment values, debug exposure.

### dependency_risk

Suspicious package, unpinned dependency, direct Git dependency, lifecycle hook, registry change.

### ci_cd_risk

Workflow exposure, secret leakage, overbroad permissions, untrusted PR execution, external upload.

### malware_behavior

Evidence-backed malware capability or behavior.

### malware_indicator

IOC or suspicious artifact related to malware, but not necessarily behavior.

### ioc

Domain, IP, URL, hash, mutex, registry key, file path, user-agent, named pipe.

### detection_rule

YARA, Sigma, Suricata, EDR, SIEM, or hunting logic.

### report_quality

Problems in a report, such as overclaiming, weak evidence, missing confidence, or unsupported ATT&CK mapping.

### evidence_gap

Missing data that limits confidence.

### unknown

Use only when no category fits.

---

## 7. Evidence types

Use these evidence types consistently:

| Evidence type     | Meaning                               |
| ----------------- | ------------------------------------- |
| string            | Literal or decoded string             |
| regex             | Pattern match                         |
| import            | Imported function or library          |
| api               | API usage observed in code            |
| decompile         | Decompiled logic                      |
| disassembly       | Instruction-level evidence            |
| dynamic           | Runtime behavior                      |
| config            | Extracted configuration               |
| network           | DNS, HTTP, TLS, socket, PCAP evidence |
| registry          | Registry key or value                 |
| file              | File system artifact                  |
| commit            | Git commit, diff, or branch evidence  |
| heuristic         | Tool-generated inference              |
| analyst_inference | Human interpretation                  |
| unsupported       | Claim has no evidence                 |

Prefer direct evidence over heuristic evidence.

---

## 8. Redaction rules

Never print full secrets or credentials.

Use these redaction formats:

| Value type        | Redaction                            |
| ----------------- | ------------------------------------ |
| API key           | `AKIA...REDACTED...ABCD`             |
| Token             | `tok_...REDACTED...9f2a`             |
| Private key       | `[PRIVATE KEY REDACTED]`             |
| Password          | `[PASSWORD REDACTED]`                |
| JWT               | `eyJ...REDACTED...sig`               |
| Cookie            | `name=[REDACTED]`                    |
| URL with password | `scheme://user:[REDACTED]@host/path` |

For suspicious external IOCs, defang when reporting publicly:

| Original               | Defanged                 |
| ---------------------- | ------------------------ |
| `http://example.com/a` | `hxxp://example[.]com/a` |
| `evil.example.com`     | `evil[.]example[.]com`   |

Do not defang values if the user explicitly needs machine-readable internal JSON for tooling.

---

## 9. Standard finding table

Use this table in human-readable reports:

| 风险 | 类别   | 标题                   | 证据                           | 置信度 | 来源 | 建议         |
| ---- | ------ | ---------------------- | ------------------------------ | ------ | ---- | ------------ |
| high | secret | API token in CI config | `TOKEN=tok_...REDACTED...9f2a` | high   | repo | rotate token |

---

## 10. Standard gap table

Use this table when limitations exist:

| 缺口              | 影响                   | 建议                         |
| ----------------- | ---------------------- | ---------------------------- |
| 未扫描 Git 历史   | 可能遗漏已删除 secret  | 扫描全历史并轮换历史泄露密钥 |
| 未执行动态分析    | 无法确认运行时网络行为 | 在隔离沙箱中观察             |
| 字符串未确认 xref | 无法证明字符串被使用   | 在 IDA/Ghidra 中检查交叉引用 |

---

## 11. Cross-skill transfer rules

### file-search to repo

Use when file-search finds:

- secret-like content in repository
- suspicious binary in repository
- CI/CD workflow issue
- suspicious script in source tree

Transfer fields:

```text
path
line
match_type
evidence
risk
confidence
```

### repo to malware-triage

Use when repo finds:

- suspicious executable
- unknown binary artifact
- macro document
- script payload
- archive containing executable payload
- file that appears to be a malware sample

Transfer fields:

```text
path
hash
file_type
commit
branch
context
```

### malware-triage to reverse-audit

Use when malware-triage produces:

- behavior claims
- IOC table
- ATT&CK mapping
- detection rules
- final report

Transfer fields:

```text
behavior
category
confidence
evidence
ioc
attack_mapping
gaps
```

### reverse-audit to malware-triage

Use when reverse-audit finds:

- missing dynamic evidence
- missing xrefs
- unsupported behavior claims
- child payload not analyzed
- packed sample not unpacked

Transfer fields:

```text
claim
gap
recommended_analysis
required_evidence
```

---

## 12. Final validation checklist

Before producing findings:

- Did every finding include evidence?
- Did I separate risk and confidence?
- Did I redact sensitive values?
- Did I avoid calling weak evidence confirmed?
- Did I include path, line, commit, or source when available?
- Did I identify gaps?
- Did I provide defensive recommendations?
- Did I avoid unsafe operational guidance?