# Cross-Skill Handoff Rules

This reference defines when one skill should hand analysis context to another skill.

Use this file when a task spans repository review, file search, malware triage, reverse-analysis audit, IOC extraction, or detection engineering.

The goal is to preserve context, avoid duplicated work, and route artifacts to the right skill.

---

## 1. Core principle

Choose the skill based on the object being analyzed.

| Object                                           | Primary skill    |
| ------------------------------------------------ | ---------------- |
| Repository, commit, branch, PR, diff             | `repo`           |
| File names, content patterns, directory search   | `file-search`    |
| Suspicious binary, script payload, macro, sample | `malware-triage` |
| Existing malware report or analysis conclusion   | `reverse-audit`  |
| Shared schema, handoff, formatting               | `common`         |

Do not force every task through `malware-triage`.  
Do not use `repo` for deep malware behavior analysis of a binary.  
Do not use `file-search` for final behavior conclusions.

---

## 2. Handoff from repo to file-search

Use this handoff when repository review needs targeted search.

Examples:

- Search for all `.env` files.
- Search for a leaked token pattern.
- Search for all references to a suspicious domain.
- Search for all binary files.
- Search for CI workflow files.
- Search for dangerous commands across the repo.

Pass this context:

```json
{
  "handoff_from": "repo",
  "handoff_to": "file-search",
  "reason": "targeted repository content search",
  "scope": "repository path, branch, or file list",
  "patterns": ["patterns to search"],
  "exclude_paths": ["optional exclusions"],
  "safety": "do not execute files"
}
```

---

## 3. Handoff from file-search to repo

Use this handoff when search results need repository context.

Examples:

- A secret-like value was found and commit history must be checked.
- A suspicious binary was found and the introducing commit matters.
- A CI workflow contains a suspicious command and needs diff review.
- A file appears risky but repository purpose may explain it.
- A match appears in multiple branches.

Pass this context:

```json
{
  "handoff_from": "file-search",
  "handoff_to": "repo",
  "reason": "repository context required",
  "matches": [
    {
      "path": "file path",
      "line": "line number or null",
      "evidence": "redacted evidence",
      "risk": "risk level",
      "confidence": "confidence level"
    }
  ],
  "questions": [
    "which commit introduced this?",
    "is this file expected?",
    "does history contain the secret?"
  ]
}
```

---

## 4. Handoff from repo to malware-triage

Use this handoff when repository audit finds an artifact that needs sample-level analysis.

Examples:

- New `.exe`, `.dll`, `.sys`, `.scr`, `.jar`, `.apk`, `.so`, `.dylib`
- Macro document
- LNK file
- Encoded script payload
- Archive containing executable payloads
- Obfuscated downloader script
- Unknown high-entropy binary blob
- Binary referenced by installer or CI

Pass this context:

```json
{
  "handoff_from": "repo",
  "handoff_to": "malware-triage",
  "reason": "suspicious artifact requires behavior triage",
  "artifact": {
    "path": "file path",
    "hash": "sha256 if available",
    "file_type": "known or unknown",
    "commit": "introducing commit if available",
    "branch": "branch name if available",
    "repository_context": "why the file is suspicious"
  },
  "safety": "static-only unless dynamic analysis is explicitly approved"
}
```

Recommended wording:

> 仓库审计发现该文件属于可疑二进制/脚本工件，建议交给 `malware-triage` 做样本级静态分析；默认不执行样本。

---

## 5. Handoff from file-search to malware-triage

Use this handoff when file search finds a suspicious standalone artifact.

Examples:

- PE/ELF/Mach-O file
- shellcode-like blob
- encoded PowerShell
- macro payload
- suspicious archive
- script with downloader behavior
- file containing C2-like config and execution logic

Pass this context:

```json
{
  "handoff_from": "file-search",
  "handoff_to": "malware-triage",
  "reason": "search found suspicious artifact",
  "artifact": {
    "path": "file path",
    "line_or_offset": "line or offset if relevant",
    "match_type": "binary | script | macro | config | unknown",
    "evidence": "redacted evidence",
    "risk": "risk level",
    "confidence": "confidence level"
  },
  "safety": "do not execute on host"
}
```

---

## 6. Handoff from malware-triage to reverse-audit

Use this handoff when malware-triage has produced claims that should be reviewed.

Examples:

- Final malware analysis report
- Behavior table
- IOC table
- ATT&CK mapping
- Detection rules
- Family attribution
- Dynamic vs static discrepancy
- High-impact conclusion such as ransomware, credential theft, or C2

Pass this context:

```json
{
  "handoff_from": "malware-triage",
  "handoff_to": "reverse-audit",
  "reason": "validate malware analysis conclusions",
  "report_sections": {
    "sample_identity": {},
    "behavior_claims": [],
    "iocs": [],
    "attack_mapping": [],
    "detection_rules": [],
    "gaps": []
  },
  "audit_focus": [
    "evidence quality",
    "confidence levels",
    "overclaiming",
    "IOC quality",
    "ATT&CK validity"
  ]
}
```

Recommended wording:

> 建议用 `reverse-audit` 复核这些行为结论，尤其是 C2、持久化、窃密、注入和 ATT&CK 映射是否有足够证据。

---

## 7. Handoff from reverse-audit to malware-triage

Use this handoff when audit identifies missing primary analysis.

Examples:

- Need to check string xrefs.
- Need to verify API arguments.
- Need to analyze unpacked payload.
- Need to inspect a dropped file.
- Need to confirm runtime behavior in sandbox.
- Need to rebuild behavior chain.
- Need to rescore IOCs.

Pass this context:

```json
{
  "handoff_from": "reverse-audit",
  "handoff_to": "malware-triage",
  "reason": "additional primary analysis required",
  "missing_evidence": [
    {
      "claim": "claim needing validation",
      "gap": "missing evidence",
      "recommended_analysis": "static or dynamic step",
      "safety": "static-only or isolated dynamic"
    }
  ]
}
```

---

## 8. Handoff from reverse-audit to repo

Use this handoff when a report quality issue is tied to repository context.

Examples:

- Malware report references a file from a repo but commit context is missing.
- A suspicious binary came from a PR.
- A detection rule was added to a repo and needs code-review context.
- A claimed secret leak needs Git history review.

Pass this context:

```json
{
  "handoff_from": "reverse-audit",
  "handoff_to": "repo",
  "reason": "repository context required for audit finding",
  "artifact_or_claim": "summary",
  "needed_context": [
    "commit history",
    "branch",
    "author",
    "diff",
    "file provenance"
  ]
}
```

---

## 9. Handoff to detection rule generation

Detection rule generation may be part of `malware-triage` or `reverse-audit`.

Generate detection rules only after:

- behavior claims are evidence-backed
- IOCs are quality-scored
- false positives are considered
- required telemetry is known
- static and dynamic evidence are separated

Do not generate high-confidence blocking rules from:

- generic strings
- imports only
- public DNS resolvers
- shared cloud/CDN infrastructure
- AV labels only
- unsupported family attribution

---

## 10. Handoff safety rules

Always preserve these safety constraints:

1. Do not execute unknown files during handoff.
2. Do not expose full secrets.
3. Do not upload samples externally unless explicitly requested.
4. Do not contact suspected C2 from production or host networks.
5. Do not improve malware functionality.
6. Do not convert weak evidence into confirmed claims.
7. Clearly state what was and was not analyzed.

---

## 11. Handoff summary format

When handing off, summarize:

| 字段               | 内容                                |
| ------------------ | ----------------------------------- |
| From               | Source skill                        |
| To                 | Target skill                        |
| Reason             | Why handoff is needed               |
| Artifact / Finding | What is being transferred           |
| Evidence           | Key evidence                        |
| Risk               | Risk level                          |
| Confidence         | Confidence level                    |
| Safety             | Constraints                         |
| Next question      | What the target skill should answer |

---

## 12. Final checklist

Before handoff:

- Is the target skill appropriate?
- Is the artifact or finding clearly described?
- Are evidence and gaps included?
- Are secrets redacted?
- Is execution avoided unless explicitly approved?
- Is the expected output clear?