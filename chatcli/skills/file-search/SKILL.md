---
name: file-search
description: Use this skill to search for files, content, patterns, or metadata in a filesystem or dataset. It does not modify files or execute code. Focus is on defensive search, evidence collection, and structured reporting.
---

# File Search Skill

## Primary goal

- Locate files or directories by name, pattern, type, or attribute.
- Search file content for strings, patterns, or structures.
- Collect metadata and evidence for analysis or triage.
- Support malware, security, or code auditing without executing files.

---

## When to use this skill

Use this skill when the user asks:

- 在目录里找文件
- 搜索指定字符串
- 搜索可疑宏/脚本
- 找二进制文件或 ELF/PE
- 提取注册表或配置文件
- 搜索 IOC 或路径
- 文件索引、搜索和分类
- 文件内容匹配
- 批量文件筛选
- Review files in a repository or folder
- Search for patterns, hashes, or metadata

---

## Input types

Accept:

- Directory path
- File path
- Filename pattern (glob, regex)
- File content pattern (string, regex, YARA-like)
- File type filter (PE, ELF, Mach-O, scripts)
- Size filter (min/max)
- Date filter (creation/modification)
- Metadata filters (owner, permissions)
- Exclude/include rules

---

## Hard rules

1. Never modify files.
2. Never execute files.
3. Never follow unsafe symbolic links without user approval.
4. Output must be structured (JSON or table).
5. Sensitive content (passwords, tokens, keys) must be redacted or marked internal-only.
6. Always annotate gaps or files not accessible.

---

## Default workflow

### Phase 1: Identify search scope

- Determine root directory or file list.
- Apply include/exclude filters.
- Identify relevant file types.
- Check permissions and access.

---

### Phase 2: File name and metadata search

- Match filename patterns (glob, regex).
- Filter by type, size, timestamps, permissions.
- Collect path, type, size, owner, last modified, hashes if required.
- Annotate inaccessible or unreadable files.

---

### Phase 3: File content search

- Open readable files safely.
- Search for:

  - Strings (keywords, patterns)
  - Regex matches
  - IOCs (IP, URL, domain, hash, mutex)
  - Suspicious macros, scripts, PowerShell commands
  - Embedded configuration or encoded content
  - Comments containing credentials or sensitive info

- Record line numbers, offsets, and evidence type.

---

### Phase 4: Evidence classification

Classify each finding:

| Evidence type  | Meaning                              |
| -------------- | ------------------------------------ |
| string_match   | Literal string match in file content |
| regex_match    | Regex pattern matched                |
| macro          | Detected macro or script             |
| binary_pattern | Byte sequence match in binary        |
| metadata       | File attributes or permissions       |
| hash_match     | File hash or checksum                |
| path_match     | Path or filename match               |
| heuristic      | Tool-inferred potential issue        |
| unsupported    | Could not read or classify           |

---

### Phase 5: Risk and confidence

- **High**: Clear evidence of sensitive or malicious content (e.g., password, private key, known IOC).
- **Medium**: Suspicious content or pattern, partially verified.
- **Low**: Weak pattern, generic string, or low-value file.
- **Unsupported**: File unreadable or evidence not found.
- **Unknown**: File type or content ambiguous.

Record confidence for each match.

---

### Phase 6: Output format

Structured JSON or table:

| File        | Path             | Type | Match type   | Match content | Line/Offset | Confidence | Risk | Notes                   |
| ----------- | ---------------- | ---- | ------------ | ------------- | ----------- | ---------- | ---- | ----------------------- |
| example.txt | /tmp/example.txt | text | string_match | "password"    | 42          | high       | high | Sensitive keyword found |

- Include inaccessible files in `Notes`.
- Include evidence type and confidence.
- Redact sensitive info in external reports.

---

### Phase 7: Gap annotation

- Files or directories inaccessible due to permissions.
- Files skipped due to type filter.
- Files too large to scan safely.
- Symbolic links skipped.
- Compressed or encrypted files not processed.

---

### Phase 8: Recommendations

- Investigate high-risk matches first.
- Remove or secure sensitive files.
- Adjust permissions on exposed files.
- Index remaining files for future search.
- Apply consistent naming and organization for scripts, binaries, and configs.

---

## Safety boundaries

- Do not execute files.
- Do not alter files.
- Do not extract live secrets unless in controlled lab and explicitly approved.
- Treat all matched credentials or keys as sensitive; redact in reports.
- Limit recursive scans to prevent host impact.
- Use safe file opening; avoid untrusted archive extraction unless sandboxed.

---

## Minimum final answer standard

- Summary of files searched.
- Number of matches per type.
- Risk and confidence assessment for each finding.
- Notes on gaps or skipped files.
- Structured JSON or table output.
- Recommendations for remediation.