# File Search Report Template

This reference defines the standard report format for the `file-search` skill.

Use this template after searching files, directories, repositories, logs, extracted artifacts, or sample collections.

The goal is to produce search results that are structured, reproducible, and safe to share.

---

## 1. Report purpose

A file-search report should answer:

1. What was searched?
2. Which patterns were used?
3. What was found?
4. Which matches are risky?
5. Which matches are weak or informational?
6. Which files were skipped or inaccessible?
7. What should be done next?

Do not execute files during search or reporting.

---

## 2. Minimum report sections

Use this structure:

1. **搜索结论**
2. **搜索范围**
3. **搜索规则 / 模式**
4. **高风险匹配**
5. **中低风险匹配**
6. **IOC / 可疑指标**
7. **敏感信息**
8. **跳过或不可访问内容**
9. **证据与置信度**
10. **建议下一步**

---

## 3. Search summary table

Use this table:

| 字段         | 值   |
| ------------ | ---- |
| 搜索范围     |      |
| 搜索目标     |      |
| 文件总数     |      |
| 已扫描文件   |      |
| 跳过文件     |      |
| 匹配总数     |      |
| 高风险匹配   |      |
| 中风险匹配   |      |
| 低风险匹配   |      |
| 不可访问内容 |      |
| 主要缺口     |      |

If counts are unavailable, write `未统计`.

---

## 4. Pattern table

Use this table to document search patterns:

| 模式名称              | 类型           | 用途         | 说明                        |
| --------------------- | -------------- | ------------ | --------------------------- |
| Secret keywords       | string / regex | 查找凭据     | password, api_key, token    |
| Suspicious PowerShell | string / regex | 查找脚本风险 | -enc, IEX, FromBase64String |
| IOC URL               | regex          | 查找 URL     | http, hxxp, ftp             |
| Binary extensions     | glob           | 查找二进制   | exe, dll, so, jar           |

Pattern types:

```text
string
regex
glob
binary
metadata
hash
heuristic
```

---

## 5. High-risk match table

Use this table for high and critical findings:

| 风险 | 类型   | 文件   | 行/偏移 | 证据                         | 置信度 | 建议              |
| ---- | ------ | ------ | ------- | ---------------------------- | ------ | ----------------- |
| high | secret | `.env` | 12      | `API_KEY=sk...REDACTED...x9` | high   | rotate and remove |

Rules:

- Redact secrets.
- Defang suspicious external IOCs when appropriate.
- Include line or offset if available.
- Include confidence.
- Include safe recommendation.

---

## 6. Medium and low-risk match table

Use this table:

| 风险   | 类型               | 文件         | 行/偏移 | 证据            | 说明                     |
| ------ | ------------------ | ------------ | ------- | --------------- | ------------------------ |
| medium | suspicious_command | `install.sh` | 18      | `curl ... | sh` | download-execute pattern |
| low    | keyword            | `README.md`  | 41      | `password`      | documentation context    |

---

## 7. IOC table

Use this table for indicators:

| IOC             | 类型   | 价值         | 文件         | 行/偏移 | 建议动作 | 说明                        |
| --------------- | ------ | ------------ | ------------ | ------- | -------- | --------------------------- |
| `example[.]com` | domain | medium_value | `config.txt` | 8       | enrich   | suspicious domain in config |

IOC values:

```text
high_value
medium_value
low_value
do_not_block_blindly
```

Suggested actions:

```text
block
monitor
hunt
enrich
internal_only
do_not_block_blindly
```

Do not recommend blocking shared infrastructure as standalone indicators.

---

## 8. Sensitive information table

Use this table for secrets or sensitive data:

| 类型        | 文件     |   行 | 证据                     | 风险     | 建议              |
| ----------- | -------- | ---: | ------------------------ | -------- | ----------------- |
| private_key | `id_rsa` |    1 | `[PRIVATE KEY REDACTED]` | critical | rotate and remove |
| token       | `.npmrc` |    3 | `npm_...REDACTED...a91`  | high     | revoke token      |

Do not print full secret values.

---

## 9. Skipped file table

Use this table:

| 文件          | 原因     | 影响               | 建议                     |
| ------------- | -------- | ------------------ | ------------------------ |
| `large.bin`   | 文件过大 | 可能遗漏二进制指标 | 单独进行二进制扫描       |
| `archive.zip` | 未解压   | 可能遗漏压缩包内容 | 在隔离目录安全展开后扫描 |
| `secret.enc`  | 加密文件 | 内容不可见         | 获取授权密钥后再分析     |

Common skip reasons:

```text
permission denied
file too large
binary skipped
archive not extracted
encrypted
unsupported encoding
symlink skipped
path excluded
read error
```

---

## 10. Evidence and confidence explanation

Use this table:

| 证据类型          | 强度     | 说明                           |
| ----------------- | -------- | ------------------------------ |
| Full private key  | strong   | 直接证明 key material 泄露     |
| Secret-like token | moderate | 结构像 token，但未验证有效性   |
| Generic keyword   | weak     | 仅为关键词匹配                 |
| URL in script     | moderate | 需结合上下文判断               |
| Binary file path  | weak     | 需要文件类型和 hash 进一步判断 |

Confidence values:

```text
confirmed
high
medium
low
unknown
```

Risk values:

```text
critical
high
medium
low
informational
unknown
```

Risk is impact.  
Confidence is certainty.

---

## 11. No-match report

If no matches were found, use:

> 当前搜索范围内未发现匹配项。

Then still include:

| 字段       | 内容 |
| ---------- | ---- |
| 搜索范围   |      |
| 使用模式   |      |
| 已扫描内容 |      |
| 跳过内容   |      |
| 限制       |      |

Do not imply that absence of matches proves absence of risk.

Use wording:

> 未发现匹配不等于不存在风险；该结论仅覆盖当前搜索范围和模式。

---

## 12. Recommended next steps

Choose relevant steps:

- 对高风险 secret 立即轮换。
- 将敏感值移出仓库或文件系统。
- 检查 Git 历史是否曾泄露 secret。
- 对可疑二进制交给 `malware-triage` 静态分析。
- 对可疑脚本进行静态解码，不要直接执行。
- 对 IOC 做威胁情报富化。
- 扩大搜索范围到历史分支、归档文件或子目录。
- 对跳过的大文件、压缩包、加密文件单独处理。
- 添加持续扫描规则。

---

## 13. Final report checklist

Before producing the report:

- Did I state the search scope?
- Did I list patterns used?
- Did I include match counts if available?
- Did I redact secrets?
- Did I defang suspicious IOCs when appropriate?
- Did I include path and line or offset?
- Did I separate high-risk from low-risk matches?
- Did I include skipped files?
- Did I explain confidence?
- Did I provide safe next steps?
- Did I avoid executing files?