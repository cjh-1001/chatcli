# Repository Diff Review Rules

This reference defines focused rules for reviewing pull requests, patches, commit ranges, and diffs.

Use this file with the `repo` skill when the user asks to review:

- a pull request
- a patch
- a commit
- a commit range
- changed files
- diff output
- security impact of changes
- suspicious additions or deletions

This reference is optimized for change review, not full repository audit.

---

## 1. Core principle

A diff review should answer:

1. What changed?
2. Which changes are risky?
3. Are secrets introduced or removed?
4. Are CI/CD or deployment paths affected?
5. Are dependencies or install scripts changed?
6. Are binaries or generated artifacts added?
7. Are suspicious commands introduced?
8. What should be reviewed before merge?

Do not execute changed code.

---

## 2. Standard diff finding object

Use this conceptual schema:

```json
{
  "commit": "Commit hash or PR identifier",
  "file": "Changed file path",
  "change_type": "added | modified | deleted | renamed | permission_change | binary_change",
  "category": "secret | ci_cd_risk | dependency_risk | suspicious_script | binary_artifact | unsafe_config | malware_indicator | privacy_risk | review_gap | unknown",
  "risk": "critical | high | medium | low | informational | unknown",
  "confidence": "confirmed | high | medium | low | unknown",
  "evidence": "Redacted diff evidence",
  "line": "Added or modified line number when available",
  "impact": "Why this change matters",
  "recommendation": "Safe review or remediation action",
  "merge_blocker": true
}
```

---

## 3. High-risk diff patterns

Treat these as high priority:

- secret added
- private key added
- `.env` added
- CI workflow added or modified
- deployment script modified
- dependency install hook added
- binary executable added
- script downloads and executes remote content
- command exfiltrates environment variables
- lockfile-only dependency change
- Docker base image changed to unknown source
- broad CI/CD permissions added
- `pull_request_target` introduced
- code obfuscation added
- minified file changed without source
- security checks disabled
- logging added for secrets
- authentication or authorization logic weakened

---

## 4. Secret diff review

Look for added or modified lines containing:

```text
password
passwd
secret
secret_key
api_key
access_token
refresh_token
client_secret
private_key
jwt_secret
database_url
connection_string
AWS_SECRET_ACCESS_KEY
GOOGLE_APPLICATION_CREDENTIALS
AZURE_CLIENT_SECRET
GITHUB_TOKEN
NPM_TOKEN
PYPI_TOKEN
```

Risk guide:

| Diff evidence                        | Risk          | Merge blocker               |
| ------------------------------------ | ------------- | --------------------------- |
| Real-looking production secret added | critical      | yes                         |
| Private key added                    | critical      | yes                         |
| Secret removed from current file     | high          | maybe; history still leaked |
| Placeholder secret in example file   | low           | no                          |
| Secret variable name with no value   | informational | no                          |

Important:

> Removing a secret in a later commit does not make it safe. If it entered Git history, rotate it.

Recommended review comment:

> 该变更疑似引入 secret。建议立即从代码中移除、轮换凭据，并检查 Git 历史和 CI 日志是否已暴露。

---

## 5. CI/CD diff review

Inspect changes to:

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

Flag additions of:

```text
permissions: write-all
pull_request_target
secrets.
printenv
env
set -x
curl -X POST
upload-artifact
docker login
kubectl
helm
terraform apply
```

High-risk CI patterns:

| Pattern                                        | Risk           |
| ---------------------------------------------- | -------------- |
| `pull_request_target` with checkout of PR code | high           |
| `permissions: write-all`                       | medium to high |
| unpinned third-party action                    | medium         |
| secrets exposed to PR workflow                 | high           |
| environment variables uploaded externally      | critical       |
| deployment from untrusted branch               | high           |
| workflow added by unrelated contributor        | medium to high |

Recommended review comment:

> 该 CI/CD 变更可能扩大权限或暴露 secret。建议使用最小权限、固定第三方 action 到 SHA，并限制 untrusted PR 对 secret 的访问。

---

## 6. Dependency diff review

Inspect changes to:

```text
package.json
package-lock.json
yarn.lock
pnpm-lock.yaml
requirements.txt
pyproject.toml
poetry.lock
Pipfile
Pipfile.lock
setup.py
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

- new dependency
- dependency source changed
- version pin loosened
- lifecycle script added
- install script added
- direct Git dependency
- HTTP URL dependency
- registry changed
- lockfile changed without manifest
- manifest changed without lockfile
- Docker base image changed
- package token added

Risk guide:

| Change                              | Risk           |
| ----------------------------------- | -------------- |
| install hook executes remote script | high           |
| dependency from unknown Git repo    | medium to high |
| HTTP package source                 | medium         |
| lockfile-only change                | medium         |
| version range loosened              | medium         |
| normal patch update                 | low to medium  |

Recommended review comment:

> 该依赖变更存在供应链风险。建议确认包来源、维护状态、安装脚本和 lockfile 是否与 manifest 一致。

---

## 7. Script diff review

Flag added or modified script lines containing:

```text
curl ... | sh
wget ... | bash
Invoke-Expression
IEX
FromBase64String
powershell -enc
certutil -urlcache
bitsadmin
mshta
rundll32
regsvr32
schtasks
reg add
systemctl enable
launchctl load
crontab
chmod +x /tmp
nc -e
```

Risk guide:

| Change                              | Risk   |
| ----------------------------------- | ------ |
| download and execute remote script  | high   |
| encoded PowerShell added            | high   |
| persistence command added           | high   |
| script prints environment variables | high   |
| admin automation change             | medium |
| documentation example               | low    |

Recommended review comment:

> 该脚本变更新增了高风险命令模式。建议确认触发路径、运行权限、网络 endpoint 和是否存在替代的安全实现。

---

## 8. Binary artifact diff review

Flag added or modified:

```text
*.exe
*.dll
*.sys
*.scr
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
```

Collect:

- file path
- size
- hash if available
- whether source exists
- whether referenced by scripts
- whether executable
- whether expected in repo
- introducing commit

Risk guide:

| Change                                        | Risk           |
| --------------------------------------------- | -------------- |
| executable added and referenced by install/CI | high           |
| driver added                                  | high           |
| macro document added                          | medium to high |
| archive containing executable                 | medium to high |
| binary asset with explanation                 | low to medium  |
| image/font asset                              | low            |

Recommended review comment:

> 该变更新增二进制工件。建议在合并前确认来源、hash、构建过程和是否应改为 release artifact，而不是直接提交到源码仓库。

---

## 9. Auth and permission diff review

Flag changes to:

- login logic
- authorization checks
- role checks
- token validation
- session handling
- password reset
- MFA
- CORS
- CSRF
- cookie flags
- encryption settings
- debug bypasses
- admin-only routes

High-risk patterns:

```text
if auth_disabled
skip_auth
debug = true
verify = false
allow_all
role == "admin" bypass
cors allow *
secure = false
httponly = false
```

Risk guide:

| Change                                  | Risk           |
| --------------------------------------- | -------------- |
| authentication bypass added             | critical       |
| authorization check removed             | critical       |
| token verification disabled             | high           |
| broad CORS allowed                      | medium to high |
| debug mode enabled in production config | high           |
| test-only bypass in test path           | low to medium  |

Recommended review comment:

> 该变更影响认证或授权边界，需要安全负责人复核，并确认是否只在测试环境生效。

---

## 10. Docker and deployment diff review

Inspect:

```text
Dockerfile
docker-compose.yml
kubernetes manifests
helm charts
terraform
ansible
cloud-init
systemd service files
```

Flag:

- root user
- privileged container
- host networking
- hostPath mount
- secrets in env
- latest tag
- curl-to-shell install
- package signature verification disabled
- exposed admin ports
- broad IAM permissions
- public bucket or security group
- TLS verification disabled

Risk guide:

| Change                        | Risk     |
| ----------------------------- | -------- |
| privileged container added    | high     |
| hostPath mount added          | high     |
| production secret in manifest | critical |
| public security group opened  | high     |
| image tag changed to latest   | medium   |
| root user remains             | medium   |

Recommended review comment:

> 该部署变更扩大了运行权限或暴露面。建议最小化权限、固定镜像版本，并将 secret 移到受控 secret manager。

---

## 11. Obfuscation and generated-code diff review

Flag:

- minified JavaScript changed without source
- generated file changed without generator input
- large single-line code blob
- base64 blob added
- hex blob added
- eval or dynamic import added
- reflection-heavy code added
- compressed payload added
- encoded PowerShell added

Risk guide:

| Change                            | Risk           |
| --------------------------------- | -------------- |
| obfuscated code in install path   | high           |
| minified code without source      | medium to high |
| generated file with source change | low to medium  |
| base64 test fixture               | low            |
| encoded payload executed          | high           |

Recommended review comment:

> 该变更新增了难以审查的混淆或生成内容。建议提供源文件、生成步骤和可复现构建说明。

---

## 12. Deletion review

Deleted lines can still matter.

Flag deletions of:

- security checks
- input validation
- authentication
- authorization
- audit logging
- TLS verification
- dependency pinning
- secret scanning
- CI checks
- tests around security-sensitive logic

Risk guide:

| Deletion                 | Risk           |
| ------------------------ | -------------- |
| auth check removed       | critical       |
| validation removed       | high           |
| TLS verification removed | high           |
| CI security scan removed | medium to high |
| old unused code removed  | low            |

Recommended review comment:

> 该删除影响安全控制，应确认是否有替代控制或测试覆盖。

---

## 13. Diff review output tables

### Summary table

| 字段             | 值   |
| ---------------- | ---- |
| 审查范围         |      |
| 变更文件数       |      |
| 高风险变更       |      |
| 中风险变更       |      |
| Secret 相关变更  |      |
| CI/CD 变更       |      |
| 依赖变更         |      |
| 二进制变更       |      |
| 建议是否阻塞合并 |      |

### Finding table

| 风险 | 文件                           |   行 | 类别       | 证据                     | 置信度 | 是否阻塞 |
| ---- | ------------------------------ | ---: | ---------- | ------------------------ | ------ | -------- |
| high | `.github/workflows/deploy.yml` |   22 | ci_cd_risk | `permissions: write-all` | high   | yes      |

### Review comment table

| 文件   |   行 | 建议评论                        |
| ------ | ---: | ------------------------------- |
| `.env` |    5 | 疑似新增 secret，建议移除并轮换 |

---

## 14. Merge decision guidance

Use these merge recommendations:

| Recommendation           | Meaning                                 |
| ------------------------ | --------------------------------------- |
| block                    | Do not merge until fixed                |
| hold_for_security_review | Needs security owner review             |
| request_changes          | Developer should revise                 |
| approve_with_notes       | Low risk with documented caveats        |
| approve                  | No material issue found in visible diff |

Block merge when:

- confirmed secret added
- private key added
- auth bypass added
- CI exfiltrates secrets
- suspicious binary executed by pipeline
- destructive command introduced
- production deployment exposure created

---

## 15. Final response structure

Use this structure:

1. **Diff 审查结论**
2. **审查范围**
3. **阻塞合并的问题**
4. **高风险变更**
5. **中低风险变更**
6. **Secret / 凭据变更**
7. **CI/CD 与供应链变更**
8. **可疑脚本或二进制**
9. **建议 Review Comment**
10. **缺口与下一步**

If no issue is found:

> 当前可见 diff 中未发现明确高风险问题，但该结论仅覆盖提供的变更范围，不代表完整仓库无风险。

---

## 16. Final checklist

Before completing diff review:

- Did I avoid executing changed code?
- Did I check added and deleted lines?
- Did I check secrets?
- Did I check CI/CD changes?
- Did I check dependencies and lockfiles?
- Did I check scripts and binaries?
- Did I distinguish risk and confidence?
- Did I redact sensitive values?
- Did I state whether merge should be blocked?
- Did I include review comments?