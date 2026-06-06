# File Search Patterns

This reference defines reusable search patterns for the `file-search` skill.

Use this file when searching files, directories, repositories, extracted samples, logs, scripts, configs, or artifact collections for:

- secrets
- IOCs
- suspicious commands
- malware-like behavior
- encoded payloads
- risky file types
- persistence artifacts
- credential access indicators
- CI/CD or deployment risks
- forensic evidence

The goal is to search safely, avoid executing files, and produce structured evidence.

---

## 1. Core rules

Do not execute files.

Do not modify files.

Do not automatically extract archives unless the user approved it and the destination is safe.

Do not print full secrets.

Every useful match should include:

- path
- line number or byte offset when available
- match type
- redacted evidence
- risk
- confidence
- reason
- recommended next step

---

## 2. Standard finding object

Use this conceptual schema for search results:

```json
{
  "path": "File path",
  "line": "Line number or null",
  "offset": "Byte offset or null",
  "match_type": "secret | ioc | suspicious_command | encoded_blob | file_type | malware_indicator | config | persistence | credential_access | network | unknown",
  "pattern": "Pattern name",
  "evidence": "Redacted match evidence",
  "risk": "critical | high | medium | low | informational | unknown",
  "confidence": "confirmed | high | medium | low | unknown",
  "reason": "Why this match matters",
  "recommended_action": "Safe next step",
  "gaps": [
    "What is not yet verified"
  ]
}
```

---

## 3. Search scope checklist

Before searching, identify:

| Field            | Meaning                                     |
| ---------------- | ------------------------------------------- |
| Root path        | Directory or file to search                 |
| Include filters  | Extensions, names, directories              |
| Exclude filters  | Vendor folders, build artifacts, huge files |
| Content mode     | Text, binary, metadata, hash, mixed         |
| Encoding mode    | UTF-8, UTF-16LE, ASCII, binary              |
| Recursion depth  | Full recursive or limited                   |
| Archive handling | Skip, list, or safely extract               |
| Secret redaction | Always enabled for reports                  |

Recommended default excludes:

```text
.git/
node_modules/
vendor/
dist/
build/
target/
__pycache__/
.venv/
venv/
.cache/
coverage/
.idea/
.vscode/
```

Do not exclude these if the user explicitly wants full coverage.

---

## 4. File type patterns

Flag these file types for review.

### Executables and binary payloads

```text
*.exe
*.dll
*.sys
*.scr
*.com
*.cpl
*.ocx
*.drv
*.efi
*.so
*.dylib
*.bin
*.dat
*.elf
*.apk
*.ipa
*.jar
*.class
```

Risk guide:

| Context                                       | Risk          |
| --------------------------------------------- | ------------- |
| Executable in source tree without explanation | medium        |
| Executable referenced by script or CI         | high          |
| Driver file                                   | high          |
| Binary in malware-analysis fixture directory  | low to medium |
| Known asset with source and checksum          | low           |

---

### Scripts and command files

```text
*.ps1
*.bat
*.cmd
*.vbs
*.vbe
*.js
*.jse
*.wsf
*.hta
*.sh
*.bash
*.zsh
*.py
*.pl
*.rb
*.php
*.lua
*.au3
```

Risk guide:

| Context                      | Risk          |
| ---------------------------- | ------------- |
| Encoded PowerShell           | high          |
| Download and execute command | high          |
| Persistence command          | high          |
| Admin automation script      | medium        |
| Normal build script          | low to medium |

---

### Documents and containers

```text
*.docm
*.xlsm
*.pptm
*.doc
*.xls
*.ppt
*.rtf
*.pdf
*.lnk
*.iso
*.img
*.vhd
*.vhdx
*.zip
*.rar
*.7z
*.tar
*.gz
```

Risk guide:

| Context                               | Risk           |
| ------------------------------------- | -------------- |
| Macro-enabled document                | medium to high |
| LNK file in source tree               | medium to high |
| ISO containing scripts or executables | high           |
| Archive with executables              | medium         |
| Documentation PDF                     | low            |

---

## 5. Secret patterns

Search for variable names and token-like structures.

### Generic secret names

```text
password
passwd
pwd
secret
secret_key
api_key
apikey
api-token
access_token
refresh_token
auth_token
bearer
client_secret
private_key
jwt_secret
session_secret
cookie_secret
webhook_secret
db_password
database_url
connection_string
smtp_password
```

Risk guide:

| Evidence                                       | Risk          |
| ---------------------------------------------- | ------------- |
| Real-looking value assigned to secret variable | high          |
| Secret in `.env` or CI config                  | high          |
| Placeholder in example file                    | low           |
| Commented placeholder                          | low           |
| Empty value                                    | informational |

---

### Cloud credential names

```text
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
aws_access_key_id
aws_secret_access_key
AWS_SESSION_TOKEN
GOOGLE_APPLICATION_CREDENTIALS
private_key_id
client_email
auth_provider_x509_cert_url
AZURE_CLIENT_SECRET
AZURE_TENANT_ID
AZURE_CLIENT_ID
CLOUDFLARE_API_TOKEN
CLOUDFLARE_GLOBAL_KEY
DIGITALOCEAN_ACCESS_TOKEN
DO_SPACES_KEY
DO_SPACES_SECRET
```

Risk guide:

| Evidence                         | Risk             |
| -------------------------------- | ---------------- |
| Access key plus secret pair      | critical         |
| Service account JSON private key | critical         |
| Token in active CI/deploy file   | critical or high |
| Key name without value           | low              |
| Example value                    | low              |

---

### Private key markers

```text
-----BEGIN PRIVATE KEY-----
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
-----BEGIN DSA PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN PGP PRIVATE KEY BLOCK-----
```

Risk guide:

| Evidence                     | Risk          |
| ---------------------------- | ------------- |
| Complete private key block   | critical      |
| Encrypted private key        | high          |
| Test key clearly marked fake | low to medium |
| Public certificate only      | low           |

Redact private key contents as:

```text
[PRIVATE KEY REDACTED]
```

---

### Package registry tokens

```text
NPM_TOKEN
npm_
PYPI_TOKEN
pypi-
GITHUB_TOKEN
ghp_
github_pat_
GITLAB_TOKEN
glpat-
DOCKERHUB_TOKEN
QUAY_TOKEN
```

Risk guide:

| Evidence                     | Risk                          |
| ---------------------------- | ----------------------------- |
| Token in active config or CI | high                          |
| Token in deleted history     | high; rotation still required |
| Placeholder token            | low                           |

---

## 6. IOC patterns

Search for common indicators.

### Hashes

```text
MD5:      32 hex characters
SHA1:     40 hex characters
SHA256:   64 hex characters
SHA512:   128 hex characters
```

Use hash matches carefully.

| Context                     | Risk           |
| --------------------------- | -------------- |
| Known malware hash list     | high           |
| Random checksum in lockfile | low            |
| File integrity hash         | informational  |
| Hash with malware label     | medium to high |

---

### URLs

Look for:

```text
http://
https://
ftp://
ws://
wss://
hxxp://
hxxps://
```

Classify:

| Evidence                      | Risk                 |
| ----------------------------- | -------------------- |
| URL in downloader command     | high                 |
| URL in decoded malware config | high                 |
| Unknown URL in script         | medium               |
| Documentation URL             | low                  |
| GitHub/Microsoft/Google URL   | do_not_block_blindly |

Defang suspicious URLs in reports:

```text
hxxp://example[.]com/path
```

---

### Domains

Look for domain-like strings.

Risk guide:

| Evidence                     | Risk                 |
| ---------------------------- | -------------------- |
| Domain passed to network API | high                 |
| Domain in C2 config          | high                 |
| Domain in documentation      | low                  |
| CDN or cloud shared domain   | do_not_block_blindly |
| Local test domain            | low                  |

Defang suspicious domains:

```text
example[.]com
```

---

### IP addresses

Look for IPv4 and IPv6.

Risk guide:

| Evidence                       | Risk                 |
| ------------------------------ | -------------------- |
| Public IP contacted by malware | high                 |
| Public IP in config            | medium               |
| RFC1918 private IP             | low or internal_only |
| Localhost                      | low                  |
| Public DNS resolver            | do_not_block_blindly |

Examples of values not to block blindly:

```text
127.0.0.1
0.0.0.0
8.8.8.8
1.1.1.1
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
```

---

## 7. Suspicious command patterns

### PowerShell

Search for:

```text
powershell
pwsh
-enc
-encodedcommand
FromBase64String
Invoke-Expression
IEX
Invoke-WebRequest
iwr
Invoke-RestMethod
irm
DownloadString
DownloadFile
Start-Process
New-Object Net.WebClient
Set-ExecutionPolicy Bypass
-NoProfile
-WindowStyle Hidden
```

Risk guide:

| Pattern                                | Risk   |
| -------------------------------------- | ------ |
| EncodedCommand plus download           | high   |
| IEX plus remote content                | high   |
| Hidden window plus execution bypass    | high   |
| Admin script using PowerShell normally | medium |
| Documentation example                  | low    |

---

### Windows LOLBins

Search for:

```text
cmd.exe
rundll32.exe
regsvr32.exe
mshta.exe
wscript.exe
cscript.exe
certutil.exe
bitsadmin.exe
wmic.exe
schtasks.exe
sc.exe
reg.exe
forfiles.exe
installutil.exe
msbuild.exe
msiexec.exe
```

High-risk combinations:

```text
regsvr32 /s /n /u /i:http
mshta http
rundll32 javascript:
certutil -urlcache -split -f
bitsadmin /transfer
schtasks /create
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

---

### Linux and macOS

Search for:

```text
curl
wget
bash -c
sh -c
chmod +x
crontab
systemctl enable
launchctl load
osascript
python -c
perl -e
nc -e
ncat
socat
base64 -d
openssl enc
```

High-risk combinations:

```text
curl ... | sh
wget ... | bash
chmod +x /tmp/
crontab -l
systemctl enable
launchctl load
nc -e
```

---

## 8. Persistence patterns

### Windows

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
RunOnce
CurrentVersion\Policies\Explorer\Run
Image File Execution Options
AppInit_DLLs
Winlogon
Startup
schtasks /create
CreateService
StartService
sc create
WMI EventConsumer
```

### Linux

```text
crontab
/etc/cron
/etc/systemd/system
systemctl enable
/etc/init.d
~/.bashrc
~/.profile
~/.ssh/authorized_keys
```

### macOS

```text
LaunchAgents
LaunchDaemons
launchctl load
LoginItems
~/Library/LaunchAgents
/Library/LaunchDaemons
```

Risk guide:

| Evidence                                 | Risk          |
| ---------------------------------------- | ------------- |
| Persistence command in executable script | high          |
| Persistence path string only             | medium        |
| Legitimate installer service             | low to medium |
| Documentation mention                    | low           |

---

## 9. Credential access patterns

Search for:

```text
Login Data
Cookies
Web Data
Local State
CryptUnprotectData
DPAPI
lsass.exe
MiniDumpWriteDump
SAM
SYSTEM
SECURITY
NTDS.dit
GetAsyncKeyState
SetWindowsHookEx
Clipboard
id_rsa
id_ed25519
.kube/config
.aws/credentials
.azure
.gcloud
```

Risk guide:

| Evidence                          | Risk          |
| --------------------------------- | ------------- |
| Script reads credential store     | high          |
| Browser DB path plus exfil/upload | high          |
| Credential path string only       | medium        |
| Security tool test fixture        | low to medium |

Do not provide instructions for extracting real credentials.

---

## 10. Ransomware and destructive patterns

Search for:

```text
vssadmin delete shadows
wmic shadowcopy delete
bcdedit /set
wbadmin delete catalog
cipher /w
wevtutil cl
ransom
decrypt
recover files
README_FOR_DECRYPT
Your files have been encrypted
```

Also search for:

```text
FindFirstFile
FindNextFile
CryptEncrypt
BCryptEncrypt
AES
RSA
ChaCha
extension
```

Risk guide:

| Evidence                             | Risk |
| ------------------------------------ | ---- |
| Shadow deletion command              | high |
| Ransom note text                     | high |
| File traversal plus encryption logic | high |
| Crypto API only                      | low  |
| Documentation about ransomware       | low  |

---

## 11. Obfuscation and encoding patterns

Search for:

```text
base64
FromBase64String
Convert.FromBase64String
atob
btoa
eval
exec
marshal.loads
pickle.loads
zlib.decompress
gzip
xor
rot13
charcode
String.fromCharCode
unescape
```

Suspicious when combined with:

- process execution
- network download
- persistence
- credential access
- file write
- reflection or dynamic import

Risk guide:

| Evidence                          | Risk          |
| --------------------------------- | ------------- |
| Encoded blob decoded and executed | high          |
| Encoded config decoded only       | medium        |
| Base64 test fixture               | low           |
| Binary data asset                 | informational |

---

## 12. CI/CD and deployment patterns

Search for:

```text
.github/workflows
.gitlab-ci.yml
Jenkinsfile
circleci
azure-pipelines
pull_request_target
permissions: write-all
secrets.
env
printenv
set -x
curl -X POST
upload-artifact
docker login
kubectl
helm
terraform
ansible
```

High-risk patterns:

```text
env | curl
printenv
echo $SECRET
pull_request_target with secrets
permissions: write-all
untrusted third-party action
unpinned action
```

Risk guide:

| Evidence                          | Risk          |
| --------------------------------- | ------------- |
| Secrets sent to external endpoint | critical      |
| PR workflow exposes secrets       | high          |
| Unpinned action                   | medium        |
| Normal deployment script          | low to medium |

---

## 13. Search result risk guide

Use this table to classify matches.

| Match                         | Risk     | Confidence     |
| ----------------------------- | -------- | -------------- |
| Full private key              | critical | confirmed      |
| Cloud key pair                | critical | high           |
| Token-like value in CI config | high     | high           |
| Download-execute script       | high     | high           |
| Encoded PowerShell            | high     | medium to high |
| URL in suspicious script      | medium   | medium         |
| Generic keyword `password`    | low      | low            |
| Placeholder secret            | low      | high           |
| Public DNS resolver           | low      | high           |
| Unreadable file               | unknown  | unknown        |

Risk and confidence are different:

- Risk = potential impact.
- Confidence = how sure the match means what it appears to mean.

---

## 14. Redaction rules

Never print full secrets.

Use these formats:

| Value             | Redaction                            |
| ----------------- | ------------------------------------ |
| API key           | `AKIA...REDACTED...ABCD`             |
| Token             | `tok_...REDACTED...9f2a`             |
| Private key       | `[PRIVATE KEY REDACTED]`             |
| Password          | `[PASSWORD REDACTED]`                |
| JWT               | `eyJ...REDACTED...sig`               |
| URL with password | `scheme://user:[REDACTED]@host/path` |
| Cookie            | `name=[REDACTED]`                    |

For suspicious malware IOCs, defang:

| Original               | Defanged                 |
| ---------------------- | ------------------------ |
| `http://example.com/a` | `hxxp://example[.]com/a` |
| `evil.example.com`     | `evil[.]example[.]com`   |

---

## 15. Standard output tables

### Search summary

| 字段     | 值   |
| -------- | ---- |
| 搜索范围 |      |
| 文件数   |      |
| 可读文件 |      |
| 跳过文件 |      |
| 匹配数   |      |
| 高风险   |      |
| 中风险   |      |
| 低风险   |      |
| 缺口     |      |

---

### Match table

| 风险 | 类型   | 文件   | 行/偏移 | 证据                         | 置信度 | 建议              |
| ---- | ------ | ------ | ------- | ---------------------------- | ------ | ----------------- |
| high | secret | `.env` | 12      | `API_KEY=sk...REDACTED...x9` | high   | rotate and remove |

---

### Skipped file table

| 文件          | 原因   | 影响         | 建议                       |
| ------------- | ------ | ------------ | -------------------------- |
| `archive.zip` | 未解压 | 可能遗漏内容 | 在隔离目录中安全展开后扫描 |

---

## 16. Final response structure

Use this structure:

1. **搜索结论**
2. **搜索范围**
3. **高风险匹配**
4. **中低风险匹配**
5. **IOC / 可疑指标**
6. **敏感信息**
7. **跳过或不可访问内容**
8. **证据与置信度**
9. **建议下一步**

If no matches are found, say:

> 当前搜索范围内未发现匹配项。

Then include:

- searched paths
- patterns used
- skipped files
- limitations

---

## 17. Final validation checklist

Before answering:

- Did I avoid executing files?
- Did I avoid modifying files?
- Did I redact secrets?
- Did I defang suspicious external IOCs?
- Did I include file paths and line numbers when available?
- Did I separate risk and confidence?
- Did I list skipped or inaccessible files?
- Did I avoid calling weak matches confirmed threats?
- Did I provide safe next steps?