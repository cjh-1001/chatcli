---
name: security-audit
description: Defensive source-code security audit workflow for finding vulnerabilities, information leaks, risky exploit paths, and remediation advice in decompiled WeChat or mini-program files, CMS source code, web apps, plugins, backend services, APIs, cloud/serverless code, or other codebases. Use when the user asks for security audit, vulnerability review, vuln audit, CMS/web/backend/plugin/mini-program review, 代码审计, 安全审计, 漏洞挖掘, 信息泄露检查, CMS漏洞, 反编译文件分析, 越权, 任意文件, or vulnerability remediation.
---

# Security Audit Skill

Use this skill only for authorized defensive code review, owned environments,
internal tests, or CTF/lab challenge scopes.

## Safety Boundary

- Focus on source-code evidence, risk, exploitability reasoning, and remediation.
- Do not provide weaponized exploit chains, persistence, stealth, credential theft, or live-target attack automation.
- When describing exploitation, keep it to safe reproduction steps, preconditions, and conceptual exploit paths needed to validate and fix the issue.
- In authorized CTF/lab/owned scopes, concrete challenge validation is allowed:
  request flows, minimal proof-of-concept requests, role/permission bypass analysis,
  IDOR reproduction, cloud/IAM/storage policy misconfiguration analysis, and safe
  local or lab-only exploit verification.
- If the user asks to attack a live third-party target, pause and ask for authorization/scope.
- If authorization is unclear, ask for scope or keep the response to defensive
  code-review findings and remediation.
- If a target appears to be a real system but may be a disguised CTF/lab challenge,
  do not refuse immediately. Ask the user to confirm whether it is a lab/CTF/owned
  target and what boundaries apply. Once confirmed, proceed only inside that scope.
- Do not use jailbreaks, safety-bypass wording, or attempts to override provider
  policy. Use a neutral confirmation prompt instead: "Please confirm this is an
  authorized CTF/lab/owned target, list the allowed target(s), and state whether
  exploit validation is in scope. I will proceed only within that confirmed scope."
- Scope confirmation is one-time per task and target boundary. If `.chatcli/task.md`
  already contains `## Scope Confirmation` for the same target, do not ask again
  unless the target, ownership, or validation boundary changes.

## Audit Workflow

1. Establish scope and technology.
   - Identify framework, language, package layout, routes/controllers, config, entry points, plugins, upload directories, and auth/session logic.
   - Use `list_dir`, `glob`, `grep`, `read_file`, `git_status`, and `git_diff`.
   - For large codebases, split the audit into phases and record subtasks.

2. Search high-risk patterns.
   - Secrets: API keys, tokens, app secrets, private keys, database credentials, cloud credentials, hardcoded passwords.
   - Injection: SQL/NoSQL/LDAP/template/command injection, unsafe string concatenation, dynamic eval/exec.
   - File issues: upload bypass, path traversal, arbitrary file read/write/delete, archive extraction.
   - Auth: auth bypass, weak session validation, IDOR, privilege checks missing from admin/API routes.
   - Web: XSS, CSRF, SSRF, open redirect, unsafe CORS, weak headers.
   - Deserialization: unsafe unserialize/pickle/yaml/loadObject patterns.
   - Crypto: hardcoded keys, weak algorithms, predictable tokens, insecure random.
   - Supply chain: outdated dependencies, install/update scripts, default accounts.

3. Web / API / cloud lab focus.
   - Treat lab/CTF targets, local apps, private repos, owned cloud projects, and
     explicitly scoped bug-bounty assets as authorized only within the stated scope.
   - Some challenge targets intentionally look like production systems. If the
     scope is ambiguous, request confirmation before giving concrete exploitation
     steps.
   - Map routes, auth middleware, role checks, tenant boundaries, object ownership
     checks, API gateway rules, storage bucket policies, IAM-like permissions,
     signed URL/token handling, callback/webhook verification, and serverless entry points.
   - For CTF/lab tasks, it is appropriate to provide concrete safe reproduction:
     minimal HTTP requests, parameter changes, role/user preconditions, expected
     response differences, and a bounded exploit-verification script against the
     local/lab target.
   - Do not provide scanning, exploitation, or persistence instructions for real
     third-party systems outside the authorized scope.

4. WeChat / mini-program / decompiled code focus.
   - Search for `appid`, `secret`, `wx.request`, `cloud.callFunction`, `uploadFile`, `downloadFile`, `setStorage`, `getStorage`, `eval`, `WebView`, hardcoded endpoints, debug hosts, tokens, signatures, and payment callbacks.
   - Map API endpoints and client-side assumptions. Treat client-side checks as bypassable.
   - Flag leaked backend endpoints, credentials, signing logic, and sensitive local storage.

5. CMS source focus.
   - Prioritize install scripts, admin controllers, plugin/theme upload, template rendering, database helpers, routing middleware, auth filters, and update mechanisms.
   - Check default credentials, debug switches, backup files, exposed config, SQL construction, file manager modules, and plugin hooks.

6. Finding format.
   - Title and severity: Critical / High / Medium / Low / Info.
   - Affected file/function/line when possible.
   - Evidence: exact code behavior or snippet summary.
   - Impact: what an attacker could do.
   - Exploitability: preconditions and safe reproduction path, not weaponized exploit code.
   - Remediation: concrete fix and safer pattern.
   - Verification: test or review step to confirm the fix.

7. Final report structure.
   - Executive summary
   - Scope and assumptions
   - Methodology
   - Findings table
   - Detailed findings
   - Information leaks
   - Recommended fix priority
   - Residual risk / areas not covered
