---
name: audit
description: Code and implementation audit workflow for reviewing changes, plans, risks, regressions, security issues, missing tests, and whether a task should be split before coding. Use when the user asks for review/audit/检查/审计, before large or risky implementation work, after code changes, or when deciding if the current task is complete.
aliases:
  - review
triggers:
  - review
  - audit
  - risk
  - regression
  - missing tests
  - code review
  - 检查
  - 审计
  - 评审
  - 风险
---

# Audit Skill

Use this workflow for review and risk assessment.

1. Establish scope.
   - Use `git_status` first when a repository is available.
   - Use `git_diff` to inspect changed code before judging.
   - If the task is about a planned change, inspect relevant files with `grep`, `glob`, and `read_file`.

2. Identify risks before proposing fixes.
   - Correctness bugs and regressions
   - Data loss, destructive operations, or permission risks
   - Missing validation, error handling, or edge cases
   - Missing tests or tests that do not exercise the changed behavior
   - UX/API compatibility changes

3. Report findings first.
   - Order by severity.
   - Include file/line references when possible.
   - Be concrete: explain the failure mode, not just the style concern.
   - If no issue is found, say that clearly and list residual test gaps.

4. For pre-implementation audits.
   - Decide whether the request needs subtasks.
   - Identify choices that need user confirmation.
   - Recommend the smallest safe implementation path.

5. Do not edit code during an audit unless the user explicitly asks for fixes.
