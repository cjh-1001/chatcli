---
name: coding
description: Phased software engineering workflow for implementing, fixing, refactoring, testing, and verifying code changes. Use for coding tasks such as implement, fix, refactor, optimize, test, debug, feature work, source changes, 修复, 实现, 添加, 重构, 优化, 测试, or any request that changes source files.
---

# Coding Skill

Use this workflow for implementation work.

1. Plan before editing.
   - Inspect the codebase with read-only tools.
   - Use `git_status` to understand existing changes.
   - Restate requirements and identify affected files.
   - If multiple viable approaches exist, ask the user to choose and recommend one.

2. Split work into phases.
   - Keep each phase small enough to verify.
   - Update `.chatcli/task.md` subtasks during autonomous work.
   - Prefer `edit_file` for one replacement and `multi_edit` for several replacements in the same file.
   - Use `write_file` mainly for new files or full rewrites.

3. Verify each phase.
   - Add or update focused tests when behavior is testable.
   - Run the relevant tests before marking a phase done.
   - If tests fail, fix the failure before moving on.
   - If tests cannot run, record the exact blocker and use the next-best validation.

4. Keep the user involved only for meaningful choices.
   - Ask for confirmation when tradeoffs affect architecture, UX, data, compatibility, or destructive operations.
   - Do not ask for routine implementation details that can be inferred from the codebase.

5. Finish cleanly.
   - Run a final relevant test/check.
   - Use `git_status` or `git_diff` to summarize what changed.
   - Report changed files, tests run, and any residual risks.
