# Overview

This workflow is for authorized remote analysis through the Tencent Cloud Guest
Agent on a Windows server.

Use it when:

- the sample is already on the Tencent Cloud server;
- the user asks to inspect server-side tool status;
- the user wants remote static analysis, remote IDA/Ghidra, or dynamic/network
  observation;
- `remote_guest` is configured.

## Decision Flow

1. Check server health:

```text
remote_guest action=health
```

2. Check server tools:

```text
remote_guest action=tools
```

3. Decide dynamic scope:

- Explicit dynamic request: use a dynamic plan.
- Explicit static-only/no-execution request: use a static-only plan.
- Not specified: ask once whether dynamic analysis is required.

4. Prepare using server-side `sample_path`; do not upload unless requested.

5. Run, status-check, download, and inspect result files.

## Important Distinction

`/tools check` is local. It checks the client machine.

`remote_guest tools` is remote. It checks the Tencent Cloud server.

Always use `remote_guest tools` for Tencent Cloud availability.
