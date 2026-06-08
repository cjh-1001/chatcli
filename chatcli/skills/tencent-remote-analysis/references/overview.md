# Overview

This workflow is for authorized remote analysis through the Tencent Cloud Guest
Agent on a Windows server.

Use it when:

- the sample is already on the Tencent Cloud server;
- a remote directory contains multiple samples that should be analyzed
  sequentially;
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

4. Choose invocation shape:

- Single server-side sample: use `remote_guest prepare/run` with `sample_path`.
- Remote directory, batch, queue, or "依次/逐个/one by one" request: use
  `remote_batch_analyze` with `sample_dir` and `pattern`, or `sample_paths` if
  the user named individual files.
- Missing remote path: ask one concise question for the Tencent Cloud server
  path. Do not ask the user to rewrite the request as command flags.

5. Prepare using server-side `sample_path`; do not upload unless requested.

6. Run, status-check, download, and inspect result files.

## Conversational Batch Request

When the user says something like:

```text
把腾讯云服务器 C:\samples 文件夹里的恶意样本依次分析，静态和动态都做
```

call:

```text
remote_batch_analyze sample_dir=C:\samples pattern=*.exe analysis_plan=<dynamic-plan>
```

If the user says:

```text
我把样本放到腾讯云服务器了，帮我依次分析
```

ask only for the remote server directory or file paths, then call
`remote_batch_analyze` after the user answers.

## Important Distinction

`/tools check` is local. It checks the client machine.

`remote_guest tools` is remote. It checks the Tencent Cloud server.

Always use `remote_guest tools` for Tencent Cloud availability.
