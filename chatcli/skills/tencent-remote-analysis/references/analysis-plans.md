# Analysis Plans

Use JSON-like dictionaries as `analysis_plan` in `remote_guest prepare` or
`remote_guest run`.

## Static + IDA

Default first-pass remote analysis:

```json
{
  "static": true,
  "ida": true,
  "ghidra": false,
  "dynamic": false,
  "network": false,
  "verify": true
}
```

## Static + IDA + Ghidra

Use when IDA output is insufficient or cross-validation is useful:

```json
{
  "static": true,
  "ida": true,
  "ghidra": true,
  "dynamic": false,
  "network": false,
  "verify": true
}
```

Ghidra is slow. Do not call `analyzeHeadless` directly with no arguments.

## Dynamic Observation

Use only when dynamic analysis is explicitly requested:

```json
{
  "static": true,
  "ida": true,
  "ghidra": false,
  "dynamic": true,
  "network": true,
  "verify": true
}
```

## Dry Run

Use `mode=dry_run` only to verify orchestration paths. Use `mode=real` for
actual static analysis.

## Sequential Remote Batch

Use `remote_batch_analyze` when the user asks for a remote directory, multiple
remote samples, queue-style processing, or says samples should be analyzed
"依次", "逐个", "one by one", or "sequentially".

Static-first batch:

```json
{
  "sample_dir": "C:\\samples",
  "pattern": "*.exe",
  "analysis_plan": {
    "static": true,
    "ida": true,
    "ghidra": false,
    "dynamic": false,
    "network": false,
    "verify": true
  }
}
```

Dynamic batch only when explicitly requested:

```json
{
  "sample_dir": "C:\\samples",
  "pattern": "*.exe",
  "analysis_plan": {
    "static": true,
    "ida": true,
    "ghidra": false,
    "dynamic": true,
    "network": true,
    "verify": true
  },
  "dynamic_config": {
    "timeout_seconds": 300,
    "collectors": ["pcap", "procmon", "tshark"]
  }
}
```

`remote_batch_analyze` submits each `run` request with `background=true`, then
polls `remote_guest status`. This avoids blocking on a long HTTP request while
the sample executes. If the user needs the REPL back immediately, set
`wait=false`; then report the generated `case_id` values and tell the user to
use `remote_guest action=status` and `remote_guest action=download` later.

Isolation warning: `remote_batch_analyze` runs cases sequentially but does not
restore a VM snapshot between samples. If strong isolation is required, run one
dynamic sample at a time, download results, restore the Tencent Cloud snapshot,
and only then continue to the next sample. Do not present a multi-sample dynamic
batch as cleanly isolated unless rollback occurred between samples.

If the user names individual remote files, use:

```json
{
  "sample_paths": ["C:\\samples\\a.exe", "C:\\samples\\b.exe"],
  "analysis_plan": {
    "static": true,
    "ida": true,
    "verify": true
  }
}
```

Do not manually loop with repeated `remote_guest run` calls for batch work.
Let `remote_batch_analyze` run, wait, and download each case before starting
the next.
