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
