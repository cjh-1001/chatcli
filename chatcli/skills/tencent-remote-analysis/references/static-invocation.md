# Static Invocation

Remote static analysis runs through `remote_guest run` after a prepared case.

## Prepare

```text
remote_guest action=prepare sample_path=C:\samples\sample.exe analysis_plan=<plan>
```

## Run

```text
remote_guest action=run case_id=<case-id> mode=real
```

## Static Tools

The standalone server static stage writes:

```text
static/binary_inspect.json
static/strings.txt
static/capa.json
static/floss.txt
static/diec.txt
static/exiftool.txt
static/upx_list.txt
static/yara_matches.json
```

IDA writes:

```text
reverse/ida_headless.json
reverse/ida_headless.stdout.txt
reverse/ida_headless.stderr.txt
```

Ghidra writes:

```text
reverse/ghidra_headless.txt
```

## Interpretation

Treat failed tools as limitations, not benign evidence. For tiny, malformed, or
dummy files, tools like capa and exiftool can return non-zero while still being
callable.

Use evidence from at least two independent sources before making high-confidence
claims.
