# Result Handling

After `run`, call:

```text
remote_guest action=status case_id=<case-id>
remote_guest action=download case_id=<case-id>
```

Downloaded results are stored under:

```text
.chatcli/remote_results/<case-id>/
```

## Output Checklist

Static:

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

Reverse:

```text
reverse/ida_headless.json
reverse/ghidra_headless.txt
```

Dynamic:

```text
dynamic/dynamic_status.json
dynamic/network.pcapng
dynamic/network_summary.json
dynamic/dns.txt
dynamic/http.txt
dynamic/conversations.txt
dynamic/procmon.pml
```

Verify:

```text
verify/server_status_after.json
```

## Reporting Rules

- Cite result file names in findings.
- Separate static capability from observed runtime behavior.
- If dynamic files are absent, report that dynamic telemetry was not collected.
- If `ghidra_headless.txt` is absent and `ghidra=false`, do not claim Ghidra was
  run.
- Do not infer C2 contact from static strings alone. Require PCAP, Procmon,
  Sysmon, process/network telemetry, or equivalent runtime evidence.
