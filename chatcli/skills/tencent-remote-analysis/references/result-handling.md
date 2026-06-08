# Result Handling

After `run`, call:

```text
remote_guest action=status case_id=<case-id>
remote_guest action=download case_id=<case-id>
```

If the analysis included dynamic execution on the Tencent Cloud server, the
download step must be followed by rollback to the configured snapshot:

```text
remote_vm_control action=stop dry_run=false
remote_vm_control action=restore_snapshot dry_run=false
remote_vm_control action=status
```

Do not restore before downloading results. Do not say `TASK COMPLETE` until the
post-rollback status check succeeds.

Downloaded results are stored under:

```text
.chatcli/remote_results/<case-id>/
```

## Batch Results

For `remote_batch_analyze`, inspect every completed item in the tool metadata:

```text
results[].case_id
results[].sample_path
results[].status
results[].local_dir
results[].download_error
```

Report a per-sample status table before writing conclusions. For failed or
missing samples, include the case ID, remote sample path, error, and whether the
batch stopped because `stop_on_failure=true`.

When multiple local result directories exist, do not merge evidence blindly.
Keep per-sample evidence separate, then add a cross-sample comparison only after
the individual findings are clear.

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
dynamic/network_summary.txt
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
- Use dynamic artifacts to revise the original static analysis, not to create a
  detached process report. Each important static hypothesis should be marked
  `confirmed`, `refuted`, `unobserved`, or `inconclusive` and the final behavior
  chain/confidence/gaps should be updated accordingly.
- If dynamic files are absent, report that dynamic telemetry was not collected.
- If `ghidra_headless.txt` is absent and `ghidra=false`, do not claim Ghidra was
  run.
- Do not infer C2 contact from static strings alone. Require PCAP, Procmon,
  Sysmon, process/network telemetry, or equivalent runtime evidence.
- The final HTML must contain the normal malware-report sections (conclusion,
  identity, attack chain, capabilities, IOC, impact, detection, limitations)
  plus evidence-chain and dynamic validation/evidence sections when dynamic
  execution was in scope.
  In the structured report JSON, use `dynamic_validation` for the static-vs-
  dynamic validation matrix and `dynamic_evidence` for execution/process/file/
  registry/network artifact summaries. Use `evidence_chain` to map each final
  claim to static evidence, dynamic evidence, source artifacts, interpretation,
  confidence, and gaps.
- The final report visible headings and narrative must be Simplified Chinese.
  English is acceptable only for tool names, file names, API names, command
  names, rule formats, hashes, IOC values, and technical identifiers.
- A checklist or `TASK COMPLETE` summary is only an internal process note.
