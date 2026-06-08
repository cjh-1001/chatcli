# Tool Inventory

Use `remote_guest tools` as the source of truth for Tencent Cloud tools.

## Interface Selection

Choose the remote tool by intent:

| Intent | Preferred ChatCLI tool | Notes |
| --- | --- | --- |
| Check Guest Agent reachability | `remote_guest action=health` | First call for remote work. |
| Check Tencent Cloud server tools | `remote_guest action=tools` | Do not use local `/tools check` for remote availability. |
| Analyze one server-side sample | `remote_guest action=prepare`, then `run/status/download` | Use `sample_path`; upload only when requested. |
| Analyze one sample with defaults | `remote_guest action=analyze` | Uses the shared default static/dynamic plan. |
| Analyze a remote directory or multiple samples | `remote_batch_analyze` | Runs one sample at a time and downloads before moving on. |
| Watch live runtime telemetry | `remote_guest action=monitor` | Source for `/dashboard` and child observer summaries. |
| Stop or rollback Tencent Cloud VM | `remote_vm_control` | Use after dynamic results are downloaded. |
| Run direct server commands | `remote_guest action=exec` | Use only for diagnostics or non-sample utilities. |

Legacy `remote_submit`, `remote_watch`, and `remote_consume` may still exist in
the registry, but for Tencent Cloud Guest Agent workflows prefer
`remote_guest` and `remote_batch_analyze`.

Expected server-side entries:

```text
capa          analysis_python
floss         analysis_python
yara-python   analysis_python
yara_rules    analysis_config
diec          static_external
exiftool      static_external
upx           static_external
ida           headless_reverse
ghidra        headless_reverse, optional/slow
procmon       collector
dumpcap       collector
tshark        collector
sysmon        collector
zeek          optional collector
suricata      optional collector
```

## Environment Variables

The server agent recognizes these variables:

```text
IDA_PATH
CHATCLI_TOOL_DIEC
CHATCLI_TOOL_UPX
CHATCLI_TOOL_EXIFTOOL
GHIDRA_HEADLESS_PATH
CHATCLI_TOOL_GHIDRA
CHATCLI_YARA_RULES
CHATCLI_TOOL_PROCMON
CHATCLI_TOOL_DUMPCAP
CHATCLI_TOOL_TSHARK
CHATCLI_TOOL_SYSMON
CHATCLI_TOOL_ZEEK
CHATCLI_TOOL_SURICATA
CHATCLI_TOOL_WEVTUTIL
```

## YARA

`yara-python` is the Python library. A missing external `yara.exe` CLI does not
block the current remote static pipeline when both of these are true:

```text
yara-python.available == true
yara_rules.available == true
```

## Wireshark

For automation, use:

```text
dumpcap.exe
tshark.exe
```

Do not use Wireshark GUI for automated dynamic analysis.
