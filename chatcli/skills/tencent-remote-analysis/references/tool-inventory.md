# Tool Inventory

Use `remote_guest tools` as the source of truth for Tencent Cloud tools.

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
