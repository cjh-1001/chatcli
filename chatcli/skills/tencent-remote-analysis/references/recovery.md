# Recovery

Use this when the Guest Agent is unresponsive, port 8443 is occupied, or a
heavy tool such as Ghidra blocks the single worker.

## Kill Port 8443 Owner

On the Tencent Cloud server PowerShell:

```powershell
$pid8443 = (Get-NetTCPConnection -LocalPort 8443 -State Listen).OwningProcess
Stop-Process -Id $pid8443 -Force
```

## Kill Stuck Agent or Ghidra

```powershell
Get-CimInstance Win32_Process |
  Where-Object {
    $_.CommandLine -like '*chatcli_guest_agent.py*' -or
    $_.CommandLine -like '*analyzeHeadless*' -or
    $_.CommandLine -like '*ghidra*' -or
    $_.ProcessName -like 'java*'
  } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
```

## Restart Agent

```powershell
$env:CHATCLI_AGENT_DIR="C:\analysis"
$env:CHATCLI_GUEST_AGENT_TOKEN=[Environment]::GetEnvironmentVariable("CHATCLI_GUEST_AGENT_TOKEN","Machine")
$env:IDA_PATH=[Environment]::GetEnvironmentVariable("IDA_PATH","Machine")
$env:CHATCLI_TOOL_DIEC=[Environment]::GetEnvironmentVariable("CHATCLI_TOOL_DIEC","Machine")
$env:CHATCLI_TOOL_UPX=[Environment]::GetEnvironmentVariable("CHATCLI_TOOL_UPX","Machine")
$env:CHATCLI_TOOL_EXIFTOOL=[Environment]::GetEnvironmentVariable("CHATCLI_TOOL_EXIFTOOL","Machine")
$env:GHIDRA_HEADLESS_PATH=[Environment]::GetEnvironmentVariable("GHIDRA_HEADLESS_PATH","Machine")
$env:CHATCLI_TOOL_GHIDRA=[Environment]::GetEnvironmentVariable("CHATCLI_TOOL_GHIDRA","Machine")
$env:CHATCLI_YARA_RULES=[Environment]::GetEnvironmentVariable("CHATCLI_YARA_RULES","Machine")
$env:CHATCLI_TOOL_PROCMON=[Environment]::GetEnvironmentVariable("CHATCLI_TOOL_PROCMON","Machine")
$env:CHATCLI_TOOL_DUMPCAP=[Environment]::GetEnvironmentVariable("CHATCLI_TOOL_DUMPCAP","Machine")
$env:CHATCLI_TOOL_TSHARK=[Environment]::GetEnvironmentVariable("CHATCLI_TOOL_TSHARK","Machine")

py -3 C:\chatcli-server\chatcli_guest_agent.py --host 0.0.0.0 --port 8443
```

After restart, verify from the client:

```text
remote_guest action=health
remote_guest action=tools
```
