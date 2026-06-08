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

py -3 C:\chatcli-server\chatcli_guest_agent.py --host 0.0.0.0 --port 8443