"""Generate deploy_remote.ps1 from standalone_agent.py."""
import base64
from pathlib import Path

HERE = Path(__file__).parent

# Read and encode the standalone agent
agent_py = HERE / "standalone_agent.py"
b64 = base64.b64encode(agent_py.read_bytes()).decode()

# Build the PowerShell deploy script
lines = []
lines.append("# chatcli Remote Agent — 一键部署（不依赖 GitHub）")
lines.append("$ErrorActionPreference = \"Stop\"")
lines.append("Write-Host \"=== chatcli Remote Agent ===\" -ForegroundColor Cyan")
lines.append("")
lines.append("if (-not (Get-Command python -ErrorAction SilentlyContinue)) {")
lines.append("    Write-Host \"请先装 Python 3.10+: https://python.org\" -ForegroundColor Red; exit 1")
lines.append("}")
lines.append("Write-Host \"Python: $(python --version)\" -ForegroundColor Green")
lines.append("")
lines.append("Write-Host \"安装依赖...\" -ForegroundColor Yellow")
lines.append("pip install fastapi uvicorn python-multipart --quiet")
lines.append("Write-Host \"完成\" -ForegroundColor Green")
lines.append("")
lines.append("Write-Host \"部署 Agent...\" -ForegroundColor Yellow")
lines.append("$b64 = @'")
lines.append(b64)
lines.append("'@")
lines.append("$pyCode = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64 -replace '\\s',''))")
lines.append("Set-Content -Path C:\\chatcli_agent.py -Value $pyCode -Encoding UTF8")
lines.append("")
lines.append("# Generate random token")
lines.append("$chars = (48..57) + (65..90) + (97..122)")
lines.append("$token = -join ($chars | Get-Random -Count 48 | ForEach { [char]$_ })")
lines.append("[Environment]::SetEnvironmentVariable(\"CHATCLI_GUEST_AGENT_TOKEN\", $token, \"Machine\")")
lines.append("$env:CHATCLI_GUEST_AGENT_TOKEN = $token")
lines.append("")
lines.append("mkdir C:\\analysis\\cases, C:\\analysis\\outbox -Force | Out-Null")
lines.append("New-NetFirewallRule -DisplayName \"chatcli Agent\" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow -ErrorAction SilentlyContinue | Out-Null")
lines.append("")
lines.append("Write-Host \"\" -ForegroundColor Green")
lines.append("Write-Host \"=== 部署完成 ===\" -ForegroundColor Cyan")
lines.append("Write-Host \"Token: $token\" -ForegroundColor Yellow")
lines.append("Write-Host \"\"")
lines.append("Write-Host \"chatcli 侧配置:\" -ForegroundColor White")
lines.append("Write-Host \"  remote:\" -ForegroundColor Gray")
lines.append("Write-Host \"    enabled: true\" -ForegroundColor Gray")
lines.append("Write-Host \"    base_url: http://<IP>:8443\" -ForegroundColor Gray")
lines.append("Write-Host \"    guest_agent_token: $token\" -ForegroundColor Gray")
lines.append("Write-Host \"\"")
lines.append("python C:\\chatcli_agent.py --host 0.0.0.0 --port 8443")

output = "\n".join(lines) + "\n"
out_path = HERE / "deploy_remote.ps1"
out_path.write_text(output, encoding="utf-8")
print(f"Generated {out_path} ({len(output)} chars, {len(lines)} lines)")

# Quick sanity check
for i, line in enumerate(lines, 1):
    if not line.strip():
        continue
    if line[0] == '$' and '=' not in line[:30]:
        pass  # multi-line variable assignment is fine
print("Done.")
