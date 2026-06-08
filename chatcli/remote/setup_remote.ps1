# chatcli Tencent Cloud analysis server bootstrap
# Run on the Tencent Cloud Windows server as Administrator.
# This script prepares the environment for C:\chatcli-server\chatcli_guest_agent.py.

$ErrorActionPreference = "Stop"

Write-Host "=== chatcli Guest Agent bootstrap ===" -ForegroundColor Cyan

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    Write-Host "Python launcher 'py' was not found. Install Python 3.10+ and enable PATH." -ForegroundColor Red
    exit 1
}

Write-Host "[1/4] Installing Python dependencies..." -ForegroundColor Yellow
py -3 -m pip install --upgrade pip
py -3 -m pip install "fastapi>=0.115.0" "uvicorn[standard]>=0.30.0" "python-multipart>=0.0.9"

Write-Host "[2/4] Creating server directories..." -ForegroundColor Yellow
$dirs = @(
    "C:\chatcli-server",
    "C:\analysis",
    "C:\analysis\cases",
    "C:\analysis\outbox",
    "C:\analysis\rules",
    "C:\analysis\tmp",
    "C:\samples"
)
foreach ($dir in $dirs) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}
[Environment]::SetEnvironmentVariable("CHATCLI_AGENT_DIR", "C:\analysis", "Machine")
$env:CHATCLI_AGENT_DIR = "C:\analysis"

Write-Host "[3/4] Configuring Guest Agent token..." -ForegroundColor Yellow
$token = [Environment]::GetEnvironmentVariable("CHATCLI_GUEST_AGENT_TOKEN", "Machine")
if (-not $token) {
    $chars = (48..57) + (65..90) + (97..122)
    $token = -join ($chars | Get-Random -Count 48 | ForEach-Object { [char]$_ })
    [Environment]::SetEnvironmentVariable("CHATCLI_GUEST_AGENT_TOKEN", $token, "Machine")
}
$env:CHATCLI_GUEST_AGENT_TOKEN = $token

Write-Host "[4/4] Opening local firewall port 8443..." -ForegroundColor Yellow
if (-not (Get-NetFirewallRule -DisplayName "chatcli Guest Agent" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "chatcli Guest Agent" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow | Out-Null
}

$agent = "C:\chatcli-server\chatcli_guest_agent.py"
Write-Host ""
Write-Host "Bootstrap complete." -ForegroundColor Green
Write-Host "Copy server\chatcli_guest_agent.py from the client machine to:" -ForegroundColor White
Write-Host "  $agent" -ForegroundColor Gray
Write-Host ""
Write-Host "Start command:" -ForegroundColor White
Write-Host "  py -3 $agent --host 0.0.0.0 --port 8443" -ForegroundColor Gray
Write-Host ""
Write-Host "Default sample drop directory:" -ForegroundColor White
Write-Host "  C:\samples" -ForegroundColor Gray
Write-Host ""
Write-Host "Natural-language batch example from the chatcli client:" -ForegroundColor White
Write-Host "  把腾讯云服务器 C:\samples 文件夹里的恶意样本依次分析" -ForegroundColor Gray
Write-Host ""
Write-Host "Token for chatcli client config:" -ForegroundColor White
Write-Host "  $token" -ForegroundColor Yellow
