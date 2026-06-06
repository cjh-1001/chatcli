# chatcli 腾讯云分析服务器 — 一键部署脚本
# 在腾讯云 Windows 服务器上以管理员身份运行
# 用法: powershell -ExecutionPolicy Bypass -File setup_remote.ps1

$ErrorActionPreference = "Stop"
Write-Host "=== chatcli 远程分析服务器部署 ===" -ForegroundColor Cyan

# ── 1. 检查 Python ──────────────────────────────────────────
Write-Host "[1/5] 检查 Python..." -ForegroundColor Yellow
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "Python 未安装。请先从 https://python.org 下载 Python 3.10+" -ForegroundColor Red
    Write-Host "安装时勾选 'Add Python to PATH'" -ForegroundColor Red
    exit 1
}
Write-Host "  Python: $(python --version)" -ForegroundColor Green

# ── 2. 安装 chatcli ─────────────────────────────────────────
Write-Host "[2/5] 安装 chatcli + 依赖..." -ForegroundColor Yellow
pip install --upgrade pip
pip install "fastapi>=0.115.0" "uvicorn[standard]>=0.30.0" "python-multipart>=0.0.9"
pip install git+https://github.com/cjh-1001/chatcli.git

Write-Host "  chatcli + Guest Agent 依赖已安装" -ForegroundColor Green

# ── 3. 创建目录结构 ─────────────────────────────────────────
Write-Host "[3/5] 创建分析工作目录..." -ForegroundColor Yellow
$dirs = @(
    "C:\analysis",
    "C:\analysis\inbox",
    "C:\analysis\outbox",
    "C:\analysis\cases",
    "C:\analysis\tmp",
    "C:\tools"
)
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
}
Write-Host "  目录结构已创建: C:\analysis\" -ForegroundColor Green

# ── 4. 设置 Guest Agent Token ───────────────────────────────
Write-Host "[4/5] 配置 Guest Agent Token..." -ForegroundColor Yellow

$existingToken = [Environment]::GetEnvironmentVariable("CHATCLI_GUEST_AGENT_TOKEN", "Machine")
if (-not $existingToken) {
    # 生成随机 token
    $token = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 48 | ForEach-Object { [char]$_ })
    [Environment]::SetEnvironmentVariable("CHATCLI_GUEST_AGENT_TOKEN", $token, "Machine")
    Write-Host "  已生成并保存 Token: $token" -ForegroundColor Green
    Write-Host "  *** 请复制此 Token！chatcli 侧配置需要用到 ***" -ForegroundColor Magenta
} else {
    Write-Host "  Token 已存在" -ForegroundColor Green
}

# ── 5. 防火墙放行 ───────────────────────────────────────────
Write-Host "[5/5] 配置防火墙..." -ForegroundColor Yellow
$rule = Get-NetFirewallRule -DisplayName "chatcli Guest Agent" -ErrorAction SilentlyContinue
if (-not $rule) {
    New-NetFirewallRule `
        -DisplayName "chatcli Guest Agent" `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort 8443 `
        -Action Allow | Out-Null
    Write-Host "  防火墙规则已添加: TCP 8443" -ForegroundColor Green
} else {
    Write-Host "  防火墙规则已存在" -ForegroundColor Green
}

# ── 完成 ────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== 部署完成 ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "启动 Guest Agent:" -ForegroundColor White
Write-Host "  python -m chatcli.remote.guest_agent.main --host 0.0.0.0 --port 8443" -ForegroundColor Gray
Write-Host ""
Write-Host "如需开机自启，用 Task Scheduler 创建一个任务:" -ForegroundColor White
Write-Host "  - Trigger: At system startup" -ForegroundColor Gray
Write-Host "  - Action: python -m chatcli.remote.guest_agent.main --host 0.0.0.0 --port 8443" -ForegroundColor Gray
Write-Host ""
Write-Host "chatcli 侧配置 (config.yaml):" -ForegroundColor White
Write-Host "  remote:" -ForegroundColor Gray
Write-Host "    enabled: true" -ForegroundColor Gray
Write-Host "    base_url: http://<腾讯云IP>:8443" -ForegroundColor Gray
Write-Host "    guest_agent_token: <上面生成的 Token>" -ForegroundColor Gray
Write-Host ""
Write-Host "或设置环境变量:" -ForegroundColor White
Write-Host '  $env:CHATCLI_REMOTE_URL = "http://<腾讯云IP>:8443"' -ForegroundColor Gray
Write-Host '  $env:CHATCLI_GUEST_AGENT_TOKEN = "<Token>"' -ForegroundColor Gray
