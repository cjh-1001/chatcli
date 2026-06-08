# chatcli

chatcli 是一个本地命令行 AI 助手，把聊天模型接到文件读写、搜索、Git、命令执行、逆向分析等工具上。它可以交互使用，也可以单次提问，适合在项目目录里直接让模型读代码、改代码、查问题、跑工具。

## 快速启用

### 1. 安装

从 GitHub 安装：

```powershell
pip install git+https://github.com/cjh-1001/chatcli.git
```

本地开发安装：

```powershell
git clone https://github.com/cjh-1001/chatcli.git
cd chatcli
pip install -e .
```

chatcli 需要 Python 3.10 或更高版本。

逆向分析可选依赖：

```powershell
# pyproject extras
pip install -e ".[reverse]"

# 或 requirements 文件
py -3 -m pip install -r requirements-reverse.txt
```

`requirements.txt` 和 `requirements-reverse.txt` 只是安装入口，实际依赖版本统一维护在 `pyproject.toml`。`requirements-reverse.txt` 没有并入 `requirements.txt`，是为了避免普通聊天/代码场景默认安装 `angr`、`frida`、`flare-capa` 这类体积更大、安装更慢的逆向依赖。

`reverse` 会安装 Python 包类依赖：`angr`、`frida`/`frida-tools`、`flare-capa`、`flare-floss`。Ghidra、Detect It Easy、YARA、UPX、ExifTool 这类独立程序仍需要单独安装。

### 1.1 验证安装

安装完成后，先确认 `chatcli` 命令可用：

```powershell
chatcli --version
```

如果提示 `'chatcli' 不是内部或外部命令`，说明 Python Scripts 目录不在 PATH 里。用下面这条命令代替，效果完全一样：

```powershell
python -m chatcli.main --version
```

> **Windows 常见问题**：安装 Python 时如果没有勾选 "Add Python to PATH"，或者 pip 安装的 Scripts 目录没有被加入 PATH，就会找不到 `chatcli` 命令。最简单的办法是一直用 `python -m chatcli.main` 代替 `chatcli`。也可以参考[安装排错](#安装排错)彻底修复 PATH。

### 2. 初始化配置

推荐先创建全局配置，这样像 Claude 一样在任意目录直接运行 `chatcli` 都能用同一套 provider/API key 设置：

```powershell
chatcli --setup --global
```

它会创建：

```text
~/.chatcli/config.yaml
~/.chatcli/context.md
```

`~/.chatcli/config.yaml` 是用户级配置，所有项目默认都可以复用。`~/.chatcli/context.md` 是全局上下文，可以写长期偏好、常用约定和固定提示词。

如果只想给当前项目创建单独配置：

```powershell
chatcli --setup --local
```

它会创建：

```text
.chatcli/config.yaml
.chatcli/context.md
```

项目级配置会覆盖全局配置。已经在项目里有 `.chatcli/config.yaml` 时，如果仍想强制使用全局配置：

```powershell
chatcli --global
```

在没有任何配置时，直接运行：

```powershell
chatcli
```

chatcli 会自动创建当前项目的 `.chatcli/config.yaml` 并进入交互式配置向导。也可以手动初始化或重新进入当前项目配置向导：

```powershell
chatcli --setup
```

设置了 `CHATCLI_CONFIG` 时，chatcli 会优先使用并在缺失时创建该路径指向的配置文件。

### 3. 配置 API Key

推荐用环境变量，不要把真实 key 写进仓库。

Anthropic:

```powershell
$env:ANTHROPIC_API_KEY="你的 Anthropic API Key"
```

OpenAI:

```powershell
$env:OPENAI_API_KEY="你的 OpenAI API Key"
```

OpenAI-compatible 或自定义网关：

```powershell
$env:CHATCLI_PROVIDER="openai-compatible"
$env:CHATCLI_MODEL="你的模型名"
$env:CHATCLI_API_BASE="https://你的接口地址/v1"
$env:CHATCLI_API_KEY="你的 API Key"
```

MiMo / xiaomimimo.com 网关：

```powershell
$env:MIMO_API_KEY="你的 MiMo API Key"
```

也可以用统一覆盖变量：

```powershell
$env:CHATCLI_API_KEY="你的 API Key"
```

优先级说明：

- `CHATCLI_API_KEY` 优先级最高。
- Anthropic 默认读取 `ANTHROPIC_API_KEY`。
- OpenAI 和通用兼容接口默认读取 `OPENAI_API_KEY`。
- `api_base` 包含 `xiaomimimo.com` 时优先读取 `MIMO_API_KEY`，没有再读取 `OPENAI_API_KEY`。

macOS/Linux 写法：

```bash
export ANTHROPIC_API_KEY="你的 Anthropic API Key"
export OPENAI_API_KEY="你的 OpenAI API Key"
export CHATCLI_API_KEY="你的 API Key"
```

## 常用命令

> 如果 `chatcli` 命令找不到，把 `chatcli` 替换为 `python -m chatcli.main` 即可。

交互模式：

```powershell
chatcli
```

单次提问：

```powershell
chatcli "帮我检查这个项目的入口文件"
```

强制使用全局配置：

```powershell
chatcli --global "帮我检查这个项目的入口文件"
```

脚本友好的单次输出：

```powershell
chatcli --print "总结当前目录结构"
```

从 stdin 输入：

```powershell
Get-Content .\error.log | chatcli --print "分析这个错误日志"
```

查看帮助：

```powershell
chatcli --help
```

查看版本：

```powershell
chatcli --version
```

## 安装排错

### Windows: `chatcli` 命令找不到

```powershell
'chatcli' 不是内部或外部命令，也不是可运行的程序
```

**原因**：Python Scripts 目录（如 `C:\Program Files\Python310\Scripts\`）不在系统 PATH 中。

**解决方式一**：用 `python -m chatcli.main` 代替（推荐）

```powershell
# 把 chatcli 替换为 python -m chatcli.main，效果完全一样
python -m chatcli.main
python -m chatcli.main --setup --global
python -m chatcli.main "你的问题"
```

**解决方式二**：把 Scripts 加入 PATH 后重开终端

```powershell
# 找到 Scripts 目录
python -c "import sysconfig; print(sysconfig.get_path('scripts'))"

# 输出类似：C:\Program Files\Python310\Scripts
# 把输出路径加入 PATH：
setx PATH "%PATH%;C:\Program Files\Python310\Scripts"
```

### Windows: 安装时 `tiktoken` 编译失败

**原因**：`tiktoken` 需要 Rust toolchain 才能编译。现在 `tiktoken` 已经是可选依赖，不会阻塞安装。如果报错，用下面命令跳过：

```powershell
pip install git+https://github.com/cjh-1001/chatcli.git --no-deps
pip install anthropic openai rich prompt-toolkit pyyaml httpx
```

> 没有 `tiktoken` 时 chatcli 会用字符启发式算法估算 token 数，不影响正常使用。

### 常见问题速查

| 症状 | 解决 |
|------|------|
| `chatcli` 命令找不到 | `python -m chatcli.main` |
| `No API key found` | 设置 `CHATCLI_API_KEY` 环境变量或运行 `chatcli --setup` |
| `Python 3.10+ required` | 升级 Python 到 3.10 或更高版本 |
| 安装后 import 报错 | 确认 `pip install -e .` 运行在项目根目录 |
| 只想装逆向 Python 依赖 | `py -3 -m pip install -r requirements-reverse.txt` |

## 配置示例

仓库里的 [config.example.yaml](config.example.yaml) 是无密钥完整模板，字段集合和 `chatcli --setup` 生成的默认配置保持一致，包括权限、上下文压缩、逆向工具路径、IDA MCP 和本地临时目录等配置。

GitHub 上看不到你的 `.chatcli/config.yaml` 是正常现象：它包含 API key、本机绝对路径和会话状态，已经被 `.gitignore` 排除。不要把 `api_key`、真实网关地址或本机工具路径提交到 Git；这些值只写在本机的 `~/.chatcli/config.yaml` 或项目内 `.chatcli/config.yaml`。

常用本机路径字段：

```yaml
ida_path: ""                 # Example: 'D:/IDA Pro/idat.exe'
ghidra_path: ""              # Example: 'D:/Tools/ghidra_11.1.2_PUBLIC'
die_path: ""                 # Example: 'D:/Tools/DetectItEasy/stuff/diec.exe'
exiftool_path: ""            # Example: 'D:/Tools/exiftool.exe'
upx_path: ""                 # Example: 'D:/Tools/upx.exe'
ida_mcp_url: ""              # Example: http://127.0.0.1:13337/mcp
ida_mcp_start_command: ""
ida_mcp_auto_prepare: false
ida_mcp_auto_start: false
ida_mcp_tool_limit: 80
```

## Provider 配置

Anthropic:

```yaml
provider:
  provider: anthropic
  model: claude-sonnet-4-6
```

OpenAI:

```yaml
provider:
  provider: openai
  model: gpt-4.1
```

OpenAI-compatible:

```yaml
provider:
  provider: openai-compatible
  model: your-model
  api_base: https://your-endpoint.example.com/v1
```

Text-tools provider:

```yaml
provider:
  provider: text-tools
  model: your-model
  api_base: https://your-endpoint.example.com/v1
```

可用 provider：

- `anthropic`
- `openai`
- `openai-compatible`
- `text-tools`

## 环境变量

| 变量 | 作用 |
| --- | --- |
| `CHATCLI_API_KEY` | 统一 API key 覆盖，优先级最高 |
| `ANTHROPIC_API_KEY` | Anthropic 默认 key |
| `OPENAI_API_KEY` | OpenAI 和兼容接口默认 key |
| `MIMO_API_KEY` | MiMo / xiaomimimo.com key |
| `CHATCLI_PROVIDER` | 覆盖 provider |
| `CHATCLI_MODEL` | 覆盖模型名 |
| `CHATCLI_API_BASE` | 覆盖 API base URL |
| `CHATCLI_CONFIG` | 指定配置文件路径 |
| `IDA_PATH` | 指定 IDA/idat 路径，用于逆向分析工具 |
| `IDA_MCP_URL` | 指定 IDA MCP HTTP endpoint，例如 `http://127.0.0.1:13337/mcp` |
| `IDA_MCP_START_COMMAND` | 指定 `ida_mcp_ensure` 自动启动 IDA MCP 服务时执行的命令 |
| `IDA_MCP_AUTO_PREPARE` | 为 true 时，模型调用前自动探测并注册具体 IDA MCP tools |
| `IDA_MCP_AUTO_START` | 为 true 时，auto prepare 阶段允许执行 `ida_mcp_start_command` |
| `IDA_MCP_TOOL_LIMIT` | 限制预接入时暴露给模型的具体 IDA MCP tool 数量 |
| `GHIDRA_HEADLESS_PATH` | 指定 Ghidra `analyzeHeadless` 路径 |
| `GHIDRA_HOME` | 指定 Ghidra 安装目录，chatcli 会查找 `support/analyzeHeadless` |
| `CHATCLI_REMOTE_URL` | 远程 Guest Agent 地址，例如 `http://1.2.3.4:8443`，设置后自动启用 remote |
| `CHATCLI_REMOTE_HOST` | 远程服务器 SSH 主机名或 IP，设置后自动启用 remote |
| `CHATCLI_REMOTE_USER` | 远程 SSH 用户名 |
| `CHATCLI_REMOTE_KEY` | 远程 SSH 私钥路径 |
| `CHATCLI_GUEST_AGENT_TOKEN` | Guest Agent Bearer Token，本地和远程服务器必须一致 |
| `TENCENTCLOUD_SECRET_ID` | 腾讯云 API SecretId，用于 VM 生命周期控制 |
| `TENCENTCLOUD_SECRET_KEY` | 腾讯云 API SecretKey |
| `TENCENTCLOUD_REGION` | 腾讯云地域，例如 `ap-guangzhou` |
| `TENCENTCLOUD_INSTANCE_ID` | 腾讯云实例 ID |

## IDA MCP 接入

chatcli 内置两条 IDA 路线：

- `ida_analyze` / `ida_focus_decompile`：直接调用本机 `idat.exe` 跑 headless IDAPython，适合批量静态分析。
- `ida_mcp_ensure` / `ida_mcp_probe` / `ida_mcp_list_tools` / `ida_mcp_call`：连接 IDA MCP HTTP 服务，适合让模型和打开中的 IDA 数据库交互。

最小配置：

```yaml
ida_path: "D:/IDA Pro/idat.exe"
ida_mcp_url: "http://127.0.0.1:13337/mcp"
ida_mcp_start_command: ""
ida_mcp_auto_prepare: true
ida_mcp_auto_start: false
```

如果使用 `idalib-mcp` 这类 headless 服务，常见 endpoint 是：

```yaml
ida_mcp_url: "http://127.0.0.1:8745/mcp"
ida_mcp_start_command: "py -m idalib_mcp.server --port 8745"
ida_mcp_auto_prepare: true
ida_mcp_auto_start: true
ida_mcp_tool_limit: 80
```

使用顺序：

1. 在 IDA 里启动/加载 IDA MCP 插件，或配置 `ida_mcp_start_command` 让 chatcli 自动启动 headless MCP 服务。
2. 让 chatcli 先调用 `ida_mcp_ensure` 或 `ida_mcp_probe`，确认 endpoint 可连接并列出 MCP tools。
3. 再用 `ida_mcp_call` 调指定 MCP tool，例如反编译函数、查询 xref、重命名符号等。

`ida_mcp_ensure` 的行为是：先探测 `ida_mcp_url`，如果不可用且存在 `ida_mcp_start_command`，就后台执行启动命令，然后轮询 `tools/list` 直到 MCP endpoint 可用。GUI 插件型 IDA MCP 通常仍需要你先打开 IDA 或让插件自动加载；headless 服务型 MCP 更适合自动拉起。

如果开启 `ida_mcp_auto_prepare: true`，chatcli 会在第一次模型调用前完成接入：探测/可选启动 endpoint，读取 MCP `tools/list`，并把每个具体 MCP tool 注册成模型可直接调用的 chatcli tool，例如 MCP 的 `decompile_function` 会暴露成类似 `ida_mcp_decompile_function` 的工具。这样后续模型不需要先问你怎么接入，想用时可以直接调。

IDA MCP 工具默认在 `ask` 权限组，因为部分 MCP tool 可能修改 IDB，例如重命名、注释、patch 或数据库保存。

## 其他逆向分析工具接入

除 IDA 外，chatcli 还支持这些辅助分析入口：

- `external_static_analyze`：运行已安装的 `capa`、`diec`、`floss`、`exiftool`。输出前会生成 `AI Evidence Summary`，优先提取 capability、packer、混淆字符串、行为线索。
- `ghidra_probe` / `ghidra_analyze`：调用 Ghidra HeadlessAnalyzer，对本地二进制导出函数、imports、strings、候选函数和可选伪代码 JSON，可作为 IDA 的交叉验证。
- `angr_triage`：调用 Python 包 `angr` 做轻量静态 triage，提取 loader 架构、imports、strings 和可选 CFGFast 函数候选。

### 本地静态分析工具配置

本地分析不需要腾讯云服务器。只要在本机装好 Python 包和独立工具，chatcli 就可以直接用 `/malware`、`external_static_analyze`、`ida_analyze`、`ghidra_analyze`、`yara_scan` 等工具分析本地样本。

Python 包类静态工具：

```powershell
py -3 -m pip install flare-capa flare-floss yara-python pefile lief capstone
```

独立程序类工具需要安装后放到 PATH，或配置路径：

```powershell
$env:IDA_PATH="C:\Program Files\IDA Professional 9.0\idat.exe"
$env:DIE_PATH="C:\Tools\DetectItEasy\diec.exe"
$env:EXIFTOOL_PATH="C:\Tools\exiftool.exe"
$env:UPX_PATH="C:\Tools\upx.exe"
```

也可以写进 `config.yaml`：

```yaml
ida_path: "C:/Program Files/IDA Professional 9.0/idat.exe"
die_path: "C:/Tools/DetectItEasy/diec.exe"
exiftool_path: "C:/Tools/exiftool.exe"
upx_path: "C:/Tools/upx.exe"
capa_path: ""     # 通常不用填；会自动识别 flare-capa Python 包或 capa.exe
floss_path: ""    # 通常不用填；会自动识别 flare-floss Python 包或 floss.exe
yara_path: ""     # 通常不用填；yara_scan 会优先使用 yara-python
```

检查本机静态工具识别情况：

```powershell
chatcli "/tools check capa floss yara-python die ida ghidra exiftool upx --versions"
```

本机样本分析示例：

```powershell
chatcli "/malware C:\samples\suspicious.exe 做本地静态分析，不使用腾讯云"
```

也可以让模型显式调用工具：

```powershell
chatcli "对 C:\samples\suspicious.exe 运行 binary_inspect、external_static_analyze、yara_scan、ida_analyze，并汇总行为证据"
```

注意：`diec` 和 IDA 是独立程序，不是 Python 包；如果识别不到，优先检查 `DIE_PATH`、`IDA_PATH` 或 PATH。`flare-capa`、`flare-floss`、`yara-python` 是 Python 包，只要当前 `py -3` 能 import，就能被健康检查识别。

Ghidra 配置示例：

```powershell
$env:GHIDRA_HOME="D:\ghidra_11.3"
# 或
$env:GHIDRA_HEADLESS_PATH="D:\ghidra_11.3\support\analyzeHeadless.bat"
```

angr 是可选 Python 包，不会默认安装：

```powershell
py -3 -m pip install angr
```

推荐逆向分析顺序：

1. `binary_inspect`
2. `external_static_analyze`
3. `ida_analyze` 或 `ghidra_analyze`
4. `reverse_evidence_map`
5. `ida_focus_decompile` / IDA MCP / `angr_triage` 做定点分析

### 恶意样本分析结果分享

完成 `/malware` 静态分析后，可以用 `/malware-share` 生成一个适合团队流转的 ZIP 包。默认不会打包样本二进制，只包含样本哈希/元数据、脱敏后的报告、当前任务上下文和 `manifest.json`：

```powershell
chatcli "/malware-share C:\samples\suspicious.exe --report .chatcli\reports\malware-triage-xxx.html"
```

也可以不传 `--report`，chatcli 会优先使用 `.chatcli/reports/` 下最新的报告：

```powershell
chatcli "/malware-share C:\samples\suspicious.exe"
```

生成位置默认是 `.chatcli/share/`。如果确实是在授权实验室渠道内交接样本本体，可以显式加入 `--include-sample`，样本会以 `sample/<name>.quarantine` 名称放入包内；不要把该选项用于公开分享或不受控渠道。

## 腾讯云远程分析

chatcli 可以连接部署在腾讯云服务器上的 Guest Agent，让模型通过 `remote_guest` 工具查看服务器状态、检查分析工具、运行远端样本分析任务、下载结果，并在分析后收集服务器是否出现异常迹象的快照。

这个功能适合授权实验室环境。不要把 Guest Agent 暴露给不可信网络；至少要配置强随机 token、腾讯云安全组白名单，并把样本执行环境和日常业务环境隔离。

### 1. 在腾讯云服务器部署服务端单文件

腾讯云服务器不需要拉取整个项目。服务端只需要上传一个文件：

```text
C:\chatcli-server\chatcli_guest_agent.py
```

这个文件在本项目里的位置是：

```text
server/chatcli_guest_agent.py
```

从本机上传到腾讯云服务器即可，例如：

```powershell
# 在服务器上创建目录
New-Item -ItemType Directory -Force C:\chatcli-server | Out-Null
```

然后把本机的 `server/chatcli_guest_agent.py` 放到：

```text
C:\chatcli-server\chatcli_guest_agent.py
```

服务器上安装基础依赖：

```powershell
py -3 -m pip install fastapi uvicorn python-multipart
```

也可以先在服务器上运行本项目的 `chatcli/remote/setup_remote.ps1` 做基础环境初始化；它只创建目录、安装 Guest Agent 依赖、配置 token 和防火墙，不会拉取整个 chatcli 项目。

如果要跑静态分析库，再安装 Python 包：

```powershell
py -3 -m pip install flare-capa flare-floss yara-python
```

如果要跑流量/动态采集，再单独安装 Wireshark/TShark、Sysmon、Zeek、Suricata 等采集工具；不要求把 chatcli 完整项目安装到服务器。

创建工作目录，设置环境变量：

```powershell
$env:CHATCLI_AGENT_DIR="C:\analysis"
$env:CHATCLI_GUEST_AGENT_TOKEN="换成强随机token"

New-Item -ItemType Directory -Force C:\analysis\cases, C:\analysis\outbox, C:\analysis\tmp | Out-Null
```

启动服务：

```powershell
py -3 C:\chatcli-server\chatcli_guest_agent.py --host 0.0.0.0 --port 8443
```

如果要长期运行，先在服务器上写一个启动脚本 `C:\chatcli-server\start_agent.ps1`：

```powershell
$env:CHATCLI_AGENT_DIR="C:\analysis"
$env:CHATCLI_GUEST_AGENT_TOKEN="<token>"
py -3 C:\chatcli-server\chatcli_guest_agent.py --host 0.0.0.0 --port 8443
```

再用任务计划程序创建开机自启任务：

```text
Program/script: powershell
Arguments: -ExecutionPolicy Bypass -File C:\chatcli-server\start_agent.ps1
Start in: C:\chatcli-server
```

服务器工作目录默认是 `C:\analysis`，也可以通过 `CHATCLI_AGENT_DIR` 改：

```text
C:\analysis\
  cases\      # case 元数据和 job.json
  outbox\     # 分析结果
```

`remote_guest tools` 会把工具分成几类：

- `analysis_python`：Python 分析库，例如 `flare-capa`、`flare-floss`、`yara-python`。
- `built_in_static`：服务端内置静态能力，例如 `binary_inspect`、`strings`。
- `headless_reverse`：Headless 逆向工具，例如 `IDA/idat`、`Ghidra analyzeHeadless`。
- `static_external`：独立静态分析程序，例如 `diec`、`yara`、`exiftool`、`upx`。
- `collector`：动态/网络采集工具，例如 `dumpcap`、`tshark`、`zeek`、`suricata`、`sysmon`、`procmon`。
- `external`：独立外部程序，例如 `diec`、`powershell`、`wevtutil`。
- `analysis_config`：分析配置，例如 YARA 规则路径。

如果要让 `tools` 状态检查识别自定义采集工具路径，可以在服务器上设置：

```powershell
$env:CHATCLI_TOOL_TSHARK="C:\Program Files\Wireshark\tshark.exe"
$env:CHATCLI_TOOL_DUMPCAP="C:\Program Files\Wireshark\dumpcap.exe"
$env:CHATCLI_TOOL_SYSMON="C:\Program Files\reverseTools\Sysmon.exe"
$env:CHATCLI_TOOL_ZEEK="C:\Tools\Zeek\bin\zeek.exe"
$env:CHATCLI_TOOL_SURICATA="C:\Program Files\Suricata\suricata.exe"
$env:CHATCLI_TOOL_DIEC="C:\Tools\diec.exe"
$env:CHATCLI_YARA_RULES="C:\rules\index.yar"
$env:IDA_PATH="C:\Program Files\IDA Professional 9.0\idat.exe"
```

工具识别排查：

```powershell
chatcli "用 remote_guest tools 查看腾讯云服务器上的分析工具"
```

注意：这里查的是腾讯云服务器，不是本机。`flare-capa`、`flare-floss`、`yara-python` 是服务器上的 Python 包；只要服务器运行 Guest Agent 的 Python 能 `import capa/floss/yara`，`remote_guest tools` 就会识别。`diec` 和 IDA 是服务器上的独立程序，必须安装在服务器并放到服务器 PATH，或在服务器上显式配置路径：

```powershell
$env:CHATCLI_TOOL_DIEC="C:\Tools\DetectItEasy\diec.exe"
$env:IDA_PATH="C:\Program Files\IDA Professional 9.0\idat64.exe"
# 也可以指向 idat.exe；如果把 IDA_PATH 指到 IDA 安装目录，Guest Agent 会尝试查找 idat64.exe/idat.exe
$env:IDA_PATH="C:\Program Files\IDA Professional 9.0\idat.exe"
```

腾讯云侧还需要放行网络：

- Windows 防火墙允许 TCP `8443` 入站。
- 腾讯云安全组只允许你的本机 IP 访问 `8443`，不要开放给全网。

### 2. 在本机配置连接

可以写到 `config.yaml`：

```yaml
remote:
  enabled: true
  base_url: "http://<腾讯云公网IP>:8443"
  guest_agent_token: "换成强随机token"
```

也可以只用环境变量：

```powershell
$env:CHATCLI_REMOTE_URL="http://<腾讯云公网IP>:8443"
$env:CHATCLI_GUEST_AGENT_TOKEN="换成强随机token"
```

如果要使用腾讯云实例启动、停止、快照恢复，还需要：

```yaml
remote:
  enabled: true
  base_url: "http://<腾讯云公网IP>:8443"
  guest_agent_token: "换成强随机token"
  tencent_region: "ap-guangzhou"
  tencent_instance_id: "lhins-xxxxxx"
  tencent_snapshot_id: "lh_snap-xxxxxx"
```

并通过环境变量提供腾讯云密钥：

```powershell
$env:TENCENTCLOUD_SECRET_ID="..."
$env:TENCENTCLOUD_SECRET_KEY="..."
```

### 3. 调试通讯

先确认 HTTP 服务能访问：

```powershell
Invoke-RestMethod "http://<腾讯云公网IP>:8443/api/v1/health"
```

再让 chatcli 调工具检查：

```powershell
chatcli "用 remote_guest 检查远程 Guest Agent health"
chatcli "用 remote_guest metrics 查看腾讯云服务器状态指标，include_probes=true"
chatcli "用 remote_guest tools 查看远程分析工具是否可用"
```

`metrics` 会返回平台、Python 版本、工作目录、磁盘空间、最近 case 和工具可用数量。`include_probes=true` 时还会额外采集 `ipconfig/netstat/tasklist` 等诊断输出。

### 4. 使用远端已有样本分析

如果样本已经在腾讯云服务器上，例如：

```text
C:\samples\suspicious.exe
```

可以让 chatcli 直接创建 case，不需要上传样本：

```powershell
chatcli "用 remote_guest prepare，sample_path=C:\samples\suspicious.exe，analysis_plan={static:true,dynamic:true,network:true,verify:true}"
```

也可以一步执行默认流水线：

```powershell
chatcli "用 remote_guest analyze 分析远端样本 C:\samples\suspicious.exe，mode=real"
```

默认流水线是：

```text
static -> ida(headless) -> dynamic -> network -> verify
```

当前 `static` 会调用服务器上可用的静态工具并写入 `outbox/<case_id>/static/`。如果服务器设置了 `IDA_PATH`，`ida` 阶段会调用 IDA headless：

```powershell
$env:IDA_PATH="C:\Program Files\IDA Professional 9.0\idat.exe"
```

IDA 结果会写入：

```text
outbox/<case_id>/reverse/ida_headless.json
```

`verify` 会在分析后写入：

```text
outbox/<case_id>/verify/server_status_after.json
```

其中包含进程、网络连接、服务、计划任务和近期系统事件等快照，用来辅助判断服务器是否出现异常迹象。

> 注意：动态采集器会按 `dynamic_config.collectors` 启用 Procmon、PCAP/TShark、Sysmon、Zeek、Suricata 等能力；未安装或不可用的工具会记录在 `dynamic/dynamic_status.json`，不会阻断其他可用采集器。

### 5. 动态监控表盘

监控表盘不需要单独部署第二个服务；它复用腾讯云服务器上的 Guest Agent。开启方式是：

1. 在腾讯云服务器启动 Guest Agent：

```powershell
$env:CHATCLI_AGENT_DIR="C:\analysis"
$env:CHATCLI_GUEST_AGENT_TOKEN="<token>"
py -3 C:\chatcli-server\chatcli_guest_agent.py --host 0.0.0.0 --port 8443
```

2. 在本机配置连接：

```powershell
$env:CHATCLI_REMOTE_URL="http://<腾讯云公网IP>:8443"
$env:CHATCLI_GUEST_AGENT_TOKEN="<token>"
```

3. 运行远端分析后，在 chatcli 交互模式打开表盘：

```text
/dashboard
/dashboard case-xxxx
/dashboard case-xxxx --refresh 2
/dashboard case-xxxx --no-probes
```

表盘会轮询：

```text
GET /api/v1/health
GET /api/v1/cases
GET /api/v1/monitor/snapshot?case_id=<case>&probes=true
```

显示内容包括远端健康状态、case 状态、动态采集状态、PCAP 字节数、collector 事件数量、进程/网络/注册表/计划任务/文件活动 observer 摘要，以及本地 `/observe` 子观察器状态。

如果只想让模型拉一次快照，可以用：

```powershell
chatcli "用 remote_guest monitor 查看 case_id=case-xxxx 的动态监控状态"
```

### 6. 流量采集和 Procmon 调用

流量采集和 Procmon 都通过 Guest Agent 的动态分析 job 接口启动，不是单独的 `procmon` endpoint。调用方式是在 `analysis_plan` 里启用动态分析，并在 `dynamic_config.collectors` 里指定采集器：

```powershell
chatcli "用 remote_guest prepare，sample_path=C:\samples\a.exe，analysis_plan={static:true,ida:true,dynamic:true,network:true,verify:true}，dynamic_config={timeout_seconds:300,collectors:[pcap,procmon,tshark],network_interface:'1'}"
chatcli "用 remote_guest run 运行上一步的 case_id，mode=real"
```

也可以用自然语言：

```text
对腾讯云服务器 C:\samples\a.exe 做静态和动态分析，开启 Procmon 和流量采集
```

服务端需要能找到这些工具：

```powershell
$env:CHATCLI_TOOL_PROCMON="C:\Tools\Procmon64.exe"
$env:CHATCLI_TOOL_DUMPCAP="C:\Program Files\Wireshark\dumpcap.exe"
$env:CHATCLI_TOOL_TSHARK="C:\Program Files\Wireshark\tshark.exe"
$env:CHATCLI_TOOL_SYSMON="C:\Program Files\reverseTools\Sysmon.exe"
$env:CHATCLI_TOOL_ZEEK="C:\Tools\Zeek\bin\zeek.exe"
$env:CHATCLI_TOOL_SURICATA="C:\Program Files\Suricata\suricata.exe"
```

先检查远端工具状态：

```powershell
chatcli "用 remote_guest tools 检查远端 procmon、dumpcap、tshark、sysmon、zeek、suricata 是否可用"
```

动态 runner 的顺序是：

```text
dumpcap 启动 -> Procmon 启动 -> 执行样本 -> 停止 Procmon/dumpcap -> Procmon/Sysmon 导出 -> tshark/Zeek/Suricata 解析 PCAP
```

结果会写入：

```text
dynamic/dynamic_status.json
dynamic/network.pcapng
dynamic/network_summary.txt
dynamic/dns.txt
dynamic/http.txt
dynamic/conversations.txt
dynamic/tls_sni.txt
dynamic/tcp_syn.txt
dynamic/targeted_network_iocs.txt
dynamic/procmon.pml
dynamic/procmon.csv
dynamic/targeted_process_tree.txt
dynamic/targeted_file_activity.txt
dynamic/targeted_registry_activity.txt
dynamic/targeted_persistence.txt
dynamic/sysmon.evtx
dynamic/sysmon.txt
dynamic/zeek/
dynamic/suricata/
```

### 7. 远端目录批量顺序分析

如果样本已经放在腾讯云服务器目录里，可以用独立的批处理工作流按文件名顺序逐个分析。这个流程调用 `remote_batch_analyze` 工具：每个样本都会先 `prepare`、再 `run`、等待完成并下载结果，然后才进入下一个样本；它不会修改 chatcli 原本的模型工具轮询逻辑。

静态优先：

```powershell
chatcli "/remote-batch C:\samples --pattern *.exe --output-dir .chatcli\remote_results"
```

需要动态分析时显式开启：

```powershell
chatcli "/remote-batch C:\samples --pattern *.exe --dynamic --output-dir .chatcli\remote_results"
```

也可以指定多个远端样本路径：

```powershell
chatcli "/remote-batch --sample C:\samples\a.exe --sample C:\samples\b.exe --dynamic"
```

常用选项：

```text
--recursive              递归扫描远端目录
--max N                  最多处理 N 个样本
--dry-run                使用 Guest Agent dry_run
--continue-on-failure    单个样本失败后继续处理后续样本
--no-download            不自动下载结果
--no-wait                提交 case 后立即返回，不等待远端分析完成
--run-timeout N          提交 run 请求的 HTTP 超时秒数，默认 60
```

底层工具也可以直接由模型调用：`remote_batch_analyze(sample_dir="C:\\samples", pattern="*.exe", analysis_plan={...})`。

如果交互里感觉 `remote_batch_analyze` 卡住，优先使用：

```powershell
chatcli "/remote-batch C:\samples --pattern *.exe --dynamic --no-wait"
```

它会返回每个样本的 `case_id`。之后用：

```powershell
chatcli "用 remote_guest status 查看 case_id=case-xxxx"
chatcli "用 remote_guest download 下载 case_id=case-xxxx 的结果"
```

### 8. 查看状态和下载结果

运行后查询 case：

```powershell
chatcli "用 remote_guest list 列出远程分析 case"
chatcli "用 remote_guest status 查看 case_id=case-xxxx 的状态"
```

下载结果：

```powershell
chatcli "用 remote_guest download 下载 case_id=case-xxxx 的结果"
```

结果会保存到本机：

```text
.chatcli/remote_results/<case_id>/
```

下载后可以继续让模型按角色分析：

```powershell
chatcli "读取 .chatcli/remote_results/case-xxxx，分析 static、dynamic、network、verify 结果并输出结论"
```

### 9. 分析后检查服务器受攻击情况

可以随时采集远程服务器安全快照：

```powershell
chatcli "用 remote_guest security 检查腾讯云服务器是否有异常迹象"
```

这个动作会采集网络连接、进程、服务、计划任务、近期系统事件和最近 outbox 状态。它不会直接判定“已被攻陷”，而是把证据集中起来，便于模型和人工复核。

### 外部工具下载指引

| 工具 | 用途 | 安装/下载 |
| --- | --- | --- |
| Ghidra | Headless 反编译、函数/xref/字符串交叉验证 | [GitHub Releases](https://github.com/NationalSecurityAgency/ghidra/releases) |
| Detect It Easy / diec | 文件类型、编译器、packer/protector 识别 | [官网](https://detect-it-easy.github.io/) |
| YARA | 规则扫描、样本分类 | [GitHub](https://github.com/VirusTotal/yara) |
| UPX | UPX 壳解包 | [官网](https://upx.github.io/) / [GitHub](https://github.com/upx/upx) |
| ExifTool | 元数据提取 | [官网](https://exiftool.org/) |
| Wireshark / TShark | PCAP/网络流量分析 | [官网](https://www.wireshark.org/download.html) |
| jadx | APK/DEX 反编译 | [GitHub](https://github.com/skylot/jadx) |
| ILSpy / ilspycmd | .NET 反编译 | [GitHub Releases](https://github.com/icsharpcode/ILSpy/releases) |

安装后确认对应命令能被 PATH 找到，例如 `diec`、`yara`、`upx`、`exiftool`、`tshark`、`jadx`、`ilspycmd`。Ghidra 可用 `GHIDRA_HOME` 或 `GHIDRA_HEADLESS_PATH` 配置。

## IDA 内置辅助脚本

项目还包含可直接在 IDA 里运行的 IDAPython 脚本，位置：

```text
chatcli/ida_scripts/
```

- `chatcli_ai_context.py`：导出适合 AI 分析的 IDA 上下文快照，包括当前函数、伪代码/反汇编、callers/callees、字符串、注释、imports 和候选函数评分。输出 JSON 和 Markdown。
- `chatcli_ai_apply.py`：把经过人工确认的 AI 建议回写到 IDB，支持 rename、comment、color，执行前会确认。

在 IDA 中使用：

1. 打开目标数据库。
2. `File -> Script file...`
3. 选择 `chatcli/ida_scripts/chatcli_ai_context.py`
4. 把导出的 JSON/Markdown 给 chatcli 分析。
5. 如果需要回写命名/注释，生成建议 JSON 后用 `chatcli_ai_apply.py` 应用。

可选环境变量：

| 变量 | 作用 |
| --- | --- |
| `CHATCLI_IDA_EXPORT_DIR` | 指定 IDA context 导出目录 |
| `CHATCLI_IDA_MAX_FUNCS` | 候选函数数量，默认 `80` |
| `CHATCLI_IDA_MAX_STRINGS` | 导出字符串数量，默认 `400` |
| `CHATCLI_IDA_INCLUDE_PSEUDOCODE` | 是否包含 Hex-Rays 伪代码，默认开启 |
| `CHATCLI_IDA_MAX_DISASM` | 当前函数最多导出的反汇编行数 |

## 配置文件查找顺序

chatcli 启动时会按顺序读取：

1. 显式传入的配置路径
2. `CHATCLI_CONFIG`
3. 当前目录及父目录里的 `.chatcli/config.yaml`
4. 用户目录里的 `~/.chatcli/config.yaml`

环境变量会在读取配置文件后覆盖对应字段。

## 安全注意事项

- 不要提交 `.chatcli/config.yaml`、`.env`、密钥文件、测试数据或临时目录。
- 推荐只用环境变量保存 API key。
- 默认配置会把写文件、执行命令、二进制 patch、IDA 分析等高风险工具放在 `ask` 里，执行前需要确认。
- `protect_sensitive_files: true` 会保护 `.env`、密钥文件和 `.chatcli/config.yaml` 等敏感路径。

## 开发

本地安装开发版：

```powershell
pip install -e .
```

运行：

```powershell
chatcli
```

项目入口：

```text
chatcli.main:main
```

核心模块：

- `chatcli/config.py`: 配置加载和环境变量覆盖
- `chatcli/providers/`: 不同模型 provider
- `chatcli/tools/`: 本地工具实现
- `chatcli/ui.py`: 交互式界面
- `chatcli/agent.py`: 模型调用和工具循环
