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
