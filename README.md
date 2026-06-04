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

## 配置示例

`.chatcli/config.yaml` 示例：

```yaml
provider:
  provider: anthropic
  model: claude-sonnet-4-6
  api_base: ""
  max_tokens: 8192
  thinking: true
  thinking_budget: 4096

permissions:
  auto:
    - read_file
    - glob
    - grep
    - list_dir
    - git_status
    - git_diff
  ask:
    - bash
    - write_file
    - edit_file
    - multi_edit
  deny: []
  mode: default
  protect_sensitive_files: true
  sensitive:
    - .env
    - .env.*
    - "*.pem"
    - "*.key"
    - id_rsa
    - id_dsa

max_tool_rounds: 50
self_correction: true
max_self_correction_rounds: 3
show_diffs: true
search_backend: auto
```

不要把 `api_key` 写进这个文件后提交到 Git。确实要写本地 key 时，只写在本机的 `.chatcli/config.yaml`，并确认 `.chatcli/` 被 `.gitignore` 排除。

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
