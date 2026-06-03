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

### 2. 初始化配置

在你要使用 chatcli 的项目目录里直接运行：

```powershell
chatcli
```

如果当前目录或父目录没有 `.chatcli/config.yaml` / `.chatcli/config.yml`，chatcli 会自动创建配置文件并进入交互式配置向导。

也可以手动初始化或重新进入配置向导：

```powershell
chatcli --setup
```

它会创建：

```text
.chatcli/config.yaml
.chatcli/context.md
```

`.chatcli/config.yaml` 是本项目的配置文件，`.chatcli/context.md` 可以写项目背景、技术栈、约定和长期提示词。设置了 `CHATCLI_CONFIG` 时，chatcli 会优先使用并在缺失时创建该路径指向的配置文件。

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

交互模式：

```powershell
chatcli
```

单次提问：

```powershell
chatcli "帮我检查这个项目的入口文件"
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

## 配置示例

`.chatcli/config.yaml` 示例：

```yaml
provider:
  provider: anthropic
  model: claude-sonnet-4-6
  api_base: ""
  max_tokens: 8192
  thinking: true
  thinking_budget: 16000

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
