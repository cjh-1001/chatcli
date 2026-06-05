"""Rule tables for RAT/backdoor command capability mapping."""

import re

COMMAND_RULES = {
    "shell_execution": {
        "label": "远程 shell/命令执行",
        "terms": ["remote shell", "reverse shell", "cmd.exe", "powershell", "/bin/sh", "/bin/bash", "execute command", "run command", "shell"],
        "impact": "可能允许操作者在受害主机上启动 shell、脚本或系统命令。",
        "validation": "Confirm command input source, process creation arguments, and handler reachability.",
    },
    "file_operations": {
        "label": "文件管理",
        "terms": ["upload", "download", "list files", "file manager", "delete file", "read file", "write file", "mkdir", "copyfile", "findfirstfile"],
        "impact": "可能支持浏览、上传、下载、删除或修改受害主机文件。",
        "validation": "Confirm target path handling, file operation APIs, and storage/exfil path.",
    },
    "process_operations": {
        "label": "进程管理",
        "terms": ["process list", "list processes", "tasklist", "kill process", "terminateprocess", "createprocess", "openprocess", "inject"],
        "impact": "可能支持枚举、启动、终止或操纵进程。",
        "validation": "Confirm process target selection and handler code path.",
    },
    "screen_capture": {
        "label": "屏幕/窗口捕获",
        "terms": ["screenshot", "screen capture", "bitblt", "printwindow", "getdc", "desktop capture", "window capture"],
        "impact": "可能泄露屏幕、窗口或桌面内容。",
        "validation": "Confirm capture loop, image buffer, and storage/transmission path.",
    },
    "keylogging_clipboard": {
        "label": "键盘/剪贴板捕获",
        "terms": ["keylog", "keystroke", "getasynckeystate", "getkeystate", "setwindowshookex", "clipboard", "getclipboarddata"],
        "impact": "可能泄露键盘输入、剪贴板或会话材料。",
        "validation": "Confirm hook/polling loop and output handling.",
    },
    "credential_collection": {
        "label": "凭据/令牌收集",
        "terms": ["password", "credential", "cookies", "login data", "token", "wallet", "dpapi", "lsass", "kubeconfig", "aws_access_key"],
        "impact": "可能导致账号、浏览器会话、云密钥或钱包材料泄露。",
        "validation": "Confirm sensitive artifact access plus parser/decryptor/staging logic.",
    },
    "system_discovery": {
        "label": "主机/网络信息收集",
        "terms": ["systeminfo", "whoami", "hostname", "getcomputername", "getusername", "ipconfig", "netstat", "enumprocesses", "installed software"],
        "impact": "可能为操作者提供主机、用户、网络和进程上下文。",
        "validation": "Confirm collected fields and whether results feed C2 responses.",
    },
    "plugin_module": {
        "label": "插件/模块加载",
        "terms": ["plugin", "module", "load module", "load plugin", "update module", "download plugin", "reflective", "manual map"],
        "impact": "可能扩展后门能力或加载后续模块。",
        "validation": "Confirm module boundary, loading path, and execution transfer.",
    },
    "persistence_control": {
        "label": "安装/卸载/持久化控制",
        "terms": ["install", "uninstall", "persistence", "service install", "createservice", "schtasks", "run key", "autorun"],
        "impact": "可能允许远程控制持久化、安装或清理动作。",
        "validation": "Confirm persistence artifact path/value and handler reachability.",
    },
    "network_proxy_ddos": {
        "label": "代理/DDoS/网络滥用",
        "terms": ["socks", "socks5", "proxy", "udp flood", "syn flood", "http flood", "ddos", "spam", "smtp relay"],
        "impact": "可能将受害主机用于代理、DDoS、垃圾邮件或第三方滥用。",
        "validation": "Confirm command-controlled target parameters and network loop.",
    },
}

ID_PATTERNS = [
    re.compile(r"\b(?:cmd|command|opcode|op|task)[_\-\s]*(?:id)?\s*[:=]\s*([A-Za-z0-9_.:-]{1,48})", re.IGNORECASE),
    re.compile(r"\b(?:CMD|COMMAND|OP|TASK)_[A-Z0-9_]{2,48}\b"),
    re.compile(r"\b(?:case|opcode)\s+0x[0-9a-f]{1,8}\b", re.IGNORECASE),
]

