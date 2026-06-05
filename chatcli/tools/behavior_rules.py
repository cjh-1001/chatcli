"""Rule tables for behavior capability mapping."""

CAPABILITY_RULES = {
    "initial_access_artifact": {
        "label": "初始投递/入口工件迹象",
        "min_terms": 2,
        "terms": [
            ".lnk", "macro", "vba", "ole", "document.xml", "powershell -enc",
            "mshta", "wscript", "cscript", "hta", "cve-", "invoice", "attachment",
            "dropper",
        ],
        "validation": [
            "Confirm the container, script, shortcut, or exploit artifact that starts execution.",
            "Identify the launched child process or dropped payload boundary.",
        ],
    },
    "loader_staging": {
        "label": "Loader/多阶段加载迹象",
        "min_terms": 2,
        "terms": [
            "loadlibrary", "getprocaddress", "virtualalloc", "virtualprotect",
            "ntallocatevirtualmemory", "mz", "pe header", "shellcode", "reflective",
            "manual map", "resource", "decompress", "decrypt payload", "payload",
        ],
        "validation": [
            "Identify the decoded or carved payload boundary and execution transfer point.",
            "Separate generic API resolution from an actual staged loader path.",
        ],
    },
    "privilege_escalation": {
        "label": "提权/权限操纵迹象",
        "terms": [
            "sedebugprivilege", "seimpersonateprivilege", "adjusttokenprivileges",
            "openthreadtoken", "duplicatetoken", "uac", "fodhelper", "runas",
            "bypassuac", "pkexec", "sudo", "setuid", "privilege escalation",
        ],
        "validation": [
            "Confirm privilege check, token manipulation, or exploit trigger code path.",
            "Do not claim successful elevation without a reachable path and target context.",
        ],
    },
    "persistence": {
        "label": "持久化迹象",
        "terms": [
            "currentversion\\run", "runonce", "startup", "schtasks", "scheduled task",
            "createservice", "regsetvalue", "regcreatekey", "systemd", "cron",
            "launchagent",
        ],
        "validation": [
            "Confirm the exact persistence location and value/path written.",
            "Trace whether the write/create operation is reachable from execution flow.",
        ],
    },
    "c2_network": {
        "label": "C2/网络通信迹象",
        "terms": [
            "http://", "https://", "socket", "connect", "send", "recv", "winhttp",
            "internetopen", "user-agent", "beacon", "sleep", "gate.php", "panel",
            "telegram", "discord", "webhook",
        ],
        "validation": [
            "Identify endpoint source, protocol, port, and beacon or retry loop.",
            "Confirm command dispatcher or data exchange semantics before claiming C2.",
        ],
    },
    "command_execution": {
        "label": "命令执行迹象",
        "terms": [
            "cmd.exe", "powershell", "wscript", "cscript", "/bin/sh", "/bin/bash",
            "shellexecute", "createprocess", "system(", "popen", "rundll32",
            "regsvr32", "mshta",
        ],
        "validation": [
            "Trace command construction and user-controlled or C2-controlled inputs.",
            "Confirm process creation arguments and triggering conditions.",
        ],
    },
    "process_injection": {
        "label": "进程注入迹象",
        "terms": [
            "openprocess", "virtualallocex", "writeprocessmemory",
            "createremotethread", "ntqueueapcthread", "queueuserapc",
            "setthreadcontext", "zwunmapviewofsection", "process hollowing",
            "reflective loader", "manual map",
        ],
        "validation": [
            "Confirm call sequence, target process, and payload buffer origin.",
            "Identify the execution transfer edge after the remote write or mapping.",
        ],
    },
    "credential_access": {
        "label": "凭据访问迹象",
        "terms": [
            "lsass", "dpapi", "login data", "cookies", "sam", "security hive",
            ".ssh", "id_rsa", "kubeconfig", "aws_access_key", "token",
            "credential", "password",
        ],
        "validation": [
            "Tie credential-related strings to file, registry, memory, or API access paths.",
            "Avoid claiming theft from generic words without collection/exfil evidence.",
        ],
    },
    "browser_cloud_credentials": {
        "label": "浏览器/云凭据访问迹象",
        "min_terms": 2,
        "terms": [
            "login data", "local state", "cookies", "key4.db", "logins.json",
            "chrome", "firefox", "edge", "wallet", "aws_access_key_id",
            "secret_access_key", "azure_refresh_token", "kubeconfig",
            "serviceaccount", "credentials.json", "gcloud", "docker config",
        ],
        "validation": [
            "Tie browser or cloud credential artifacts to file access and parsing/decryption logic.",
            "Confirm whether collected credentials are staged or transmitted.",
        ],
    },
    "collection": {
        "label": "信息收集/文件收集迹象",
        "terms": [
            "screenshot", "bitblt", "clipboard", "keylog", "getkeystate",
            "findfirstfile", "findnextfile", "documents", "desktop", "downloads",
            ".doc", ".xls", ".pdf",
        ],
        "validation": [
            "Confirm collected target paths, file filters, or capture APIs.",
            "Trace where collected data is stored or transmitted.",
        ],
    },
    "exfiltration": {
        "label": "数据外传迹象",
        "min_terms": 2,
        "terms": [
            "upload", "multipart", "post", "send", "ftp", "sftp", "smtp",
            "webdav", "archive", "zip", "rar", "telegram", "discord webhook",
        ],
        "validation": [
            "Connect collection/staging evidence to a network send or upload path.",
            "Identify destination and payload format before claiming exfiltration.",
        ],
    },
    "defense_evasion": {
        "label": "防御规避/反分析迹象",
        "terms": [
            "isdebuggerpresent", "checkremotedebuggerpresent", "amsi", "etw",
            "windefend", "defender", "firewall", "eventlog", "virtualbox",
            "vmware", "sandbox", "sleep", "cpuid",
        ],
        "validation": [
            "Separate anti-analysis checks from security-tool tampering.",
            "For tampering claims, confirm service/process/registry modification code paths.",
        ],
    },
    "security_tool_tampering": {
        "label": "安全工具对抗/日志破坏迹象",
        "terms": [
            "windefend", "set-mppreference", "disableantispyware", "exclusionpath",
            "exclusionprocess", "sc stop", "taskkill", "terminateprocess",
            "wevtutil cl", "clear-eventlog", "eventlog", "firewall", "edr",
            "avp.exe", "msmpeng.exe",
        ],
        "validation": [
            "Confirm the targeted product, process, service, registry value, or log source.",
            "Report defensive impact only; avoid operational disablement recipes.",
        ],
    },
    "discovery": {
        "label": "主机/网络发现迹象",
        "terms": [
            "getcomputername", "getusername", "ipconfig", "systeminfo", "whoami",
            "net view", "net user", "net group", "wmic", "netstat",
            "enumprocesses", "process32first",
        ],
        "validation": [
            "Confirm enumeration target and whether results feed C2, staging, or branching.",
            "Do not elevate generic system API imports to discovery behavior alone.",
        ],
    },
    "ad_discovery": {
        "label": "AD/域环境发现迹象",
        "terms": [
            "ldap", "active directory", "domain controller", "net group",
            "net user /domain", "nltest", "dsquery", "kerberos", "krbtgt",
            "samaccountname", "objectsid", "ldap_query", "domain admins",
        ],
        "validation": [
            "Confirm domain query APIs or commands and the queried object classes.",
            "Trace whether discovered AD data feeds lateral movement or credential targeting.",
        ],
    },
    "lateral_movement": {
        "label": "横向移动迹象",
        "min_terms": 2,
        "terms": [
            "admin$", "c$", "psexec", "wmic", "winrm", "rdp", "net use",
            "smb", "ssh", "remote service", "remote task",
        ],
        "validation": [
            "Confirm remote host selection, credential use, and remote execution path.",
            "Treat protocol strings alone as weak leads.",
        ],
    },
    "impact": {
        "label": "破坏/勒索影响迹象",
        "terms": [
            "vssadmin", "shadowcopy", "bcdedit", "wbadmin", "ransom", "decrypt",
            "encrypt", "deletefile", "wipe", "mbr", "recovery",
        ],
        "validation": [
            "Confirm destructive file, volume, backup, or encryption code paths.",
            "Avoid impact claims from ransom words or crypto imports alone.",
        ],
    },
    "c2_variants": {
        "label": "C2 变种/隐蔽通道迹象",
        "min_terms": 2,
        "terms": [
            "dns", "doh", "dns over https", "websocket", "tor", ".onion", "dga",
            "githubusercontent", "gist.github", "pastebin", "telegram", "discord",
            "webhook", "irc", "mqtt", "p2p", "proxy", "socks",
        ],
        "validation": [
            "Identify the transport, destination source, and message format.",
            "Confirm command, beacon, or data exchange semantics before claiming C2.",
        ],
    },
    "rootkit_driver": {
        "label": "驱动/rootkit 迹象",
        "min_terms": 2,
        "terms": [
            "deviceiocontrol", "ioctl", "driver", ".sys", "ntoskrnl",
            "pssetcreateprocessnotifyroutine", "pssetloadimagenotifyroutine",
            "fltregisterfilter", "minifilter", "zwsetinformationprocess",
            "obregistercallbacks", "createservice",
        ],
        "validation": [
            "Confirm driver file/service artifacts, device names, and IOCTL handlers statically.",
            "Do not load drivers; map behavior from imports, strings, and disassembly.",
        ],
    },
    "cloud_container": {
        "label": "云/容器凭据或环境访问迹象",
        "terms": [
            "169.254.169.254", "metadata.google.internal", "kubeconfig",
            "serviceaccount", "docker.sock", "aws_access_key", "azure",
            "gcp", "iam/security-credentials", "kubectl", "kubelet",
            "containerd.sock", "ecs/metadata", "credentials.json",
        ],
        "validation": [
            "Confirm metadata or credential path access and the destination of collected data.",
            "Separate cloud environment discovery from credential theft.",
        ],
    },
    "mobile_iot": {
        "label": "移动/IoT 平台迹象",
        "terms": [
            "android.permission", "accessibilityservice", "device_admin",
            "read_sms", "send_sms", "contacts", "imei", "busybox", "telnet",
            "/etc/init.d", "watchdog", "iptables", "dnsmasq",
        ],
        "validation": [
            "Confirm platform package/manifest evidence and execution context.",
            "For IoT, identify architecture, init mechanism, and network behavior.",
        ],
    },
    "api_hashing_obfuscation": {
        "label": "API hashing/导入隐藏迹象",
        "min_terms": 2,
        "terms": [
            "api hash", "hash api", "hashed api", "ror13", "crc32",
            "peb", "fs:[30h]", "gs:[60h]", "ldr", "export directory",
            "getprocaddress", "loadlibrary", "kernel32.dll", "ntdll.dll",
            "resolve api", "import resolver",
        ],
        "validation": [
            "Confirm export-name walking, hash constants, or resolved API table construction.",
            "Map resolved API guesses to later behavior before using them as behavior evidence.",
        ],
    },
    "dll_sideload_hijack": {
        "label": "DLL 侧载/搜索顺序劫持迹象",
        "min_terms": 2,
        "terms": [
            "dll side", "sideload", "side-load", "search order", "dll hijack",
            "proxy dll", "export forwarding", "ordinal", "version.dll",
            "winmm.dll", "dbghelp.dll", "dinput8.dll", "msimg32.dll",
            "cryptbase.dll", "wlbsctrl.dll",
        ],
        "validation": [
            "Identify the host binary, suspicious DLL path, and export/proxy surface.",
            "Confirm relative load path or search-order abuse rather than a normal DLL import.",
        ],
    },
    "lotl_abuse": {
        "label": "Living-off-the-land 工具滥用迹象",
        "min_terms": 2,
        "terms": [
            "certutil", "bitsadmin", "mshta", "rundll32", "regsvr32",
            "wmic", "powershell", "installutil", "msiexec", "schtasks",
            "forfiles", "curl", "wget", "living off the land", "lolbin",
        ],
        "validation": [
            "Confirm the launched binary, arguments, and parent process context.",
            "Separate benign administration strings from sample-controlled execution.",
        ],
    },
    "rat_backdoor_control": {
        "label": "RAT/后门命令控制迹象",
        "min_terms": 2,
        "terms": [
            "command id", "cmd id", "dispatcher", "command dispatcher",
            "remote shell", "reverse shell", "plugin", "module", "task id",
            "heartbeat", "sleep jitter", "beacon interval", "download",
            "upload", "execute", "list processes", "file manager",
        ],
        "validation": [
            "Identify command parsing, dispatch table, or handler functions.",
            "Tie command handling to a local IPC or network/C2 data source before claiming remote control.",
        ],
    },
    "keylogging_capture": {
        "label": "键盘/屏幕/剪贴板捕获迹象",
        "min_terms": 2,
        "terms": [
            "setwindowshookex", "wh_keyboard", "wh_keyboard_ll",
            "getasynckeystate", "getkeystate", "keylog", "keystroke",
            "bitblt", "printwindow", "getdc", "screenshot", "screen capture",
            "openclipboard", "getclipboarddata", "webcam", "avicap",
        ],
        "validation": [
            "Confirm the capture callback or polling loop and captured data buffer.",
            "Trace whether captured data is stored, staged, or transmitted.",
        ],
    },
    "wallet_clipboard_hijack": {
        "label": "钱包/剪贴板劫持迹象",
        "min_terms": 2,
        "terms": [
            "wallet.dat", "seed phrase", "mnemonic", "bitcoin", "ethereum",
            "monero", "litecoin", "usdt", "erc20", "trc20", "clipboard",
            "setclipboarddata", "openclipboard", "address replacement",
            "replace address",
        ],
        "validation": [
            "Confirm clipboard monitoring or wallet artifact access plus replacement or collection logic.",
            "Treat currency words alone as weak leads unless tied to clipboard, wallet, or exfil paths.",
        ],
    },
    "miner": {
        "label": "加密货币挖矿迹象",
        "min_terms": 2,
        "terms": [
            "stratum", "xmrig", "xmr", "cryptonight", "mining", "miner",
            "mining pool", "pool", "wallet", "hashrate", "opencl", "cuda",
            "cpu affinity", "threads",
        ],
        "validation": [
            "Confirm pool/config and wallet or worker identifier evidence.",
            "Identify resource-use or miner module clues before claiming monetization impact.",
        ],
    },
    "ddos_bot_proxy": {
        "label": "Botnet/DDoS/代理滥用迹象",
        "min_terms": 2,
        "terms": [
            "udp flood", "syn flood", "http flood", "slowloris", "ddos",
            "socks5", "socks proxy", "proxy server", "listen port",
            "smtp", "spam", "irc", "bot id", "botnet", "join #",
            "flood duration",
        ],
        "validation": [
            "Confirm command-controlled flood/proxy/spam module logic and target parameter source.",
            "Report third-party abuse risk defensively without providing operational recipes.",
        ],
    },
    "worm_propagation": {
        "label": "蠕虫/自传播迹象",
        "min_terms": 2,
        "terms": [
            "autorun.inf", "usb", "removable", "admin$", "c$", "net share",
            "copyfile", "shfileoperation", "subnet", "scan range", "spread",
            "bruteforce", "mapi", "address book", "mail contacts",
            "remote copy",
        ],
        "validation": [
            "Confirm target enumeration plus copy/drop and launch mechanism.",
            "Distinguish propagation from ordinary file copy or lateral-movement strings.",
        ],
    },
    "ransomware_anti_recovery": {
        "label": "勒索/反恢复迹象",
        "min_terms": 2,
        "terms": [
            "vssadmin", "delete shadows", "wmic shadowcopy", "wbadmin",
            "bcdedit", "recoveryenabled", "bootstatuspolicy", "ransom note",
            "decrypt instructions", ".locked", ".encrypted", "encrypt files",
            "extension list", "shadowcopy",
        ],
        "validation": [
            "Confirm file traversal plus encryption/write/rename or recovery-disabling code path.",
            "Do not claim ransomware from ransom text or crypto terms alone.",
        ],
    },
    "bootkit_uefi": {
        "label": "Bootkit/UEFI/启动链破坏迹象",
        "min_terms": 2,
        "terms": [
            "\\efi\\boot", "bootmgfw", "efi system partition", "esp",
            "uefi", "mbr", "boot sector", "physicaldrive",
            "setfirmwareenvironmentvariable", "bcdedit", "bootkit",
            "bootloader",
        ],
        "validation": [
            "Confirm boot/firmware/volume write target and execution context.",
            "Treat boot strings as high-risk leads until a concrete write or modification path is found.",
        ],
    },
    "supply_chain_update_abuse": {
        "label": "供应链/更新通道滥用迹象",
        "min_terms": 2,
        "terms": [
            "update.exe", "updater", "auto update", "plugin", "extension",
            "manifest", "package.json", "npm", "pip", "maven", "nuget",
            "signed binary", "certificate", "publisher", "install script",
            "postinstall",
        ],
        "validation": [
            "Confirm trusted update/plugin/package path abuse and payload boundary.",
            "Separate normal package metadata from malicious installation or loading behavior.",
        ],
    },
    "file_infector": {
        "label": "文件感染/病毒式修改迹象",
        "min_terms": 3,
        "terms": [
            "infect", "append overlay", "entry point", "section header",
            "pe header", "findfirstfile", "findnextfile", ".exe", ".scr",
            "setfilepointer", "writefile", "mapviewoffile", "checksum",
            "cavity",
        ],
        "validation": [
            "Confirm executable-file enumeration plus PE modification or appended payload logic.",
            "Distinguish infection from benign resource or installer file writes.",
        ],
    },
}

BOUNDARY_TERMS = {
    "amsi", "etw", "sam", "post", "send", "recv", "zip", "rar", "rdp",
    "smb", "ssh", "gcp", "dns", "doh", "tor", "irc", "mqtt", "p2p",
    "uac", "ole", "hta", "mz", "xmr", "usb", "esp", "mbr", "smtp",
    "npm", "pip", "cuda",
}

STRONG_CLUSTERS = {
    "process_injection": {"openprocess", "virtualallocex", "writeprocessmemory", "createremotethread"},
    "loader_staging": {"virtualalloc", "virtualprotect", "shellcode", "reflective", "manual map"},
    "privilege_escalation": {"sedebugprivilege", "adjusttokenprivileges", "seimpersonateprivilege", "uac"},
    "persistence": {"currentversion\\run", "regsetvalue", "createservice", "schtasks"},
    "c2_network": {"connect", "send", "recv", "http://", "https://", "user-agent"},
    "c2_variants": {"doh", "websocket", "tor", ".onion", "dga", "telegram", "discord", "webhook"},
    "security_tool_tampering": {"windefend", "set-mppreference", "disableantispyware", "wevtutil cl"},
    "rootkit_driver": {"deviceiocontrol", "ioctl", "ntoskrnl", "fltregisterfilter", "obregistercallbacks"},
    "impact": {"vssadmin", "shadowcopy", "bcdedit", "encrypt", "deletefile"},
    "api_hashing_obfuscation": {"api hash", "ror13", "peb", "export directory", "resolve api"},
    "dll_sideload_hijack": {"sideload", "search order", "dll hijack", "export forwarding"},
    "lotl_abuse": {"certutil", "bitsadmin", "mshta", "regsvr32", "rundll32"},
    "rat_backdoor_control": {"command id", "dispatcher", "remote shell", "plugin", "heartbeat"},
    "keylogging_capture": {"setwindowshookex", "getasynckeystate", "bitblt", "getclipboarddata"},
    "wallet_clipboard_hijack": {"wallet.dat", "seed phrase", "setclipboarddata", "address replacement"},
    "miner": {"stratum", "xmrig", "mining pool", "wallet"},
    "ddos_bot_proxy": {"udp flood", "syn flood", "socks5", "botnet"},
    "worm_propagation": {"autorun.inf", "admin$", "copyfile", "subnet", "spread"},
    "ransomware_anti_recovery": {"vssadmin", "delete shadows", "ransom note", "encrypt files"},
    "bootkit_uefi": {"\\efi\\boot", "physicaldrive", "setfirmwareenvironmentvariable", "bootkit"},
    "supply_chain_update_abuse": {"updater", "manifest", "package.json", "postinstall"},
    "file_infector": {"infect", "append overlay", "entry point", "section header"},
}

CLAIM_GATES = {
    "c2_network": [
        "Require endpoint/config plus socket/HTTP code path, beacon loop, command dispatcher, or runtime network evidence before confirmed C2 claims.",
    ],
    "c2_variants": [
        "Require transport-specific message flow or platform API usage before confirmed covert/alternate C2 claims.",
    ],
    "process_injection": [
        "Require allocation/write/execution call sequence, target process, and payload buffer origin before confirmed injection claims.",
    ],
    "credential_access": [
        "Require credential artifact access plus parsing/decryption or staging path before confirmed credential theft claims.",
    ],
    "browser_cloud_credentials": [
        "Require browser/cloud credential file access plus parser/decryptor or exfil/staging evidence before confirmed theft claims.",
    ],
    "exfiltration": [
        "Require collection/staging evidence tied to upload/send destination before confirmed exfiltration claims.",
    ],
    "lateral_movement": [
        "Require remote target selection plus remote execution/authentication evidence before confirmed lateral movement claims.",
    ],
    "impact": [
        "Require destructive file/volume/backup/encryption code path before confirmed ransomware/wiper impact claims.",
    ],
    "security_tool_tampering": [
        "Require targeted product/process/service/registry/log modification path before confirmed tampering claims.",
    ],
    "rootkit_driver": [
        "Require driver/service artifacts plus device/IOCTL or kernel callback evidence before rootkit claims.",
    ],
    "privilege_escalation": [
        "Require privilege/token/exploit trigger path and target context before confirmed elevation claims.",
    ],
    "rat_backdoor_control": [
        "Require command parser/dispatcher plus IPC or network-controlled input before confirmed RAT/backdoor control claims.",
    ],
    "keylogging_capture": [
        "Require capture loop/callback plus storage, staging, or transmission path before confirmed keylogging/screen-capture claims.",
    ],
    "wallet_clipboard_hijack": [
        "Require clipboard/wallet monitoring plus replacement, staging, or exfiltration logic before confirmed hijacking/theft claims.",
    ],
    "miner": [
        "Require miner module/config plus pool and wallet/worker evidence before confirmed cryptomining claims.",
    ],
    "ddos_bot_proxy": [
        "Require command-controlled flood, proxy, or spam module logic before confirmed botnet-abuse claims.",
    ],
    "worm_propagation": [
        "Require target enumeration plus copy/drop and execution mechanism before confirmed worm propagation claims.",
    ],
    "ransomware_anti_recovery": [
        "Require file traversal/encryption or recovery-disabling code path before confirmed ransomware/anti-recovery claims.",
    ],
    "bootkit_uefi": [
        "Require boot/firmware/volume modification path before confirmed bootkit or boot-chain tampering claims.",
    ],
    "supply_chain_update_abuse": [
        "Require trusted update/plugin/package abuse path and payload boundary before confirmed supply-chain claims.",
    ],
    "file_infector": [
        "Require executable enumeration plus PE modification or appended payload logic before confirmed file-infector claims.",
    ],
}

