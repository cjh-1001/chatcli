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
    "silent_downloader": {
        "label": "静默下载/下载执行迹象",
        "min_terms": 2,
        "terms": [
            "silent download", "background download", "download cradle",
            "download and execute", "http download", "drop url",
            "urldownloadtofile", "urlmon", "wininet", "winhttp",
            "downloadfile", "invoke-webrequest", "start-bitstransfer",
            "bitsadmin", "certutil -urlcache", "curl.exe", "wget",
            "powershell -enc", "mshta", "wscript", "静默下载",
        ],
        "validation": [
            "Monitor URL source, download API/tool, destination path, and whether the downloaded file is executed.",
            "Distinguish normal updater/download logic from hidden download-and-run behavior controlled by the sample.",
        ],
    },
    "payload_dropper": {
        "label": "投放载荷/病毒文件迹象",
        "min_terms": 2,
        "terms": [
            "dropper", "drop file", "writefile", "createfile", "copyfile",
            "extract resource", "findresource", "loadresource",
            "embedded payload", "resource payload", "payload.exe",
            "stage2", "cabinet", "expand.exe", "self-extract",
            "%temp%", "temp\\", "appdata", "programdata", "投放病毒",
        ],
        "validation": [
            "Monitor payload source, dropped file path, file hash or format, and launch or persistence edge.",
            "Separate installer/resource extraction from malicious payload staging before using confirmed wording.",
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
    "uac_bypass": {
        "label": "UAC 绕过迹象",
        "min_terms": 2,
        "terms": [
            "uac", "bypassuac", "uac bypass", "fodhelper", "eventvwr",
            "sdclt", "computerdefaults", "cmstp", "auto elevate",
            "autoelevate", "consent.exe", "delegateexecute",
            "shellopen\\command", "ms-settings",
        ],
        "validation": [
            "Confirm the auto-elevate binary, registry path, or COM handler abused.",
            "Do not claim successful elevation without a reachable trigger and integrity-level context.",
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
    "service_persistence": {
        "label": "服务持久化迹象",
        "min_terms": 2,
        "terms": [
            "createservice", "openservice", "startservice", "changeserviceconfig",
            "service install", "service name", "services.exe", "sc create",
            "sc.exe create", "new-service", "system\\currentcontrolset\\services",
        ],
        "validation": [
            "Confirm the service name, binary path, start type, and creation or modification path.",
            "Separate benign service-management imports from reachable persistence logic.",
        ],
    },
    "scheduled_task_persistence": {
        "label": "计划任务持久化迹象",
        "min_terms": 2,
        "terms": [
            "schtasks /create", "schtasks.exe", "taskschd", "itaskservice",
            "registeredtask", "task scheduler", "scheduled task",
            "\\microsoft\\windows\\", "at.exe", "new-scheduledtask",
        ],
        "validation": [
            "Confirm task name, trigger, action, and creation or registration code path.",
            "Treat task-scheduler strings alone as candidate persistence until the action is known.",
        ],
    },
    "startup_folder_persistence": {
        "label": "启动目录/LNK 持久化迹象",
        "min_terms": 2,
        "terms": [
            "startup folder", "shell:startup", "common startup",
            "start menu\\programs\\startup", "\\startup\\", ".lnk",
            "shortcut", "wscript.shell", "createshortcut",
        ],
        "validation": [
            "Confirm Startup folder path, shortcut target, and write/copy operation.",
            "Separate benign shortcut creation from autostart persistence.",
        ],
    },
    "account_persistence": {
        "label": "账户持久化迹象",
        "min_terms": 2,
        "terms": [
            "hidden account", "guest account", "activate guest", "enable guest",
            "adsi", "winnt://", "net user /add", "net localgroup administrators",
            "user clone", "clone user", "rid 500", "sam copy", "rid hijack",
        ],
        "validation": [
            "Confirm local/domain account creation, enablement, group change, or RID/user-clone artifact.",
            "Do not claim persistence from account strings without modification evidence.",
        ],
    },
    "accessibility_hijack_persistence": {
        "label": "辅助功能/屏保劫持持久化迹象",
        "min_terms": 2,
        "terms": [
            "sethc.exe", "sticky keys", "utilman.exe", "osk.exe",
            "magnify.exe", "narrator.exe", "accessibility features",
            "screensaver", "scrnsave.exe", "logon.scr", "screen saver",
            "debugger", "image file execution options", "ifeo", "粘滞键", "屏保",
        ],
        "validation": [
            "Confirm replacement, debugger hijack, or registry value that launches the payload.",
            "Tie the accessibility or screensaver artifact to logon-screen or session-triggered execution.",
        ],
    },
    "registry_autostart_extension_persistence": {
        "label": "注册表自启动扩展持久化迹象",
        "min_terms": 2,
        "terms": [
            "currentversion\\run", "runonce", "runservices", "runservicesonce",
            "winlogon", "userinit", "shell", "logon scripts", "appinit_dlls",
            "active setup", "stubpath", "clsid", "inprocserver32",
            "com hijack", "com object hijack", "telemetrycontroller",
            "print monitor", "print monitors", "monitor dll",
        ],
        "validation": [
            "Confirm exact registry key/value, payload path, and write operation.",
            "Prefer the specific sub-technique name in reports when the key family is known.",
        ],
    },
    "ifeo_debugger_persistence": {
        "label": "IFEO Debugger/映像劫持持久化迹象",
        "min_terms": 2,
        "terms": [
            "image file execution options", "ifeo", "debugger",
            "globalflag", "silentprocessexit", "monitorprocess",
            "sethc.exe", "utilman.exe", "lsass.exe",
        ],
        "validation": [
            "Confirm IFEO target image, Debugger or SilentProcessExit value, and payload path.",
            "Separate diagnostic/debug configuration from persistence or dump-trigger abuse.",
        ],
    },
    "bits_jobs_persistence": {
        "label": "BITS Jobs 持久化迹象",
        "min_terms": 2,
        "terms": [
            "bitsadmin", "bits job", "background intelligent transfer",
            "createbitsjob", "setnotifycmdline", "bitsadmin /create",
            "bitsadmin /setnotifycmdline", "bitsadmin /resume",
            "bitsadmin /setminretrydelay",
        ],
        "validation": [
            "Confirm BITS job creation, notify command, transfer source, and resume/trigger behavior.",
            "Distinguish normal BITS transfer use from persistence via notify command execution.",
        ],
    },
    "wmi_persistence": {
        "label": "WMI 事件持久化迹象",
        "min_terms": 2,
        "terms": [
            "__eventfilter", "commandlineeventconsumer", "active scripteventconsumer",
            "__filtertoconsumerbinding", "root\\subscription", "wmieventconsumer",
            "wmi persistence", "wmiprvse", "managementeventwatcher",
            "set-wmiinstance", "wmic /namespace",
        ],
        "validation": [
            "Confirm the WMI namespace, filter, consumer, and binding artifacts.",
            "Trace the consumer command or script payload before reporting confirmed persistence.",
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
    "c2_config_protocol": {
        "label": "C2 配置/协议线索",
        "min_terms": 2,
        "terms": [
            "beacon interval", "sleep jitter", "campaign id", "bot id",
            "victim id", "command id", "uri path", "user-agent",
            "gate.php", "panel", "config decrypt", "encrypted config",
            "rc4 key", "xor key", "mutex", "callback path",
        ],
        "validation": [
            "Recover the decoded config fields or protocol constants before treating this as strong C2 evidence.",
            "Tie config/protocol fields to network send/receive or command-dispatch code paths.",
        ],
    },
    "named_pipe_ipc": {
        "label": "命名管道/本地 IPC 控制迹象",
        "min_terms": 2,
        "terms": [
            "\\\\.\\pipe\\", "createnamedpipe", "connectnamedpipe",
            "transactnamedpipe", "callnamedpipe", "impersonatenamedpipeclient",
            "pipe server", "pipe client", "named pipe", "ipc channel",
        ],
        "validation": [
            "Confirm pipe name, server/client role, message format, and command or payload flow.",
            "Distinguish local IPC plumbing from operator-controlled command channels.",
        ],
    },
    "remote_access_tool_abuse": {
        "label": "远程访问工具滥用迹象",
        "min_terms": 2,
        "terms": [
            "anydesk", "teamviewer", "screenconnect", "connectwise",
            "splashtop", "rustdesk", "ultravnc", "tightvnc", "vnc",
            "rdpwrap", "remote access", "remote desktop", "ngrok",
        ],
        "validation": [
            "Confirm the remote-access tool artifact, installation path, configuration, or launch command.",
            "Avoid treating admin-tool names alone as malicious without sample-controlled deployment evidence.",
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
            "ntallocatevirtualmemory", "createremotethread", "ntqueueapcthread", "queueuserapc",
            "setthreadcontext", "zwunmapviewofsection", "process hollowing",
            "reflective loader", "manual map",
        ],
        "validation": [
            "Confirm call sequence, target process, and payload buffer origin.",
            "Identify the execution transfer edge after the remote write or mapping.",
        ],
    },
    "process_masquerading": {
        "label": "进程伪装/父进程伪造迹象",
        "min_terms": 2,
        "terms": [
            "ppid spoof", "parent process spoof", "spoofed parent",
            "updateprocthreadattribute", "proc_thread_attribute_parent_process",
            "masquerade", "process masquerading", "renamed payload",
            "explorer.exe", "svchost.exe", "rundll32.exe", "signed parent",
        ],
        "validation": [
            "Confirm the parent-process attribute, copied/renamed path, or misleading process identity.",
            "Separate normal process names from deliberate masquerading logic.",
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
    "banking_credential_theft": {
        "label": "网银/金融凭据窃取迹象",
        "min_terms": 2,
        "terms": [
            "bank", "banking", "financial", "webinject", "web inject",
            "form grabber", "formgrabber", "browser hook", "wininet hook",
            "httpsendrequest", "internetreadfile", "pr_write", "ssl_read",
            "zeus", "two-factor", "2fa", "tan", "otp", "银行窃密",
        ],
        "validation": [
            "Monitor browser/API hook point, targeted banking or payment site, captured form fields, and staging or exfil path.",
            "Do not claim banking theft from finance words alone without browser/session/form capture evidence.",
        ],
    },
    "lsass_dumping": {
        "label": "LSASS/凭据转储迹象",
        "min_terms": 2,
        "terms": [
            "lsass", "minidumpwritedump", "comsvcs.dll", "procdump",
            "nanodump", "sekurlsa", "logonpasswords", "psscapture",
            "psscapturesnapshot", "handlekatz", "processdump-jabber",
            "minidump callbacks", "direct syscalls", "direct syscall",
            "dbghelp.dll", "process dump", "dump lsass", "lsass.dmp",
            "authentication id", "msv :", "ntlm", "sekurlsa::logonpasswords",
        ],
        "validation": [
            "Confirm the LSASS target plus dump API, helper DLL, or dumping tool logic.",
            "Do not claim credential theft from LSASS strings without dump or memory-read evidence.",
        ],
    },
    "silent_process_exit_dump": {
        "label": "SilentProcessExit 转储配置迹象",
        "min_terms": 2,
        "terms": [
            "silentprocessexit", "silentprocessExit\\lsass.exe", "globalflag",
            "monitorprocess", "reportingmode", "dumptype", "dumpfolder",
            "image file execution options", "ifeo", "lsass.exe",
        ],
        "validation": [
            "Confirm SilentProcessExit/IFEO registry path, dump settings, and LSASS target.",
            "Treat configuration-only evidence as pending until dump trigger or artifact is observed.",
        ],
    },
    "ssp_credential_capture": {
        "label": "SSP/mimilib 凭据捕获迹象",
        "min_terms": 2,
        "terms": [
            "security packages", "mimilib", "mimilib.dll", "kiwissp.log",
            "ssp", "security support provider", "authentication package",
            "hklm\\system\\currentcontrolset\\control\\lsa", "wdigest",
            "useLogonCredential", "lsa package",
        ],
        "validation": [
            "Confirm Security Packages/SSP modification, DLL artifact, or in-memory SSP injection path.",
            "For persistence claims, confirm reboot requirement or authentication-event capture artifact.",
        ],
    },
    "registry_credential_dumping": {
        "label": "SAM/LSA/缓存域凭据转储迹象",
        "min_terms": 2,
        "terms": [
            "sam", "security hive", "system hive", "reg save",
            "hklm\\sam", "hklm\\security", "hklm\\system",
            "lsa secrets", "cached logons", "cached domain credentials",
            "secretsdump", "samlib", "lsass policy", "lsadump::sam",
            "lsadump::secrets", "hash ntlm", "$machine.acc",
            "defaultpassword", "_sc_", "sam.hiv", "system.hiv",
            "security.hiv", "esentutl", "vssadmin", "diskshadow",
        ],
        "validation": [
            "Confirm registry hive access or save operations plus parsing or exfiltration path.",
            "Separate ordinary registry reads from credential-hive dumping behavior.",
        ],
    },
    "ntds_dumping": {
        "label": "NTDS.dit/域凭据库转储迹象",
        "min_terms": 2,
        "terms": [
            "ntds.dit", "ntdsutil", "esentutl", "volume shadow copy",
            "vssadmin", "diskshadow", "domain controller", "system hive",
            "active directory database", "dit extraction",
        ],
        "validation": [
            "Confirm NTDS.dit access/copy plus SYSTEM hive or key material handling.",
            "Treat domain-controller strings alone as weak unless tied to database extraction.",
        ],
    },
    "dcsync_replication": {
        "label": "DCSync/目录复制凭据访问迹象",
        "min_terms": 2,
        "terms": [
            "dcsync", "drsuapi", "dsgetncchanges", "replicating directory changes",
            "replicating directory changes all", "krbtgt", "ntdsapi",
            "domain controller", "directory replication",
        ],
        "validation": [
            "Confirm directory-replication API usage, target domain context, and credential material requested.",
            "Do not claim DCSync from domain strings without replication semantics.",
        ],
    },
    "kerberos_ticket_access": {
        "label": "Kerberos 票据/roasting 迹象",
        "min_terms": 2,
        "terms": [
            "kerberoast", "as-rep roast", "asreproast", "tgs-rep",
            "tgt", "tgs", "kirbi", "klist", "sekurlsa::tickets",
            "golden ticket", "silver ticket", "kerberos ticket",
        ],
        "validation": [
            "Confirm Kerberos ticket request, extraction, cache access, or ticket artifact handling.",
            "Report ticket access defensively without providing cracking or forgery workflow details.",
        ],
    },
    "dpapi_credential_access": {
        "label": "DPAPI/Windows Vault 凭据访问迹象",
        "min_terms": 2,
        "terms": [
            "dpapi", "cryptunprotectdata", "masterkey", "protect\\",
            "credhist", "windows vault", "credential manager",
            "vaultcli", "credman", "local state",
        ],
        "validation": [
            "Confirm protected blob, masterkey, or Windows Vault access plus decrypt/parsing logic.",
            "Do not treat DPAPI imports alone as credential theft.",
        ],
    },
    "ssh_private_key_access": {
        "label": "SSH/私钥凭据访问迹象",
        "min_terms": 2,
        "terms": [
            ".ssh", "id_rsa", "id_ed25519", "private key",
            "authorized_keys", "known_hosts", ".pem", ".ppk",
            "openssh", "ssh key",
        ],
        "validation": [
            "Confirm private-key file discovery/access and staging or use context.",
            "Separate benign SSH client strings from key harvesting behavior.",
        ],
    },
    "unix_shadow_access": {
        "label": "Unix/Linux shadow/passwd 凭据访问迹象",
        "min_terms": 2,
        "terms": [
            "/etc/shadow", "/etc/passwd", "/etc/security/passwd",
            "shadow-", "getpwnam", "getspnam", "unshadow",
            "passwd file", "shadow file",
        ],
        "validation": [
            "Confirm privileged password database access and whether hashes are parsed or staged.",
            "Separate platform discovery from credential database collection.",
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
    "archive_staging": {
        "label": "归档/压缩暂存迹象",
        "min_terms": 2,
        "terms": [
            "archive", "zip", "rar", "7z", "tar", "gzip",
            "compress-archive", "zipfile", "minizip", "create archive",
            "staging directory", "temp archive", "documents", "desktop",
        ],
        "validation": [
            "Confirm collected file inputs, archive path, and whether the archive feeds exfiltration.",
            "Separate installer/resource compression from attacker data staging.",
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
        "label": "防御规避/反分析综合迹象",
        "min_terms": 2,
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
    "anti_debug": {
        "label": "反调试迹象",
        "terms": [
            "isdebuggerpresent", "checkremotedebuggerpresent",
            "ntqueryinformationprocess", "debug port", "debug object",
            "beingdebugged", "peb", "outputdebugstring", "breakpoint",
            "hardware breakpoint", "debugger",
        ],
        "validation": [
            "Confirm the anti-debug check site and the branch or behavior it controls.",
            "Separate generic imports from reachable anti-debug decision logic.",
        ],
    },
    "anti_vm_sandbox": {
        "label": "反虚拟机/沙箱迹象",
        "min_terms": 2,
        "terms": [
            "virtualbox", "vmware", "vbox", "qemu", "xen", "hyper-v",
            "sandbox", "cpuid", "rdtsc", "wine", "cuckoo",
            "vmtools", "vboxservice", "vboxtray",
        ],
        "validation": [
            "Identify the VM/sandbox artifact checked and the resulting branch or delay path.",
            "Avoid treating environment strings alone as confirmed sandbox evasion.",
        ],
    },
    "execution_delay": {
        "label": "延迟执行/时间规避迹象",
        "min_terms": 2,
        "terms": [
            "sleep", "sleepex", "nanosleep", "waitforsingleobject",
            "gettickcount", "queryperformancecounter", "rdtsc",
            "time delay", "delayed execution", "long sleep", "jitter",
        ],
        "validation": [
            "Confirm the delay duration, loop, or time-skipping check and its control-flow impact.",
            "Distinguish ordinary retry/backoff from anti-analysis delay.",
        ],
    },
    "telemetry_bypass": {
        "label": "安全遥测绕过迹象",
        "terms": [
            "amsi", "amsiscanbuffer", "amsiinit", "etw", "etweventwrite",
            "nttraceevent", "patch amsi", "patch etw", "unhook",
            "syscall", "direct syscall", "amsi bypass", "etw bypass",
            "amsiutils", "string obfuscation",
        ],
        "validation": [
            "Confirm the patch, hook removal, or direct-syscall code path and target API.",
            "Report defensive visibility impact without giving operational bypass steps.",
        ],
    },
    "security_tool_tampering": {
        "label": "安全工具对抗/日志破坏迹象",
        "terms": [
            "windefend", "set-mppreference", "disableantispyware", "exclusionpath",
            "exclusionprocess", "sc stop", "taskkill", "terminateprocess",
            "wevtutil cl", "clear-eventlog", "eventlog", "defender", "firewall", "edr",
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
    "byovd_abuse": {
        "label": "BYOVD/脆弱驱动滥用迹象",
        "min_terms": 2,
        "terms": [
            "byovd", "bring your own vulnerable driver", "vulnerable driver",
            "capcom.sys", "gdrv.sys", "dbutil", "iqvw64e.sys",
            "aswarpot.sys", "rtcore64.sys", "driver load", "createservice",
            "deviceiocontrol", "ioctl", "kernel primitive",
        ],
        "validation": [
            "Confirm the driver artifact, load/service path, and IOCTL or kernel primitive usage.",
            "Do not load drivers; keep analysis static or in an authorized isolated lab.",
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
    "adware_browser_manipulation": {
        "label": "广告投放/浏览器配置篡改迹象",
        "min_terms": 2,
        "terms": [
            "adware", "advertisement", "popup", "pop-up", "inject ads",
            "browser helper object", "bho", "urlsearchhook", "webbrowser",
            "homepage", "search provider", "default search", "newtab",
            "proxyenable", "autoconfigurl", "hosts file", "toolbar",
            "browser toolbar", "投放广告",
        ],
        "validation": [
            "Monitor browser home/search/proxy/hosts modifications, injected ad surface, and process or extension responsible.",
            "Separate potentially unwanted adware behavior from ordinary browser preference changes.",
        ],
    },
    "browser_extension_toolbar": {
        "label": "浏览器扩展/工具条植入迹象",
        "min_terms": 2,
        "terms": [
            "browser extension", "install extension", "extensioninstallforcelist",
            "chrome\\user data", "edge\\user data", "firefox\\profiles",
            "manifest.json", "xpi", "toolbar", "browser toolbar",
            "browser helper object", "bho", "iexplore",
            "explorer\\browser helper objects", "inprocserver32", "浏览器工具条",
        ],
        "validation": [
            "Monitor extension ID, manifest, installation path, policy key, BHO CLSID, and loaded DLL or script.",
            "Confirm the sample creates or modifies the browser add-on artifact before reporting toolbar persistence.",
        ],
    },
    "user_deception_fraud": {
        "label": "欺诈诱导/伪装提示迹象",
        "min_terms": 2,
        "terms": [
            "fake login", "phishing", "scam", "fraud", "fake update",
            "fake antivirus", "tech support scam", "overlay window",
            "credential prompt", "payment required", "messagebox",
            "invoice", "security warning", "网页弹窗", "欺诈用户",
        ],
        "validation": [
            "Monitor lure text, displayed window or web overlay, requested action, and resulting credential/payment/execution path.",
            "Avoid overclaiming fraud from UI strings unless the prompt is reachable and tied to malicious outcome.",
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
    "npm", "pip", "cuda", "bho", "xpi", "tan", "otp",
}

STRONG_CLUSTERS = {
    "process_injection": {"openprocess", "virtualallocex", "writeprocessmemory", "createremotethread"},
    "silent_downloader": {"urldownloadtofile", "invoke-webrequest", "certutil -urlcache", "bitsadmin", "download and execute"},
    "payload_dropper": {"dropper", "extract resource", "findresource", "embedded payload", "payload.exe"},
    "loader_staging": {"virtualalloc", "virtualprotect", "shellcode", "reflective", "manual map"},
    "privilege_escalation": {"sedebugprivilege", "adjusttokenprivileges", "seimpersonateprivilege", "uac"},
    "uac_bypass": {"fodhelper", "computerdefaults", "cmstp", "delegateexecute", "shellopen\\command"},
    "persistence": {"currentversion\\run", "regsetvalue", "createservice", "schtasks"},
    "service_persistence": {"createservice", "startservice", "sc create", "system\\currentcontrolset\\services"},
    "scheduled_task_persistence": {"schtasks /create", "taskschd", "registeredtask", "new-scheduledtask"},
    "startup_folder_persistence": {"startup folder", "shell:startup", "common startup", ".lnk", "createshortcut"},
    "account_persistence": {"hidden account", "guest account", "adsi", "net user /add", "user clone"},
    "accessibility_hijack_persistence": {"sethc.exe", "sticky keys", "utilman.exe", "screensaver", "scrnsave.exe"},
    "registry_autostart_extension_persistence": {"runservices", "winlogon", "appinit_dlls", "active setup", "inprocserver32"},
    "ifeo_debugger_persistence": {"image file execution options", "ifeo", "debugger", "silentprocessexit"},
    "bits_jobs_persistence": {"bitsadmin", "bits job", "setnotifycmdline", "bitsadmin /setnotifycmdline"},
    "wmi_persistence": {"__eventfilter", "commandlineeventconsumer", "__filtertoconsumerbinding", "root\\subscription"},
    "c2_network": {"connect", "send", "recv", "http://", "https://", "user-agent"},
    "c2_config_protocol": {"beacon interval", "sleep jitter", "command id", "config decrypt", "encrypted config"},
    "named_pipe_ipc": {"\\\\.\\pipe\\", "createnamedpipe", "connectnamedpipe", "impersonatenamedpipeclient"},
    "remote_access_tool_abuse": {"anydesk", "teamviewer", "screenconnect", "rustdesk", "rdpwrap"},
    "c2_variants": {"doh", "websocket", "tor", ".onion", "dga", "telegram", "discord", "webhook"},
    "security_tool_tampering": {"windefend", "set-mppreference", "disableantispyware", "wevtutil cl"},
    "anti_debug": {"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "beingdebugged"},
    "anti_vm_sandbox": {"virtualbox", "vmware", "sandbox", "cpuid", "vboxservice"},
    "execution_delay": {"sleep", "sleepex", "gettickcount", "queryperformancecounter", "rdtsc"},
    "telemetry_bypass": {"amsi", "amsiscanbuffer", "etweventwrite", "patch amsi", "patch etw"},
    "rootkit_driver": {"deviceiocontrol", "ioctl", "ntoskrnl", "fltregisterfilter", "obregistercallbacks"},
    "byovd_abuse": {"byovd", "vulnerable driver", "iqvw64e.sys", "gdrv.sys", "deviceiocontrol"},
    "impact": {"vssadmin", "shadowcopy", "bcdedit", "encrypt", "deletefile"},
    "api_hashing_obfuscation": {"api hash", "ror13", "peb", "export directory", "resolve api"},
    "dll_sideload_hijack": {"sideload", "search order", "dll hijack", "export forwarding"},
    "process_masquerading": {"ppid spoof", "parent process spoof", "proc_thread_attribute_parent_process", "process masquerading"},
    "lsass_dumping": {"lsass", "minidumpwritedump", "comsvcs.dll", "procdump", "nanodump", "handlekatz"},
    "silent_process_exit_dump": {"silentprocessexit", "monitorprocess", "reportingmode", "dumptype", "dumpfolder"},
    "ssp_credential_capture": {"security packages", "mimilib", "mimilib.dll", "kiwissp.log", "security support provider"},
    "registry_credential_dumping": {"hklm\\sam", "hklm\\security", "reg save", "lsa secrets", "cached domain credentials", "lsadump::sam"},
    "banking_credential_theft": {"webinject", "web inject", "form grabber", "browser hook", "httpsendrequest"},
    "ntds_dumping": {"ntds.dit", "ntdsutil", "esentutl", "volume shadow copy", "diskshadow"},
    "dcsync_replication": {"dcsync", "drsuapi", "dsgetncchanges", "replicating directory changes"},
    "kerberos_ticket_access": {"kerberoast", "as-rep roast", "asreproast", "kirbi", "sekurlsa::tickets"},
    "dpapi_credential_access": {"dpapi", "cryptunprotectdata", "masterkey", "windows vault", "vaultcli"},
    "ssh_private_key_access": {"id_rsa", "id_ed25519", "private key", ".pem", ".ppk"},
    "unix_shadow_access": {"/etc/shadow", "/etc/passwd", "getspnam", "unshadow"},
    "lotl_abuse": {"certutil", "bitsadmin", "mshta", "regsvr32", "rundll32"},
    "rat_backdoor_control": {"command id", "dispatcher", "remote shell", "plugin", "heartbeat"},
    "keylogging_capture": {"setwindowshookex", "getasynckeystate", "bitblt", "getclipboarddata"},
    "adware_browser_manipulation": {"adware", "inject ads", "browser helper object", "default search", "proxyenable"},
    "browser_extension_toolbar": {"browser extension", "extensioninstallforcelist", "manifest.json", "browser helper object", "inprocserver32"},
    "user_deception_fraud": {"fake login", "phishing", "fake update", "fake antivirus", "credential prompt"},
    "archive_staging": {"archive", "zip", "7z", "compress-archive", "staging directory"},
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
    "c2_config_protocol": [
        "Require decoded config/protocol fields tied to network or command-dispatch code before strong C2 claims.",
    ],
    "named_pipe_ipc": [
        "Require pipe name, role, message format, and command/payload flow before confirmed IPC control claims.",
    ],
    "remote_access_tool_abuse": [
        "Require sample-controlled install, launch, configuration, or persistence evidence before confirmed remote-access-tool abuse claims.",
    ],
    "c2_variants": [
        "Require transport-specific message flow or platform API usage before confirmed covert/alternate C2 claims.",
    ],
    "process_injection": [
        "Require allocation/write/execution call sequence, target process, and payload buffer origin before confirmed injection claims.",
    ],
    "silent_downloader": [
        "Require download source plus destination and execution, persistence, or staging evidence before confirmed silent-download claims.",
    ],
    "payload_dropper": [
        "Require embedded/source payload plus write/drop path and launch or persistence edge before confirmed payload-dropping claims.",
    ],
    "credential_access": [
        "Require credential artifact access plus parsing/decryption or staging path before confirmed credential theft claims.",
    ],
    "banking_credential_theft": [
        "Require banking/payment target plus browser/session/form capture and staging or exfiltration evidence before confirmed banking-theft claims.",
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
    "process_masquerading": [
        "Require parent-process spoofing, renamed payload, or misleading identity evidence before confirmed masquerading claims.",
    ],
    "anti_debug": [
        "Require a reachable anti-debug check and a branch, delay, or behavior change before confirmed anti-debug claims.",
    ],
    "anti_vm_sandbox": [
        "Require concrete VM/sandbox artifact checks and behavior change before confirmed sandbox-evasion claims.",
    ],
    "execution_delay": [
        "Require timing logic tied to anti-analysis behavior before confirmed delay-evasion claims.",
    ],
    "telemetry_bypass": [
        "Require patching, unhooking, or direct telemetry-bypass code path before confirmed visibility-bypass claims.",
    ],
    "rootkit_driver": [
        "Require driver/service artifacts plus device/IOCTL or kernel callback evidence before rootkit claims.",
    ],
    "byovd_abuse": [
        "Require vulnerable driver artifact plus load path and IOCTL/kernel primitive evidence before confirmed BYOVD claims.",
    ],
    "privilege_escalation": [
        "Require privilege/token/exploit trigger path and target context before confirmed elevation claims.",
    ],
    "uac_bypass": [
        "Require auto-elevate abuse artifacts plus reachable trigger path before confirmed UAC bypass claims.",
    ],
    "wmi_persistence": [
        "Require WMI filter, consumer, binding, and payload evidence before confirmed persistence claims.",
    ],
    "service_persistence": [
        "Require service name, binary path, and create/modify/start evidence before confirmed service persistence claims.",
    ],
    "scheduled_task_persistence": [
        "Require task name, trigger, action, and registration evidence before confirmed scheduled-task persistence claims.",
    ],
    "startup_folder_persistence": [
        "Require Startup folder path plus shortcut/file write and payload target before confirmed startup-folder persistence claims.",
    ],
    "account_persistence": [
        "Require account creation, enablement, group modification, or RID/user-clone artifact before confirmed account persistence claims.",
    ],
    "accessibility_hijack_persistence": [
        "Require accessibility/screen-saver replacement or debugger/registry hijack plus payload path before confirmed persistence claims.",
    ],
    "registry_autostart_extension_persistence": [
        "Require exact autostart registry key/value and payload path before confirmed registry-extension persistence claims.",
    ],
    "ifeo_debugger_persistence": [
        "Require IFEO target image plus Debugger/SilentProcessExit value and payload path before confirmed IFEO persistence claims.",
    ],
    "bits_jobs_persistence": [
        "Require BITS job plus notify command or trigger behavior before confirmed BITS persistence claims.",
    ],
    "rat_backdoor_control": [
        "Require command parser/dispatcher plus IPC or network-controlled input before confirmed RAT/backdoor control claims.",
    ],
    "lsass_dumping": [
        "Require LSASS target plus dump API/helper/tool evidence before confirmed credential dumping claims.",
    ],
    "silent_process_exit_dump": [
        "Require SilentProcessExit/IFEO registry configuration plus LSASS target before confirmed dump-configuration claims.",
    ],
    "ssp_credential_capture": [
        "Require SSP/Security Packages modification, mimilib artifact, or in-memory SSP injection evidence before confirmed credential-capture claims.",
    ],
    "registry_credential_dumping": [
        "Require SAM/SECURITY/SYSTEM hive access or save operation plus parser/staging evidence before confirmed registry credential dumping claims.",
    ],
    "ntds_dumping": [
        "Require NTDS.dit access/copy plus supporting hive/key material before confirmed domain credential database dumping claims.",
    ],
    "dcsync_replication": [
        "Require directory replication semantics and domain context before confirmed DCSync claims.",
    ],
    "kerberos_ticket_access": [
        "Require Kerberos ticket request, extraction, cache, or artifact handling before confirmed ticket-access claims.",
    ],
    "dpapi_credential_access": [
        "Require protected blob/masterkey/Vault access plus decrypt/parsing logic before confirmed DPAPI credential access claims.",
    ],
    "ssh_private_key_access": [
        "Require private-key file access plus staging, use, or exfiltration context before confirmed SSH key theft claims.",
    ],
    "unix_shadow_access": [
        "Require passwd/shadow database access plus parsing or staging evidence before confirmed Unix credential dumping claims.",
    ],
    "keylogging_capture": [
        "Require capture loop/callback plus storage, staging, or transmission path before confirmed keylogging/screen-capture claims.",
    ],
    "wallet_clipboard_hijack": [
        "Require clipboard/wallet monitoring plus replacement, staging, or exfiltration logic before confirmed hijacking/theft claims.",
    ],
    "adware_browser_manipulation": [
        "Require browser setting, proxy, hosts, toolbar, or injected-ad modification path before confirmed adware/browser-manipulation claims.",
    ],
    "browser_extension_toolbar": [
        "Require extension/BHO/toolbar artifact plus creation, policy installation, or load evidence before confirmed browser-toolbar claims.",
    ],
    "user_deception_fraud": [
        "Require reachable deceptive UI or web overlay plus requested action and malicious outcome before confirmed fraud claims.",
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
    "archive_staging": [
        "Require collected file inputs plus archive output path before confirmed archive-staging claims.",
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

