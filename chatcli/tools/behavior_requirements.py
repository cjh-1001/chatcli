"""Evidence composition requirements for malware behavior candidates."""

from __future__ import annotations

from typing import Any


BEHAVIOR_REQUIREMENTS: dict[str, dict[str, Any]] = {
    "c2_network": {
        "groups": {
            "transport or endpoint": {"http://", "https://", "socket", "connect", "winhttp", "internetopen"},
            "exchange or beacon clue": {"send", "recv", "user-agent", "beacon", "sleep", "gate.php", "panel"},
        },
        "cap": "medium",
    },
    "silent_downloader": {
        "groups": {
            "download method or tool": {
                "urldownloadtofile", "urlmon", "wininet", "winhttp",
                "downloadfile", "invoke-webrequest", "start-bitstransfer",
                "bitsadmin", "certutil -urlcache", "curl.exe", "wget",
            },
            "silent or execution context": {
                "silent download", "background download", "download cradle",
                "download and execute", "http download", "drop url",
                "powershell -enc", "mshta", "wscript", "静默下载",
            },
        },
        "cap": "medium",
    },
    "payload_dropper": {
        "groups": {
            "payload source or extraction": {
                "dropper", "extract resource", "findresource", "loadresource",
                "embedded payload", "resource payload", "stage2", "cabinet",
                "self-extract", "投放病毒",
            },
            "drop path or file write": {
                "drop file", "writefile", "createfile", "copyfile",
                "payload.exe", "expand.exe", "%temp%", "temp\\",
                "appdata", "programdata",
            },
        },
        "cap": "medium",
    },
    "c2_config_protocol": {
        "groups": {
            "config or protocol field": {
                "beacon interval", "sleep jitter", "campaign id", "bot id",
                "victim id", "command id", "uri path", "callback path",
            },
            "decoded config or protocol anchor": {
                "config decrypt", "encrypted config", "rc4 key", "xor key",
                "mutex", "user-agent", "gate.php", "panel",
            },
        },
        "cap": "medium",
    },
    "named_pipe_ipc": {
        "groups": {
            "pipe artifact or API": {
                "\\\\.\\pipe\\", "createnamedpipe", "connectnamedpipe",
                "transactnamedpipe", "callnamedpipe", "named pipe",
            },
            "control or role context": {
                "pipe server", "pipe client", "ipc channel", "impersonatenamedpipeclient",
            },
        },
        "cap": "medium",
    },
    "remote_access_tool_abuse": {
        "groups": {
            "remote access tool": {
                "anydesk", "teamviewer", "screenconnect", "connectwise",
                "splashtop", "rustdesk", "ultravnc", "tightvnc", "vnc",
                "rdpwrap",
            },
            "deployment or access context": {"remote access", "remote desktop", "ngrok"},
        },
        "cap": "medium",
    },
    "process_injection": {
        "groups": {
            "remote process access": {"openprocess"},
            "remote memory or mapping": {"virtualallocex", "ntallocatevirtualmemory", "zwunmapviewofsection"},
            "remote write or execution transfer": {
                "writeprocessmemory", "createremotethread", "ntqueueapcthread",
                "queueuserapc", "setthreadcontext",
            },
        },
        "cap": "medium",
    },
    "persistence": {
        "groups": {
            "persistence location": {
                "currentversion\\run", "runonce", "startup", "schtasks",
                "scheduled task", "systemd", "cron", "launchagent",
            },
            "create or modify action": {"createservice", "regsetvalue", "regcreatekey", "schtasks"},
        },
        "cap": "medium",
    },
    "uac_bypass": {
        "groups": {
            "auto-elevate target": {"fodhelper", "eventvwr", "sdclt", "computerdefaults", "cmstp", "consent.exe"},
            "hijack or trigger artifact": {
                "delegateexecute", "shellopen\\command", "ms-settings",
                "bypassuac", "uac bypass", "autoelevate", "auto elevate",
            },
        },
        "cap": "medium",
    },
    "wmi_persistence": {
        "groups": {
            "WMI filter, consumer, or binding": {
                "__eventfilter", "commandlineeventconsumer",
                "active scripteventconsumer", "__filtertoconsumerbinding",
            },
            "namespace or creation action": {
                "root\\subscription", "wmi persistence",
                "set-wmiinstance", "wmic /namespace",
            },
        },
        "cap": "medium",
    },
    "service_persistence": {
        "groups": {
            "service creation or modification": {
                "createservice", "startservice", "changeserviceconfig",
                "service install", "sc create", "sc.exe create", "new-service",
            },
            "service identity or registry path": {
                "service name", "services.exe", "system\\currentcontrolset\\services",
            },
        },
        "cap": "medium",
    },
    "scheduled_task_persistence": {
        "groups": {
            "task creation or registration": {
                "schtasks /create", "schtasks.exe", "taskschd", "itaskservice",
                "registeredtask", "new-scheduledtask",
            },
            "task identity or trigger context": {
                "task scheduler", "scheduled task", "\\microsoft\\windows\\", "at.exe",
            },
        },
        "cap": "medium",
    },
    "startup_folder_persistence": {
        "groups": {
            "startup location": {
                "startup folder", "shell:startup", "common startup",
                "start menu\\programs\\startup", "\\startup\\",
            },
            "shortcut or payload write": {".lnk", "shortcut", "wscript.shell", "createshortcut"},
        },
        "cap": "medium",
    },
    "account_persistence": {
        "groups": {
            "account persistence technique": {
                "hidden account", "guest account", "activate guest",
                "enable guest", "user clone", "clone user", "rid hijack",
            },
            "account modification method": {
                "adsi", "winnt://", "net user /add",
                "net localgroup administrators", "rid 500", "sam copy",
            },
        },
        "cap": "medium",
    },
    "accessibility_hijack_persistence": {
        "groups": {
            "hijacked feature": {
                "sethc.exe", "sticky keys", "utilman.exe", "osk.exe",
                "magnify.exe", "narrator.exe", "screensaver",
                "scrnsave.exe", "logon.scr", "screen saver", "粘滞键", "屏保",
            },
            "execution or hijack context": {
                "accessibility features", "debugger", "image file execution options",
                "ifeo", "screensaver", "scrnsave.exe", "logon.scr", "screen saver",
            },
        },
        "cap": "medium",
    },
    "registry_autostart_extension_persistence": {
        "groups": {
            "autostart key family": {
                "currentversion\\run", "runonce", "runservices",
                "runservicesonce", "winlogon", "logon scripts",
                "appinit_dlls", "active setup", "telemetrycontroller",
                "print monitor", "print monitors",
            },
            "payload value or extension point": {
                "userinit", "shell", "stubpath", "clsid",
                "inprocserver32", "com hijack", "com object hijack",
                "monitor dll",
            },
        },
        "cap": "medium",
    },
    "ifeo_debugger_persistence": {
        "groups": {
            "IFEO target or key": {
                "image file execution options", "ifeo", "sethc.exe",
                "utilman.exe", "lsass.exe", "silentprocessexit",
            },
            "debugger or dump trigger value": {"debugger", "globalflag", "monitorprocess"},
        },
        "cap": "medium",
    },
    "bits_jobs_persistence": {
        "groups": {
            "BITS job creation or control": {
                "bitsadmin", "bits job", "background intelligent transfer",
                "createbitsjob", "bitsadmin /create",
            },
            "notify or resume execution": {
                "setnotifycmdline", "bitsadmin /setnotifycmdline",
                "bitsadmin /resume", "bitsadmin /setminretrydelay",
            },
        },
        "cap": "medium",
    },
    "security_tool_tampering": {
        "groups": {
            "security target": {"windefend", "defender", "eventlog", "firewall", "edr", "avp.exe", "msmpeng.exe"},
            "tamper action": {
                "set-mppreference", "disableantispyware", "exclusionpath",
                "exclusionprocess", "sc stop", "taskkill", "terminateprocess",
                "wevtutil cl", "clear-eventlog",
            },
        },
        "cap": "medium",
    },
    "process_masquerading": {
        "groups": {
            "masquerading or parent-spoof action": {
                "ppid spoof", "parent process spoof", "spoofed parent",
                "updateprocthreadattribute", "proc_thread_attribute_parent_process",
                "masquerade", "process masquerading", "renamed payload",
            },
            "misleading process identity": {"explorer.exe", "svchost.exe", "rundll32.exe", "signed parent"},
        },
        "cap": "medium",
    },
    "credential_access": {
        "groups": {
            "credential artifact": {
                "lsass", "dpapi", "login data", "cookies", "sam",
                "security hive", ".ssh", "id_rsa", "kubeconfig", "aws_access_key",
            },
            "secret or credential context": {"token", "credential", "password", "cookies"},
        },
        "cap": "low",
    },
    "banking_credential_theft": {
        "groups": {
            "banking or payment target": {
                "bank", "banking", "financial", "zeus",
                "two-factor", "2fa", "tan", "otp", "银行窃密",
            },
            "browser or form capture": {
                "webinject", "web inject", "form grabber", "formgrabber",
                "browser hook", "wininet hook", "httpsendrequest",
                "internetreadfile", "pr_write", "ssl_read",
            },
        },
        "cap": "medium",
    },
    "browser_cloud_credentials": {
        "groups": {
            "credential store or file": {
                "login data", "local state", "cookies", "key4.db", "logins.json",
                "kubeconfig", "credentials.json", "docker config",
            },
            "browser, cloud, or container context": {
                "chrome", "firefox", "edge", "aws_access_key_id",
                "secret_access_key", "azure_refresh_token", "gcloud", "serviceaccount",
            },
        },
        "cap": "medium",
    },
    "lsass_dumping": {
        "groups": {
            "LSASS target": {"lsass", "dump lsass"},
            "dump method or tool": {
                "minidumpwritedump", "comsvcs.dll", "procdump",
                "nanodump", "sekurlsa", "logonpasswords", "psscapture",
                "psscapturesnapshot", "handlekatz", "processdump-jabber",
                "minidump callbacks", "direct syscalls", "direct syscall",
                "dbghelp.dll", "process dump", "lsass.dmp",
            },
        },
        "cap": "medium",
    },
    "silent_process_exit_dump": {
        "groups": {
            "SilentProcessExit or IFEO path": {
                "silentprocessexit", "silentprocessexit\\lsass.exe",
                "image file execution options", "ifeo",
            },
            "dump configuration": {"monitorprocess", "reportingmode", "dumptype", "dumpfolder", "globalflag"},
        },
        "cap": "medium",
    },
    "ssp_credential_capture": {
        "groups": {
            "SSP or LSA package artifact": {
                "security packages", "mimilib", "mimilib.dll",
                "ssp", "security support provider", "authentication package",
                "hklm\\system\\currentcontrolset\\control\\lsa",
            },
            "capture or credential artifact": {"kiwissp.log", "wdigest", "uselogoncredential", "lsa package"},
        },
        "cap": "medium",
    },
    "registry_credential_dumping": {
        "groups": {
            "credential hive or secret store": {
                "sam", "security hive", "system hive", "hklm\\sam",
                "hklm\\security", "hklm\\system", "lsa secrets",
                "cached logons", "cached domain credentials", "sam.hiv",
                "system.hiv", "security.hiv",
            },
            "dump or parser action": {
                "reg save", "secretsdump", "samlib", "lsass policy",
                "lsadump::sam", "lsadump::secrets", "hash ntlm",
                "$machine.acc", "defaultpassword", "_sc_", "esentutl",
                "vssadmin", "diskshadow",
            },
        },
        "cap": "medium",
    },
    "ntds_dumping": {
        "groups": {
            "domain credential database": {"ntds.dit", "active directory database", "dit extraction"},
            "copy or snapshot method": {
                "ntdsutil", "esentutl", "volume shadow copy",
                "vssadmin", "diskshadow", "system hive", "domain controller",
            },
        },
        "cap": "medium",
    },
    "dcsync_replication": {
        "groups": {
            "replication method": {
                "dcsync", "drsuapi", "dsgetncchanges",
                "replicating directory changes", "replicating directory changes all",
                "directory replication",
            },
            "domain target context": {"krbtgt", "ntdsapi", "domain controller"},
        },
        "cap": "medium",
    },
    "kerberos_ticket_access": {
        "groups": {
            "Kerberos ticket or roasting method": {
                "kerberoast", "as-rep roast", "asreproast",
                "tgs-rep", "golden ticket", "silver ticket",
            },
            "ticket artifact or cache": {"tgt", "tgs", "kirbi", "klist", "sekurlsa::tickets", "kerberos ticket"},
        },
        "cap": "medium",
    },
    "dpapi_credential_access": {
        "groups": {
            "DPAPI or Vault material": {
                "dpapi", "masterkey", "protect\\", "credhist",
                "windows vault", "credential manager", "local state",
            },
            "decrypt or access API": {"cryptunprotectdata", "vaultcli", "credman"},
        },
        "cap": "medium",
    },
    "ssh_private_key_access": {
        "groups": {
            "private-key artifact": {"id_rsa", "id_ed25519", "private key", ".pem", ".ppk", "ssh key"},
            "SSH directory or context": {".ssh", "authorized_keys", "known_hosts", "openssh"},
        },
        "cap": "medium",
    },
    "unix_shadow_access": {
        "groups": {
            "credential database": {"/etc/shadow", "/etc/passwd", "/etc/security/passwd", "passwd file", "shadow file"},
            "privileged lookup or parsing": {"getpwnam", "getspnam", "unshadow", "shadow-"},
        },
        "cap": "medium",
    },
    "lateral_movement": {
        "groups": {
            "remote target or protocol": {"admin$", "c$", "smb", "ssh", "rdp", "winrm"},
            "remote execution or auth action": {"psexec", "wmic", "net use", "remote service", "remote task"},
        },
        "cap": "medium",
    },
    "worm_propagation": {
        "groups": {
            "propagation vector or target discovery": {
                "autorun.inf", "usb", "removable", "admin$", "c$",
                "net share", "subnet", "scan range", "mapi", "address book", "mail contacts",
            },
            "copy or spread action": {"copyfile", "shfileoperation", "spread", "remote copy"},
        },
        "cap": "medium",
    },
    "exfiltration": {
        "groups": {
            "staging or payload format": {"archive", "zip", "rar", "multipart"},
            "transfer channel": {"upload", "post", "send", "ftp", "sftp", "smtp", "webdav", "telegram", "discord webhook"},
        },
        "cap": "medium",
    },
    "archive_staging": {
        "groups": {
            "archive mechanism": {
                "archive", "zip", "rar", "7z", "tar", "gzip",
                "compress-archive", "zipfile", "minizip", "create archive",
            },
            "collected data or staging path": {
                "staging directory", "temp archive", "documents", "desktop",
            },
        },
        "cap": "medium",
    },
    "adware_browser_manipulation": {
        "groups": {
            "adware or browser surface": {
                "adware", "advertisement", "popup", "pop-up", "inject ads",
                "browser helper object", "bho", "urlsearchhook", "webbrowser",
                "toolbar", "browser toolbar", "投放广告",
            },
            "browser configuration change": {
                "homepage", "search provider", "default search", "newtab",
                "proxyenable", "autoconfigurl", "hosts file",
            },
        },
        "cap": "medium",
    },
    "browser_extension_toolbar": {
        "groups": {
            "extension or toolbar artifact": {
                "browser extension", "install extension", "manifest.json",
                "xpi", "toolbar", "browser toolbar", "browser helper object",
                "bho", "iexplore", "浏览器工具条",
            },
            "installation or persistence location": {
                "extensioninstallforcelist", "chrome\\user data",
                "edge\\user data", "firefox\\profiles",
                "explorer\\browser helper objects", "inprocserver32",
            },
        },
        "cap": "medium",
    },
    "user_deception_fraud": {
        "groups": {
            "deceptive lure or prompt": {
                "fake login", "phishing", "scam", "fraud", "fake update",
                "fake antivirus", "tech support scam", "overlay window",
                "网页弹窗", "欺诈用户",
            },
            "requested action or sensitive outcome": {
                "credential prompt", "payment required", "messagebox",
                "invoice", "security warning",
            },
        },
        "cap": "medium",
    },
    "ransomware_anti_recovery": {
        "groups": {
            "recovery impact": {"vssadmin", "delete shadows", "wmic shadowcopy", "wbadmin", "bcdedit", "shadowcopy"},
            "ransomware file impact": {"ransom note", "decrypt instructions", ".locked", ".encrypted", "encrypt files", "extension list"},
        },
        "cap": "medium",
    },
    "byovd_abuse": {
        "groups": {
            "vulnerable driver artifact": {
                "byovd", "bring your own vulnerable driver", "vulnerable driver",
                "capcom.sys", "gdrv.sys", "dbutil", "iqvw64e.sys",
                "aswarpot.sys", "rtcore64.sys",
            },
            "driver load or kernel interaction": {
                "driver load", "createservice", "deviceiocontrol", "ioctl", "kernel primitive",
            },
        },
        "cap": "medium",
    },
}


def cap_confidence(value: str, cap: str) -> str:
    rank = {"high": 3, "medium": 2, "low": 1}
    return value if rank.get(value, 0) <= rank.get(cap, 0) else cap


def behavior_requirement_gaps(category: str, matched_terms: set[str]) -> tuple[list[str], str | None]:
    requirement = BEHAVIOR_REQUIREMENTS.get(category)
    if not requirement:
        return [], None
    missing = []
    for label, terms in requirement["groups"].items():
        if not (matched_terms & terms):
            missing.append(label)
    if not missing:
        return [], None
    cap = str(requirement.get("cap") or "medium")
    gaps = [
        (
            "Behavior composition gap: missing "
            f"{label} evidence needed to raise {category} beyond candidate wording."
        )
        for label in missing
    ]
    return gaps, cap
