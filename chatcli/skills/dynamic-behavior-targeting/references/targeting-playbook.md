# Dynamic Behavior Targeting Playbook

Use this reference to convert static malware findings into concrete dynamic
targets and focused artifact screening. Preserve raw artifacts, then generate
small outputs that answer the static hypotheses.

## Target Plan Schema

Use this structure in `dynamic_config.validation_targets` when supported, or as
a sidecar `dynamic_targeting_plan.json` next to the dynamic artifacts.

```json
{
  "behaviors": ["c2_beacon", "persistence", "dropper"],
  "network_indicators": {
    "domains": ["example.test"],
    "ips": ["203.0.113.10"],
    "urls": ["http://example.test/a"],
    "ports": [80, 443],
    "uri_paths": ["/gate.php"],
    "user_agents": ["StaticUserAgent/1.0"]
  },
  "watch_processes": ["sample.exe", "rundll32.exe", "powershell.exe"],
  "watch_paths": ["%TEMP%", "%APPDATA%", "Startup"],
  "watch_registry": [
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services"
  ],
  "watch_services_tasks": ["suspected-service-or-task-name"],
  "screening_outputs": [
    "dynamic/targeted_network_iocs.txt",
    "dynamic/targeted_process_tree.txt",
    "dynamic/targeted_persistence.txt"
  ]
}
```

## Behavior To Target Map

| Static behavior | Primary targets | PCAP screening | Host telemetry screening |
| --- | --- | --- | --- |
| C2 beacon or downloader | domains, IPs, URLs, ports, user-agent, sample/child process | DNS queries, HTTP requests, TLS SNI, SYN attempts, conversation cadence | process tree, command line, loaded WinINet/WinHTTP/socket DLLs |
| DNS fallback or DGA | candidate domains, resolver APIs, query cadence | `dns.qry.name`, NXDOMAIN cadence, query order | process responsible for DNS and timing around execution |
| HTTP upload or exfil staging | host, URI, method, content type, decoy files, archive paths | HTTP POST/PUT, content length, user-agent, retry behavior | file reads before upload, archive/temp staging writes |
| Dropper or payload write | temp/appdata/current directory, embedded filename, child process | follow-on download or callback only if expected | file create/write, PE drops, hash dropped files, child execution |
| Persistence | Run keys, Services, Startup, scheduled task, WMI paths | usually secondary unless install depends on C2 | registry writes, task/service creation, startup file writes |
| Process injection or hollowing | sample process, target names, child process chain | secondary traffic from injected/child process | process creation, remote activity indicators, module loads, Sysmon events |
| Credential/browser/wallet access | browser profiles, wallet paths, DPAPI, LSASS, decoy profiles | staging followed by upload or connection attempts | decoy file reads, sensitive path access, process access events |
| Recon or discovery | command strings, WMI, process/software queries | optional if results are sent out | child commands, registry reads, WMI/process enumeration |
| Ransomware or impact | decoy directory, extension list, ransom note, backup commands | optional key retrieval/C2 | burst file renames/writes, note creation, backup deletion commands |
| Lateral movement | SMB/RPC/WinRM/PsExec/WMI indicators, lab-only hosts | SMB/RPC/WinRM flows, fan-out, auth failures | child tools, network connections, remote execution artifacts |

## PCAP Screening Commands

Run against `dynamic/network.pcapng` after capture. Keep the full PCAP even when
the filtered outputs are empty.

```text
tshark -r dynamic/network.pcapng -q -z conv,ip
tshark -r dynamic/network.pcapng -q -z conv,tcp
tshark -r dynamic/network.pcapng -Y dns -T fields -e frame.time -e ip.src -e dns.qry.name -e dns.flags.rcode
tshark -r dynamic/network.pcapng -Y http.request -T fields -e frame.time -e ip.src -e http.host -e http.request.method -e http.request.uri -e http.user_agent
tshark -r dynamic/network.pcapng -Y "tls.handshake.extensions_server_name" -T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.extensions_server_name
tshark -r dynamic/network.pcapng -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport
```

For known static indicators, add display filters instead of capture filters:

```text
dns.qry.name contains "example.test"
http.host contains "example.test" || http.request.uri contains "/gate.php"
ip.addr == 203.0.113.10 || tcp.port == 443
http.user_agent contains "StaticUserAgent"
```

## Procmon And Host Telemetry Screening

Procmon captures can be large. Prefer exporting or viewing focused classes of
events after the run:

- process tree and command lines for the sample and children
- `CreateFile`, `WriteFile`, `SetRenameInformationFile`, and delete operations
- registry writes under Run, RunOnce, Services, Winlogon, IFEO, WMI, and policy
  keys
- service and scheduled task creation
- module loads near injection or network activity
- reads from decoy files, browser profiles, wallet paths, or credential stores
- cleanup, self-delete, and script/LOLBins launched by the sample

If command-line Procmon export is available on the analysis VM, export PML to a
machine-screenable format before summarizing. If export is unavailable, report
the PML path and the manual filters used.

Expected focused outputs:

```text
dynamic/targeted_network_iocs.txt
dynamic/targeted_process_tree.txt
dynamic/targeted_file_activity.txt
dynamic/targeted_registry_activity.txt
dynamic/targeted_persistence.txt
dynamic/targeted_credential_access.txt
dynamic/targeted_host_timeline.txt
dynamic/sysmon.txt
dynamic/zeek/
dynamic/suricata/
```

## Evidence Rules

- Match static endpoints by exact host/IP/path first; then evaluate nearby
  fallback domains, redirects, and failed connection attempts.
- Tie network findings back to the sample process or spawned child when host
  telemetry allows it.
- Treat empty filtered outputs as `unobserved`, not `refuted`, unless the
  trigger and environment were adequate.
- Treat collector errors, missing tools, empty PCAP caused by wrong interface,
  failed Procmon export, and timeout as `inconclusive`.
- Cite both the focused output and raw artifact path in the report.
