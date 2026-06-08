# Dynamic Invocation

Use this only when dynamic analysis is explicitly requested and the server is an
authorized isolated analysis environment.

## Collector Roles

```text
Procmon   process, file, registry, DLL/module, process-tree telemetry
dumpcap   packet capture writer for PCAP/PCAPNG
tshark    packet parsing and network summaries
Sysmon    optional Windows event telemetry
Zeek      optional PCAP-to-structured-network-log post-processing
Suricata  optional PCAP alert/protocol-log post-processing
verify    post-run server-state snapshot
monitor   live dashboard snapshot and observer-agent summaries
```

On Windows analysis servers, treat `Zeek` and `Suricata` as optional only.
They are not part of the baseline dynamic stack and should not block a run if
missing or unstable. The baseline path is `Procmon + dumpcap + tshark + Sysmon`.

## Pre-flight

Call:

```text
remote_guest action=tools
```

Verify:

```text
procmon.available == true
dumpcap.available == true
tshark.available == true
wevtutil.available == true   # required for Sysmon EVTX/text export
```

Optional, only when explicitly installed and stable on the target Windows host:

```text
zeek.available == true
suricata.available == true
```

Identify network interfaces:

```text
remote_guest exec command='"C:\Program Files\Wireshark\dumpcap.exe" -D'
```

Prefer the primary server NIC, usually `以太网`. Use loopback only for localhost
traffic.

## Interface Invocation

Procmon and traffic capture are invoked through the Guest Agent dynamic job
interface. There is no separate `remote_guest action=procmon` endpoint. Use
`prepare`/`run` or `analyze` with `analysis_plan.dynamic=true` and
`dynamic_config.collectors`:

```text
remote_guest action=prepare sample_path=C:\samples\a.exe analysis_plan={
  "static": true,
  "ida": true,
  "dynamic": true,
  "network": true,
  "verify": true
} dynamic_config={
  "timeout_seconds": 300,
  "collectors": ["pcap", "procmon", "tshark"],
  "network_interface": "1"
}

remote_guest action=run case_id=<case-id> mode=real
```

The dynamic runner starts collectors before the sample:

```text
dumpcap -> Procmon -> sample -> stop Procmon/dumpcap -> tshark parse
```

Collector tool paths come from environment variables on the Tencent Cloud
server:

```text
CHATCLI_TOOL_PROCMON=C:\Tools\Procmon64.exe
CHATCLI_TOOL_DUMPCAP=C:\Program Files\Wireshark\dumpcap.exe
CHATCLI_TOOL_TSHARK=C:\Program Files\Wireshark\tshark.exe
CHATCLI_TOOL_SYSMON=C:\Program Files\reverseTools\Sysmon.exe
CHATCLI_TOOL_WEVTUTIL=wevtutil
CHATCLI_TOOL_ZEEK=zeek
CHATCLI_TOOL_SURICATA=suricata
```

`CHATCLI_TOOL_ZEEK` and `CHATCLI_TOOL_SURICATA` are optional Windows extras;
leave them unset unless the server has known-good installs.

Use `remote_guest action=tools` to verify the server sees these paths before
running dynamic analysis. If `procmon.available=false`, the interface can still
run PCAP-only if dumpcap is available; if both Procmon and dumpcap are missing,
dynamic analysis is skipped with `dynamic/_SKIPPED`.

## Targeted Validation Inputs

Dynamic collection should be driven by static hypotheses whenever static output
contains endpoints, process names, file paths, registry keys, service names, or
scheduled task names. Use `../dynamic-behavior-targeting/SKILL.md` to build the
plan first.

Preferred config shape when supported by the runner:

```text
dynamic_config={
  "timeout_seconds": 300,
  "collectors": ["pcap", "procmon", "tshark", "sysmon"],
  "network_interface": "1",
  "validation_targets": {
    "behaviors": ["c2_beacon", "persistence"],
    "network_indicators": {
      "domains": ["example.test"],
      "ips": ["203.0.113.10"],
      "ports": [80, 443],
      "uri_paths": ["/gate.php"]
    },
    "watch_processes": ["sample.exe", "rundll32.exe"],
    "watch_paths": ["%TEMP%", "%APPDATA%", "Startup"],
    "watch_registry": [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    ]
  }
}
```

If the current runner does not consume `validation_targets`, keep the same data
as `dynamic/targeting_plan.json` or `dynamic/dynamic_targeting_plan.json` in the
case notes and apply it during result screening. Preserve the raw
`network.pcapng` and `procmon.pml`; targeted outputs are summaries, not
replacements.

## Intended Collector Sequence

1. Create:

```text
outbox/<case_id>/dynamic/
```

2. Start packet capture before execution:

```text
dumpcap -i <interface> -w outbox/<case_id>/dynamic/network.pcapng
```

3. Start Procmon when process/file/registry telemetry is needed:

```text
Procmon.exe /AcceptEula /Quiet /Minimized /BackingFile outbox/<case_id>/dynamic/procmon.pml
```

4. Stop Procmon after the observation window:

```text
Procmon.exe /Terminate
```

5. Export Procmon and Sysmon when requested:

```text
Procmon.exe /AcceptEula /OpenLog outbox/<case_id>/dynamic/procmon.pml /SaveAs outbox/<case_id>/dynamic/procmon.csv
wevtutil epl Microsoft-Windows-Sysmon/Operational outbox/<case_id>/dynamic/sysmon.evtx /ow:true
wevtutil qe Microsoft-Windows-Sysmon/Operational /f:text /c:2000 /rd:true
```

6. Parse PCAP:

```text
tshark -r outbox/<case_id>/dynamic/network.pcapng -T json
tshark -r outbox/<case_id>/dynamic/network.pcapng -q -z conv,ip
tshark -r outbox/<case_id>/dynamic/network.pcapng -Y dns
tshark -r outbox/<case_id>/dynamic/network.pcapng -Y http
zeek -r outbox/<case_id>/dynamic/network.pcapng
suricata -r outbox/<case_id>/dynamic/network.pcapng -l outbox/<case_id>/dynamic/suricata -k none
```

Write:

```text
dynamic/network_summary.json
dynamic/dns.txt
dynamic/http.txt
dynamic/conversations.txt
dynamic/tls_sni.txt
dynamic/tcp_syn.txt
dynamic/targeted_network_iocs.txt
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

Only include `dynamic/zeek/` and `dynamic/suricata/` when those tools are
actually present and stable on the Windows host.

## Live Dashboard / Observer Agents

While the dynamic job is running, poll:

```text
remote_guest action=monitor case_id=<case-id>
```

Use the monitor snapshot as the live dashboard source. It reports:

- process observer status
- network observer status and PCAP byte growth
- registry Run key probes
- scheduled task and service probes
- recent analysis-directory file activity
- dynamic collector events from `dynamic/dynamic_status.json`

## How To Open The Dashboard

The dashboard is client-side Rich UI backed by the existing Guest Agent. No
second server is required.

Server side:

```text
py -3 C:\chatcli-server\chatcli_guest_agent.py --host 0.0.0.0 --port 8443
```

Client config must have either:

```text
CHATCLI_REMOTE_URL=http://<public-ip>:8443
CHATCLI_GUEST_AGENT_TOKEN=<token>
```

or equivalent `remote.enabled`, `remote.base_url`, and
`remote.guest_agent_token` in config.

Interactive client commands:

```text
/dashboard
/dashboard <case-id>
/dashboard <case-id> --refresh 2
/dashboard <case-id> --no-probes
```

Use `--no-probes` when the server is slow or when repeated tasklist/netstat/
registry probes are too noisy. Use `remote_guest action=monitor case_id=<case>`
for a one-shot textual snapshot instead of the live dashboard.

## Current Implementation Boundary

Current dynamic support records configured collectors in:

```text
dynamic/dynamic_status.json
```

Do not claim runtime behavior unless actual dynamic artifacts exist.

## Required Post-Dynamic Rollback

After any remote dynamic analysis:

1. Call `remote_guest action=status case_id=<case-id>` until the case is done or failed.
2. Call `remote_guest action=download case_id=<case-id>` and verify local result files exist.
3. Only after result download, restore the server rollback snapshot:

```text
remote_vm_control action=stop dry_run=false
remote_vm_control action=restore_snapshot dry_run=false
remote_vm_control action=status
```

Do not say `TASK COMPLETE` until the rollback status check succeeds. If the
rollback snapshot is not configured, or the restore operation fails, report the
blocker and leave the task incomplete.
