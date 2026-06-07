# Dynamic Invocation

Use this only when dynamic analysis is explicitly requested and the server is an
authorized isolated analysis environment.

## Collector Roles

```text
Procmon   process, file, registry, DLL/module, process-tree telemetry
dumpcap   packet capture writer for PCAP/PCAPNG
tshark    packet parsing and network summaries
Sysmon    optional Windows event telemetry
verify    post-run server-state snapshot
monitor   live dashboard snapshot and observer-agent summaries
```

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
```

Identify network interfaces:

```text
remote_guest exec command='"C:\Program Files\Wireshark\dumpcap.exe" -D'
```

Prefer the primary server NIC, usually `以太网`. Use loopback only for localhost
traffic.

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

5. Parse PCAP:

```text
tshark -r outbox/<case_id>/dynamic/network.pcapng -T json
tshark -r outbox/<case_id>/dynamic/network.pcapng -q -z conv,ip
tshark -r outbox/<case_id>/dynamic/network.pcapng -Y dns
tshark -r outbox/<case_id>/dynamic/network.pcapng -Y http
```

Write:

```text
dynamic/network_summary.json
dynamic/dns.txt
dynamic/http.txt
dynamic/conversations.txt
```

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
