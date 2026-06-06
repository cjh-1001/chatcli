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

## Current Implementation Boundary

Current dynamic support records configured collectors in:

```text
dynamic/dynamic_status.json
```

Do not claim runtime behavior unless actual dynamic artifacts exist.
