---
name: dynamic-behavior-targeting
description: Use this skill when Codex needs to turn static malware analysis findings into a focused dynamic validation and screening plan. Triggers include targeted Procmon filtering, PCAP/TShark screening, static-to-dynamic behavior targeting, choosing what process, registry path, file path, domain, IP, URL, port, or protocol to monitor, reducing noisy dynamic artifacts, mapping behavior_capability_map results to dynamic_config validation_targets, and deciding how to screen captured packets and host telemetry.
---

# Dynamic Behavior Targeting

## Purpose

Convert static behavior hypotheses into a targeted dynamic validation plan so
runtime collection is not treated as a generic "capture everything and inspect
later" pass. Keep raw PCAP/PML artifacts, but produce smaller behavior-focused
screening outputs that answer each static claim.

## Safety Boundary

- Use only authorized isolated environments, disposable VMs, or remote analysis
  servers.
- Do not execute unknown samples on the analyst host.
- Do not provide bypass, credential extraction, destructive, or live C2
  operation instructions.
- Do not discard raw PCAP/PML just because a targeted filter is defined.
  Targeted outputs are triage aids, not the only evidence.
- Do not claim behavior is absent unless the trigger, runtime window, and
  tooling were sufficient for that specific behavior.

## Progressive References

Load only what is needed:

- `references/targeting-playbook.md`
  Use for the target-plan schema, behavior-to-filter map, PCAP/TShark field
  extraction, Procmon/Sysmon screening priorities, and output naming.
- `../malware-behavior-validation/SKILL.md`
  Use when the task is a broader static-to-dynamic validation workflow.
- `../tencent-remote-analysis/references/dynamic-invocation.md`
  Use when the dynamic run is executed through Tencent Cloud Guest Agent.

## Workflow

1. Build the behavior hypothesis ledger from static results:
   - category and label from `behavior_capability_map` or manual analysis
   - static evidence: string, import, xref, pseudocode, config, or tool output
   - expected runtime artifact
   - trigger condition, arguments, decoy files, or environment dependency
   - confidence before validation

2. Create a targeting plan before execution:
   - `behaviors`: behavior categories to validate
   - `network_indicators`: domains, URLs, IPs, ports, URI paths, user agents
   - `watch_processes`: sample name, expected child names, likely LOLBins
   - `watch_paths`: temp, appdata, startup, browser profile, wallet, decoy paths
   - `watch_registry`: Run keys, Services, Winlogon, IFEO, WMI, policy keys
   - `watch_services_tasks`: service names, task names, WMI consumers
   - `screening_outputs`: files to generate from PCAP/Procmon/Sysmon

3. Configure dynamic collection from the plan:
   - Keep `dynamic_config.collectors=["pcap","procmon","tshark"]` when both
     host and network evidence may matter.
   - Add `dynamic_config.validation_targets` when the runner supports it.
   - If the runner does not consume `validation_targets` yet, still write a
     sidecar `dynamic_targeting_plan.json` and use it during artifact review.
   - Prefer post-capture filtering over capture-time exclusion unless the
     environment is too noisy; over-narrow capture filters can lose child-process
     or fallback behavior.

4. Screen artifacts against each hypothesis:
   - PCAP: conversations, DNS, HTTP, TLS SNI, SYN attempts, static IOC matches,
     cadence, retry interval, and failed connections.
   - Procmon/Sysmon: process tree, command lines, file writes, registry writes,
     service/task creation, module loads, decoy access, cleanup/self-delete.
   - Runner status: missing collectors, timeout, empty PCAP, Procmon export
     failure, unavailable interface, or rollback gap.

5. Revise behavior conclusions:
   - `confirmed`: runtime artifact directly supports the static hypothesis.
   - `refuted`: expected artifact did not appear under a valid trigger.
   - `unobserved`: not seen, but trigger/environment may be incomplete.
   - `inconclusive`: capture, export, timeout, permission, anti-analysis, or
     dependency issues prevent a conclusion.

## Required Output

Produce a targeting and evidence table before final reporting:

| Static hypothesis | Targeted monitors | Screening output | Match rule | Result | Confidence after | Gap |
| --- | --- | --- | --- | --- | --- | --- |

The final report must cite the focused screening outputs and the raw artifact
paths. Do not use a collector start/stop log as behavior evidence.
