# ChatCLI Tool Registry Reference

Use this reference when a skill needs to choose a ChatCLI tool name. Use the
registered names below; do not infer a tool name from a Python filename or helper
module.

## Core Local Tools

| Goal | Registered tools |
| --- | --- |
| Read/search files | `read_file`, `glob`, `grep`, `list_dir`, `binary_find`, `binary_hexdump` |
| Edit files | `write_file`, `edit_file`, `multi_edit` |
| Repository context | `git_status`, `git_diff` |
| Web and enrichment | `web_search`, `web_fetch`, `dns_lookup`, `ip_lookup`, `json_extract` |

## Static Malware And Reverse Tools

| Goal | Registered tools |
| --- | --- |
| File identity and metadata | `binary_inspect`, `external_static_analyze` |
| Strings and decoded data | `encoded_string_extract`, `obfuscated_data_map` |
| YARA/UPX/static utilities | `yara_scan`, `upx_unpack`, `tool_health_check` |
| IDA headless and focused review | `ida_probe`, `ida_analyze`, `ida_focus_decompile`, `ida_deobfuscate` |
| IDA MCP | `ida_mcp_ensure`, `ida_mcp_probe`, `ida_mcp_list_tools`, `ida_mcp_call` |
| Ghidra and angr | `ghidra_probe`, `ghidra_analyze`, `angr_triage` |
| Reverse evidence maps | `reverse_evidence_map`, `reverse_technique_map`, `runtime_string_hooks` |

## Behavior, IOC, And Detection Tools

| Goal | Registered tools |
| --- | --- |
| Capability mapping | `behavior_capability_map`, `command_capability_map` |
| Claim validation and coverage | `behavior_claim_validator`, `behavior_coverage_matrix`, `evidence_graph` |
| Attack chain and ATT&CK | `attack_chain_builder`, `attack_technique_planner`, `attack_technique_mapper` |
| IOC scoring and rule linting | `ioc_quality_classifier`, `detection_rule_lint` |
| Evidence package | `malware_share_package` |

## Tencent Remote Tools

| Goal | Registered tools |
| --- | --- |
| Main Guest Agent interface | `remote_guest` |
| Sequential remote sample batches | `remote_batch_analyze` |
| VM lifecycle and rollback | `remote_vm_control` |
| Legacy remote compatibility | `remote_submit`, `remote_watch`, `remote_consume`, `remote_fetch`, `remote_exec` |
| Result orchestration | `orchestrate_results` |

For Tencent Cloud Guest Agent workflows, prefer `remote_guest` and
`remote_batch_analyze`; use legacy remote tools only when a legacy workflow is
already active.

## Functional Tool Chains

Use these chains as defaults when the user gives a goal instead of a specific
tool request.

| User goal | Tool chain | Success artifact | Fallback |
| --- | --- | --- | --- |
| Identify a suspicious file | `binary_inspect` -> `external_static_analyze` | hashes, file type, sections/imports, packer hints | If external tools are missing, continue from `binary_inspect` and state the gap. |
| Extract strings/config/IOCs | `encoded_string_extract` -> `obfuscated_data_map` -> `ioc_quality_classifier` | decoded strings, config leads, scored IOC table | If decoding fails, keep raw strings as low-confidence leads. |
| Map behavior from static evidence | `behavior_capability_map` -> `command_capability_map` -> `behavior_claim_validator` | behavior claims with evidence and confidence | If claims are weak, use `behavior_coverage_matrix` to list missing evidence. |
| Build attack narrative | `evidence_graph` -> `attack_chain_builder` -> `attack_technique_mapper` | evidence graph, stage sequence, ATT&CK mapping | If evidence is sparse, keep hypotheses separate from findings. |
| Deep reverse a function | `ida_probe` or `ghidra_probe` -> `ida_analyze` or `ghidra_analyze` -> `ida_focus_decompile` | function-level evidence, xrefs, pseudocode | If headless tools are absent, use static artifacts and `binary_find`/`binary_hexdump`. |
| Validate detection rules | draft rule -> `detection_rule_lint` -> `attack_technique_mapper` | linted YARA/Sigma/Suricata plus mapped behavior | If linting is unsupported, manually state syntax and false-positive limits. |
| Run one Tencent remote sample | `remote_guest health` -> `tools` -> `prepare` -> `run` -> `monitor/status` -> `download` | local `.chatcli/remote_results/<case-id>/` directory | If remote is unavailable, do not run locally; report the connectivity/tool gap. |
| Run remote sample directory | `remote_batch_analyze` | per-sample result directories and status table | If the REPL must return quickly, set `wait=false` and report the case IDs for later status/download. |
| Finish dynamic remote work | `remote_guest download` -> `remote_vm_control stop` -> `restore_snapshot` -> `status` | downloaded results and confirmed rollback | If rollback fails, report the blocker and do not mark the task complete. |

Do not skip the success artifact check. A tool call only supports a final claim
when its expected artifact or structured output exists and has been inspected.
