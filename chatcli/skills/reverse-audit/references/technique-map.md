# Reverse Technique Map

Use this map to choose the next reverse-engineering technique from observed
signals. The main window should use this as a routing map; detailed function work
can be delegated to child windows.

## Selection Loop

1. Identify signals:
   - file shape: PE/ELF/Mach-O, driver/user-mode, sections, entropy, imports;
   - data shape: strings sparse/dense, high-entropy blobs, encoded runs, constants;
   - code shape: normal CFG, flattened state machine, giant generated function,
     opaque predicates, junk jumps, invalid disassembly;
   - objective: understand behavior, recover strings, solve validation, patch
     audit, build solver, or carve data.
2. Pick the smallest next technique that can produce evidence.
3. Record evidence in `.chatcli/task.md`.
4. If the detailed work is large, spawn a child window and keep only its summary
   and record path in the main context.

## Signal To Technique

| Signal | Likely Cause | First Tools | Next Technique | Child Strategy |
| --- | --- | --- | --- | --- |
| IDA `auto_wait` stalls | packer, giant generated function, invalid CFG | `binary_inspect`, background `ida_analyze` bounded | continue with partial IDA + data map | child runs IDA; main continues static triage |
| Unusual section name or high entropy | packed/encrypted data | `obfuscated_data_map`, `encoded_string_extract` | map xrefs to blob, locate decoder | child analyzes blob xrefs |
| Sparse visible strings | encrypted/runtime strings | `encoded_string_extract`, `obfuscated_data_map` | hook decrypt routine or API | child generates/runtime hook plan |
| Many `jmp $+5`, junk jumps | junk code/flow noise | `ida_deobfuscate` | report/patch IDA database, rebuild CFG | child maps noisy function |
| Giant function | flattened VM/generated code | `ida_deobfuscate` function maps | analyze mapped blocks, not full decompile | one child per block cluster |
| Switch dispatcher / indirect jumps | control-flow flattening | `ida_deobfuscate` | identify dispatcher, state updates, payload blocks | child reconstructs transition table |
| Constant true/false branches | opaque predicates | `ida_deobfuscate` | patch IDA database only, verify CFG improves | child validates selected branches |
| Crypto constants or high-entropy blob xrefs | encryption/hash/checksum | `obfuscated_data_map`, `binary_find` | identify algorithm and key source | child analyzes one decrypt/hash function |
| DeviceIoControl / driver pair | user-driver protocol | `binary_inspect`, `ida_analyze` | map IOCTLs, buffers, side channels | one child for app protocol, one for driver dispatch |
| Anti-debug/timing imports | local challenge gate | imports + IDA xrefs | classify gate, avoid live evasion | child maps anti-debug checks |
| Standard library noise / stripped PE | no symbols | `ida_deobfuscate` signatures/API roles | apply FLIRT, role-label functions | child labels high-score functions |
| Runtime-only plaintext | decrypt after execution | `runtime_string_hooks` | dump return/buffer strings, re-run extraction | child prepares hook script and collector |
| Many byte-wise equations | tedious local validation | focused decompile + scratch script | model constraints, use Z3 if available | child reconstructs one stage |
| Clear success/failure path but many branches | path constraint challenge | IDA addresses + scratch harness | use angr-style find/avoid if installed | child builds symbolic plan |
| Opcode loop / dispatch table | custom VM | `ida_deobfuscate` maps + hexdump | identify pc/opcode/handlers, trace-diff | child maps opcode group |
| .NET/Python/APK/WASM/JAR | managed/bytecode format | `binary_inspect`, strings/resources | use native decompiler/extractor route | child handles format-specific extraction |
| Maze/game state mutations | graph search challenge | IOCTL/state reads, constants, hexdump | build BFS/DFS over verified state model | child maps state transition |

## Technique Recipes

### Data Recovery Route

Use when IDA cannot explain a region.

1. Run `obfuscated_data_map`.
2. For each suspicious section/blob:
   - record file offset, RVA, entropy, and magic/constant hits;
   - find xrefs in IDA or map to function ranges;
   - choose static decode, carve/decompress, or runtime dump.
3. If a transform is local and bounded, create a scratch decoder.
4. If plaintext exists only after runtime decrypt, use `runtime_string_hooks`.

### Giant Function Route

1. Run `ida_deobfuscate` with pseudocode off and capped instruction scan.
2. Use `function_maps` to list high-signal blocks:
   - strings/API blocks;
   - high successor blocks;
   - indirect jump/dispatcher blocks;
   - junk-heavy blocks.
3. Spawn child tasks for block clusters.
4. Main window builds the role map from child summaries.

### Flattened State Machine Route

1. Identify dispatcher block and state variable updates.
2. Separate transition predicates from payload blocks.
3. Remove only high-confidence opaque predicates/junk in IDA database.
4. Re-run a narrow map and compare CFG improvement.
5. Decompile only cleaned, small regions.

### Driver/User Pair Route

1. Map user-mode calls to `CreateFileW` and `DeviceIoControl`.
2. Extract device names, event names, IOCTL constants, input/output buffers.
3. In the driver, map `DriverEntry`, dispatch table setup, IOCTL handler, and
   shared event/object names.
4. Align user actions with driver side effects.
5. Build a solver only from verified protocol/side-channel evidence.

### Constraint Solver Route

1. Use focused decompile or pseudocode to extract input length, byte domains,
   equations, table lookups, and final comparisons.
2. Reconstruct the check in `.chatcli/tmp/scratch.py`.
3. Use direct inversion first; use Z3 only when constraints are tangled but local.
4. Verify the candidate input against the reconstructed local check.

### Symbolic Execution Route

1. Identify concrete success and failure addresses from strings/branches.
2. Check whether the binary is simple enough: stdin/argv/memory input, few syscalls,
   no heavy anti-debug, no complex threads, no self-modifying code.
3. If angr is installed, build a local find/avoid sketch in scratch; otherwise
   produce the plan and continue static constraint extraction.
4. Do not use symbolic execution against live services or credential material.

### Custom VM Route

1. Identify dispatch loop, bytecode pointer, opcode fetch, stack/register storage,
   and handler table.
2. Map handlers by side effects, not by decompiling the whole VM.
3. Compare traces for nearby inputs when local execution is explicitly allowed;
   otherwise statically map opcode handlers and data tables.
4. Reimplement only the minimal opcode subset needed for validation.

### Format-Specific Route

1. Confirm format first: CLR/.NET, PyInstaller/pyc, APK/DEX, JAR/class, WASM,
   firmware/ROM, or packed native.
2. Use extraction/decompiler tools native to that format when installed.
3. Hand off from managed/bytecode code to native libraries only at verified
   JNI/PInvoke/FFI/import boundaries.

## Main Window Policy

- Keep the main context small: decisions, evidence, maps, child summaries.
- Put function dumps, pseudocode, and long traces in child records or JSON files.
- Compression should preserve `.chatcli/task.md` and child summaries; after
  compression, continue from the durable state rather than repeating triage.
- Do not claim completion while required child findings are pending.
