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

### Code Shape Signals

| Signal | Likely Cause | First Tools | Next Technique | Child Strategy |
| --- | --- | --- | --- | --- |
| IDA `auto_wait` stalls | packer, giant generated function, invalid CFG | `binary_inspect`, background `ida_analyze` bounded | continue with partial IDA + data map | child runs IDA; main continues static triage |
| Giant function | flattened VM/generated code | `ida_deobfuscate` function maps | analyze mapped blocks, not full decompile | one child per block cluster |
| Switch dispatcher / indirect jumps | control-flow flattening | `ida_deobfuscate` | identify dispatcher, state updates, payload blocks | child reconstructs transition table |
| Constant true/false branches | opaque predicates | `ida_deobfuscate` | patch IDA database only, verify CFG improves | child validates selected branches |
| Many `jmp $+5`, junk jumps, unreachable blocks | junk code / dead code insertion | `ida_deobfuscate` | report/patch IDA database, rebuild CFG | child maps noisy function |
| Repeated `push imm` near `esp` refs, sparse static strings | stack string construction | `encoded_string_extract`, IDA string scan | decode char bytes from push immediates, FLOSS tight-string mode | child decodes stack string candidates |
| `call [reg]`, `call [reg+off]`, `jmp [reg]` no xref | indirect call obfuscation | IDA + hexdump around call table | trace reg value source, identify dispatch table | child maps one call target cluster |
| Complex arithmetic equivalent to simple op (e.g. `(a\|b)-(a&b)` for `a^b`) | instruction substitution / MBA obfuscation | IDA pseudocode + pattern review | flag as obfuscated; escalate to symbolic simplification if blocking | child simplifies one expression cluster |

### Data Shape Signals

| Signal | Likely Cause | First Tools | Next Technique | Child Strategy |
| --- | --- | --- | --- | --- |
| Unusual section name (.vmp0, .themida, .enigma1, .mackt) or high entropy | packed/encrypted data | `obfuscated_data_map`, `encoded_string_extract` | identify packer family, map xrefs to blob, locate decoder | child analyzes blob xrefs |
| Sparse visible strings + `push imm` clusters | encrypted or stack-built strings | `encoded_string_extract`, `obfuscated_data_map` | hook decrypt routine or extract stack chars | child generates hook plan or decodes stack chars |
| Crypto constants or high-entropy blob xrefs | encryption/hash/checksum | `obfuscated_data_map`, `binary_find` | identify algorithm and key source | child analyzes one decrypt/hash function |
| Runtime-only plaintext | decrypt after execution | `runtime_string_hooks` | dump return/buffer strings, re-run extraction | child prepares hook script and collector |
| Encrypted resource entries (RT_RCDATA high entropy) | resource encryption | `binary_inspect` resources, `binary_find` FindResource/LockResource | trace decrypt routine on loaded resource | child maps resource decrypt chain |
| `.tls` section present, TLS callbacks in directory | TLS callback anti-debug or early init | `binary_inspect` PE headers | inspect TLS callback addresses, classify as init or anti-debug | child analyzes each callback |

### Import & API Signals

| Signal | Likely Cause | First Tools | Next Technique | Child Strategy |
| --- | --- | --- | --- | --- |
| Anti-debug/timing imports (IsDebuggerPresent, NtQueryInformationProcess, QueryPerformanceCounter, RDTSC, GetTickCount, Sleep) | local challenge gate | imports + IDA xrefs + `binary_find` constants | classify gate, map decision branch, plan static patch | child maps anti-debug checks |
| `fs:[0x30]` / `gs:[0x60]` segment reads, PEB offset access | manual PEB anti-debug (BeingDebugged, NtGlobalFlag, HeapFlags) | IDA disasm — search for `fs:`/`gs:` segment overrides | inspect PEB offset target, classify which PEB field | child catalogs PEB-access locations |
| GetThreadContext / SetThreadContext, DR register access | hardware breakpoint detection | imports + IDA xrefs | identify DR register inspection, plan HW-breakpoint-aware strategy | child maps DR check sites |
| `repne scasb` over code region, CRC of `.text`, `0xCC` byte scan | software breakpoint / INT3 integrity check | `binary_find` for `0xCC` scan patterns + IDA xrefs | classify integrity guard, handle before patching | child maps integrity check routine |
| SEH/VEH setup + deliberate crash (INT 2D, invalid handle, UD2) | exception-based anti-debug | IDA: `__try/__except` patterns, `SetUnhandledExceptionFilter` | classify exception trap type, identify diverge path | child traces one exception handler chain |
| FindWindow / EnumWindows with debugger class names | debugger window enumeration | `binary_find` for "OllyDbg", "WinDbg", "x64dbg" strings | classify as environment gate, plan bypass | child maps window enum check |
| CreateToolhelp32Snapshot + Process32First/Next, parent PID check | parent process or process-name detection | imports + IDA xrefs + `binary_find` for process name strings | classify as environment gate | child maps process enum check |
| VM-specific registry keys, MAC OUI, CPUID hypervisor leaf, SIDT/SLDT | VM detection | `binary_find` for VM strings, IDA for CPUID/SIDT asm | classify VM check type, plan static patch | child catalogs VM detection sites |
| Very few imports + LoadLibrary/GetProcAddress + PEB traversal (`fs:[0x30]+0xc`) | API hashing / dynamic import resolution | `binary_find` for hash constants (ror13/CRC32), IDA for export-table walk | reverse hash function, build lookup table, label resolved APIs | child reconstructs one DLL's hash table |
| Delayed import directory present, `__delayLoadHelper2` | delayed-load imports hidden from normal IAT | `binary_inspect` PE delayed-import directory | parse delay-load table, add to import analysis | child maps delay-loaded functions |
| Near-zero imports + VirtualProtect on import data regions near entry | IAT encryption | `binary_inspect`, IDA for VirtualProtect + GetProcAddress loops | identify decrypt+fill loop, plan runtime dump or static reconstruction | child maps IAT resolution routine |

### Packer & Protector Signals

| Signal | Likely Cause | First Tools | Next Technique | Child Strategy |
| --- | --- | --- | --- | --- |
| VirtualProtect(PAGE_EXECUTE_READWRITE) on `.text`, FlushInstructionCache, code writes | self-modifying code (SMC) | imports + IDA xrefs to VirtualProtect + write patterns | dump post-decrypt memory, re-analyze plaintext | child traces SMC decrypt loop |
| High entropy, few imports, broken sections, tail jump / `push + retn` to OEP | custom packer (non-UPX) | `binary_inspect`, `binary_hexdump` near entry | identify OEP via tail jump or stack pivot, plan memory dump + import rebuild | child handles dump + rebuild |
| `CreateProcess(CREATE_SUSPENDED)` + `NtUnmapViewOfSection` + `WriteProcessMemory` + `ResumeThread` | process hollowing / RunPE | imports + IDA xrefs | map loader stages, identify injected payload | child traces loader chain per stage |
| DeviceIoControl / driver pair | user-driver protocol | `binary_inspect`, `ida_analyze` | map IOCTLs, buffers, side channels | one child for app protocol, one for driver dispatch |
| Standard library noise / stripped PE | no symbols | `ida_deobfuscate` signatures/API roles | apply FLIRT, role-label functions | child labels high-score functions |

### Solving & Constraint Signals

| Signal | Likely Cause | First Tools | Next Technique | Child Strategy |
| --- | --- | --- | --- | --- |
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

### Anti-Debug Triage Route

Use when the binary has anti-debugging checks that block analysis.

1. **Catalog all checks.** Scan imports for debugger APIs, search for `fs:[0x30]`
   / `gs:[0x60]` segment reads, look for `RDTSC`/`CPUID` inline asm, check TLS
   directory, and scan for `0xCC` byte-search loops.
2. **Classify each gate type:**
   - PEB flag check (BeingDebugged, NtGlobalFlag, HeapFlags) → patch the PEB
     byte comparison or hook the read
   - Hardware BP check (GetThreadContext, DR registers) → use software BP or
     NOP the check
   - INT3 scan / code CRC → identify the integrity guard first, then patch
     the comparison constant
   - Timing check (RDTSC, QueryPerformanceCounter) → NOP the threshold branch
     or set threshold to impossibly large value
   - Exception trap (INT 2D, CloseHandle(invalid), SEH/VEH) → classify the
     diverge path and NOP the detection branch
   - Window enumeration (FindWindow, EnumWindows) → NOP the detection branch
   - Parent process check → NOP the comparison or return expected parent name
3. **Map the decision chain.** Identify success/failure paths after each check.
   Record each check's offset, type, and bypass strategy in `.chatcli/task.md`.
4. **Patch or bypass in dependency order.** Some checks protect others — if check
   B validates the code region that contains check A's patch, handle B first.
5. **Verify.** After each patch, confirm the check no longer triggers and the
   program reaches the next stage.

### Anti-VM Triage Route

Use when the binary detects virtualized environments.

1. **Identify VM detection method:**
   - Registry key probe → `binary_find` for VM-related key paths
   - Process name enumeration → `binary_find` for `vmtoolsd`, `VBoxService` etc.
   - Filesystem artifact → `binary_find` for driver paths (.sys files)
   - MAC address OUI → `binary_find` for `00:0C:29`, `00:50:56`, `08:00:27`
   - CPUID hypervisor leaf → IDA for `cpuid` with `eax=0x40000000`
   - SIDT/SLDT/SGDT/STR → IDA for these instructions near branches
   - WMI query strings → `binary_find` for `Win32_ComputerSystem`, `Win32_BIOS`
2. **Classify the check as static or runtime:**
   - Static check (reads registry/filesystem once at startup) → patch the
     comparison branch or stub the return value
   - Runtime check (periodic or before critical operations) → patch all
     instances or hook the detection function
3. **Patch strategy per type:**
   - Registry/filesystem → NOP the branch after `RegQueryValueEx`/`CreateFile`
   - CPUID/SIDT → NOP the comparison after the asm block
   - MAC address → patch the OUI comparison constant
   - Process name → patch the string comparison or the enum loop exit condition
4. **Record findings.** Document each VM check location, type, and bypass in
   `.chatcli/task.md`. Many samples chain multiple VM checks — ensure all are
   found before claiming success.

### Self-Modifying Code (SMC) Route

1. Identify SMC signals: `VirtualProtect` with `PAGE_EXECUTE_READWRITE` on
   `.text` or a code region, `FlushInstructionCache` calls, or direct memory
   writes followed by jumps into the written region.
2. Locate the decrypt/write loop. Break on the `VirtualProtect` call and single-
   step through the write loop, or statically trace which bytes are modified.
3. For XOR-based SMC: extract the key buffer and XOR data from static analysis,
   write a scratch decoder in `.chatcli/tmp/scratch.py`.
4. For nested SMC (decrypted code contains further decryptors): repeat the
   process layer by layer. Dump memory after each layer's decrypt loop.
5. Dump the fully-decrypted code region and re-run `ida_analyze` on the dump.
6. Record each SMC layer's offsets, decrypt algorithm, and key source.

### API Hash Resolution Route

Use when the binary resolves APIs by hashing function names instead of using
the static IAT.

1. Identify the hash function: `binary_find` for known hash constants —
   ROR13 (ror by 13, common in shellcode), CRC32 (table lookup), FNV-1a
   (base `0x352c9a7e`, prime `0x1000193`), djb2 (hash=5381, `hash*33+c`).
2. Locate the export-table walking loop in IDA. The pattern is:
   - Walk PEB→LDR→InMemoryOrderModuleList to find the target DLL
   - Parse the DLL's PE export directory (NumberOfNames, AddressOfNames, etc.)
   - Hash each export name and compare to the target hash
   - Resolve the matched function address via AddressOfFunctions ordinal table
3. Reverse the hash function and build a lookup table:
   - For known DLLs (kernel32, ntdll, user32), precompute hashes for all exports
   - Match target hashes found in the binary to actual API names
4. Label resolved APIs in IDA or in `.chatcli/task.md`. Re-run
   `reverse_evidence_map` with the resolved names as keywords.
5. If the hash algorithm is custom, reconstruct it from pseudocode into a
   scratch script, then generate the lookup table.

### Custom Packer Unpacking Route

Use when the binary is packed but not with a standard packer like UPX.

1. **Identify packer signals:**
   - High entropy in multiple sections, few or no meaningful imports
   - Small import table (often just LoadLibrary, GetProcAddress, VirtualAlloc,
     VirtualProtect, ExitProcess)
   - Entry point in an unusual section, or section is writable+executable
   - Tail jump pattern: unconditional `jmp` or `push addr; retn` at the end of
     the entry section, jumping to a different section (the OEP)
   - Stack pivot: `mov esp, const` or `popad` before the OEP jump
2. **Identify the Original Entry Point (OEP):**
   - Look for the tail jump at the end of the unpacking stub
   - Set a breakpoint on the tail jump target, run, then dump
   - Alternatively, look for `VirtualProtect` restoring original section
     permissions before the OEP jump
3. **Dump the unpacked process memory:**
   - After OEP execution begins, the original code is fully decrypted in memory
   - Dump the relevant memory regions (`.text`, `.rdata`, `.data`)
4. **Rebuild imports:**
   - The original IAT may be destroyed or encrypted; after unpacking, the packer
     resolves APIs and writes them to an IAT region
   - Identify the IAT region (usually pointed to by indirect calls) and extract
     the resolved API addresses
   - Match addresses to DLL exports to rebuild the import table
5. **Handle stolen bytes:**
   - Some packers copy the first N bytes of the OEP into the stub, then jump to
     OEP+N. The original bytes at OEP are garbage.
   - Identify stolen bytes by comparing OEP bytes with what the tail jump does
     before jumping (e.g., it executes a few instructions then jumps to OEP+N)
6. **Re-run analysis on the unpacked binary.** After dumping + import rebuilding,
   run `binary_inspect` and `ida_analyze` on the clean output.

## Main Window Policy

- Keep the main context small: decisions, evidence, maps, child summaries.
- Put function dumps, pseudocode, and long traces in child records or JSON files.
- Compression should preserve `.chatcli/task.md` and child summaries; after
  compression, continue from the durable state rather than repeating triage.
- Do not claim completion while required child findings are pending.
