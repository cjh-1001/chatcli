# Reverse Competition Playbook

Use this reference only for authorized local binaries, CTF/crackme tasks,
owned software, internal training samples, or defensive malware triage. Keep
runtime manipulation local to the provided artifact. Do not turn these methods
into real software piracy, arbitrary process injection, persistence, stealth,
EDR/AV bypass, credential theft, or live-target access.

## Standard Main-Window Thinking

1. Identify the sample.
   - Path, SHA256, size, format, architecture, subsystem, entry point.
   - Sections, entropy, imports, strings, resources, packer clues.
   - Decide: simple, medium, packed/obfuscated, driver/IOCTL, web/cloud-adjacent,
     or unknown.

2. Choose the shortest winning path.
   - Derive correct input when possible.
   - Write a solver when the transform is local.
   - Patch a copied binary when the decision point is known.
   - Hook/instrument only when runtime-only data or anti-tamper makes static
     solving inefficient.
   - Use local injection/harness only when the challenge design requires runtime
     manipulation.

3. Analyze evidence in order.
   - Lightweight triage first.
   - IDA entry analysis order next.
   - Candidate functions and xrefs next.
   - Verify offsets/constants with binary_find and binary_hexdump.
   - Record completed work in Reverse Analysis State.

4. Deliver a reproducible chain.
   - Root cause.
   - Evidence.
   - Technique chosen and why.
   - Implementation steps.
   - Verification.
   - Rollback/residual risk.

## String Clue Handling

- Success/failure text: find xrefs, identify branch or validation return.
- Prompt text: find input collection function and caller.
- Flag format: derive constraints; search both ASCII and UTF-16LE.
- Admin/role/license/debug words: map permission gate or feature flag.
- Base64/hex/URL-like blobs: test reversible decoding before assuming crypto.
- High-entropy blobs: check compression/encryption/resource packing.
- URLs/IPs/domains: for local challenge, treat as simulated unless scope confirms
  live interaction; prefer static analysis.
- Registry/file/device names: map environment checks or IOCTL-style challenge.
- Error messages: often mark failure path; xref them before patching.
- No useful strings: use imports, entry order, function shape, constants, and
  entropy instead.

## Import Clue Handling

- strcmp/strncmp/memcmp/lstrcmp: compare gate; inspect arguments and caller.
- scanf/fgets/read/recv/GetDlgItemText/GetWindowText: input source.
- IsDebuggerPresent/CheckRemoteDebuggerPresent/NtQueryInformationProcess:
  anti-debug check; identify branch and local patch/hook candidate.
- QueryPerformanceCounter/GetTickCount/Sleep: timing gate or anti-debug.
- Crypt/hash imports or MD5/SHA constants: reconstruct transform; do not call
  hashes "decryptable".
- VirtualAlloc/VirtualProtect/CreateThread/LoadLibrary/GetProcAddress: unpacking,
  shellcode-like staging, dynamic import, or challenge loader behavior.
- CreateFile/ReadFile/WriteFile/RegOpen: file/registry key dependency.
- DeviceIoControl/CreateFile on device path: driver/IOCTL challenge; do not load
  drivers, analyze statically.
- WinHTTP/WinInet/socket APIs: network-like challenge; confirm scope before live
  traffic, prefer static/server-simulated reasoning.

## Validation Patterns

- Direct string compare: recover expected string or patch final branch.
- Character loop: reconstruct constraints and solve with Python.
- Table lookup: dump table, model transform, solve forward or invert.
- Bitmask/checksum: identify accumulated state and target constant.
- CRC: search polynomial/table, reconstruct checksum, solve input if bounded.
- Hash compare: reconstruct input path and digest; brute force only toy local
  keyspaces clearly intended by the challenge.
- Crypto-like routine: identify algorithm, key, IV/nonce, mode, padding, and key
  source. If key is local, reconstruct; if external/secret, report blocker.
- State machine: map state transitions and success state.
- VM/bytecode: identify bytecode blob, dispatcher, opcode table, and success
  condition; write a small emulator only for the local challenge.
- Multi-stage gate: solve in dependency order and record each stage.
- Permission gate: map role/source/feature flag and success path.

## Packing And Obfuscation

- UPX signatures/sections: use UPX unpack then re-run triage.
- High entropy with few imports: likely packed; avoid trusting strings.
- Dynamic imports: look for LoadLibrary/GetProcAddress and API name blobs.
- OEP-style challenge: identify unpacking stub and transition to real code.
- Control-flow flattening: find dispatcher, state variable, and cases.
- Opaque predicates: use data flow and branch effects instead of trusting names.
- String encryption: locate decrypt routine and call sites; reconstruct local
  decryptor in scratch.
- Anti-disassembly tricks: rely on IDA reanalysis, hexdump, and targeted xrefs.

## Runtime Analysis For Local Challenges

Use runtime work only for authorized local samples.

- Debugger breakpoints: input collection, compare call, success/failure branch,
  decrypt routine, and API gates.
- Watchpoints: expected string buffers, decoded blobs, checksum state.
- Trace: loops and state machines when static pseudocode is unclear.
- API hook/stub: replace local API result to test a hypothesis.
- Frida-style local hook: instrument challenge process functions or APIs.
- Loader/harness: start the provided executable and patch/instrument in scope.
- DLL/proxy loading: only for local challenge and only when the challenge loads
  that library path by design.

Never add stealth, persistence, process hiding, EDR/AV bypass, credential access,
or unrelated process targeting.

## Patch Techniques

- Branch flip: only after understanding condition and success/failure path.
- NOP skip: use when code block is nonessential and integrity is understood.
- Return patch: force validation function result when caller semantics are known.
- Constant patch: change expected value only when protected regions are understood.
- IAT/import patch: redirect local copied binary imports for challenge behavior.
- Code cave: insert small local patch only when size constraints prevent inline
  patching; preserve control flow and alignment.
- Detour-style patch: redirect to local patch code and return safely.
- Resource patch: modify embedded strings/blobs only when format and integrity
  are understood.
- Integrity guard: identify and handle before modifying protected bytes.

Always record original SHA256, patched SHA256, offset, old bytes, new bytes,
confidence, and rollback.

## Anti-Debug Technique Catalog

Use this catalog to identify and bypass common anti-debugging techniques in
authorized CTF/crackme samples. Every technique should be classified and a
static patch or hook plan recorded before proceeding.

### PEB-Based Detection

**BeingDebugged (PEB+0x2):** The simplest check — reads `BYTE PTR fs:[0x30]+2`
(x86) or `BYTE PTR gs:[0x60]+2` (x64). Set to `0x01` by the kernel when a
process is being debugged. Also accessible via `IsDebuggerPresent()` API.

- Detection: `binary_find` for `fs:[0x30]`/`gs:[0x60]` access patterns in
  disassembly, or `IsDebuggerPresent` in imports
- Bypass: patch the `cmp` that tests the PEB byte, NOP the conditional branch,
  or set `BeingDebugged=0` via a debugger plugin before the check runs

**NtGlobalFlag (PEB+0x68 x86 / PEB+0xBC x64):** When a process is *launched*
by a debugger (not attached), Windows sets heap debug flags in this field.
Typical debugger value is `0x70` (FLG_HEAP_ENABLE_TAIL_CHECK |
FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS). Not set when
attaching to an already-running process.

- Detection: segment read at `PEB+0x68`/`PEB+0xBC` followed by `cmp`/`test`
  against `0x70`
- Bypass: patch the comparison constant, NOP the branch, or attach to the
  process instead of launching it from the debugger

**HeapFlags / ForceFlags:** The process heap at `PEB+0x18` (ProcessHeap) has
`Flags` at offset `+0x0C` (normal=`0x02`, debug=`0x50000062`) and `ForceFlags`
at `+0x10` (normal=`0x00`, debug=`0x40000060`).

- Detection: read `PEB->ProcessHeap` then dereference Flags/ForceFlags offsets
- Bypass: patch the comparison values, or use `_NO_DEBUG_HEAP=1` environment
  variable when launching

### Hardware Breakpoint Detection

**GetThreadContext / DR Register Inspection:** The code calls `GetThreadContext`
on itself and inspects `Dr0`-`Dr3` and `Dr7` in the `CONTEXT` structure.
Non-zero DR registers indicate hardware breakpoints are set.

- Detection: `GetThreadContext` import + CONTEXT access via IDA
- Bypass: use software breakpoints (INT3) for your own analysis, NOP the
  detection branch, or zero out the CONTEXT DR fields before the check reads
  them
- Alternative form: SEH handler receives a `CONTEXT` record; the handler
  inspects DR fields from the exception context

### Software Breakpoint / INT3 Detection

**0xCC Byte Scanning:** A routine iterates over the `.text` section (or a
specific function range) searching for `0xCC` bytes using `repne scasb` or
a simple loop. If any INT3 bytes are found, the binary exits or corrupts
execution.

- Detection: `binary_find` for `0xCC` as a searched byte, or IDA for
  `repne scasb` patterns over code addresses
- Bypass: use hardware breakpoints instead of software BPs, or NOP the
  scanning routine entirely

**Code Checksum / CRC32 Integrity:** Instead of scanning for `0xCC`, a
checksum (CRC32, MD5, custom hash) is computed over the code region at
runtime and compared to a precomputed expected value. Any modification
(including patching or breakpoints) changes the hash.

- Detection: checksum/hash import + comparison over code-section addresses,
  or a loop accumulating a CRC over function bytes
- Bypass: patch the comparison to always match, or recompute the checksum
  after modifying bytes (identify the checksum algorithm first)

### Timing-Based Detection

**RDTSC:** The `RDTSC` instruction reads the CPU timestamp counter. A common
pattern: `CPUID` (serializing) → `RDTSC` → store → (code under analysis) →
`CPUID` → `RDTSC` → compare delta to threshold. Single-stepping causes the
delta to far exceed the threshold.

- Detection: `RDTSC` mnemonic near conditional branches, often paired with
  `CPUID`
- Bypass: NOP the timing comparison branch, patch the threshold to `0xFFFFFFFF`,
  or avoid single-stepping through timed regions

**QueryPerformanceCounter / GetTickCount / timeGetTime:** API-based timing
with the same principle — measure before and after a code block, compare to
threshold.

- Detection: timing API imports + comparison logic after paired calls
- Bypass: same as RDTSC — NOP the branch or patch the threshold

### Exception-Based Detection

**CloseHandle (invalid handle):** The code calls `CloseHandle` with an invalid
pseudo-handle (e.g., `0xDEADBEEF`) inside a `__try/__except` block. Normally
it returns `FALSE` with `ERROR_INVALID_HANDLE`. Under a debugger, the kernel
raises `EXCEPTION_INVALID_HANDLE` (0xC0000008), which the `__except` handler
catches to detect the debugger.

- Detection: `CloseHandle` with a constant that is clearly not a valid handle
  (often `0xDEADBEEF` or `0xBAADF00D`), wrapped in SEH `__try/__except`
- Bypass: configure debugger to pass `EXCEPTION_INVALID_HANDLE` to the program,
  or NOP the `__except` block's detection logic

**INT 2D (kernel debugger check):** In user mode without a kernel debugger,
`INT 2D` sets EIP to skip 1 byte after the instruction. With a kernel debugger
present, EIP behavior differs. The code checks the resulting EIP to detect
kernel debuggers.

- Detection: `INT 2D` instruction followed by EIP/rIP-dependent logic
- Bypass: NOP the INT 2D and the EIP check

**UnhandledExceptionFilter / SetUnhandledExceptionFilter:** The presence of a
debugger changes how unhandled exceptions are dispatched. Some protectors hook
or check `SetUnhandledExceptionFilter` to detect if a debugger has modified
the exception chain.

- Detection: `SetUnhandledExceptionFilter` or `UnhandledExceptionFilter` in
  imports, or `NtQueryInformationProcess(ProcessDebugPort)` near exception setup
- Bypass: NOP the detection branch; these are usually auxiliary checks

### TLS Callback Detection

TLS callbacks execute before the PE entry point (`AddressOfEntryPoint`),
triggered by `DLL_PROCESS_ATTACH` during loader initialization. Anti-debug
code placed here runs before the debugger can pause at the entry point.

- Detection: check PE `IMAGE_DIRECTORY_ENTRY_TLS` (data directory index 9);
  `binary_inspect` lists `.tls` section presence. IDA shows callback addresses.
- Bypass: configure debugger to break on "System breakpoint" (ntdll!Ldrp...),
  not "Entry Point"; or patch the TLS callback array to NULL in the PE header

### Window & Process Enumeration

**FindWindow / EnumWindows:** Searches for debugger window class names
("OllyDbg", "WinDbgFrameClass", "IDAWDebugger", "x64dbg", "Qt5QWindowIcon").

- Detection: `FindWindowA`/`FindWindowW` or `EnumWindows` in imports +
  debugger-related window class strings
- Bypass: NOP the detection branch after the window search

**Parent Process Check:** Uses `CreateToolhelp32Snapshot` + `Process32First`/
`Process32Next` (or `NtQueryInformationProcess` with `ProcessBasicInformation`)
to find the parent process name. Checks if parent is `explorer.exe` (normal)
vs. a debugger or command shell.

- Detection: toolhelp32 imports + process name comparison strings
- Bypass: NOP the comparison or return the expected parent name

**SeDebugPrivilege Check:** Uses `OpenProcessToken` + `LookupPrivilegeValue` +
`PrivilegeCheck` to determine if the process has `SeDebugPrivilege`, indicating
it was launched from a privileged/debugger context.

- Detection: `LookupPrivilegeValueW` with `SeDebugPrivilege` string +
  `PrivilegeCheck` in imports
- Bypass: NOP the privilege check branch

## Anti-VM Detection

Use this section when the binary attempts to detect virtualized environments.
CTF/crackme samples often include VM detection that must be bypassed to
analyze the sample inside a VM.

### Registry Artifacts

The binary enumerates or probes VM-specific registry keys:

| VM | Registry Keys |
| --- | --- |
| VMware | `HKLM\SOFTWARE\VMware, Inc.\VMware Tools` |
| VirtualBox | `HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions`, `HKLM\SYSTEM\CurrentControlSet\Services\VBox*` |
| Hyper-V | `HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters` |
| QEMU | `HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\...\Identifier` containing "QEMU" |
| Parallels | `HKLM\SOFTWARE\Parallels\Parallels Tools` |
| Xen | `HKLM\SYSTEM\CurrentControlSet\Services\xenevtchn` |

- Detection: `RegOpenKeyEx`/`RegQueryValueEx` imports + registry path strings
- Bypass: NOP the branch after each registry probe, or add expected VM registry
  keys to the analysis VM so it appears "native"

### Process Name Detection

Uses `CreateToolhelp32Snapshot` + `Process32First`/`Process32Next` to enumerate
running processes and match against a blacklist:
- VMware: `vmtoolsd.exe`, `VMwareTray.exe`, `VMwareService.exe`
- VirtualBox: `VBoxService.exe`, `VBoxTray.exe`
- Hyper-V: `vmms.exe`, `vmwp.exe`
- Others: `xenservice.exe`, `prl_tools.exe`, `vdagent.exe`

- Detection: toolhelp32 imports + blacklisted process name strings
- Bypass: NOP the match branch or patch the process name comparison

### Hardware / CPUID Detection

**CPUID hypervisor bit:** `cpuid` with `eax=1` returns bit 31 of ECX as the
hypervisor-present bit. With `eax=0x40000000`, returns hypervisor vendor
string in EBX:ECX:EDX — `"VMwareVMware"`, `"VBoxVBoxVBox"`, `"KVMKVMKVM"`,
`"Microsoft Hv"`, `"XenVMMXenVMM"`.

**SIDT Red Pill:** The `SIDT` instruction stores the IDT base address. On
bare metal, the IDT base is typically in the `0x80xxxxxx` range. In VMs,
the address is shifted. Similarly `SGDT` (GDT), `SLDT` (LDT), and `STR`
(task register) reveal VM-specific relocation patterns.

**MAC Address OUI:** `GetAdaptersInfo` / `GetAdaptersAddresses` returns MAC
addresses. VM vendor OUIs: VMware `00:0C:29`, `00:50:56`, `00:05:69`;
VirtualBox `08:00:27`; Parallels `00:1C:42`.

**VMware I/O port:** Reading from port `0x5658` ("VX") with the magic value
in EAX returns the VMware version in EBX if running inside VMware.

- Detection: `CPUID`/`SIDT`/`SGDT`/`SLDT` inline asm near branches,
  `GetAdaptersInfo` import + OUI comparison, or `IN` instruction with
  VMware magic port
- Bypass: NOP the comparison after each detection point, or patch the expected
  value to match what the VM returns

### WMI / System String Detection

Queries WMI (`Win32_ComputerSystem`, `Win32_BIOS`, `Win32_BaseBoard`) for
manufacturer/model strings: `"VMware Virtual Platform"`, `"VirtualBox"`,
`"QEMU Standard PC"`, `"innotek GmbH"`, `"Bochs"`, `"Microsoft Corporation
Virtual Machine"`.

Also checks via `GetSystemFirmwareTable('ACPI', ...)` for BIOS/ACPI strings.

- Detection: WMI query strings, `GetSystemFirmwareTable` import
- Bypass: NOP the comparison branches, or hook the WMI query to return
  non-VM strings

### VM Artifact Triage Strategy

1. Catalog all VM checks: `binary_find` for VM-related strings + IDA for
   detection API xrefs
2. Order checks by dependency: some checks run early and exit before later
   checks are reached — handle these first
3. Prefer patching the decision branch, not the detection data: NOP the
   conditional after each check rather than trying to fake every registry key
4. Verify after each bypass: confirm the binary reaches the next detection
   point or proceeds to the actual validation logic

## Self-Modifying Code (SMC) Handling

Self-modifying code decrypts or modifies its own instructions at runtime.
Static analysis sees only encrypted bytes; dynamic analysis is needed.

### Detection Signals

- `VirtualProtect` with `PAGE_EXECUTE_READWRITE` on `.text` or a code section
- `FlushInstructionCache` calls (required after modifying executable memory)
- `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` followed by writes and indirect
  calls into the allocated region
- Direct memory writes to code pages (after VirtualProtect makes them writable)
- The `.text` section has `IMAGE_SCN_MEM_WRITE` flag (unusual for normal code)

### Analysis Approach

1. **Break on VirtualProtect:** Set a breakpoint on `VirtualProtect` calls
   that target code addresses. Record the region being made writable.
2. **Trace the write loop:** After VirtualProtect returns, the decrypt loop
   writes plaintext into the code region. Single-step or set a hardware
   breakpoint on the first write to the target region.
3. **Dump post-decrypt code:** After the write loop completes and before
   execution jumps into the decrypted region, dump the now-plaintext code.
4. **For XOR-based SMC:** Extract the XOR key buffer from static analysis.
   If the key is a fixed byte array, write a scratch decoder script.
5. **For nested SMC:** Repeat the process for each layer. Each decrypted
   layer may contain another decrypt stub. Mark layer depths in `.chatcli/task.md`.
6. **Re-analyze the dump:** Run `binary_inspect` and `ida_analyze` on the
   dumped plaintext code for full analysis.

### Static Reconstruction (When Execution is Not Allowed)

- Identify the decryptor stub location and algorithm
- Extract the encrypted payload offset and size
- Reconstruct the decrypt algorithm in `.chatcli/tmp/scratch.py`
- Decrypt statically and verify with `binary_hexdump` at expected offsets
- If the key is derived from runtime values (PEB, timestamp, etc.), stop
  at a report describing the missing key material

## API Hashing Resolution

When the binary has very few imports but uses `LoadLibrary`/`GetProcAddress`
extensively, it likely resolves APIs by hashing function names at runtime.

### Recognizing API Hashing

- Import table has only ~5-10 APIs (often just `LoadLibraryA`, `GetProcAddress`,
  `VirtualAlloc`, `VirtualProtect`, `ExitProcess`)
- IDA shows a loop walking the PEB loader data: `fs:[0x30]` → `+0x0C` (PEB_LDR_DATA)
  → `+0x14` (InMemoryOrderModuleList) → walk list
- The loop parses PE export directories: reads `NumberOfNames`, `AddressOfNames`,
  `AddressOfNameOrdinals`, `AddressOfFunctions`
- Each export name is fed into a hash function; the result is compared to a target hash
- When a match is found, the corresponding function address is stored

### Common Hash Algorithms

| Algorithm | Constants / Pattern |
| --- | --- |
| ROR13 | `ror eax, 13` (rotate right by 13 bits); common in shellcode and malware |
| CRC32 | Table lookup with 256 DWORD entries (standard polynomial `0xEDB88320`) |
| FNV-1a | Base `0x811C9DC5` (32-bit) or `0xCBF29CE484222325` (64-bit), multiply by prime |
| djb2 | Initialize `5381`, `hash = hash * 33 + c` |
| MurmurHash2 | Multiply by `0x5BD1E995`, shift by 24 |

### Resolution Workflow

1. **Find the hash function:** In IDA, locate the `GetProcAddress` call sites
   and work backwards to find where the second argument (API name string) comes
   from. The hash function processes a string and compares to a constant.
2. **Extract target hashes:** Collect all hash constants compared in the
   resolution loop. Each hash corresponds to one API the binary wants to call.
3. **Reverse the hash algorithm:** Reconstruct from pseudocode into a scratch
   Python script. Verify against a known API name to confirm correctness.
4. **Build a lookup table:** Compute the hash for every export of the target
   DLLs (kernel32.dll, ntdll.dll, user32.dll, etc.). Match each target hash
   to its API name.
5. **Label the resolved APIs:** Update `.chatcli/task.md` with the mapping
   `hash_value -> DLL!FunctionName`. Use `ida_deobfuscate` with API-role
   labels, or manually mark resolved functions in IDA.
6. **If the hash is custom:** Reconstruct from IDA pseudocode, write a Python
   equivalent, and test against the PE export list of the expected DLL.

## Custom Packer Triage

When a binary is packed with a non-standard packer (not UPX, ASPack, etc.).

### Identifying the Packer Type

- **UPX:** Section names `.upx0`, `.upx1`; `UPX!` string after unpacking stub;
  can use `upx_unpack` tool directly
- **VMProtect:** Sections `.vmp0`, `.vmp1`; very small import table (often just
  kernel32 and a few APIs); multiple code sections with high entropy
- **Themida:** Section `.themida`; complex multi-threaded unpacking; anti-debug
  and anti-VM checks in the unpacking stub
- **Enigma Protector:** Sections `.enigma1`, `.enigma2`
- **Custom/unknown:** No recognizable section names; small import table; high
  entropy in code sections; unusual entry point behavior

### Custom Unpacking Steps

1. **Find the OEP (Original Entry Point):**
   - Set a breakpoint on `VirtualProtect` with execute-read-write on a code
     section — this often happens just before jumping to the OEP
   - Look for a tail jump at the end of the first code section: an unconditional
     `jmp` or `push addr; retn` that crosses section boundaries
   - Look for a stack pivot: `mov esp, const` or `popad` restoring the original
     stack before jumping to OEP
   - Alternatively, use entropy-based OEP detection: after unpacking, the
     executing code region's entropy drops as plaintext code runs

2. **Dump the process:**
   - Break at OEP (or shortly after, once all sections are decrypted)
   - Dump the entire process memory, or at minimum dump the relevant sections
     (`.text`, `.rdata`, `.data`, and any custom code sections)

3. **Rebuild the import table:**
   - Identify the IAT location: find indirect calls (`call [addr]`) in the
     unpacked code and trace back to the table of resolved API addresses
   - For each address in the IAT, determine which DLL!Function it points to
     by matching against the DLL's loaded base + export RVA
   - Rebuild a PE import directory from the resolved IAT entries

4. **Handle stolen bytes (OEP corruption):**
   - Some packers move the first 5-20 bytes of the original entry point into
     the packer stub. The bytes at OEP in the dump are garbage.
   - Identify stolen bytes: look at what instructions the tail jump region
     executes before jumping to OEP+N. Those instructions are the stolen bytes.
   - Copy the stolen bytes back to OEP in the dumped file, or prepend them
     to the dump's entry point

5. **Fix section alignment and entry point:**
   - Set the PE entry point to the identified OEP RVA
   - Adjust section raw/virtual sizes if the dump expanded them
   - Recalculate PE checksum (optional)

6. **Verify the unpacked binary:** Run `binary_inspect` and `ida_analyze` on
   the rebuilt binary. Confirm imports resolve sensibly, strings are visible,
   and pseudocode is coherent.

### When Not to Fully Unpack

- If the packer requires an online key server to decrypt (beyond CTF scope):
  report the blocker and the static evidence
- If the unpacking stub contains live anti-debug that cannot be safely bypassed
  in the local lab: report each check and a bypass plan
- If the binary is too complex for full unpacking: focus on extracting specific
  data (strings, config, key material) via targeted runtime hooks rather than
  full unpacking

## Hooking And Local Injection Decision Tree

Use hooking/injection only when a simpler method is insufficient.

- Need to observe runtime-decoded data: hook decrypt routine or watch buffer.
- Need to bypass environment check: hook local API or patch copied branch.
- Need dynamic key generated at runtime: instrument function and dump key.
- Need to alter import behavior: IAT/import patch or local proxy library.
- Need to manipulate a challenge-created process: local loader/harness.

For every hook/injection chain, document:

- Target artifact and SHA256.
- Target function/API/address.
- Before/after behavior.
- Why solver/simple patch is insufficient.
- Run/build command for the local challenge.
- Verification result.
- Undo/rollback.

## Common Blockers

- IDA sparse output: packed, wrong architecture, loader stub, or stripped sample.
- Pseudocode misleading: obfuscation, bad types, or wrong function boundaries.
- Patch has no effect: patched wrong branch, integrity guard, second check, or
  cached/runtime-generated value.
- Solver fails: missed encoding, wide strings, signed/unsigned mismatch, endian
  issue, checksum initialization, or multi-stage dependency.
- Injection/hook fails: wrong bitness, wrong process/function, ASLR address not
  rebased, API called through wrapper, or target exits before hook attaches.

## Report Template

- Scope: local CTF/owned challenge only.
- Target identity.
- Fast path decision.
- Evidence table.
- Candidate function map.
- Root cause.
- Chain:
  1. technique,
  2. implementation,
  3. verification.
- Patch/hook/injection details when used.
- Solver script path when used.
- Residual risks and blockers.
- TASK COMPLETE only when reproducible.
