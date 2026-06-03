---
name: reverse-audit
description: Authorized reverse-engineering and crackme/CTF validation-audit workflow. Use for /reverse, /crack, /crackme, /patch, binary patch audits, PE/ELF/Mach-O triage, validation logic review, crypto/encoding/compression/hash review, anti-debug review, packed binary triage, driver/IOCTL analysis, or local binary audit tasks.
metadata:
  aliases:
    - reverse
    - crackme
    - binary-audit
  triggers:
    - /reverse
    - /crack
    - /crackme
    - /patch
    - ida
    - idapython
    - binary
    - pe
    - elf
    - macho
    - crackme
    - ctf
    - control-flow flattening
    - opaque predicate
    - encrypted strings
    - packed
    - ioctl
    - driver
    - 逆向
    - 反编译
    - 花指令
    - 控制流扁平化
    - 不透明谓词
    - 字符串加密
---

# Reverse Audit Skill

Use this workflow only for authorized local binaries, owned software, internal
training samples, malware triage, or CTF/crackme challenges. Do not help with
piracy, DRM bypass, real-world license bypass, credential theft, persistence,
stealth, real unauthorized access, or privilege escalation. Do not execute unknown
binaries.

For malware, trojan, backdoor, RAT, or suspicious attack samples, use this skill
for focused function-level reverse engineering, unpacking evidence, decoder/config
logic, API hashing, IOCTL mapping, or pseudocode interpretation. Use the
`malware-triage` reporting structure for the final defensive conclusion: attack
behavior chain, evidence, confidence, IOCs, impact assessment, detection ideas,
and containment/remediation guidance. Do not turn malware reversing notes into
payload improvement, persistence/evasion implementation, credential theft
automation, or live C2 operation instructions.

For authorized CTF/crackme training samples, practical challenge-solving is
allowed when it is evidence-driven and local to the artifact. It is appropriate
to teach static triage, string/import analysis, pseudocode interpretation,
validation-logic reconstruction, toy local brute force, scratch solver scripts,
simulated local permission-gate analysis, and patch-audit reasoning on patched
copies. Keep each step tied to observed offsets, functions, strings, constants,
imports, hexdumps, or pseudocode. If the same technique would become a real
product/license/DRM bypass, real unauthorized access, or privilege escalation,
frame it only as local challenge analysis and refuse generalized real-world
misuse.

For official competitions that provide a local executable to crack or exploit,
complete local challenge chains are allowed: analysis, solver, harness, hook,
loader, local-only injection, byte patch, IAT/import patch, code-cave patch,
detour-style patch, or debugger/Frida-style instrumentation when the target and
scope are clearly the provided challenge artifact. Do not generalize these into
real software piracy, arbitrary process injection, persistence, stealth, EDR/AV
bypass, credential theft, or unauthorized access.

If a binary, endpoint, domain, cloud resource, or scenario appears to imitate a
real system, do not assume it is unauthorized. Ask the user to confirm whether it
is a CTF/lab/owned target and what scope boundaries apply. After confirmation,
continue only within the confirmed challenge scope.

Do not use jailbreaks, safety-bypass wording, or attempts to override provider
policy. Use a neutral confirmation prompt instead: "Please confirm this is an
authorized CTF/lab/owned target, list the allowed target(s), and state whether
exploit validation is in scope. I will proceed only within that confirmed scope."

Scope confirmation is one-time per task and target boundary. If `.chatcli/task.md`
already contains `## Scope Confirmation` for the same target, do not ask again
unless the target, ownership, or validation boundary changes.

## Default Flow

1. Establish scope and identity.
   - Read `.chatcli/task.md` first. If it contains `## Reverse Analysis State`,
     treat it as persistent state for completed phases, analyzed functions,
     verified evidence, solver/patch notes, and open questions.
   - Use `binary_inspect` first for hashes, format, architecture, entry point,
     imports, sections, entropy, strings, and packer clues. This lightweight
     triage should guide later IDA analysis.
   - Use `encoded_string_extract` when visible strings are sparse, encoded blobs
     are likely, or a memory dump from debugging is available.
   - Use `obfuscated_data_map` when IDA cannot recover meaningful code/data,
     when sections are high entropy, when strings are sparse, or when embedded
     encrypted/compressed blobs are suspected.
   - Use `git_status` only if the binary is part of a repo.
   - Record target path, SHA256, size, and whether the task is analysis-only,
     patch-audit, or patched-copy generation.

2. Pick the analysis path.
   - If IDA is configured and function logic matters, use `ida_analyze` after
     lightweight triage. Use binary_inspect strings/imports/packer clues as IDA
     analysis hints.
   - On a new machine, after an "IDA executable not found" error, or when the
     configured path is uncertain, run `ida_probe` before retrying IDA tools. If
     it cannot resolve IDA, continue with `binary_inspect`,
     `encoded_string_extract`, `obfuscated_data_map`, `binary_find`, and
     `binary_hexdump`, and report the missing IDA configuration clearly.
   - After `ida_analyze` or `ida_deobfuscate` writes JSON, run
     `reverse_evidence_map` before drawing conclusions. Use it to compactly
     extract imports, strings, xrefs, candidate functions, pseudocode hits, and
     function-map targets. Avoid brittle ad-hoc shell/Python scraping of large
     JSON files, especially on Windows shells.
   - After `reverse_evidence_map` identifies concrete function starts, use
     `ida_focus_decompile` on those addresses/names to get focused pseudocode,
     disassembly, calls, and string references. This is the fastest path for
     locating IOCTL handlers, side-channel routines, decryptors, and validation
     branches.
   - In the chatcli main window, prefer background child-window IDA jobs for slow
     binaries. While the child runs IDA/deobfuscation, keep the main window moving
     with static triage, encoded string extraction, import/section reasoning, and
     patch-risk planning.
   - If control-flow flattening, opaque predicates, junk instructions, or
     stripped PE function recovery are likely, use `ida_deobfuscate` after
     `ida_analyze`. Keep `patch_database=false` first for evidence gathering;
     enable IDA-database patching only after the report is plausible.
   - Pass `plugin_scripts` or `plugin_modules` to `ida_deobfuscate` when a local
     Unflatten, OLLVM/LLVM-deobf, D-810, or Hex-Rays CTREE cleanup script is
     already installed. Pass `signatures` for IDA FLIRT/library signature passes.
   - If IDA is unavailable, continue with `binary_inspect`, `binary_find`,
     `binary_hexdump`, and external static tools when installed.
   - For packed/high-entropy binaries, identify packer clues before trusting
     strings or pseudocode. Use `upx_unpack` only when UPX is indicated and the
     task is authorized.
   - Running IDA is not the analysis. After `ida_analyze`, interpret the evidence:
     entry analysis order, candidate functions, important strings, imports,
     function names, pseudocode, suspicious constants, branch decisions, and likely
     validation or permission-gate routines.
   - If large IDA JSON already exists, do not read it wholesale into context.
     Use `reverse_evidence_map` with focused keywords such as `DeviceIoControl`,
     IOCTL names, event names, driver APIs, success/failure strings, credential,
     maze, side-channel, or suspected function names.

3. Locate evidence before proposing a patch.
   - Use `binary_find` for exact strings, magic bytes, branch opcodes, constants,
     or UTF-16LE strings.
   - Use `binary_hexdump` around every candidate offset.
   - For every candidate, capture original bytes, file offset, nearby context,
     and why that byte sequence maps to the suspected logic.

4. Patch only with strong evidence.
   - Prefer `binary_patch` with `output_path` omitted so it creates a patched
     copy automatically.
   - Use `old_hex` or `expected_sha256` whenever possible.
   - Never patch by guesswork. If evidence is weak, produce a patch plan instead
     of modifying bytes.
   - Keep replacement bytes the same length unless the tool explicitly supports
     resizing and the file format impact has been analyzed.

5. Report clearly.
   - Include the original SHA256 and patched SHA256.
   - Include offsets in both hex and decimal.
   - Include original bytes, replacement bytes, confidence, and risks.
   - State whether the original file was modified or a patched copy was created.
   - For crackme/CTF tasks, include concrete next actions or a small local solver
     plan when the validation algorithm is sufficiently understood.
   - Update `## Reverse Analysis State` before final reporting so context
     compression or session restore can resume without repeating work.

## Persistent State Marking

Use `.chatcli/task.md` as the durable reverse-analysis notebook.

- Mark phases under `### Phase Checklist`.
- Add IDA or static-analysis candidates under `### Candidate Functions`.
- After analyzing a function, add or update an entry under `### Analyzed Functions`:
  `- [x] 0xADDR name - role - evidence - conclusion - next step`.
- After verifying a string, constant, branch, or file offset, add it under
  `### Verified Evidence`.
- Track solver scripts, derived inputs, patch candidates, risks, and blockers
  under `### Solver / Patch Notes`.
- Track unresolved checks under `### Open Questions`.
- On resume, do not re-analyze entries already marked `[x]` unless new evidence
  contradicts them or the target changed.

## Skill Improvement Feedback

When reverse analysis reveals a reusable workflow improvement, tool pattern, or
clearer safety boundary, preserve it for future runs.

- If the user explicitly asks to improve a skill, update the relevant `SKILL.md`
  directly and keep the edit concise.
- If a tool sequence proves useful across samples, add it as a workflow note only
  when it generalizes beyond the current binary.
- If the skill is too conservative or unclear, clarify the allowed CTF/lab/owned
  workflow and the real-world misuse boundary.
- Do not add target-specific flags, offsets, hashes, credentials, or one-off
  findings to the skill. Put those in `.chatcli/task.md` or scratch notes instead.
- Prefer improving `reverse-audit` for reverse-engineering lessons and
  `security-audit` for web/cloud/code-audit lessons.

## References

- For broad competition tactics, string/import clue handling, patch/hook decision
  trees, and blocker triage, read `references/competition-playbook.md`. Load it
  when the user asks for many/frontier techniques, when the sample is not simple,
  or when the current chain is blocked.
- For fast technique selection, large binaries, giant functions, encrypted data,
  IDA stalls, function-map routing, child-window delegation, or compression-aware
  planning, read `references/technique-map.md` before choosing the next tool path.
  Use it as the main-window routing map; keep detailed work in child records.
- When simple crackme tactics are insufficient, when the task may need Z3/angr,
  custom VM analysis, language/platform-specific reversing, dynamic-oracle
  planning, packed-loader triage, or IOCTL state-machine solving, read
  `references/github-reverse-patterns.md`. Use it to choose the next practical
  route, then record the chosen route in `.chatcli/task.md`.

## Common Situations

### Competition Fast Path

Use this as the default practical route for official local exe challenges.

1. Identify the shape fast.
   - `binary_inspect`: arch, format, entropy, sections, imports, strings.
   - If packed/high entropy: identify packer first; UPX can be unpacked, non-UPX
     needs a packer plan.
   - If strings show prompts/success/failure: search xrefs and validation branch.
   - If strings are sparse: use IDA entry order, candidate functions, imports, and
     pseudocode shape.

2. Pick the shortest winning technique.
   - Visible compare or hardcoded expected value -> derive input or branch patch.
   - Local transform/hash/checksum -> reconstruct solver in `.chatcli/tmp/scratch.py`.
   - Multi-stage checks -> solve in dependency order; record each checked stage.
   - Anti-debug/timing/env gate -> identify check, then local static patch/hook plan.
   - Integrity guard blocks patch -> analyze and handle integrity before patching.
   - Runtime-only value or challenge-designed dynamic gate -> local hook/instrumentation.
   - Encrypted runtime strings -> generate local Frida/x64dbg hook templates with
     `runtime_string_hooks`, then analyze dumped memory/plaintext with
     `encoded_string_extract`.
   - Patch-resistant or import/API gate -> copied-binary IAT/import patch or local loader.
   - Only use injection/harness when solver or simple patch is insufficient.

3. Verify before claiming success.
   - Every patch needs exact file offset, original bytes, replacement bytes, and
     expected original SHA256.
   - Every solver needs input constraints, algorithm, and expected output.
   - Every hook/injection needs target function/API/address, before/after behavior,
     scope, undo path, and reason simpler methods were insufficient.

4. Produce a judge-ready deliverable.
   - What the bug/check is.
   - How the chain reaches success.
   - Commands/scripts/patch bytes for the local challenge.
   - Verification result or exact remaining blocker.
   - `TASK COMPLETE` only when the chain is reproducible or the blocker is proven.

### CTF Exploit Chain Deliverable

For official local exe challenges, produce a complete chain that a judge can
reproduce.

- Target identity: path, SHA256, size, format, architecture.
- Scope statement: local provided challenge only; original file preserved unless
  a patched copy is explicitly requested.
- Initial triage: strings/imports/sections/packer clues and IDA candidate map.
- Vulnerability or validation root cause: exact function, branch, comparison,
  transform, import, or data structure.
- Technique chosen and why:
  - solver/input derivation,
  - local harness,
  - local hook/instrumentation,
  - byte patch,
  - IAT/import patch,
  - code-cave or detour-style patch,
  - local challenge injection.
- Implementation:
  - keep scripts in `.chatcli/tmp/scratch.py` unless promoting a final artifact,
  - patched binaries must be copied outputs,
  - include exact offsets, old bytes, new bytes, and expected SHA256 when patching,
  - include build/run commands only for the local challenge scope.
- Verification:
  - show the expected success condition,
  - explain how the patch/hook/solver reaches it,
  - record residual risks and rollback path.

Do not present a chain as complete until the evidence, implementation, and
verification path all line up.

### Local Hooking / Injection for CTF Samples

Use this only for authorized local challenge artifacts.

- Prefer the least invasive technique that solves the challenge:
  1. derive the correct input,
  2. write a local solver,
  3. patch a copied binary,
  4. hook or instrument a local function/API,
  5. use a local loader/injection harness only when the challenge design calls
     for runtime manipulation.
- Allowed local examples include API stubbing, local DLL/proxy loading for the
  provided sample, import-table redirection on a copied binary, debugger scripts,
  Frida-style hooks against the local challenge process, or a loader that starts
  the provided executable and instruments it for the challenge goal.
- Every hook/injection plan must identify:
  - target process and why it is in scope,
  - target function/API/address,
  - expected before/after behavior,
  - how to undo it,
  - why a simpler solver or patch is insufficient.
- Never include persistence, stealth, process-hiding, injection into unrelated
  processes, credential access, EDR/AV bypass, or live third-party targeting.

### IDA Analysis Playbook

Teach the analysis process while solving the task.

1. Start with identity and shape.
   - Note architecture, entry point, imports, sections, function count, strings,
     and whether pseudocode is available.
   - If output looks sparse or packed, say so and switch to packer/static triage.
   - Use lightweight triage from `binary_inspect` to seed IDA hypotheses.

2. Build hypotheses from IDA evidence.
   - Strings: success/failure messages, flag formats, menu text, role names,
     error messages, encoded blobs, URLs, file names, registry keys, or debug text.
   - Imports: input APIs, string compare, crypto/hash libraries, debugger checks,
     file/network/device APIs, timing APIs, or Windows privilege-related APIs.
   - Entry analysis order: analyze reachable functions from the entry path first.
   - Candidate functions: prioritize high-score candidates and their evidence.
   - Evidence map: if there are existing IDA/deobfuscation JSON files, run
     `reverse_evidence_map` first and use its matched imports, strings, xrefs,
     pseudocode hits, and function-map targets as the function-level work queue.
   - Focus decompile: for each high-value candidate, call `ida_focus_decompile`
     instead of re-running broad `ida_analyze`. Use its pseudocode and disassembly
     samples to assign a function role and update `.chatcli/task.md`.
   - Functions/pseudocode: comparisons, loops over user input, switch statements,
     table lookups, checksum/hash calculations, bitmasks, branch returns, and
     success/failure paths.

3. Explain before acting.
   - For each candidate routine, state what it likely does, what evidence supports
     it, and what is still uncertain.
   - Do not jump straight to patching. First identify the validation decision,
     the inputs, the expected value or transform, and the failure path.
   - Do not spend time on unused/unreferenced functions unless strings, imports,
     xrefs, call graph, or pseudocode make them relevant.

4. Verify with targeted tools.
   - Use `binary_find` for strings, constants, branch bytes, or candidate opcodes.
   - Use `binary_hexdump` around each candidate offset.
   - Use `.chatcli/tmp/scratch.py` to reconstruct local transforms or toy solvers.

5. Produce a teaching-style result.
   - Show the reasoning chain: evidence -> hypothesis -> verification -> result.
   - Include concrete next steps when evidence is incomplete.
   - For patch audits, include exact file offsets and original/replacement bytes
     only after the decision point is understood.

### Simple Sample Workflow

Use this for straightforward crackmes, password checks, flag checks, and local
permission gates.

1. Run `ida_analyze` when available, otherwise `binary_inspect`.
2. Identify success/failure strings, input prompts, compare imports, and candidate
   functions.
3. Explain the most likely validation routine in plain language.
4. Verify exact strings/constants with `binary_find` and nearby bytes with
   `binary_hexdump`.
5. If the transform is local and small, reconstruct it in `.chatcli/tmp/scratch.py`
   and produce a candidate input or flag.
6. If patch audit is requested, patch only the understood validation decision and
   create a patched copy.

Expected output for simple samples:

- Identity and protections
- Candidate validation function(s)
- Validation logic explanation
- Solver or input derivation when possible
- Patch-audit plan or patched copy only when requested

### Medium Sample Workflow

Use this when the binary has multiple candidate checks, anti-debug logic, checksum
guards, simple obfuscation, encoded blobs, crypto/hash-like routines, or simulated
authorization gates.

1. Triage protections first.
   - Check entropy, sections, imports, packer clues, anti-debug/timing imports,
     checksum/hash/crypto constants, and suspicious resources or blobs.
2. Build a candidate map.
   - Rank IDA candidate functions by evidence: xrefs to strings, compare/crypto
     imports, role/auth names, branch returns, and pseudocode shape.
   - Separate input collection, transformation, comparison, failure handling, and
     integrity checks.
3. Reduce uncertainty before patching.
   - Verify constants and byte locations with `binary_find` and `binary_hexdump`.
   - Reconstruct transforms in `.chatcli/tmp/scratch.py`; keep iterations in the
     same scratch file.
   - If there are multiple checks, solve or explain them in dependency order.
4. Handle common blockers.
   - If packed, identify packer first; use `upx_unpack` only when UPX is indicated.
   - If integrity-protected, identify the guard before changing bytes.
   - If anti-debug exists, report the check and use static patch-audit candidates
     only for authorized local challenges.
5. Report what is known, what is likely, and what still needs evidence.

Expected output for medium samples:

- Protection and packer assessment
- Candidate function map with evidence
- Validation or permission-gate data flow
- Reconstructed algorithm or bounded solver plan
- Verified offsets/constants
- Patch risks and next steps

### String or Flag Comparison

- Search for visible strings with `binary_find query_ascii` and
  `binary_find query_wide`.
- Inspect nearby bytes with `binary_hexdump`.
- If IDA is available, inspect xrefs to the string and summarize the validation
  function.
- Patch only after identifying the actual decision point, not merely the string.

### Conditional Branch Around Validation

- Identify the branch location from IDA pseudocode/disassembly or a byte search.
- Verify the bytes with `binary_hexdump`.
- Common audit patterns include short conditional jumps and compare-result
  branches, but do not assume opcode meaning without nearby context.
- Patch copies only, and report the semantic risk: branch inversion, forced
  success, or skipped error path.

### Checksum, CRC, or Hash Guard

- Treat checksum logic as a separate integrity control.
- Search for imports and constants first; do not patch a visible branch until
  integrity checks are understood.
- If a patch changes protected regions, explain that verification may fail and
  identify the integrity routine as the next target for audit.

### Anti-Debug or Environment Checks

Anti-debug checks are gate mechanisms that detect analysis tools. Map every
check before patching — some checks protect other checks via integrity guards.

**Cataloging all checks:**

- Import-based: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`,
  `NtQueryInformationProcess` (ProcessDebugPort=7, ProcessDebugFlags=0x1F,
  ProcessDebugObjectHandle=30), `OutputDebugStringA`/`OutputDebugStringW`
- Manual PEB access: `fs:[0x30]` (x86) or `gs:[0x60]` (x64) segment reads
  — check offsets BeingDebugged(+0x2), NtGlobalFlag(+0x68/+0xBC),
  HeapFlags(+0x18→+0x0C/ForceFlags+0x10)
- Hardware breakpoint detection: `GetThreadContext`/`SetThreadContext` +
  CONTEXT.Dr0-Dr3/Dr7 inspection, or SEH handler inspecting CONTEXT DR fields
- Software breakpoint detection: `repne scasb` scanning for `0xCC` bytes in
  `.text`, CRC32/checksum over code regions comparing to precomputed constant
- Timing checks: `RDTSC` + `CPUID` pairs comparing delta to threshold,
  `QueryPerformanceCounter`, `GetTickCount`, `timeGetTime`
- Exception-based traps: `CloseHandle(INVALID_HANDLE_VALUE)` in `__try/__except`,
  `INT 2D` followed by EIP inspection, `UnhandledExceptionFilter` hooking
- Thread-based: `CreateThread` launching a background thread that periodically
  checks debugger presence while the main thread appears clean
- TLS callback: code in PE TLS directory executed before the entry point;
  anti-debug checks here run before the debugger can pause at EntryPoint
- Window enumeration: `FindWindow`/`EnumWindows` searching for debugger window
  class names ("OllyDbg", "WinDbgFrameClass", "x64dbg", "Qt5QWindowIcon")
- Parent process check: `CreateToolhelp32Snapshot` + `Process32First`/`Next`
  checking parent process name against debugger/shell names
- SeDebugPrivilege: `OpenProcessToken` + `PrivilegeCheck` for debug privilege
- Self-tracing: the process invokes `DebugActiveProcess` on itself (fails if
  already being debugged)

**Bypass strategy (in order of preference):**
1. Patch the decision branch after the check (NOP the conditional jump)
2. Patch the comparison constant (make the threshold impossibly large)
3. Hook the detection API to return non-debugged values
4. Only use runtime bypass (ScyllaHide, TitanHide) when static patching
   is impractical for the number of checks

**Recording findings:**
- For each check: record offset, type, detection method, bypass method, and
  whether the check affects other checks (integrity guard relationship)
- Update `### Analyzed Functions` and `### Verified Evidence` in
  `.chatcli/task.md`
- If a check is a decoy (visible exit vs. silent branch), note which path
  is the real detection and which is noise

### Anti-VM Checks

VM detection is a specialization of environment checks. The binary probes
hardware, registry, filesystem, or process artifacts to detect if it runs
inside a virtual machine.

**Detection categories:**

- Registry keys: VMware (`SOFTWARE\VMware, Inc.\VMware Tools`), VirtualBox
  (`SOFTWARE\Oracle\VirtualBox Guest Additions`, `SYSTEM\...\Services\VBox*`),
  Hyper-V, QEMU, Parallels, Xen
- Process names: `vmtoolsd.exe`, `VMwareTray.exe`, `VBoxService.exe`,
  `VBoxTray.exe`, `vmms.exe`, `vmwp.exe`, `xenservice.exe`, `prl_tools.exe`
- Filesystem artifacts: driver files (`VBoxMouse.sys`, `vmhgfs.sys`,
  `vmmouse.sys`), directories (`C:\Program Files\VMware\`)
- Hardware/CPUID: `cpuid` hypervisor bit (leaf 1, ECX bit 31), hypervisor
  vendor string (leaf 0x40000000 → "VMwareVMware", "VBoxVBoxVBox", "KVMKVMKVM",
  "Microsoft Hv", "XenVMMXenVMM"), SIDT/SGDT/SLDT/STR IDT/GDT base relocation
- MAC address OUI: VMware `00:0C:29`/`00:50:56`/`00:05:69`, VirtualBox
  `08:00:27`, Parallels `00:1C:42`
- WMI queries: `Win32_ComputerSystem.Manufacturer` = "VMware, Inc.",
  `Win32_BIOS.Version` containing "VBOX", etc.
- VMware I/O port: backdoor port `0x5658` ("VX")

**Analysis approach:**
1. `binary_find` for VM-related strings (registry paths, process names, MAC
   prefixes, WMI class names, "VMware", "VirtualBox", "VBOX", "QEMU")
2. IDA xrefs from found strings to detection functions
3. Classify each detection as static (runs once at startup) or runtime
   (periodic or before critical operations)
4. For each check, NOP the conditional branch after the detection
5. If many checks are chained, identify the earliest exit point and patch
   there first — this lets you bypass all downstream checks at once

**Recording:** Document each VM detection location, type, and bypass in
`### Verified Evidence`. Label the detection method and the patch offset.

### Self-Modifying Code Analysis

SMC decrypts or modifies its own instructions at runtime. Static analysis
sees only encrypted bytes.

**Detection:**
- `VirtualProtect` with `PAGE_EXECUTE_READWRITE` targeting `.text` or code
  pages, followed by memory writes and `FlushInstructionCache`
- `.text` section with `IMAGE_SCN_MEM_WRITE` flag (unusual)
- `VirtualAlloc(PAGE_EXECUTE_READWRITE)` → write → indirect call into region

**Analysis:**
1. Break on `VirtualProtect` calls targeting code regions
2. Trace the write/decrypt loop after VirtualProtect returns
3. For XOR-based SMC: extract key buffer, compute plaintext in scratch script
4. For nested SMC (decrypted code contains more decryptors): repeat per layer
5. Dump post-decrypt region and re-run `ida_analyze` on the dump
6. If execution is not allowed: reconstruct decrypt algorithm from static
   analysis of the decrypt stub; extract key material offsets; report the
   algorithm and key source, stop before guessing runtime-derived keys

### Stack String Recovery

When static string scanning is sparse but IDA shows many `push imm`/`mov [esp+N], imm`
instructions near function prologues, strings are built on the stack at runtime.

**Identification:**
- Repeated `push imm32` with ASCII-printable bytes in the immediate values
- `mov BYTE PTR [esp+N], 0x??` / `mov BYTE PTR [rbp-N], 0x??` writing
  character sequences
- Reference to the stack pointer passed to a string API (strcmp, printf, etc.)

**Extraction:**
1. Identify the byte-construction sequence in IDA
2. Extract immediate byte values in order → reconstruct the string
3. For multi-string functions, group pushes/movs by the target buffer address
   (different `esp`/`rbp` offsets = different strings)
4. Use `encoded_string_extract` or FLOSS tight-string mode for automated
   extraction
5. If the characters are XOR'd with a key: extract the key, decode, verify

### API Hash Resolution

When imports are nearly empty but the binary uses `LoadLibrary`/`GetProcAddress`
extensively, APIs are resolved by hashing function names.

**Finding the hash function:**
- Locate `GetProcAddress` call sites in IDA
- Trace backwards to find: the PEB walk (`fs:[0x30]`/`gs:[0x60]` → LDR →
  module list → export directory), the hash loop (processes DLL export names),
  and the target hash constants compared in the loop
- Common hash algorithms: ROR13 (rotate-right 13, shellcode), CRC32 (256-entry
  table, polynomial `0xEDB88320`), FNV-1a (base `0x811C9DC5`, prime
  `0x01000193`), djb2 (init `5381`, `hash*33+c`)

**Resolution:**
1. Reconstruct the hash function in `.chatcli/tmp/scratch.py`
2. Precompute hashes for all exports of the target DLLs (kernel32, ntdll,
   user32, etc.)
3. Match the target hash constants found in the binary to actual API names
4. Record the mapping `hash -> DLL!FunctionName` in `.chatcli/task.md`
5. Use `ida_deobfuscate` with API-role labels to propagate resolved names

### Encoding, Compression, Hashing, or Encryption

Treat these as different cases before trying to "decrypt" anything.

- Encoding clues:
  - Base64/Base32 alphabets, URL encoding, hex strings, UTF-16LE strings.
  - Reversible transforms with no secret key.
- Compression clues:
  - zlib/gzip/deflate magic bytes, LZ-style markers, imports, or large low-entropy
    output after a transform.
- Hashing clues:
  - One-way comparison logic, fixed digest lengths, MD5/SHA constants, bcrypt/argon2
    strings, or imports from crypto libraries.
  - Do not claim a hash can be "decrypted". Audit how it is computed and compared.
- Encryption clues:
  - AES/DES/RC4/ChaCha constants, S-box tables, key schedule code, block sizes,
    IV/nonces, padding checks, crypto imports, or high-entropy blobs.

Workflow:

1. Use `binary_inspect` for imports, strings, entropy, and section clues.
2. Use `obfuscated_data_map` to identify high-entropy regions, suspicious
   sections, embedded or XOR-hidden magic, base64-like blobs, AES/CRC constants,
   and recommended static/dynamic next steps.
3. Use `binary_find` for known constants, alphabets, magic bytes, key strings,
   IV-like byte sequences, and error messages.
4. Use `binary_hexdump` around candidate blobs and constants.
5. Identify where key material comes from:
   - hardcoded constant,
   - user input,
   - file/config/registry,
   - device/IOCTL response,
   - network or server response,
   - derived value such as machine ID, timestamp, or checksum.
6. If the algorithm and key material are fully local and authorized, reconstruct
   the transform in `.chatcli/tmp/scratch.py` and iterate on that same script.
7. If key material is external, unknown, or credentials-related, stop at an audit
   finding and explain what evidence is missing. Do not brute-force real
   passwords, tokens, keys, or credentials.

### IDA Cannot Recover Meaningful Data

When IDA output is mostly invalid code, giant generated functions, sparse strings,
or high-entropy data, do not keep forcing decompilation.

- Reframe the task as data recovery:
  - Map suspicious sections and high-entropy windows with `obfuscated_data_map`.
  - Look for plain or XOR-hidden magic, base64-like runs, crypto constants, and
    data blobs whose xrefs lead to decrypt/decompress routines.
  - Use `function_maps` from `ida_deobfuscate` to connect blobs to candidate
    routines and high-signal basic blocks.
- Choose the next path from evidence:
  - Plain embedded blob -> carve and inspect/decompress separately.
  - XOR-hidden magic -> decode local window/dump and re-run string extraction.
  - Crypto constants or high-entropy blob with xrefs -> identify key source and
    decrypt routine before writing a solver.
  - Runtime-only plaintext -> generate `runtime_string_hooks`, dump memory after
    decrypt, then run `encoded_string_extract` on the dump.
- Keep claims bounded. If the key source is external, missing, or credential-like,
  report the blocker and the exact evidence needed instead of guessing.

Patch-audit notes:

- Prefer patching the local validation decision only when the exact comparison
  and failure path are understood.
- Do not patch random crypto constants to "make it work".
- If an integrity check protects the encrypted blob or patched region, identify
  that integrity check as a separate finding before patching.
- For CTF/crackme samples, bounded local brute force of a toy keyspace is allowed
  only when the challenge design clearly implies it and the input/keyspace is
  local to the sample.

### Crackme Solver Construction

- Reconstruct the validation routine from local evidence before writing a solver.
- Put scratch solvers in `.chatcli/tmp/scratch.py` and iterate there.
- Keep brute force bounded to toy challenge spaces, such as short fixed-length
  flags, local checksums, small integer seeds, or intentionally embedded keys.
- Do not brute-force real passwords, tokens, product keys, online services, or
  credential material.
- Report assumptions, input format, candidate constraints, and verification
  limits. If a transform depends on server data, device identity, or unknown
  secrets, stop at an audit finding instead of guessing.

### Simulated Permission Gates

For local CTF/crackme binaries, permission or authorization bypass usually means
the challenge embeds a simulated check, not a real system target.

- Identify local-only gates such as role comparisons, admin/debug feature flags,
  ACL-like lookup tables, license-like training checks, menu unlock bits, or
  branch paths that hide a challenge flag.
- Explain how the gate is represented in code and data: constants, strings,
  imports, xrefs, comparisons, table indexes, bitmasks, or return values.
- It is allowed to produce a local solver or patched-copy audit when the exact
  gate and failure/success path are understood.
- Do not provide instructions for bypassing real OS permissions, cloud/IAM
  controls, web app authorization, network access controls, product licensing,
  DRM, EDR, sandboxing, or live third-party systems.

### Packed or Obfuscated Binary

- Use entropy, section names, imports, and packer strings from `binary_inspect`.
- If UPX is indicated, use `upx_unpack` and then re-run `binary_inspect`.
- Use `ida_deobfuscate` to identify flattened switch/state-machine dispatchers,
  high-confidence opaque predicates, junk instructions, and API-role function
  labels in stripped PE files. Treat automatic patching as an IDA-database aid,
  not proof of original logic.
- For local Unflatten/OLLVM/Hex-Rays plugins, use `ida_deobfuscate` with
  `plugin_modules` or `plugin_scripts` so built-in branch/junk cleanup, plugin
  deobfuscation, FLIRT signatures, API-role labeling, and pseudocode export run
  in one IDA batch.
- If non-UPX packing is likely, provide a manual static-analysis plan rather
  than claiming the code is understood.

### Large Binary / Giant Function Mapping

Use this when the file has large high-entropy sections, many generated strings,
or IDA creates giant functions that are too slow to fully decompile.

1. Build the coarse map first.
   - `binary_inspect`: format, sections, entropy, imports, strings, packer clues.
   - `encoded_string_extract`: visible strings, decoded base64/hex/XOR, memory dump
     strings if available.
   - Background `ida_analyze`: entry order, candidate functions, imports, strings.
   - `ida_deobfuscate` with `include_pseudocode=false`,
     `max_instructions_per_function=1000..5000`, and bounded `auto_wait_timeout`.

2. Rank data before code.
   - Put functions into roles using string xrefs, import/API groups, entry reachability,
     section/range location, function size, call graph position, and deobfuscation clues.
   - Treat huge generated functions as containers. Do not try full Hex-Rays decompile
     first; use `function_maps` and mapped basic blocks to choose small regions.
   - Prioritize blocks with strings, API calls, many successors, indirect jumps,
     junk jumps, switch/dispatcher shape, or references from entry/candidate paths.

3. Construct the function role map.
   - For each important function record: address, size, basic block count, role
     hypothesis, evidence, mapped blocks, strings/imports, and next region to inspect.
   - Split giant functions into regions by CFG blocks or address ranges. Analyze
     one region at a time and mark only proven conclusions.
   - For flattened/state-machine code, identify dispatcher blocks, state update
     blocks, transition predicates, and payload blocks before attempting to rebuild
     original control flow.

4. Analyze incrementally.
   - Start from high-signal blocks and xrefs, not from the first byte of a giant function.
   - Use hexdumps or IDA snippets around selected blocks to verify exact evidence.
   - Re-run narrower IDA/deobfuscation passes with lower `max_functions` or lower
     per-function instruction caps when the broad map is enough.
   - Escalate to Hex-Rays pseudocode only for small candidate functions or selected
     cleaned functions; avoid full pseudocode export on giant functions.
   - For multiple candidate functions or large function regions, delegate detailed
     function-level work to child windows with `chatcli_auto_request` child tasks.
     Each child should analyze one function/range, write a compact record under
     `.chatcli/children/`, and finish with a summary. The main window should use
     only child summaries and record paths to plan the next step.

Expected output for large samples:

- File and section risk map.
- Function role map with evidence.
- Giant-function block map and selected high-signal regions.
- Current hypotheses, confirmed evidence, and next block/function to inspect.
- Clear statement of what was intentionally deferred because it is generated,
  low-signal, or too large for first-pass analysis.

### Runtime String Extraction

- Prefer static extraction first: `binary_inspect`, then `encoded_string_extract`.
- When strings only exist after a local decrypt routine runs, use
  `runtime_string_hooks` to generate Frida/x64dbg templates for the authorized
  local sample. Prefer the generated Frida collector when bulk export is needed.
- Hook the known decrypt function, module offset, or exported decrypt-like APIs;
  dump return values and output buffer arguments.
- Feed memory dumps or exported plaintext files back into `encoded_string_extract`
  to deduplicate strings and identify decoded base64/hex/XOR artifacts.

### Driver or IOCTL-Oriented Challenge

- Do not load or execute the driver.
- Use `binary_inspect` and IDA when available.
- Identify device names, IOCTL constants, dispatch routines, and user-mode
  caller strings.
- Keep any solver/probe scripts in `.chatcli/tmp/scratch.py` and iterate there.

### Patch Audit Deliverable

When `/patch` or patch audit is requested, end with:

- Target and SHA256
- Findings summary
- Candidate offsets and evidence
- Patch action taken or patch plan
- Patched output path if created
- Verification limits and residual risk
- `TASK COMPLETE` only when the audit or patched-copy generation is complete
