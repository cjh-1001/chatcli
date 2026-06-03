# GitHub-Sourced Reverse Patterns

Use this reference when simple strings/imports/IDA candidate review is not enough.
Keep every technique scoped to authorized local CTF/crackme/owned samples.

## Source Themes

- `ljagiello/ctf-skills` emphasizes a layered CTF reverse workflow: quick wins,
  static tools, dynamic tools, emulation, language/platform-specific handling,
  CTF patterns, and runtime oracle techniques.
- `Hustcw/Angr_Tutorial_For_CTF` demonstrates using angr for CTF path solving,
  especially when a binary has a clear success/failure path but tedious manual
  branch constraints.
- `alphaSeclab/awesome-reverse-engineering` and `awesome-ghidra` are broad
  tool indexes; treat them as tool-selection references, not as proof of a
  solution.
- Public CTF writeup repositories are most useful for recognizing pattern
  families: byte-wise checks, custom VMs, packed loaders, anti-debug gates,
  hash/crypto constants, runtime strings, IOCTL mazes, and language-specific
  bytecode.

## Escalation Ladder

1. **Fast evidence first.**
   - Identify file type, arch, imports, sections, entropy, strings, and obvious
     success/failure text.
   - If a static string or constant exists, locate xrefs and verify offsets
     before solver/patch work.
   - Check PE directories: TLS callbacks (directory index 9), delayed imports
     (directory index 13), and debug directory (index 6) all execute code or
     resolve imports outside the normal IAT path.

2. **Switch from decompilation to constraints when logic is repetitive.**
   - Use a scratch Python solver for byte-wise arithmetic, XOR, table lookups,
     CRC-like transforms, and small fixed-length checks.
   - Use Z3 when conditions are bit-vector/boolean constraints or the input
     length is known but equations are tedious.
   - Use angr when there is a clear `find` success address and `avoid` failure
     address, input is stdin/argv/memory, and the binary is not dominated by
     unsupported syscalls, threads, self-modifying code, or heavy anti-debug.
   - **MBA / instruction substitution:** When pseudocode shows complex arithmetic
     like `(a | b) - (a & b)` where `a ^ b` suffices, or `(x << 3) - x` instead
     of `x * 7`, the code uses Mixed Boolean-Arithmetic obfuscation. Do not
     manually decompile each expression. Flag the function as MBA-obfuscated
     and escalate to symbolic simplification (Triton, Z3, Arybo). Identify seed
     constants in `.data` and treat expressions as constraint systems.

3. **For custom VMs, avoid full reimplementation first.**
   - Identify dispatch loop, bytecode pointer, opcode table, stack/register
     storage, and handler boundaries.
   - Trace or statically log `(pc, opcode, stack/register top)` for two nearby
     inputs, then diff traces to find the real validation transform.
   - Reimplement only the small semantic core once opcode roles are known.
   - **TLS callbacks as VM init:** Some custom VMs initialize their bytecode
     or state machine inside a TLS callback, before the entry point executes.
     If the binary uses a VM and has a `.tls` section, analyze the TLS callback
     for VM setup (bytecode decryption, opcode table construction, initial
     state seeding). Otherwise the VM at the entry point appears to process
     "garbage" bytecode that is actually initialized by the TLS callback.

4. **For runtime-only values, use an oracle only after scope is clear.**
   - Prefer static reconstruction. If the value is decrypted or computed only at
     runtime, generate a local hook/debugger plan.
   - Hook compare/decrypt APIs or candidate functions to capture expected bytes,
     buffers, return values, and key material for the local sample.
   - **Direct syscall / Hell's Gate:** When the binary invokes syscalls directly
     (not through ntdll.dll exports), it bypasses user-mode API hooks entirely.
     Variants include: (a) resolving SSNs from ntdll.dll's export directory by
     parsing Zw* function bytes, (b) "Sorting Hat" — sorting Zw* exports by
     address and deriving SSNs by ordinal index, (c) locating a `syscall; ret`
     gadget in ntdll.dll at runtime for clean call-stack origin. Identify the
     SSN resolution method, cross-reference SSNs with OS-specific syscall tables,
     and label which Nt* function each syscall corresponds to. Recognize that
     `syscall` instructions with no corresponding IAT entries indicate this
     advanced API obfuscation.
   - Never generalize this to live software, credential capture, persistence, or
     stealth. If execution is not explicitly allowed, stop at a plan.

5. **For anti-analysis and packing, classify before fighting tools.**
   - High entropy, strange sections, sparse imports, broken section headers,
     TLS callbacks, sleeps, ptrace/debugger checks, and hash-resolved imports are
     routing signals.
   - UPX can be unpacked when indicated. For custom packers, map loader stages,
     decode loops, magic headers, and decrypted buffers; do not trust first-pass
     pseudocode.
   - **API hashing — detailed PEB walk:** The code walks `PEB->LDR_DATA->
     InMemoryOrderModuleList` (accessed via `fs:[0x30]+0x0C` on x86 or
     `gs:[0x60]+0x18` on x64), locates the target DLL by name hash or by walking
     the list to a known position, parses the DLL's export directory
     (NumberOfNames, AddressOfNames, AddressOfNameOrdinals, AddressOfFunctions),
     hashes each export name, and compares to a target hash. Common hash
     functions: ROR13 (`ror eax, 13`), CRC32 (256-entry table lookup with
     polynomial `0xEDB88320`), FNV-1a (base `0x811C9DC5`, prime `0x01000193`),
     djb2 (init `5381`, `hash*33 + c`). To resolve: reverse the hash function,
     precompute hashes for all exports of the target DLLs, and match the
     constants found in the binary. Use `ida_deobfuscate` with API-role
     labeling to propagate resolved names through the IDA database.
   - **Integrity guard escalation:** When a patch has no effect or the binary
     crashes after patching, an integrity guard is likely recomputing a checksum
     over the modified region. Do not keep patching blindly. Steps:
     1. Identify the guard: search for CRC32/checksum/hash loops that iterate
        over the patched function's address range.
     2. Determine the protected region (start/end addresses).
     3. Determine the comparison: where is the computed checksum compared, and
        what happens on mismatch (exit, crash, corrupt execution).
     4. Handle the guard before the validation logic: either (a) patch the
        checksum comparison to always report "match", (b) recompute the checksum
        after your patches and update the expected constant, or (c) NOP the
        integrity check entirely and verify the rest of the binary still works.
     5. Many packers have nested guards (guard B protects guard A). Solve
        from the outermost guard inward.
   - **IAT encryption:** The binary stores the IAT in encrypted form and
     resolves it at runtime via a custom loader. Signals: near-zero visible
     imports despite substantial functionality, `VirtualProtect` on import
     data regions near entry, or encrypted bytes at the expected IAT location.
     Handling: identify the decrypt+fill loop (often `VirtualProtect` → XOR
     decrypt → `GetProcAddress` loop → write to IAT → re-protect), break after
     the loop completes, and dump the resolved IAT. Reconstruct the import
     table from the dumped addresses.
   - If ELF section headers are corrupted but program headers are intact, parse
     program headers or patch metadata in a copy so tools can load it.

6. **For language and platform formats, use the native route.**
   - .NET: identify CLR/NativeAOT; use decompiler-oriented logic and search for
     managed string/crypto/check routines.
   - Python: identify PyInstaller/pyc; extract archive/bytecode before native
     reversing.
   - Java/Android: use APK/JAR manifest, resources, DEX strings, JADX-style
     decompile, and native library handoff points.
   - WASM: inspect exports/imports, memory offsets, and simple linear-memory
     transforms.
   - Firmware/IoT/ROM: identify architecture, base address, vectors, memory map,
     and custom file/container formats before function analysis.

7. **For IOCTL/driver challenges, pair user-mode and driver evidence.**
   - Enumerate IOCTL constants from the app and driver.
   - In the driver, locate dispatch routine, device creation, symbolic links,
     input/output buffer handling, and state mutation.
   - Build a state machine from reset/get-state/move/query operations. For maze
     or game drivers, solve the state graph statically when possible.
   - Do not load or run drivers unless the user explicitly confirms a local lab
     environment for execution.

## Solver Templates To Prefer

- Byte-wise direct check: extract target bytes/constants, invert transform per
  position, verify with a local scratch script.
- Multi-stage validation: separate input collection, normalization, transform,
  comparison, failure path, and success path.
- Table/state-machine: model state transitions and run BFS/DFS over constrained
  printable input.
- Hash-like local transform: first determine whether it is invertible. If not,
  use bounded brute force only for toy CTF keyspaces.
- Crypto-like routine: identify algorithm, mode, key source, IV/nonce, padding,
  and data source before attempting decryption.

## When To Stop Broad Analysis

- You already have a candidate function with evidence: use focused decompile,
  hexdump, or a child task instead of another broad IDA pass.
- IDA JSON exists: run `reverse_evidence_map` rather than reading raw JSON.
- A function is huge/generated: map basic blocks and delegate one region at a
  time.
- The blocker is execution-only and execution is not allowed: report the static
  evidence and a local-lab plan, not a guessed result.

## Advanced Anti-Debug Escalation

When standard anti-debug bypasses (NOP IsDebuggerPresent, patch PEB) are
insufficient, the binary likely uses layered or exotic detection.

### Multi-Layer Detection Chains

1. **Map all detection points before patching any.** Run `binary_find` for all
   known anti-debug API and constant patterns, then cross-reference with IDA.
2. **Identify detection dependencies.** If check B validates the integrity of
   the code region containing check A's patch, B must be handled first.
3. **Some checks are decoys.** A visible `IsDebuggerPresent` call that exits
   on detection may be a red herring — the real validation skips a different
   branch if the function returns normally. Never assume the first check found
   is the only one.
4. **Thread-based detection.** A background thread periodically checks debugger
   presence (PEB flags, window enumeration, timing). The main thread appears
   clean. Identify `CreateThread` calls and analyze thread routines separately.

### Debugger-Specific Detection

- **OllyDbg:** `FindWindow("OllyDbg")`, `OutputDebugString` exception trick,
  `OpenProcess("OLLYDBG")` to find the OllyDbg process
- **x64dbg:** `FindWindow("Qt5QWindowIcon")` (Qt-based), `FindWindow("x64dbg")`,
  checking for `x64dbg.exe` process
- **WinDbg:** `FindWindow("WinDbgFrameClass")`, checking for `windbg.exe` process,
  `NtQuerySystemInformation(SystemKernelDebuggerInformation)`
- **IDA:** `FindWindow("IDAWDebugger")`, checking for `idaq.exe`/`idaq64.exe` process

### Instruction-Level Detection (Trace / Single-Step Checks)

- **TF flag check:** The code sets the Trap Flag (bit 8 of EFLAGS) via
  `pushfd; or dword [esp], 0x100; popfd` and checks if the flag is still
  set after the next instruction. A debugger single-stepping clears TF.
- **Code checksum with random sampling:** Instead of scanning the entire
  `.text` section, the check randomly samples bytes at deterministic
  offsets and compares to expected values. Harder to find all check sites.
- **INT 1 handler:** Sets up a handler for `EXCEPTION_SINGLE_STEP` that
  modifies execution. If a debugger intercepts INT 1 first, the handler
  never fires, and behavior diverges.

## Direct Syscall / Hell's Gate

An advanced API obfuscation technique that bypasses user-mode hooks by
invoking kernel syscalls directly.

### Variants

1. **Static SSN embedding:** The syscall number (SSN) is hardcoded in the
   binary. Works only on the target OS version/build. Detection: `syscall`
   instruction preceded by `mov eax, <const>` where the constant matches
   known SSNs.
2. **Dynamic SSN resolution from ntdll.dll:** Parses ntdll.dll's export
   directory, locates Zw* functions by name, reads the function bytes to
   extract the SSN (typically at `Zw*+4` as `mov eax, <SSN>`), and stores
   the SSN for direct syscall use. Detection: PEB walk to find ntdll +
   export-table parsing + byte reads from Zw* function starts.
3. **Sorting Hat:** Sorts Zw* export addresses by RVA. Since the Zw* stubs
   in ntdll are laid out sequentially in the binary, sorting by address
   gives the ordinal order. The SSN for the Nth function is N. This avoids
   reading `.text` bytes entirely, evading integrity checks on ntdll.
   Detection: calls to sort/compare export addresses, no byte reading from
   function bodies.
4. **Indirect syscall / Hell's Gate:** Instead of embedding `syscall`
   instructions, the binary scans ntdll.dll for a `syscall; ret` gadget and
   calls it indirectly. This keeps the call stack clean (appears to originate
   from ntdll). Detection: `syscall` instruction in the binary, indirect
   call/jump to ntdll address ranges, scanning for `0F 05 C3` byte pattern.

### Analysis Workflow

1. **Identify that syscalls are in use:** `binary_find` for `syscall` (bytes
   `0F 05`) instructions. If `syscall` exists in user-mode code, direct
   syscalls are being used.
2. **Determine the resolution method:** In IDA, trace the SSN origin. If
   `mov eax, <const>` before `syscall`, it's static embedding — cross-
   reference the constant against OS-specific syscall tables. If there's
   a parsing loop over ntdll exports, it's dynamic resolution.
3. **Cross-reference SSNs to identify the Nt* functions:**
   - Windows 10/11 syscall tables are version-specific. Use a reference
     table (e.g., `j00ru/windows-syscalls` on GitHub)
   - Map `SSN -> Nt*FunctionName` for the target OS version
4. **Label the resolved syscalls:** Update `.chatcli/task.md` with the
   mapping. If IDA is available, label the call sites with the resolved
   Nt* function names.
5. **For indirect syscalls:** The `syscall; ret` gadget is in ntdll.dll.
   The SSN is still set before the indirect call. Trace the SSN and
   cross-reference as above. The indirect call target is the gadget
   address in ntdll, not the original syscall site.

### Limitations (CTF Context)

- Syscall-based code has very few IAT entries, making static triage difficult.
  Always run `reverse_evidence_map` with kernel-API keywords after identifying
  syscalls.
- SSNs change between Windows builds. If the challenge binary targets a
  specific Windows build, use that build's syscall table for cross-referencing.
- Indirect syscalls cannot be statically traced to their Nt* equivalents
  because the gadget address changes per boot (ASLR). Focus on the SSN
  resolution code, not the indirect call target.
