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

2. **Switch from decompilation to constraints when logic is repetitive.**
   - Use a scratch Python solver for byte-wise arithmetic, XOR, table lookups,
     CRC-like transforms, and small fixed-length checks.
   - Use Z3 when conditions are bit-vector/boolean constraints or the input
     length is known but equations are tedious.
   - Use angr when there is a clear `find` success address and `avoid` failure
     address, input is stdin/argv/memory, and the binary is not dominated by
     unsupported syscalls, threads, self-modifying code, or heavy anti-debug.

3. **For custom VMs, avoid full reimplementation first.**
   - Identify dispatch loop, bytecode pointer, opcode table, stack/register
     storage, and handler boundaries.
   - Trace or statically log `(pc, opcode, stack/register top)` for two nearby
     inputs, then diff traces to find the real validation transform.
   - Reimplement only the small semantic core once opcode roles are known.

4. **For runtime-only values, use an oracle only after scope is clear.**
   - Prefer static reconstruction. If the value is decrypted or computed only at
     runtime, generate a local hook/debugger plan.
   - Hook compare/decrypt APIs or candidate functions to capture expected bytes,
     buffers, return values, and key material for the local sample.
   - Never generalize this to live software, credential capture, persistence, or
     stealth. If execution is not explicitly allowed, stop at a plan.

5. **For anti-analysis and packing, classify before fighting tools.**
   - High entropy, strange sections, sparse imports, broken section headers,
     TLS callbacks, sleeps, ptrace/debugger checks, and hash-resolved imports are
     routing signals.
   - UPX can be unpacked when indicated. For custom packers, map loader stages,
     decode loops, magic headers, and decrypted buffers; do not trust first-pass
     pseudocode.
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
