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
