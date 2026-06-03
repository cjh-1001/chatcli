"""Binary format parsers and static triage helpers."""

import math
import re
import struct


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def _cstring(data: bytes, off: int, max_len: int = 512) -> str:
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off, min(len(data), off + max_len))
    if end < 0:
        end = min(len(data), off + max_len)
    return data[off:end].decode("utf-8", errors="replace")


def _hex(n: int) -> str:
    return f"0x{n:x}"


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def _slice_entropy(data: bytes, off: int, size: int) -> float | None:
    if off < 0 or size <= 0 or off >= len(data):
        return None
    return _entropy(data[off:min(len(data), off + size)])


def _machine_name(machine: int) -> str:
    return {
        0x014C: "x86",
        0x0200: "Intel Itanium",
        0x8664: "x64",
        0x01C0: "ARM",
        0x01C4: "ARMv7",
        0xAA64: "ARM64",
    }.get(machine, f"unknown ({_hex(machine)})")


def _subsystem_name(subsystem: int) -> str:
    return {
        1: "native",
        2: "windows_gui",
        3: "windows_cui",
        5: "os2_cui",
        7: "posix_cui",
        9: "windows_ce_gui",
        10: "efi_application",
        11: "efi_boot_service_driver",
        12: "efi_runtime_driver",
        14: "xbox",
        16: "windows_boot_application",
    }.get(subsystem, f"unknown ({subsystem})")


def _elf_machine_name(machine: int) -> str:
    return {
        2: "SPARC",
        3: "x86",
        8: "MIPS",
        20: "PowerPC",
        21: "PowerPC64",
        40: "ARM",
        62: "x86-64",
        183: "AArch64",
        243: "RISC-V",
    }.get(machine, f"unknown ({machine})")


def _elf_type_name(file_type: int) -> str:
    return {
        0: "none",
        1: "relocatable",
        2: "executable",
        3: "shared_object",
        4: "core",
    }.get(file_type, f"unknown ({file_type})")


def _elf_section_type(section_type: int) -> str:
    return {
        0: "NULL",
        1: "PROGBITS",
        2: "SYMTAB",
        3: "STRTAB",
        4: "RELA",
        8: "NOBITS",
        9: "REL",
        11: "DYNSYM",
        14: "INIT_ARRAY",
        15: "FINI_ARRAY",
        0x6FFFFFF6: "GNU_HASH",
        0x6FFFFFFF: "VERSYM",
    }.get(section_type, _hex(section_type))


def _unpack(fmt: str, data: bytes, off: int):
    size = struct.calcsize(fmt)
    if off < 0 or off + size > len(data):
        return None
    return struct.unpack_from(fmt, data, off)


def _read_elf(data: bytes) -> dict:
    if len(data) < 0x34 or data[:4] != b"\x7fELF":
        return {}

    elf_class = data[4]
    endian_id = data[5]
    if elf_class not in (1, 2) or endian_id not in (1, 2):
        return {"format": "ELF", "elf_error": "Unsupported ELF class or byte order."}

    is_64 = elf_class == 2
    endian = "<" if endian_id == 1 else ">"
    header = _unpack(endian + ("HHIQQQIHHHHHH" if is_64 else "HHIIIIIHHHHHH"), data, 16)
    if not header:
        return {"format": "ELF", "elf_error": "Truncated ELF header."}

    file_type, machine = header[0], header[1]
    entry = header[3]
    shoff = header[5] if is_64 else header[5]
    shentsize = header[10]
    shnum = header[11]
    shstrndx = header[12]

    sections = []
    raw_sections = []
    if shoff and shentsize:
        section_fmt = endian + ("IIQQQQIIQQ" if is_64 else "IIIIIIIIII")
        section_size = struct.calcsize(section_fmt)
        for i in range(min(shnum, 4096)):
            off = shoff + i * shentsize
            values = _unpack(section_fmt, data, off)
            if not values:
                break
            if shentsize < section_size:
                break
            if is_64:
                name_off, stype, flags, addr, file_off, size = values[:6]
            else:
                name_off, stype, flags, addr, file_off, size = values[:6]
            raw_sections.append({
                "name_off": name_off,
                "type": stype,
                "flags": flags,
                "address": addr,
                "offset": file_off,
                "size": size,
            })

    shstr = b""
    if 0 <= shstrndx < len(raw_sections):
        sec = raw_sections[shstrndx]
        start = sec["offset"]
        end = start + sec["size"]
        if 0 <= start < len(data) and start <= end <= len(data):
            shstr = data[start:end]

    for sec in raw_sections[:256]:
        name = ""
        name_off = sec["name_off"]
        if shstr and 0 <= name_off < len(shstr):
            end = shstr.find(b"\x00", name_off)
            if end < 0:
                end = len(shstr)
            name = shstr[name_off:end].decode("utf-8", errors="replace")
        sec = dict(sec)
        sec.pop("name_off", None)
        sec["name"] = name
        sec["type_name"] = _elf_section_type(sec["type"])
        sec["entropy"] = _slice_entropy(data, sec["offset"], sec["size"])
        sections.append(sec)

    return {
        "format": "ELF64" if is_64 else "ELF32",
        "endianness": "little" if endian_id == 1 else "big",
        "type": _elf_type_name(file_type),
        "machine": _elf_machine_name(machine),
        "entry": entry,
        "sections": sections,
    }


def _macho_cpu_name(cpu_type: int) -> str:
    masked = cpu_type & 0x00FFFFFF
    return {
        7: "x86",
        12: "ARM",
        18: "PowerPC",
    }.get(masked, f"unknown ({cpu_type})") + ("-64" if cpu_type & 0x01000000 else "")


def _macho_filetype_name(filetype: int) -> str:
    return {
        1: "object",
        2: "executable",
        3: "fixed_vm_shared_library",
        4: "core",
        5: "preloaded_executable",
        6: "dynamic_library",
        8: "bundle",
        10: "dynamic_linker",
        11: "dSYM",
    }.get(filetype, f"unknown ({filetype})")


def _read_macho(data: bytes) -> dict:
    if len(data) < 28:
        return {}
    magic = data[:4]
    if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        return {"format": "Mach-O universal/fat"}
    if magic not in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return {}

    is_64 = magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
    endian = "<" if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") else ">"
    header_fmt = endian + ("IiiIIIII" if is_64 else "IiiIIII")
    header = _unpack(header_fmt, data, 0)
    if not header:
        return {"format": "Mach-O", "macho_error": "Truncated Mach-O header."}

    _, cpu_type, _, filetype, ncmds, sizeofcmds, flags, *rest = header
    off = 32 if is_64 else 28
    end = min(len(data), off + sizeofcmds)
    segments = []
    entryoff = None
    for _ in range(min(ncmds, 2048)):
        command = _unpack(endian + "II", data, off)
        if not command:
            break
        cmd, cmdsize = command
        if cmdsize < 8 or off + cmdsize > end:
            break
        if cmd == 0x80000028 and cmdsize >= 24:
            values = _unpack(endian + "IIQQ", data, off)
            if values:
                entryoff = values[2]
        elif cmd == (0x19 if is_64 else 0x1):
            seg_fmt = endian + ("II16sQQQQiiII" if is_64 else "II16sIIIIiiII")
            values = _unpack(seg_fmt, data, off)
            if values:
                _, _, raw_name, vmaddr, vmsize, fileoff, filesize, *_ = values
                name = raw_name.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                segments.append({
                    "name": name,
                    "vmaddr": vmaddr,
                    "vmsize": vmsize,
                    "fileoff": fileoff,
                    "filesize": filesize,
                    "entropy": _slice_entropy(data, fileoff, filesize),
                })
        off += cmdsize

    return {
        "format": "Mach-O 64-bit" if is_64 else "Mach-O 32-bit",
        "endianness": "little" if endian == "<" else "big",
        "type": _macho_filetype_name(filetype),
        "machine": _macho_cpu_name(cpu_type),
        "entry_file_offset": entryoff,
        "flags": flags,
        "segments": segments,
    }


def _read_pe(data: bytes) -> dict:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {}
    pe_off = _u32(data, 0x3C)
    if pe_off + 0x18 >= len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return {"format": "MZ executable", "pe_error": "Missing PE signature."}

    coff = pe_off + 4
    machine = _u16(data, coff)
    section_count = _u16(data, coff + 2)
    timestamp = _u32(data, coff + 4)
    opt_size = _u16(data, coff + 16)
    characteristics = _u16(data, coff + 18)
    opt = pe_off + 24
    magic = _u16(data, opt)
    is_pe64 = magic == 0x20B
    if magic not in (0x10B, 0x20B):
        return {"format": "PE", "pe_error": f"Unknown optional header magic {_hex(magic)}."}

    entry_rva = _u32(data, opt + 16)
    if is_pe64:
        image_base = _u64(data, opt + 24)
        subsystem = _u16(data, opt + 88)
        data_dir = opt + 112
    else:
        image_base = _u32(data, opt + 28)
        subsystem = _u16(data, opt + 68)
        data_dir = opt + 96

    sections = []
    sec_off = opt + opt_size
    for i in range(section_count):
        off = sec_off + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        virtual_size = _u32(data, off + 8)
        virtual_address = _u32(data, off + 12)
        raw_size = _u32(data, off + 16)
        raw_ptr = _u32(data, off + 20)
        sections.append({
            "name": name,
            "virtual_address": virtual_address,
            "virtual_size": virtual_size,
            "raw_size": raw_size,
            "raw_ptr": raw_ptr,
            "entropy": _slice_entropy(data, raw_ptr, raw_size),
        })

    def rva_to_offset(rva: int) -> int | None:
        for s in sections:
            start = s["virtual_address"]
            size = max(s["virtual_size"], s["raw_size"])
            if start <= rva < start + size:
                off = s["raw_ptr"] + (rva - start)
                if 0 <= off < len(data):
                    return off
        return rva if 0 <= rva < len(data) else None

    imports = []
    if data_dir + 16 <= len(data):
        import_rva = _u32(data, data_dir + 8)
        import_off = rva_to_offset(import_rva) if import_rva else None
        if import_off is not None:
            desc = import_off
            for _ in range(512):
                if desc + 20 > len(data):
                    break
                oft = _u32(data, desc)
                name_rva = _u32(data, desc + 12)
                ft = _u32(data, desc + 16)
                if not any(data[desc:desc + 20]):
                    break
                dll_off = rva_to_offset(name_rva)
                dll = _cstring(data, dll_off) if dll_off is not None else f"rva:{_hex(name_rva)}"
                thunk = rva_to_offset(oft or ft)
                funcs = []
                if thunk is not None:
                    step = 8 if is_pe64 else 4
                    ordinal_flag = 0x8000000000000000 if is_pe64 else 0x80000000
                    for n in range(2048):
                        ent_off = thunk + n * step
                        if ent_off + step > len(data):
                            break
                        value = _u64(data, ent_off) if is_pe64 else _u32(data, ent_off)
                        if value == 0:
                            break
                        if value & ordinal_flag:
                            funcs.append(f"#{value & 0xffff}")
                            continue
                        name_off = rva_to_offset(value)
                        funcs.append(_cstring(data, name_off + 2) if name_off is not None else _hex(value))
                imports.append({"dll": dll, "functions": funcs})
                desc += 20

    return {
        "format": "PE32+" if is_pe64 else "PE32",
        "machine": _machine_name(machine),
        "timestamp": timestamp,
        "characteristics": characteristics,
        "image_base": image_base,
        "entry_rva": entry_rva,
        "entry_va": image_base + entry_rva,
        "subsystem": _subsystem_name(subsystem),
        "sections": sections,
        "imports": imports,
    }


def _packer_clues(data: bytes, pe: dict, elf: dict, macho: dict) -> list[str]:
    clues = []
    lowered = data[: min(len(data), 4 * 1024 * 1024)].lower()
    signatures = [
        (b"upx!", "UPX signature"),
        (b"upx0", "UPX section/string"),
        (b"upx1", "UPX section/string"),
        (b"aspack", "ASPack string"),
        (b"themida", "Themida string"),
        (b"vmprotect", "VMProtect string"),
        (b"mpress", "MPRESS string"),
        (b"petite", "Petite packer string"),
    ]
    for needle, label in signatures:
        if needle in lowered:
            clues.append(label)

    sections = []
    if pe:
        sections.extend(pe.get("sections", []))
    if elf:
        sections.extend(elf.get("sections", []))
    if macho:
        sections.extend(macho.get("segments", []))

    for section in sections:
        name = (section.get("name") or "").lower()
        ent = section.get("entropy")
        if name in {"upx0", "upx1", "upx2"}:
            clues.append(f"UPX-like section name: {section.get('name')}")
        if ent is not None and ent >= 7.2:
            clues.append(f"High entropy region {section.get('name') or '(unnamed)'}: {ent:.2f}")

    if _entropy(data) >= 7.4:
        clues.append("High whole-file entropy")

    deduped = []
    seen = set()
    for clue in clues:
        if clue not in seen:
            seen.add(clue)
            deduped.append(clue)
    return deduped


def _extract_strings(data: bytes, min_len: int, max_strings: int) -> list[str]:
    strings = []
    seen = set()
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    wide_re = re.compile((rb"(?:[\x20-\x7e]\x00){%d,}") % min_len)
    for match in ascii_re.finditer(data):
        text = match.group(0).decode("utf-8", errors="replace")
        if text not in seen:
            seen.add(text)
            strings.append(text)
        if len(strings) >= max_strings:
            return strings
    for match in wide_re.finditer(data):
        text = match.group(0).decode("utf-16le", errors="replace")
        if text not in seen:
            seen.add(text)
            strings.append(text)
        if len(strings) >= max_strings:
            return strings
    return strings

