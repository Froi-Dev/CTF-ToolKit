from __future__ import annotations

import hashlib
import math
import re
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.core.analyzers import BaseAnalyzer
from app.core.errors import ToolExecutionError
from app.core.flag_detection import FlagDetector
from app.core.tool_runner import ToolRunner
from app.schemas.reversing import ReverseAnalysisResponse


_NATIVE_FORMATS = {"ELF", "PE", "Mach-O"}
_EXECUTABLE_EXTENSIONS = {
    "ELF": {"", ".elf", ".so", ".bin", ".out"},
    "PE": {".exe", ".dll", ".sys", ".scr", ".bin"},
    "Mach-O": {"", ".dylib", ".bundle", ".bin"},
    "Java class": {".class"}, "DEX": {".dex"}, "WebAssembly": {".wasm"},
    "Python bytecode": {".pyc"}, "APK/JAR/ZIP": {".apk", ".jar", ".zip"},
}
_IMPORT_ROLES = {
    "strcmp": ("comparison", "high", "Direct string comparison is a strong validation lead."),
    "strncmp": ("comparison", "high", "Bounded string comparison is a strong validation lead."),
    "memcmp": ("comparison", "high", "Byte-array comparison may validate transformed input."),
    "fgets": ("input", "medium", "Reads user-controlled text."),
    "scanf": ("input", "medium", "Parses user-controlled input."),
    "read": ("input", "medium", "Reads data that may feed validation."),
    "gets": ("input", "high", "Reads unbounded input and is security-relevant."),
    "fopen": ("file", "medium", "May open a flag, key, or configuration file."),
    "ptrace": ("anti-analysis", "high", "Common anti-debugging primitive; call-site confirmation is required."),
    "isdebuggerpresent": ("anti-analysis", "high", "Windows debugger-detection API."),
    "system": ("process", "medium", "Executes a command when reached by the program."),
    "execve": ("process", "medium", "Executes another program when reached."),
}
_STRING_RULES = (
    ("flag-like", re.compile(r"(?:picoCTF|CTF|HTB|THM|flag)\{", re.I), "critical", "Contains a flag-format prefix."),
    ("success message", re.compile(r"correct|success|access granted|congrat", re.I), "high", "May identify the success branch."),
    ("failure message", re.compile(r"wrong|invalid|failure|try again|denied", re.I), "high", "May identify the failure branch."),
    ("input prompt", re.compile(r"password|enter (?:key|flag|input)|username", re.I), "high", "May lead to input-validation code."),
    ("flag file", re.compile(r"(?:^|[/\\])(?:flag|secret|key)(?:\.txt)?$|flag\.txt", re.I), "high", "References a likely flag or secret file."),
    ("crypto constant", re.compile(r"aes|rsa|sha-?256|md5|base64|decrypt|encrypt", re.I), "medium", "Suggests a transformation or cryptographic routine."),
    ("url", re.compile(r"https?://", re.I), "medium", "Embedded URL may be relevant program data."),
    ("debug", re.compile(r"debug|trace|assert", re.I), "low", "Debug text may preserve useful function or path clues."),
)


@dataclass(frozen=True, slots=True)
class ReversePolicy:
    max_upload_bytes: int = 64 * 1024 * 1024
    max_strings: int = 500
    max_disassembly_lines: int = 400
    minimum_string_length: int = 4


@dataclass(frozen=True, slots=True)
class ReverseInput:
    path: Path
    original_filename: str
    artifact_id: str
    custom_flag_prefix: str | None = None


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    return round(-sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values()), 4)


def _cstring(data: bytes, offset: int, limit: int = 512) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\0", offset, min(len(data), offset + limit))
    if end < 0:
        end = min(len(data), offset + limit)
    return data[offset:end].decode("utf-8", errors="replace")


def _extract_strings(data: bytes, minimum: int) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % minimum)
    for match in ascii_pattern.finditer(data):
        values.append({"offset": match.start(), "value": match.group().decode("ascii"), "encoding": "ascii"})
    for endian, pattern, codec in (
        ("utf-16le", re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum), "utf-16le"),
        ("utf-16be", re.compile(rb"(?:\x00[\x20-\x7e]){%d,}" % minimum), "utf-16be"),
    ):
        for match in pattern.finditer(data):
            values.append({"offset": match.start(), "value": match.group().decode(codec), "encoding": endian})
    return values


def _classify_string(item: dict[str, Any]) -> dict[str, Any]:
    for category, pattern, importance, reason in _STRING_RULES:
        if pattern.search(item["value"]):
            return {**item, "category": category, "importance": importance, "reason": reason}
    return {**item, "category": "notable text", "importance": "info", "reason": "Printable program data retained for investigation."}


def _importance_order(item: dict[str, Any]) -> tuple[int, int]:
    return ({"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[item["importance"]], item["offset"])


def _detect_flags(
    data: bytes,
    strings: list[dict[str, Any]],
    prefixes: list[str],
    source: str,
) -> list[dict[str, Any]]:
    flags = [
        {
            "value": flag.value,
            "matched_pattern": flag.matched_pattern,
            "source": source,
            "offset": flag.offset,
            "confidence": flag.confidence,
            "context": flag.context,
            "state": "candidate",
        }
        for flag in FlagDetector(prefixes).detect(data)
    ]
    pattern = re.compile(r"(?P<prefix>" + "|".join(re.escape(prefix) for prefix in prefixes) + r")\{[^{}\r\n]{1,256}\}")
    seen = {(item["value"], item["offset"]) for item in flags}
    for item in strings:
        if item["encoding"] not in {"utf-16le", "utf-16be"}:
            continue
        for match in pattern.finditer(item["value"]):
            offset = item["offset"] + match.start() * 2
            key = (match.group(0), offset)
            if key in seen:
                continue
            seen.add(key)
            flags.append({
                "value": match.group(0),
                "matched_pattern": f"{match.group('prefix')}{{...}}",
                "source": source,
                "offset": offset,
                "confidence": 0.93,
                "context": item["value"],
                "state": "candidate",
            })
    return sorted(flags, key=lambda item: item["offset"])


def _identify(data: bytes, filename: str) -> dict[str, Any]:
    suffix = Path(filename).suffix.lower()
    info: dict[str, Any] = {
        "detected_type": "Unknown binary/data", "format": "Unknown", "architecture": None,
        "bits": None, "endian": None, "operating_system": None, "compiler": None,
        "entry_point": None, "stripped": None, "packed": None,
    }
    if data.startswith(b"\x7fELF"):
        info.update(detected_type="ELF executable", format="ELF")
    elif data[:2] == b"MZ":
        info.update(detected_type="Portable Executable", format="PE", operating_system="Windows")
    elif data[:4] in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}:
        info.update(detected_type="Mach-O executable", format="Mach-O", operating_system="macOS/iOS")
    elif data.startswith(b"\xca\xfe\xba\xbe"):
        info.update(detected_type="Java class", format="Java class", operating_system="JVM", bits=32, endian="big")
    elif data.startswith(b"dex\n"):
        info.update(detected_type="Android DEX bytecode", format="DEX", operating_system="Android", endian="little")
    elif data.startswith(b"\x00asm"):
        info.update(detected_type="WebAssembly module", format="WebAssembly", operating_system="WebAssembly", bits=32, endian="little")
    elif data.startswith(b"PK\x03\x04"):
        info.update(detected_type="ZIP-based application/archive", format="APK/JAR/ZIP")
    elif suffix == ".pyc" or (len(data) > 4 and data[2:4] == b"\r\n"):
        info.update(detected_type="Python bytecode", format="Python bytecode", operating_system="Python")
    elif data.startswith(b"#!") or suffix in {".py", ".js", ".ps1", ".sh", ".php", ".rb", ".lua"}:
        language = {".py": "Python", ".js": "JavaScript", ".ps1": "PowerShell", ".sh": "Shell", ".php": "PHP", ".rb": "Ruby", ".lua": "Lua"}.get(suffix, "Script")
        info.update(detected_type=f"{language} script", format="Script", operating_system="Interpreted", compiler=language)
    expected = _EXECUTABLE_EXTENSIONS.get(info["format"])
    matches = expected is None or suffix in expected
    info["extension_matches"] = matches
    info["extension_reason"] = (
        "The filename extension is consistent with the detected format."
        if matches else f"The .{suffix.lstrip('.')} extension does not match detected {info['format']} content."
    )
    return info


def _parse_elf(data: bytes, info: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str], list[str], list[dict[str, Any]]]:
    if len(data) < 52 or data[4] not in (1, 2) or data[5] not in (1, 2):
        raise ValueError("The ELF header is truncated or unsupported.")
    bits = 64 if data[4] == 2 else 32
    endian = "little" if data[5] == 1 else "big"
    prefix = "<" if endian == "little" else ">"
    header_fmt = prefix + ("HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH")
    header = struct.unpack_from(header_fmt, data, 16)
    e_type, machine, entry, phoff, shoff = header[0], header[1], header[3], header[4], header[5]
    phentsize, phnum, shentsize, shnum, shstrndx = header[8], header[9], header[10], header[11], header[12]
    architectures = {3: "x86", 8: "MIPS", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}
    info.update(bits=bits, endian=endian, architecture=architectures.get(machine, f"machine-{machine}"), operating_system="Linux/Unix", entry_point=entry)
    section_fmt = prefix + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII")
    expected_sh_size = struct.calcsize(section_fmt)
    raw_sections: list[tuple[int, ...]] = []
    if shoff and shentsize >= expected_sh_size and shnum <= 8192 and shoff + shentsize * shnum <= len(data):
        raw_sections = [struct.unpack_from(section_fmt, data, shoff + index * shentsize) for index in range(shnum)]
    string_table = b""
    if raw_sections and shstrndx < len(raw_sections):
        string_header = raw_sections[shstrndx]
        start, size = string_header[4], string_header[5]
        if start + size <= len(data):
            string_table = data[start:start + size]
    sections: list[dict[str, Any]] = []
    names: list[str] = []
    for raw in raw_sections:
        name = _cstring(string_table, raw[0]) if string_table else ""
        names.append(name or f"section_{len(names)}")
        flags, address, offset, size = raw[2], raw[3], raw[4], raw[5]
        chunk = data[offset:offset + size] if offset <= len(data) else b""
        perms = "r" + ("w" if flags & 1 else "-") + ("x" if flags & 4 else "-")
        entropy = _entropy(chunk)
        suspicious = entropy >= 7.5 or name.lower().startswith(("upx", ".pack", ".protect"))
        reason = "Very high section entropy may indicate packing, compression, or encrypted data." if entropy >= 7.5 else ("Section name is associated with packed content." if suspicious else None)
        sections.append({"name": names[-1], "virtual_address": address, "file_offset": offset, "size": size, "permissions": perms, "entropy": entropy, "suspicious": suspicious, "reason": reason})
    imports: list[str] = []
    exports: list[str] = []
    for index, raw in enumerate(raw_sections):
        section_type, offset, size, link, entsize = raw[1], raw[4], raw[5], raw[6], raw[9]
        if section_type not in (2, 11) or not entsize or link >= len(raw_sections) or offset + size > len(data):
            continue
        str_header = raw_sections[link]
        strings = data[str_header[4]:str_header[4] + str_header[5]]
        symbol_fmt = prefix + ("IBBHQQ" if bits == 64 else "IIIBBH")
        symbol_size = struct.calcsize(symbol_fmt)
        for position in range(offset, offset + size, entsize):
            if position + symbol_size > len(data):
                break
            symbol = struct.unpack_from(symbol_fmt, data, position)
            if bits == 64:
                name_offset, symbol_info, _, section_index, value, _ = symbol
            else:
                name_offset, value, _, symbol_info, _, section_index = symbol
            name = _cstring(strings, name_offset)
            if not name:
                continue
            if section_index == 0 and section_type == 11:
                imports.append(name.split("@", 1)[0])
            elif section_index != 0 and (symbol_info & 0x0F) == 2:
                exports.append(name)
    program_fmt = prefix + ("IIQQQQQQ" if bits == 64 else "IIIIIIII")
    program_size = struct.calcsize(program_fmt)
    nx: bool | None = None
    relro = False
    if phoff and phentsize >= program_size and phnum <= 8192 and phoff + phentsize * phnum <= len(data):
        for index in range(phnum):
            program = struct.unpack_from(program_fmt, data, phoff + index * phentsize)
            p_type = program[0]
            flags = program[1] if bits == 64 else program[6]
            if p_type == 0x6474E551:
                nx = not bool(flags & 1)
            elif p_type == 0x6474E552:
                relro = True
    info["stripped"] = ".symtab" not in names
    info["packed"] = any(section["suspicious"] and section["name"].lower().startswith(("upx", ".pack", ".protect")) for section in sections)
    protections = [
        _protection("NX", nx, "A non-executable stack hinders injected-code execution.", "PT_GNU_STACK program header" if nx is not None else "PT_GNU_STACK was not found."),
        _protection("PIE", e_type == 3, "PIE allows the executable image to be randomized.", f"ELF type is {e_type}."),
        _protection("Canary", any(name == "__stack_chk_fail" for name in imports), "Stack canaries detect some stack corruption.", "__stack_chk_fail import lookup"),
        {"name": "RELRO", "status": "partial" if relro else "disabled", "value": "Partial" if relro else "Not detected", "significance": "RELRO makes relocation data harder to overwrite; full status needs dynamic-tag confirmation.", "evidence": "PT_GNU_RELRO program header" if relro else "PT_GNU_RELRO was not found."},
    ]
    return sections, sorted(set(imports)), sorted(set(exports)), protections


def _protection(name: str, enabled: bool | None, significance: str, evidence: str) -> dict[str, Any]:
    return {"name": name, "status": "unknown" if enabled is None else ("enabled" if enabled else "disabled"), "value": "Unknown" if enabled is None else ("Enabled" if enabled else "Disabled"), "significance": significance, "evidence": evidence}


def _parse_pe(data: bytes, info: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str], list[str], list[dict[str, Any]]]:
    if len(data) < 0x40:
        raise ValueError("The DOS header is truncated.")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("The PE signature is missing or truncated.")
    machine, count, _, symbol_pointer, symbol_count, optional_size, _ = struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
    optional = pe_offset + 24
    if optional + optional_size > len(data) or optional_size < 72:
        raise ValueError("The PE optional header is truncated.")
    magic = struct.unpack_from("<H", data, optional)[0]
    bits = 64 if magic == 0x20B else 32 if magic == 0x10B else None
    if bits is None:
        raise ValueError("The PE optional-header format is unsupported.")
    architectures = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "ARM", 0xAA64: "AArch64", 0x5064: "RISC-V 64"}
    entry_rva = struct.unpack_from("<I", data, optional + 16)[0]
    image_base = struct.unpack_from("<Q" if bits == 64 else "<I", data, optional + (24 if bits == 64 else 28))[0]
    dll_characteristics = struct.unpack_from("<H", data, optional + 70)[0]
    info.update(bits=bits, endian="little", architecture=architectures.get(machine, f"machine-0x{machine:x}"), entry_point=image_base + entry_rva, stripped=not bool(symbol_pointer and symbol_count))
    section_start = optional + optional_size
    sections: list[dict[str, Any]] = []
    section_map: list[tuple[int, int, int, int]] = []
    names: list[str] = []
    for index in range(min(count, 1024)):
        offset = section_start + index * 40
        if offset + 40 > len(data):
            break
        name = data[offset:offset + 8].split(b"\0", 1)[0].decode("ascii", errors="replace") or f"section_{index}"
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, offset + 8)
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        chunk = data[raw_offset:raw_offset + raw_size] if raw_offset <= len(data) else b""
        perms = ("r" if characteristics & 0x40000000 else "-") + ("w" if characteristics & 0x80000000 else "-") + ("x" if characteristics & 0x20000000 else "-")
        entropy = _entropy(chunk)
        suspicious = entropy >= 7.5 or name.upper().startswith("UPX")
        reason = "Very high section entropy may indicate packing, compression, or encrypted data." if entropy >= 7.5 else ("UPX section name detected." if suspicious else None)
        sections.append({"name": name, "virtual_address": image_base + virtual_address, "file_offset": raw_offset, "size": raw_size or virtual_size, "permissions": perms, "entropy": entropy, "suspicious": suspicious, "reason": reason})
        section_map.append((virtual_address, max(virtual_size, raw_size), raw_offset, raw_size))
        names.append(name)
    info["packed"] = any(name.upper().startswith("UPX") for name in names)

    def rva_to_offset(rva: int) -> int | None:
        for virtual_address, size, raw_offset, raw_size in section_map:
            if virtual_address <= rva < virtual_address + size:
                delta = rva - virtual_address
                return raw_offset + delta if delta < raw_size else None
        return rva if rva < len(data) else None

    imports: list[str] = []
    data_directory = optional + (112 if bits == 64 else 96)
    if data_directory + 16 <= optional + optional_size:
        import_rva = struct.unpack_from("<I", data, data_directory + 8)[0]
        descriptor = rva_to_offset(import_rva) if import_rva else None
        for _ in range(512):
            if descriptor is None or descriptor + 20 > len(data):
                break
            original_thunk, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", data, descriptor)
            if not any((original_thunk, name_rva, first_thunk)):
                break
            library_offset = rva_to_offset(name_rva)
            library = _cstring(data, library_offset) if library_offset is not None else ""
            thunk_offset = rva_to_offset(original_thunk or first_thunk)
            width, ordinal_mask = (8, 1 << 63) if bits == 64 else (4, 1 << 31)
            if thunk_offset is not None:
                for thunk_index in range(4096):
                    position = thunk_offset + thunk_index * width
                    if position + width > len(data):
                        break
                    value = int.from_bytes(data[position:position + width], "little")
                    if value == 0:
                        break
                    if value & ordinal_mask:
                        imports.append(f"{library}!ordinal_{value & 0xffff}")
                    else:
                        name_offset = rva_to_offset(value)
                        name = _cstring(data, name_offset + 2) if name_offset is not None else ""
                        if name:
                            imports.append(f"{library}!{name}")
            descriptor += 20
    protections = [
        _protection("ASLR", bool(dll_characteristics & 0x40), "ASLR randomizes image placement when supported.", "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"),
        _protection("DEP/NX", bool(dll_characteristics & 0x100), "DEP marks data pages non-executable.", "IMAGE_DLLCHARACTERISTICS_NX_COMPAT"),
        _protection("CFG", bool(dll_characteristics & 0x4000), "Control Flow Guard restricts indirect-call targets.", "IMAGE_DLLCHARACTERISTICS_GUARD_CF"),
    ]
    return sections, sorted(set(imports)), [], protections


def _parse_objdump(output: bytes, limit: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    lines: list[dict[str, Any]] = []
    functions: list[dict[str, Any]] = []
    current: str | None = None
    function_pattern = re.compile(r"^\s*([0-9a-fA-F]+)\s+<([^>]+)>:$")
    instruction_pattern = re.compile(r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)\s*(.+)$")
    for raw in output.decode("utf-8", errors="replace").splitlines():
        function_match = function_pattern.match(raw)
        if function_match:
            current = function_match.group(2)
            functions.append({"name": current, "address": int(function_match.group(1), 16), "likely_role": _function_role(current), "evidence": ["Function label reported by objdump."], "confidence": 0.9 if current in {"main", "WinMain"} else 0.65})
            continue
        instruction_match = instruction_pattern.match(raw)
        if instruction_match and len(lines) < limit:
            lines.append({"address": int(instruction_match.group(1), 16), "bytes": " ".join(instruction_match.group(2).split()), "instruction": instruction_match.group(3).strip(), "function": current})
    return lines, functions


def _function_role(name: str) -> str:
    lowered = name.lower()
    if lowered in {"main", "winmain", "_start"}: return "program entry or main routine"
    if any(word in lowered for word in ("check", "valid", "verify", "compare")): return "possible input validator"
    if any(word in lowered for word in ("decrypt", "decode", "transform", "xor")): return "possible data transformation"
    if "flag" in lowered or "secret" in lowered: return "possible flag/secret handling"
    return "unclassified function"


class StaticReverseAnalyzer(BaseAnalyzer[ReverseInput, ReverseAnalysisResponse]):
    name = "reverse_static"
    category = "reversing"

    def __init__(self, policy: ReversePolicy | None = None, tool_runner: ToolRunner | None = None) -> None:
        self.policy = policy or ReversePolicy()
        self._tools = tool_runner or ToolRunner({"objdump"}, default_timeout_seconds=20, default_output_limit=8 * 1024 * 1024)

    def supports(self, value: object) -> bool:
        return isinstance(value, ReverseInput) and value.path.is_file()

    def analyze(self, value: ReverseInput) -> ReverseAnalysisResponse:
        data = value.path.read_bytes()
        info = _identify(data, value.original_filename)
        sections: list[dict[str, Any]] = []
        import_names: list[str] = []
        exports: list[str] = []
        protections: list[dict[str, Any]] = []
        warnings: list[str] = []
        if info["format"] == "ELF":
            sections, import_names, exports, protections = _parse_elf(data, info)
        elif info["format"] == "PE":
            sections, import_names, exports, protections = _parse_pe(data, info)
        else:
            warnings.append("Detailed section and protection parsing is not yet available for this format; generic static evidence is still reported.")

        raw_strings = _extract_strings(data, self.policy.minimum_string_length)
        classified = sorted((_classify_string(item) for item in raw_strings), key=_importance_order)
        strings_truncated = len(classified) > self.policy.max_strings
        strings = classified[:self.policy.max_strings]
        imports = []
        for raw_name in import_names:
            library, separator, name = raw_name.rpartition("!")
            normalized = (name if separator else raw_name).split("@", 1)[0]
            role = _IMPORT_ROLES.get(normalized.lower())
            imports.append({"name": normalized, "library": library or None, "category": role[0] if role else "other", "importance": role[1] if role else "info", "reason": role[2] if role else "Imported function identified from the executable import table."})

        prefixes = ["flag", "CTF", "picoCTF", "HTB", "THM"]
        if value.custom_flag_prefix and value.custom_flag_prefix not in prefixes:
            prefixes.append(value.custom_flag_prefix)
        flags = _detect_flags(data, raw_strings, prefixes, value.original_filename)

        objdump_available = self._tools.available("objdump")
        disassembly: list[dict[str, Any]] = []
        functions: list[dict[str, Any]] = []
        if objdump_available and info["format"] in _NATIVE_FORMATS:
            try:
                execution = self._tools.run("objdump", ["-d", "--", value.path.name], cwd=value.path.parent, timeout_seconds=20, output_limit=8 * 1024 * 1024)
            except ToolExecutionError as exc:
                warnings.append(f"objdump failed safely: {exc} Static header, section, import, and string results remain available.")
            else:
                if execution.returncode == 0:
                    disassembly, functions = _parse_objdump(execution.stdout, self.policy.max_disassembly_lines)
                else:
                    warnings.append(f"objdump returned exit code {execution.returncode}; disassembly is unavailable.")
        elif info["format"] in _NATIVE_FORMATS:
            warnings.append("objdump is not installed; section, import, string, and protection analysis remains available, but disassembly is unavailable.")

        known_functions = {function["name"] for function in functions}
        for name in exports:
            if name not in known_functions:
                functions.append({"name": name, "address": None, "likely_role": _function_role(name), "evidence": ["Defined function symbol found in the executable symbol table."], "confidence": 0.8})
        functions.sort(key=lambda item: (0 if item["likely_role"] != "unclassified function" else 1, item["name"]))

        notable_strings = [item for item in strings if item["importance"] in {"critical", "high", "medium"}]
        validation_leads: list[dict[str, Any]] = []
        comparison_imports = [item for item in imports if item["category"] == "comparison"]
        for item in comparison_imports:
            validation_leads.append({"kind": "comparison call", "evidence": f"{item['name']} is present in the import table.", "interpretation": "User input may be compared directly or after a transformation.", "next_step": f"Inspect the arguments at each {item['name']} call site.", "confidence": 0.75})
        success_strings = [item for item in strings if re.search(r"correct|success|access granted|congrat", item["value"], re.I)]
        if success_strings:
            validation_leads.append({"kind": "success-path string", "evidence": f"{success_strings[0]['value']!r} at file offset 0x{success_strings[0]['offset']:x}.", "interpretation": "A cross-reference to this string should lead toward the successful validation branch.", "next_step": "Find this string's cross-references in a decompiler or disassembler and trace the controlling branch backward.", "confidence": 0.8})

        transformations = sorted({rule for item in strings for rule in ("Base64" if re.search("base64", item["value"], re.I) else "", "Cryptographic routine" if re.search("aes|rsa|sha|md5|decrypt|encrypt", item["value"], re.I) else "") if rule})
        findings: list[dict[str, Any]] = []
        if not info["extension_matches"]:
            findings.append({"severity": "high", "title": "Extension mismatch", "confidence": 0.99, "evidence": info["extension_reason"], "why_it_matters": "The artifact may be disguised and must be handled according to its actual format.", "recommendation": "Use the detected format for all subsequent analysis.", "location": "file header"})
        if info["packed"]:
            findings.append({"severity": "medium", "title": "Packer indicators detected", "confidence": 0.9, "evidence": "A section name associated with UPX or packing was found.", "why_it_matters": "Current strings and disassembly may describe the unpacking stub rather than the challenge logic.", "recommendation": "Create a temporary unpacked copy with an approved unpacker and preserve the original.", "location": "section table"})
        for flag in flags:
            findings.append({"severity": "critical", "title": "Complete flag-pattern candidate present", "confidence": flag["confidence"], "evidence": f"{flag['value']} at file offset 0x{flag['offset']:x}.", "why_it_matters": "The artifact contains a complete value matching a configured CTF flag pattern.", "recommendation": "Verify the candidate against the challenge or confirm it is used on the success path.", "location": f"file+0x{flag['offset']:x}"})
        if comparison_imports:
            names = ", ".join(item["name"] for item in comparison_imports)
            findings.append({"severity": "high", "title": "Validation comparison primitive imported", "confidence": 0.75, "evidence": f"Import table contains {names}.", "why_it_matters": "Its call sites may reveal the expected input or transformed byte array.", "recommendation": "Inspect call sites and both comparison operands.", "location": "import table"})
        for item in success_strings[:1]:
            findings.append({"severity": "high", "title": "Success-path message found", "confidence": 0.8, "evidence": f"{item['value']!r} at file offset 0x{item['offset']:x}.", "why_it_matters": "Cross-references often lead directly to validation logic.", "recommendation": "Trace cross-references and the branch that reaches this string.", "location": f"file+0x{item['offset']:x}"})
        for section in sections:
            if section["suspicious"]:
                findings.append({"severity": "medium", "title": f"Suspicious section {section['name']}", "confidence": 0.65, "evidence": section["reason"] or "Unusual section characteristics.", "why_it_matters": "High entropy or packer naming can conceal the program's real code and constants.", "recommendation": "Inspect this section and confirm whether it is compressed, encrypted, or packed.", "location": section["name"]})

        anti_debug = [item for item in imports if item["category"] == "anti-analysis"]
        dynamic: list[dict[str, Any]] = []
        for item in comparison_imports:
            registers = "On x86-64 System V inspect RDI and RSI (and RDX for memcmp)." if info["architecture"] == "x86-64" and info["operating_system"] != "Windows" else "Inspect the arguments according to the detected platform calling convention."
            dynamic.append({"breakpoint": item["name"], "why": "Capture comparison operands at runtime.", "inspect": registers, "command": f"break {item['name']}"})
        for item in anti_debug:
            dynamic.append({"breakpoint": item["name"], "why": "Confirm whether the anti-debugging import is actually called.", "inspect": "Inspect its return value and the branch that handles failure.", "command": f"break {item['name']}"})
        if not dynamic and info["entry_point"] is not None:
            dynamic.append({"breakpoint": f"0x{info['entry_point']:x}", "why": "Begin at the evidence-backed executable entry point.", "inspect": "Trace toward input, success, and failure strings; do not run outside an isolated CTF environment.", "command": f"break *0x{info['entry_point']:x}"})

        likely_locations = [f"file offset 0x{flag['offset']:x}: complete pattern candidate" for flag in flags]
        likely_locations.extend(f"string offset 0x{item['offset']:x}: {item['value']}" for item in notable_strings if re.search(r"flag\.txt|secret\.txt|key\.txt", item["value"], re.I))
        if success_strings:
            likely_locations.append(f"cross-references to success string at file offset 0x{success_strings[0]['offset']:x}")
        solving_path = ["Confirm the detected format and whether packing affects the visible program."]
        if flags:
            solving_path.append("Verify the complete flag-pattern candidate against its code or data reference.")
        elif validation_leads:
            solving_path.extend(["Follow success/failure string cross-references to the controlling branch.", "Inspect comparison operands and reverse only transformations supported by those call sites.", "Trace the successful branch to the flag source."])
        else:
            solving_path.extend(["Use the focused notable strings and functions to locate input handling.", "Inspect the branch that separates success from failure, then trace the success path to the flag source."])

        recovered: dict[str, str] = {}
        summary = f"Identified {info['detected_type']} with {len(findings)} notable finding(s), {len(validation_leads)} validation lead(s), and {len(flags)} unconfirmed flag candidate(s)."
        return ReverseAnalysisResponse(
            analysis_id=str(uuid4()), artifact_id=value.artifact_id,
            file={"name": value.original_filename, "size": len(data), "hashes": {"md5": hashlib.md5(data).hexdigest(), "sha256": hashlib.sha256(data).hexdigest()}, **info},
            protections=protections, sections=sections, strings=strings, strings_truncated=strings_truncated,
            imports=imports, exports=exports, functions=functions[:300], disassembly=disassembly,
            validation_leads=validation_leads, transformations=transformations, findings=findings,
            flags=flags, likely_flag_locations=likely_locations, recovered_values=recovered,
            dynamic_recommendations=dynamic, solving_path=solving_path,
            tools={"objdump": objdump_available}, warnings=warnings, summary=summary,
            limits={"max_upload_bytes": self.policy.max_upload_bytes, "max_strings": self.policy.max_strings, "max_disassembly_lines": self.policy.max_disassembly_lines},
        )
