"""Targeted string extraction and flag hunting."""

from __future__ import annotations

from pathlib import Path

from app.schemas.disk_forensics import StringFinding, DiskFlagCandidate, EncodedStringFinding


import re
import mmap

def scan_strings(
    path: Path, 
    regions: list[tuple[int, int, str]], 
    custom_prefixes: list[str] | None = None
) -> tuple[list[StringFinding], list[EncodedStringFinding], list[DiskFlagCandidate]]:
    """Scan regions for printable strings, encoded data, and flags."""
    strings: list[StringFinding] = []
    encoded: list[EncodedStringFinding] = []
    flags: list[DiskFlagCandidate] = []
    
    flag_pattern = re.compile(rb"picoCTF\{[^}\r\n]{1,300}\}")
    generic_flag_pattern = re.compile(rb"[A-Za-z0-9_-]{2,30}\{[^}\r\n]{3,300}\}")
    
    try:
        with path.open("rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            
            # Find picoCTF flags
            for match in flag_pattern.finditer(mm):
                val = match.group().decode("ascii", errors="ignore")
                flags.append(DiskFlagCandidate(
                    value=val,
                    source="Raw Sweep (ASCII)",
                    partition="Unknown",
                    evidence_type="Raw String",
                    confidence=0.99,
                    context="Raw disk string",
                    disk_offset=match.start(),
                    disk_offset_hex=hex(match.start()),
                ))
                
            # Generic flags
            for match in generic_flag_pattern.finditer(mm):
                val = match.group().decode("ascii", errors="ignore")
                if not val.startswith("picoCTF"):
                    flags.append(DiskFlagCandidate(
                        value=val,
                        source="Raw Sweep (ASCII)",
                        partition="Unknown",
                        evidence_type="Raw String",
                        confidence=0.80,
                        context="Raw disk string",
                        disk_offset=match.start(),
                        disk_offset_hex=hex(match.start()),
                    ))
                    
            mm.close()
    except Exception:
        pass

    return strings, encoded, flags
