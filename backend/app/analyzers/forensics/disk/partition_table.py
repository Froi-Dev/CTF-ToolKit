"""MBR, GPT, APM, and BSD partition table parsing — pure Python."""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Partition type IDs  (MBR byte → readable name)
# ---------------------------------------------------------------------------
MBR_TYPES: dict[int, str] = {
    0x00: "Empty",
    0x01: "FAT12",
    0x04: "FAT16 <32M",
    0x05: "Extended",
    0x06: "FAT16",
    0x07: "NTFS/HPFS/exFAT",
    0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)",
    0x0F: "Extended (LBA)",
    0x11: "Hidden FAT12",
    0x14: "Hidden FAT16 <32M",
    0x16: "Hidden FAT16",
    0x17: "Hidden NTFS/HPFS",
    0x1B: "Hidden FAT32 (CHS)",
    0x1C: "Hidden FAT32 (LBA)",
    0x1E: "Hidden FAT16 (LBA)",
    0x27: "Hidden NTFS (WinRE)",
    0x42: "Dynamic Disk",
    0x82: "Linux Swap",
    0x83: "Linux",
    0x84: "Hibernation",
    0x85: "Linux Extended",
    0x8E: "Linux LVM",
    0xA5: "FreeBSD",
    0xA6: "OpenBSD",
    0xA8: "Mac OS X",
    0xA9: "NetBSD",
    0xAB: "Mac OS X Boot",
    0xAF: "HFS/HFS+",
    0xBE: "Solaris Boot",
    0xBF: "Solaris",
    0xEE: "GPT Protective",
    0xEF: "EFI System",
    0xFB: "VMware VMFS",
    0xFC: "VMware Swap",
    0xFD: "Linux RAID",
}

# GPT well-known partition type GUIDs
GPT_TYPES: dict[str, str] = {
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System",
    "024dee41-33e7-11d3-9d69-0008c781f39f": "MBR Partition Scheme",
    "21686148-6449-6e6f-744e-656564454649": "BIOS Boot",
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux Filesystem",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "Linux Swap",
    "e6d6d379-f507-44c2-a23c-238f2a3df928": "Linux LVM",
    "a19d880f-05fc-4d3b-a006-743f0f84911e": "Linux RAID",
    "933ac7e1-2eb4-4f13-b844-0e14e2aef915": "Linux Home",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Microsoft Basic Data",
    "e3c9e316-0b5c-4db8-817d-f92df00215ae": "Microsoft Reserved",
    "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3": "Microsoft LDM Metadata",
    "af9b60a0-1431-4f62-bc68-3311714a69ad": "Microsoft LDM Data",
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "Windows Recovery",
    "48465300-0000-11aa-aa11-00306543ecac": "Apple HFS/HFS+",
    "7c3457ef-0000-11aa-aa11-00306543ecac": "Apple APFS",
    "55465300-0000-11aa-aa11-00306543ecac": "Apple UFS",
    "6a898cc3-1dd2-11b2-99a6-080020736631": "Apple ZFS / Solaris",
    "426f6f74-0000-11aa-aa11-00306543ecac": "Apple Boot",
}


@dataclass(frozen=True, slots=True)
class RawPartition:
    number: int
    slot: str
    start_sector: int
    end_sector: int
    sector_count: int
    type_id: str
    type_name: str
    bootable: bool
    status: str  # "allocated" | "deleted" | "extended"


@dataclass(slots=True)
class PartitionTableResult:
    table_type: str  # "mbr" | "gpt" | "apm" | "bsd" | "hybrid" | "protective-mbr" | "none" | "unknown"
    description: str
    partitions: list[RawPartition] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# MBR parsing
# ---------------------------------------------------------------------------

def _parse_mbr_entry(data: bytes, offset: int) -> tuple[int, bool, int, int, int]:
    """Parse one 16-byte MBR partition entry.
    Returns (type_id, bootable, start_lba, sector_count, status_byte).
    """
    status = data[offset]
    type_id = data[offset + 4]
    start_lba = struct.unpack_from("<I", data, offset + 8)[0]
    count = struct.unpack_from("<I", data, offset + 12)[0]
    bootable = status in (0x80, 0x00) and status == 0x80
    return type_id, bootable, start_lba, count, status


def _walk_extended(path: Path, ext_start: int, sector_size: int, max_logical: int = 60) -> list[RawPartition]:
    """Walk the EBR chain to discover logical partitions."""
    partitions: list[RawPartition] = []
    current_ebr = ext_start
    number = 5  # Logical partitions start at 5
    visited: set[int] = set()

    with path.open("rb") as fh:
        while len(partitions) < max_logical:
            if current_ebr in visited or current_ebr < 0:
                break
            visited.add(current_ebr)

            fh.seek(current_ebr * sector_size)
            ebr = fh.read(512)
            if len(ebr) < 512 or ebr[510:512] != b"\x55\xAA":
                break

            # First entry: the logical partition (relative to this EBR)
            t1, boot1, start1, count1, _ = _parse_mbr_entry(ebr, 446)
            if t1 != 0x00 and count1 > 0:
                abs_start = current_ebr + start1
                partitions.append(RawPartition(
                    number=number,
                    slot=f"Logical {number}",
                    start_sector=abs_start,
                    end_sector=abs_start + count1 - 1,
                    sector_count=count1,
                    type_id=f"0x{t1:02X}",
                    type_name=MBR_TYPES.get(t1, f"Unknown (0x{t1:02X})"),
                    bootable=boot1,
                    status="allocated",
                ))
                number += 1

            # Second entry: pointer to next EBR (relative to extended start)
            t2, _, start2, count2, _ = _parse_mbr_entry(ebr, 462)
            if t2 in (0x05, 0x0F, 0x85) and count2 > 0:
                current_ebr = ext_start + start2
            else:
                break

    return partitions


def parse_mbr(path: Path, sector_size: int = 512) -> PartitionTableResult:
    """Parse a classic MBR / DOS partition table."""
    with path.open("rb") as fh:
        mbr = fh.read(512)

    if len(mbr) < 512 or mbr[510:512] != b"\x55\xAA":
        return PartitionTableResult("none", "No valid MBR signature (0x55AA) found.")

    partitions: list[RawPartition] = []
    has_gpt_protective = False

    for i in range(4):
        offset = 446 + i * 16
        type_id, bootable, start_lba, count, _ = _parse_mbr_entry(mbr, offset)
        if type_id == 0x00:
            continue
        if type_id == 0xEE:
            has_gpt_protective = True
        status = "extended" if type_id in (0x05, 0x0F, 0x85) else "allocated"
        partitions.append(RawPartition(
            number=i + 1,
            slot=f"Primary {i + 1}",
            start_sector=start_lba,
            end_sector=start_lba + count - 1 if count > 0 else start_lba,
            sector_count=count,
            type_id=f"0x{type_id:02X}",
            type_name=MBR_TYPES.get(type_id, f"Unknown (0x{type_id:02X})"),
            bootable=bootable,
            status=status,
        ))

    # Walk extended partitions
    extended = [p for p in partitions if p.status == "extended"]
    for ext in extended:
        logicals = _walk_extended(path, ext.start_sector, sector_size)
        partitions.extend(logicals)

    if has_gpt_protective:
        return PartitionTableResult("protective-mbr", "Protective MBR found — checking for GPT.", partitions)

    return PartitionTableResult(
        "mbr",
        f"MBR/DOS partition table with {len(partitions)} entries.",
        partitions,
    )


# ---------------------------------------------------------------------------
# GPT parsing
# ---------------------------------------------------------------------------

def _guid_from_mixed_endian(data: bytes) -> str:
    """Convert a 16-byte mixed-endian GUID to standard string format."""
    if len(data) < 16:
        return "00000000-0000-0000-0000-000000000000"
    part1 = struct.unpack_from("<IHH", data, 0)
    part2 = data[8:16]
    return f"{part1[0]:08x}-{part1[1]:04x}-{part1[2]:04x}-{part2[0]:02x}{part2[1]:02x}-{part2[2]:02x}{part2[3]:02x}{part2[4]:02x}{part2[5]:02x}{part2[6]:02x}{part2[7]:02x}"


def parse_gpt(path: Path, sector_size: int = 512) -> PartitionTableResult:
    """Parse a GUID Partition Table."""
    warnings: list[str] = []
    with path.open("rb") as fh:
        fh.seek(sector_size)  # LBA 1
        header = fh.read(92)

    if len(header) < 92 or header[:8] != b"EFI PART":
        return PartitionTableResult("none", "No valid GPT header found.")

    _revision = struct.unpack_from("<I", header, 8)[0]
    _header_size = struct.unpack_from("<I", header, 12)[0]
    entry_start_lba = struct.unpack_from("<Q", header, 72)[0]
    num_entries = struct.unpack_from("<I", header, 80)[0]
    entry_size = struct.unpack_from("<I", header, 84)[0]

    if num_entries > 256:
        num_entries = 256
        warnings.append("GPT entry count was capped at 256.")
    if entry_size < 128:
        entry_size = 128

    partitions: list[RawPartition] = []
    with path.open("rb") as fh:
        fh.seek(entry_start_lba * sector_size)
        entries_data = fh.read(num_entries * entry_size)

    number = 1
    for i in range(num_entries):
        offset = i * entry_size
        if offset + 128 > len(entries_data):
            break
        entry = entries_data[offset:offset + entry_size]
        type_guid = _guid_from_mixed_endian(entry[0:16])

        # Skip empty entries
        if type_guid == "00000000-0000-0000-0000-000000000000":
            continue

        _unique_guid = _guid_from_mixed_endian(entry[16:32])
        first_lba = struct.unpack_from("<Q", entry, 32)[0]
        last_lba = struct.unpack_from("<Q", entry, 40)[0]
        _attributes = struct.unpack_from("<Q", entry, 48)[0]
        name_raw = entry[56:128]
        try:
            name = name_raw.decode("utf-16le").rstrip("\x00").strip()
        except (UnicodeDecodeError, ValueError):
            name = ""

        type_name = GPT_TYPES.get(type_guid, name or f"Unknown ({type_guid[:13]}…)")
        count = last_lba - first_lba + 1 if last_lba >= first_lba else 0

        partitions.append(RawPartition(
            number=number,
            slot=f"GPT {number}" + (f" ({name})" if name else ""),
            start_sector=first_lba,
            end_sector=last_lba,
            sector_count=count,
            type_id=type_guid,
            type_name=type_name,
            bootable=False,
            status="allocated",
        ))
        number += 1

    return PartitionTableResult(
        "gpt",
        f"GPT partition table with {len(partitions)} entries.",
        partitions,
        warnings,
    )


# ---------------------------------------------------------------------------
# APM parsing (Apple Partition Map)
# ---------------------------------------------------------------------------

def parse_apm(path: Path, sector_size: int = 512) -> PartitionTableResult:
    """Detect and parse an Apple Partition Map."""
    with path.open("rb") as fh:
        fh.seek(sector_size)
        block = fh.read(512)

    if len(block) < 512 or block[0:2] != b"PM":
        return PartitionTableResult("none", "No APM signature found.")

    map_entries = struct.unpack_from(">I", block, 4)[0]
    if map_entries > 128:
        map_entries = 128

    partitions: list[RawPartition] = []
    with path.open("rb") as fh:
        for i in range(map_entries):
            fh.seek((1 + i) * sector_size)
            entry = fh.read(512)
            if len(entry) < 512 or entry[0:2] != b"PM":
                break
            start = struct.unpack_from(">I", entry, 8)[0]
            count = struct.unpack_from(">I", entry, 12)[0]
            try:
                name = entry[16:48].split(b"\x00", 1)[0].decode("ascii", errors="replace").strip()
            except (ValueError, IndexError):
                name = ""
            try:
                type_name = entry[48:80].split(b"\x00", 1)[0].decode("ascii", errors="replace").strip()
            except (ValueError, IndexError):
                type_name = "Unknown"

            partitions.append(RawPartition(
                number=i + 1,
                slot=f"APM {i + 1}" + (f" ({name})" if name else ""),
                start_sector=start,
                end_sector=start + count - 1 if count > 0 else start,
                sector_count=count,
                type_id=type_name,
                type_name=type_name,
                bootable=False,
                status="allocated",
            ))

    return PartitionTableResult(
        "apm",
        f"Apple Partition Map with {len(partitions)} entries.",
        partitions,
    )


# ---------------------------------------------------------------------------
# Unallocated region detection
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class UnallocRegion:
    start_sector: int
    end_sector: int
    sector_count: int
    location: str  # "before-partitions" | "between-partitions" | "after-partitions"
    suspicious: bool
    reason: str | None


def find_unallocated(partitions: list[RawPartition], total_sectors: int, sector_size: int) -> list[UnallocRegion]:
    """Find unallocated disk regions between, before, and after partitions."""
    if not partitions:
        if total_sectors > 0:
            return [UnallocRegion(0, total_sectors - 1, total_sectors, "before-partitions", True,
                                  "Entire disk has no partitions — may contain a raw filesystem or hidden data.")]
        return []

    # Filter to non-extended, real partitions and sort by start
    real = sorted(
        [p for p in partitions if p.status != "extended" and p.sector_count > 0],
        key=lambda p: p.start_sector,
    )
    if not real:
        return []

    regions: list[UnallocRegion] = []
    threshold = 8  # sectors — ignore tiny alignment gaps

    # Before first partition (skip sector 0 for MBR)
    first_start = real[0].start_sector
    if first_start > 1:
        gap = first_start
        suspicious = gap > 2048  # > 1 MiB before first partition is unusual
        reason = "Space before first partition may contain hidden data." if suspicious else None
        if gap > threshold:
            regions.append(UnallocRegion(0, first_start - 1, gap, "before-partitions", suspicious, reason))

    # Between partitions
    for i in range(len(real) - 1):
        gap_start = real[i].end_sector + 1
        gap_end = real[i + 1].start_sector - 1
        gap_size = gap_end - gap_start + 1
        if gap_size > threshold:
            suspicious = gap_size * sector_size > 1024 * 1024  # > 1 MiB gap
            reason = f"Significant {_format_size(gap_size * sector_size)} gap between partitions {real[i].number} and {real[i + 1].number}." if suspicious else None
            regions.append(UnallocRegion(gap_start, gap_end, gap_size, "between-partitions", suspicious, reason))

    # After last partition
    last_end = real[-1].end_sector
    if last_end < total_sectors - 1:
        gap_start = last_end + 1
        gap_size = total_sectors - gap_start
        if gap_size > threshold:
            suspicious = gap_size * sector_size > 1024 * 1024
            reason = f"Trailing {_format_size(gap_size * sector_size)} of disk is outside all partitions." if suspicious else None
            regions.append(UnallocRegion(gap_start, total_sectors - 1, gap_size, "after-partitions", suspicious, reason))

    return regions


def _format_size(size_bytes: int) -> str:
    """Human-readable size."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KiB"
    if size_bytes < 1024 ** 3:
        return f"{size_bytes / 1024 ** 2:.1f} MiB"
    return f"{size_bytes / 1024 ** 3:.2f} GiB"


# ---------------------------------------------------------------------------
# Master dispatcher
# ---------------------------------------------------------------------------

def detect_partition_table(path: Path, sector_size: int = 512) -> PartitionTableResult:
    """Detect and parse the partition table from a disk image."""
    total_sectors = path.stat().st_size // sector_size

    # Try MBR first
    mbr_result = parse_mbr(path, sector_size)

    if mbr_result.table_type == "protective-mbr":
        # Protective MBR → try GPT
        gpt_result = parse_gpt(path, sector_size)
        if gpt_result.table_type == "gpt":
            return gpt_result
        # Protective MBR but no GPT → hybrid or corruption
        mbr_result.table_type = "hybrid"  # type: ignore[misc]
        mbr_result.description = "Protective MBR found but GPT header is missing or invalid."
        return mbr_result

    if mbr_result.table_type == "mbr" and mbr_result.partitions:
        return mbr_result

    # Try GPT at LBA 1 even without protective MBR
    gpt_result = parse_gpt(path, sector_size)
    if gpt_result.table_type == "gpt":
        return gpt_result

    # Try APM
    apm_result = parse_apm(path, sector_size)
    if apm_result.table_type == "apm":
        return apm_result

    # No partition table found — might be a single filesystem image
    return PartitionTableResult(
        "none",
        "No recognized partition table. The image may contain a single raw filesystem.",
    )
