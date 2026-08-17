"""Filesystem detection and metadata extraction (fsstat equivalent) — pure Python."""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO


@dataclass(slots=True)
class FsInfo:
    fs_type: str
    volume_label: str | None = None
    volume_uuid: str | None = None
    block_size: int | None = None
    cluster_size: int | None = None
    total_blocks: int | None = None
    free_blocks: int | None = None
    root_inode: int | None = None
    inode_count: int | None = None
    last_mounted: str | None = None
    last_mount_time: str | None = None
    last_write_time: str | None = None
    creation_time: str | None = None
    journal: bool | None = None
    dirty: bool | None = None
    details: dict[str, str | int | bool | None] = field(default_factory=dict)


def _ts(epoch: int) -> str | None:
    """Convert a Unix epoch to an ISO-8601 string, or None if zero."""
    if epoch <= 0:
        return None
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(epoch))
    except (OSError, OverflowError, ValueError):
        return None


# ---------------------------------------------------------------------------
# EXT2/3/4
# ---------------------------------------------------------------------------

def _detect_ext(fh: BinaryIO, partition_offset: int) -> FsInfo | None:
    """Read the EXT superblock at offset 1024 within the partition."""
    fh.seek(partition_offset + 1024)
    sb = fh.read(1024)
    if len(sb) < 264:
        return None
    magic = struct.unpack_from("<H", sb, 56)[0]
    if magic != 0xEF53:
        return None

    inode_count = struct.unpack_from("<I", sb, 0)[0]
    block_count = struct.unpack_from("<I", sb, 4)[0]
    free_blocks = struct.unpack_from("<I", sb, 12)[0]
    block_size_log = struct.unpack_from("<I", sb, 24)[0]
    block_size = 1024 << block_size_log

    mtime = struct.unpack_from("<I", sb, 44)[0]
    wtime = struct.unpack_from("<I", sb, 48)[0]
    mount_count = struct.unpack_from("<I", sb, 50)[0]  # actually H, but safe
    state = struct.unpack_from("<H", sb, 58)[0]

    # Feature flags
    compat_features = struct.unpack_from("<I", sb, 96)[0]
    incompat_features = struct.unpack_from("<I", sb, 100)[0]

    has_journal = bool(compat_features & 0x0004)

    # Determine EXT version
    if incompat_features & 0x0040:
        fs_type = "ext4"
    elif has_journal:
        fs_type = "ext3"
    else:
        fs_type = "ext2"

    # Volume label (16 bytes at offset 120)
    try:
        label_raw = sb[120:136]
        label = label_raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()
    except (ValueError, IndexError):
        label = None

    # UUID (16 bytes at offset 104)
    uuid_bytes = sb[104:120]
    uuid_str = (
        f"{uuid_bytes[0:4].hex()}-{uuid_bytes[4:6].hex()}-{uuid_bytes[6:8].hex()}-"
        f"{uuid_bytes[8:10].hex()}-{uuid_bytes[10:16].hex()}"
    ) if len(uuid_bytes) == 16 else None

    # Last mounted directory (64 bytes at offset 136)
    try:
        last_mounted = sb[136:200].split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip() or None
    except (ValueError, IndexError):
        last_mounted = None

    # Creation time — EXT4 only (at offset 264 if superblock is large enough)
    creation_time = None
    if len(sb) >= 268 and fs_type == "ext4":
        ct = struct.unpack_from("<I", sb, 264)[0]
        creation_time = _ts(ct)

    return FsInfo(
        fs_type=fs_type,
        volume_label=label or None,
        volume_uuid=uuid_str,
        block_size=block_size,
        total_blocks=block_count,
        free_blocks=free_blocks,
        root_inode=2,
        inode_count=inode_count,
        last_mounted=last_mounted,
        last_mount_time=_ts(mtime),
        last_write_time=_ts(wtime),
        creation_time=creation_time,
        journal=has_journal,
        dirty=state != 1,  # 1 = clean
        details={
            "mount_count": struct.unpack_from("<H", sb, 50)[0],
            "max_mount_count": struct.unpack_from("<H", sb, 52)[0],
            "incompat_features": f"0x{incompat_features:08X}",
            "compat_features": f"0x{compat_features:08X}",
        },
    )


# ---------------------------------------------------------------------------
# FAT12/16/32
# ---------------------------------------------------------------------------

def _detect_fat(fh: BinaryIO, partition_offset: int) -> FsInfo | None:
    """Read the FAT BPB / BIOS Parameter Block."""
    fh.seek(partition_offset)
    bpb = fh.read(512)
    if len(bpb) < 512:
        return None

    # Basic sanity: jump instruction at byte 0 (0xEB, 0xE9, or 0x90 pattern)
    if bpb[0] not in (0xEB, 0xE9) and bpb[0:2] != b"\x90\x90":
        # Additional check — look for valid bytes per sector
        pass

    bytes_per_sector = struct.unpack_from("<H", bpb, 11)[0]
    if bytes_per_sector not in (512, 1024, 2048, 4096):
        return None

    sectors_per_cluster = bpb[13]
    if sectors_per_cluster == 0 or (sectors_per_cluster & (sectors_per_cluster - 1)):
        return None  # Must be power of 2

    reserved_sectors = struct.unpack_from("<H", bpb, 14)[0]
    num_fats = bpb[16]
    root_entry_count = struct.unpack_from("<H", bpb, 17)[0]
    total_sectors_16 = struct.unpack_from("<H", bpb, 19)[0]
    fat_size_16 = struct.unpack_from("<H", bpb, 22)[0]
    total_sectors_32 = struct.unpack_from("<I", bpb, 32)[0]

    total_sectors = total_sectors_16 if total_sectors_16 != 0 else total_sectors_32
    if total_sectors == 0:
        return None

    # FAT32 specific
    fat_size_32 = struct.unpack_from("<I", bpb, 36)[0] if fat_size_16 == 0 else 0
    fat_size = fat_size_16 if fat_size_16 != 0 else fat_size_32

    root_dir_sectors = ((root_entry_count * 32) + (bytes_per_sector - 1)) // bytes_per_sector
    data_sectors = total_sectors - (reserved_sectors + num_fats * fat_size + root_dir_sectors)
    cluster_count = data_sectors // sectors_per_cluster if sectors_per_cluster > 0 else 0

    if cluster_count < 4085:
        fs_type = "fat12"
    elif cluster_count < 65525:
        fs_type = "fat16"
    else:
        fs_type = "fat32"

    cluster_size = sectors_per_cluster * bytes_per_sector

    # Volume label
    label = None
    if fs_type == "fat32":
        try:
            label = bpb[71:82].decode("ascii", errors="replace").strip()
        except (ValueError, IndexError):
            pass
    else:
        try:
            label = bpb[43:54].decode("ascii", errors="replace").strip()
        except (ValueError, IndexError):
            pass
    if label and label.replace(" ", "") == "":
        label = None

    return FsInfo(
        fs_type=fs_type,
        volume_label=label or None,
        block_size=bytes_per_sector,
        cluster_size=cluster_size,
        total_blocks=total_sectors,
        details={
            "bytes_per_sector": bytes_per_sector,
            "sectors_per_cluster": sectors_per_cluster,
            "reserved_sectors": reserved_sectors,
            "fat_count": num_fats,
            "fat_size_sectors": fat_size,
            "root_entry_count": root_entry_count,
            "cluster_count": cluster_count,
        },
    )


# ---------------------------------------------------------------------------
# NTFS
# ---------------------------------------------------------------------------

def _detect_ntfs(fh: BinaryIO, partition_offset: int) -> FsInfo | None:
    """Read the NTFS BPB."""
    fh.seek(partition_offset)
    boot = fh.read(512)
    if len(boot) < 84:
        return None

    oem_id = boot[3:11]
    if oem_id.rstrip(b"\x00 ") not in (b"NTFS", b"NTFS   "):
        return None

    bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
    sectors_per_cluster = boot[13]
    total_sectors = struct.unpack_from("<Q", boot, 40)[0]
    mft_cluster = struct.unpack_from("<Q", boot, 48)[0]
    mft_mirror_cluster = struct.unpack_from("<Q", boot, 56)[0]

    # MFT record size
    clusters_per_mft = boot[64]
    if clusters_per_mft > 127:
        mft_record_size = 1 << (256 - clusters_per_mft)
    else:
        mft_record_size = clusters_per_mft * sectors_per_cluster * bytes_per_sector

    cluster_size = sectors_per_cluster * bytes_per_sector

    # Serial number
    serial = struct.unpack_from("<Q", boot, 72)[0]

    return FsInfo(
        fs_type="ntfs",
        block_size=bytes_per_sector,
        cluster_size=cluster_size,
        total_blocks=total_sectors,
        details={
            "bytes_per_sector": bytes_per_sector,
            "sectors_per_cluster": sectors_per_cluster,
            "mft_cluster_offset": mft_cluster,
            "mft_mirror_cluster": mft_mirror_cluster,
            "mft_record_size": mft_record_size,
            "volume_serial": f"0x{serial:016X}",
        },
    )


# ---------------------------------------------------------------------------
# exFAT
# ---------------------------------------------------------------------------

def _detect_exfat(fh: BinaryIO, partition_offset: int) -> FsInfo | None:
    """Detect exFAT filesystem."""
    fh.seek(partition_offset)
    boot = fh.read(512)
    if len(boot) < 120:
        return None

    oem_id = boot[3:11]
    if oem_id.rstrip(b"\x00 ") != b"EXFAT":
        return None

    sector_shift = boot[108]
    cluster_shift = boot[109]
    bytes_per_sector = 1 << sector_shift if sector_shift > 0 else 512
    sectors_per_cluster = 1 << cluster_shift if cluster_shift > 0 else 1

    total_sectors = struct.unpack_from("<Q", boot, 72)[0]
    cluster_count = struct.unpack_from("<I", boot, 92)[0]

    return FsInfo(
        fs_type="exfat",
        block_size=bytes_per_sector,
        cluster_size=bytes_per_sector * sectors_per_cluster,
        total_blocks=total_sectors,
        details={
            "cluster_count": cluster_count,
            "sector_shift": sector_shift,
            "cluster_shift": cluster_shift,
        },
    )


# ---------------------------------------------------------------------------
# ISO 9660
# ---------------------------------------------------------------------------

def _detect_iso9660(fh: BinaryIO, partition_offset: int) -> FsInfo | None:
    """Detect ISO 9660 primary volume descriptor."""
    fh.seek(partition_offset + 32768)
    pvd = fh.read(2048)
    if len(pvd) < 882 or pvd[1:6] != b"CD001":
        return None

    try:
        label = pvd[40:72].decode("ascii", errors="replace").strip()
    except (ValueError, IndexError):
        label = None

    block_size = struct.unpack_from("<H", pvd, 128)[0]
    space_size = struct.unpack_from("<I", pvd, 80)[0]

    try:
        creation = pvd[813:830].decode("ascii", errors="replace").strip()
    except (ValueError, IndexError):
        creation = None

    return FsInfo(
        fs_type="iso9660",
        volume_label=label or None,
        block_size=block_size,
        total_blocks=space_size,
        creation_time=creation,
        details={"volume_set_id": pvd[190:318].split(b"\x00", 1)[0].decode("ascii", errors="replace").strip()},
    )


# ---------------------------------------------------------------------------
# Signature-only detectors (report type but don't enumerate files)
# ---------------------------------------------------------------------------

_SIMPLE_FS_SIGNATURES: list[tuple[bytes, int, str]] = [
    (b"XFSB", 0, "xfs"),
    (b"_BHRfS_M", 64, "btrfs"),
    (b"\x00\x00\x01\x00", 1024, "hfs+"),      # HFS+ magic at 1024
    (b"\x48\x2b\x00\x04", 1024, "hfs+"),       # HFS+ alternative
    (b"hsqs", 0, "squashfs"),
    (b"sqsh", 0, "squashfs"),
    (b"\x13\x7f", 1080, "minix"),              # Minix v1
    (b"\x8f\x13", 1080, "minix"),              # Minix v1 alt
    (b"\x69\x19", 1080, "minix"),              # Minix v2
    (b"\x2f\x44", 1080, "minix"),              # Minix v3
    (b"ReIsErFs", 8244, "reiserfs"),
    (b"ReIsEr2Fs", 8244, "reiserfs"),
    (b"ReIsEr3Fs", 8244, "reiserfs"),
]


def _detect_simple(fh: BinaryIO, partition_offset: int) -> FsInfo | None:
    """Check for filesystem magic bytes that we can identify but not fully enumerate."""
    for magic, offset, name in _SIMPLE_FS_SIGNATURES:
        try:
            fh.seek(partition_offset + offset)
            sample = fh.read(len(magic))
            if sample == magic:
                return FsInfo(fs_type=name)
        except OSError:
            continue
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_filesystem(path: Path, partition_offset: int) -> FsInfo | None:
    """Try to identify the filesystem at the given byte offset in the image.

    Returns *None* when no recognizable filesystem signature is found.
    """
    with path.open("rb") as fh:
        for detector in (_detect_ext, _detect_ntfs, _detect_fat, _detect_exfat, _detect_iso9660, _detect_simple):
            try:
                result = detector(fh, partition_offset)
                if result is not None:
                    return result
            except (OSError, struct.error):
                continue
    return None
