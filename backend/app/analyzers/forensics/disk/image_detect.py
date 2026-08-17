"""Disk image format detection and hashing."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

_CHUNK = 1024 * 1024  # 1 MiB read chunks for hashing


@dataclass(frozen=True, slots=True)
class ImageDetection:
    image_type: str
    mime_type: str
    sector_size: int
    description: str


# Magic-byte table for disk image formats
_IMAGE_SIGNATURES: list[tuple[bytes, int, str, str, str]] = [
    # (magic, offset, type_name, mime, description)
    (b"\x45\x46\x49\x20\x50\x41\x52\x54", 512, "gpt-raw", "application/octet-stream", "Raw disk with GPT header"),
    (b"conectix", -512, "vhd", "application/x-vhd", "VHD Virtual Hard Disk"),
    (b"KDMV", 0, "vmdk-sparse", "application/x-vmdk", "VMDK sparse extent"),
    (b"# Disk DescriptorFile", 0, "vmdk-descriptor", "application/x-vmdk", "VMDK descriptor"),
    (b"VHDX", 0, "vhdx", "application/x-vhdx", "VHDX Virtual Hard Disk"),
    (b"\x45\x56\x46\x09\x0d\x0a\xff\x00", 0, "e01", "application/x-ewf", "EnCase E01 evidence file"),
    (b"EVF", 0, "e01-legacy", "application/x-ewf", "EnCase legacy evidence file"),
    (b"AFF4", 0, "aff4", "application/x-aff4", "AFF4 forensic image"),
    (b"AFF", 0, "aff", "application/x-aff", "AFF forensic image"),
    (b"\x43\x44\x30\x30\x31", 32769, "iso9660", "application/x-iso9660-image", "ISO 9660 CD/DVD image"),
]


def _detect_image_type(path: Path, size: int) -> ImageDetection:
    """Detect the image format by inspecting magic bytes at known offsets."""
    try:
        with path.open("rb") as fh:
            header = fh.read(min(size, 65536))

            for magic, offset, name, mime, desc in _IMAGE_SIGNATURES:
                if offset == -512:
                    # Read footer (VHD)
                    if size >= 512:
                        fh.seek(size - 512)
                        footer = fh.read(512)
                        if footer.startswith(magic):
                            return ImageDetection(name, mime, 512, desc)
                    continue
                if offset < len(header) and header[offset:offset + len(magic)] == magic:
                    return ImageDetection(name, mime, 512, desc)

            # Check for ISO at standard offset
            if size > 32769 + 5:
                fh.seek(32769)
                cd001 = fh.read(5)
                if cd001 == b"CD001":
                    return ImageDetection("iso9660", "application/x-iso9660-image", 2048, "ISO 9660 CD/DVD image")

            # Check MBR signature
            if len(header) >= 512 and header[510:512] == b"\x55\xAA":
                return ImageDetection("raw-mbr", "application/octet-stream", 512, "Raw disk image with MBR signature")

            # Default: treat as raw
            return ImageDetection("raw", "application/octet-stream", 512, "Raw disk image")
    except OSError:
        return ImageDetection("raw", "application/octet-stream", 512, "Raw disk image")


def detect_image(path: Path) -> ImageDetection:
    """Detect image type and determine sector size."""
    size = path.stat().st_size
    return _detect_image_type(path, size)


def compute_hashes(path: Path) -> tuple[str, str, str]:
    """Stream-compute MD5, SHA1, SHA256 for potentially large files."""
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(_CHUNK):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
