from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FileSignature:
    name: str
    mime_type: str
    magic: bytes
    extensions: tuple[str, ...]
    description: str
    offset: int = 0


SIGNATURES: tuple[FileSignature, ...] = (
    FileSignature("png", "image/png", b"\x89PNG\r\n\x1a\n", ("png",), "PNG image"),
    FileSignature("jpeg", "image/jpeg", b"\xff\xd8\xff", ("jpg", "jpeg", "jpe"), "JPEG image"),
    FileSignature("gif", "image/gif", b"GIF87a", ("gif",), "GIF87a image"),
    FileSignature("gif", "image/gif", b"GIF89a", ("gif",), "GIF89a image"),
    FileSignature("pdf", "application/pdf", b"%PDF-", ("pdf",), "PDF document"),
    FileSignature("zip", "application/zip", b"PK\x03\x04", ("zip",), "ZIP archive"),
    FileSignature("zip", "application/zip", b"PK\x05\x06", ("zip",), "Empty ZIP archive"),
    FileSignature("zip", "application/zip", b"PK\x07\x08", ("zip",), "Spanned ZIP archive"),
    FileSignature("gzip", "application/gzip", b"\x1f\x8b\x08", ("gz", "gzip"), "Gzip-compressed data"),
    FileSignature("7z", "application/x-7z-compressed", b"7z\xbc\xaf\x27\x1c", ("7z",), "7-Zip archive"),
    FileSignature("rar", "application/vnd.rar", b"Rar!\x1a\x07\x01\x00", ("rar",), "RAR 5 archive"),
    FileSignature("rar", "application/vnd.rar", b"Rar!\x1a\x07\x00", ("rar",), "RAR archive"),
    FileSignature("elf", "application/x-elf", b"\x7fELF", ("elf", "so", "bin"), "ELF binary"),
    FileSignature("pe", "application/vnd.microsoft.portable-executable", b"MZ", ("exe", "dll", "sys"), "DOS/PE executable"),
    FileSignature("sqlite", "application/vnd.sqlite3", b"SQLite format 3\x00", ("sqlite", "sqlite3", "db"), "SQLite 3 database"),
    FileSignature("pcapng", "application/x-pcapng", b"\x0a\x0d\x0d\x0a", ("pcapng",), "PCAP Next Generation capture"),
    FileSignature("pcap", "application/vnd.tcpdump.pcap", b"\xd4\xc3\xb2\xa1", ("pcap", "cap"), "Little-endian PCAP capture"),
    FileSignature("pcap", "application/vnd.tcpdump.pcap", b"\xa1\xb2\xc3\xd4", ("pcap", "cap"), "Big-endian PCAP capture"),
    FileSignature("pcap", "application/vnd.tcpdump.pcap", b"\x4d\x3c\xb2\xa1", ("pcap", "cap"), "Nanosecond PCAP capture"),
    FileSignature("ole", "application/x-ole-storage", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", ("doc", "xls", "ppt", "msi"), "OLE compound document"),
    FileSignature("riff", "application/x-riff", b"RIFF", ("riff",), "RIFF container"),
    FileSignature("mp3", "audio/mpeg", b"ID3", ("mp3",), "MP3 audio with ID3 metadata"),
    FileSignature("mp3", "audio/mpeg", b"\xff\xfb", ("mp3",), "MPEG-1 Layer III audio"),
    FileSignature("bmp", "image/bmp", b"BM", ("bmp",), "Bitmap image"),
    FileSignature("tiff", "image/tiff", b"II*\x00", ("tif", "tiff"), "Little-endian TIFF image"),
    FileSignature("tiff", "image/tiff", b"MM\x00*", ("tif", "tiff"), "Big-endian TIFF image"),
    FileSignature("webp", "image/webp", b"WEBP", ("webp",), "WebP image", offset=8),
)

WAV_SIGNATURE = FileSignature(
    "wav", "audio/wav", b"RIFF", ("wav",), "RIFF WAVE audio"
)
WEBP_SIGNATURE = FileSignature(
    "webp", "image/webp", b"RIFF", ("webp",), "WebP image"
)


TYPE_EXTENSIONS: dict[str, tuple[str, ...]] = {
    signature.name: signature.extensions for signature in SIGNATURES
}


def root_signature(data: bytes) -> FileSignature | None:
    if len(data) >= 12 and data.startswith(b"RIFF"):
        if data[8:12] == b"WAVE":
            return WAV_SIGNATURE
        if data[8:12] == b"WEBP":
            return WEBP_SIGNATURE
    matches = [
        signature
        for signature in SIGNATURES
        if data[signature.offset :].startswith(signature.magic)
    ]
    return max(matches, key=lambda item: len(item.magic), default=None)


def scan_signatures(data: bytes, max_matches: int = 256) -> list[tuple[FileSignature, int]]:
    matches: list[tuple[FileSignature, int]] = []
    seen: set[tuple[str, int]] = set()
    for signature in SIGNATURES:
        start = 0
        while len(matches) < max_matches:
            offset = data.find(signature.magic, start)
            if offset < 0:
                break
            detected = signature
            if signature.name == "riff" and offset + 12 <= len(data):
                if data[offset + 8 : offset + 12] == b"WAVE":
                    detected = WAV_SIGNATURE
                elif data[offset + 8 : offset + 12] == b"WEBP":
                    detected = WEBP_SIGNATURE
            if (
                signature.name == "webp"
                and offset >= 8
                and data[offset - 8 : offset - 4] == b"RIFF"
            ):
                start = offset + 1
                continue
            identity = (detected.name, offset)
            if identity not in seen:
                seen.add(identity)
                matches.append((detected, offset))
            start = offset + 1
    return sorted(matches, key=lambda item: (item[1], -len(item[0].magic), item[0].name))
