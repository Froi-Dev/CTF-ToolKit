from __future__ import annotations

import re
import struct
from dataclasses import dataclass

import numpy as np

from app.analyzers.forensics.audio.context import PcmAudio
from app.core.errors import InvalidArtifactError
from app.schemas.audio import RiffChunk


_KNOWN_CHUNKS = {"fmt ", "data", "LIST", "INFO", "JUNK", "PAD ", "cue ", "fact", "bext", "iXML"}
_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")


@dataclass(frozen=True, slots=True)
class RiffParseResult:
    chunks: list[RiffChunk]
    container_end: int
    metadata: dict[str, str]
    pcm: PcmAudio | None
    warnings: list[str]


def _preview(payload: bytes) -> str | None:
    match = _PRINTABLE.search(payload[:512])
    return match.group(0)[:160].decode("ascii", errors="replace") if match else None


def _decode_pcm(payload: bytes, *, channels: int, sample_rate: int, bits: int, format_code: int, offset: int) -> PcmAudio:
    if channels < 1 or channels > 32 or sample_rate < 1 or sample_rate > 768_000:
        raise InvalidArtifactError("The WAV fmt chunk declares invalid channel or sample-rate values.")
    bytes_per_sample = (bits + 7) // 8
    frame_width = bytes_per_sample * channels
    if bytes_per_sample not in {1, 2, 3, 4} or frame_width <= 0:
        raise InvalidArtifactError("The WAV sample width is unsupported.")
    payload = payload[: len(payload) - (len(payload) % frame_width)]
    if format_code == 3 and bits == 32:
        values = np.frombuffer(payload, dtype="<f4").astype(np.float64)
        encoding = "IEEE float 32-bit LE"
    elif format_code in {1, 0xFFFE}:
        if bits == 8:
            values = (np.frombuffer(payload, dtype=np.uint8).astype(np.float64) - 128.0) / 128.0
        elif bits == 16:
            values = np.frombuffer(payload, dtype="<i2").astype(np.float64) / 32768.0
        elif bits == 24:
            packed = np.frombuffer(payload, dtype=np.uint8).reshape(-1, 3)
            integers = (
                packed[:, 0].astype(np.int32)
                | (packed[:, 1].astype(np.int32) << 8)
                | (packed[:, 2].astype(np.int32) << 16)
            )
            integers = np.where(integers & 0x800000, integers - 0x1000000, integers)
            values = integers.astype(np.float64) / 8_388_608.0
        elif bits == 32:
            values = np.frombuffer(payload, dtype="<i4").astype(np.float64) / 2_147_483_648.0
        else:
            raise InvalidArtifactError(f"{bits}-bit PCM WAV audio is unsupported.")
        encoding = f"PCM {bits}-bit LE"
    else:
        raise InvalidArtifactError(f"WAV format code {format_code} requires FFmpeg normalization.")
    return PcmAudio(
        samples=np.clip(values.reshape(-1, channels), -1.0, 1.0),
        sample_rate=sample_rate,
        bit_depth=bits,
        encoding=encoding,
        data_offset=offset,
        raw_sample_bytes=payload,
    )


def parse_wave(data: bytes) -> RiffParseResult:
    if len(data) < 12 or data[:4] not in {b"RIFF", b"RIFX"} or data[8:12] != b"WAVE":
        raise InvalidArtifactError("The working copy is not a RIFF/WAVE file.")
    if data[:4] == b"RIFX":
        raise InvalidArtifactError("Big-endian RIFX audio requires FFmpeg normalization.")

    declared_end = min(len(data), 8 + int.from_bytes(data[4:8], "little"))
    cursor = 12
    chunks: list[RiffChunk] = []
    metadata: dict[str, str] = {}
    warnings: list[str] = []
    fmt: tuple[int, int, int, int] | None = None
    data_chunk: tuple[bytes, int] | None = None
    seen: dict[str, int] = {}

    while cursor + 8 <= declared_end:
        chunk_start = cursor
        chunk_id_bytes = data[cursor : cursor + 4]
        chunk_id = chunk_id_bytes.decode("ascii", errors="replace")
        size = int.from_bytes(data[cursor + 4 : cursor + 8], "little")
        payload_start = cursor + 8
        payload_end = payload_start + size
        malformed = payload_end > declared_end
        actual_end = min(payload_end, declared_end)
        payload = data[payload_start:actual_end]
        known = chunk_id in _KNOWN_CHUNKS
        chunks.append(
            RiffChunk(
                chunk_id=chunk_id,
                offset=chunk_start,
                size=size,
                known=known,
                preview=_preview(payload),
                malformed=malformed,
            )
        )
        seen[chunk_id] = seen.get(chunk_id, 0) + 1
        if seen[chunk_id] > 1 and chunk_id in {"fmt ", "data"}:
            warnings.append(f"Duplicate {chunk_id.strip()} chunk at 0x{chunk_start:x}.")
        if malformed:
            warnings.append(f"Chunk {chunk_id!r} at 0x{chunk_start:x} exceeds the RIFF boundary.")
            break
        if chunk_id == "fmt " and len(payload) >= 16 and fmt is None:
            format_code, channels, sample_rate, _, _, bits = struct.unpack_from("<HHIIHH", payload)
            fmt = (format_code, channels, sample_rate, bits)
            metadata.update(
                wav_format_code=str(format_code),
                wav_channels=str(channels),
                wav_sample_rate=str(sample_rate),
                wav_bit_depth=str(bits),
            )
        elif chunk_id == "data" and data_chunk is None:
            data_chunk = (payload, payload_start)
        elif chunk_id == "LIST" and payload.startswith(b"INFO"):
            info_cursor = 4
            while info_cursor + 8 <= len(payload):
                key = payload[info_cursor : info_cursor + 4].decode("ascii", errors="replace")
                value_size = int.from_bytes(payload[info_cursor + 4 : info_cursor + 8], "little")
                value = payload[info_cursor + 8 : info_cursor + 8 + value_size].rstrip(b"\x00")
                metadata[f"RIFF_INFO_{key}"] = value.decode("utf-8", errors="replace")[:2048]
                info_cursor += 8 + value_size + (value_size & 1)
        cursor = payload_end + (size & 1)

    pcm = None
    if fmt and data_chunk:
        pcm = _decode_pcm(
            data_chunk[0],
            channels=fmt[1],
            sample_rate=fmt[2],
            bits=fmt[3],
            format_code=fmt[0],
            offset=data_chunk[1],
        )
    elif not fmt or not data_chunk:
        warnings.append("The WAV file is missing a usable fmt or data chunk.")
    if declared_end < len(data):
        warnings.append(f"{len(data) - declared_end} trailing bytes exist after the declared RIFF end.")
    return RiffParseResult(chunks, declared_end, metadata, pcm, warnings)


def decode_raw_pcm(
    data: bytes,
    *,
    sample_rate: int,
    bit_depth: int,
    channels: int,
    endianness: str,
    signed: bool,
) -> PcmAudio:
    if sample_rate < 1 or sample_rate > 768_000 or channels < 1 or channels > 32:
        raise InvalidArtifactError("RAW PCM parameters are outside supported bounds.")
    if bit_depth not in {8, 16, 24, 32}:
        raise InvalidArtifactError("RAW PCM bit depth must be 8, 16, 24, or 32.")
    width = bit_depth // 8
    usable = data[: len(data) - (len(data) % (width * channels))]
    byteorder = "little" if endianness == "little" else "big"
    if bit_depth == 8:
        values = np.frombuffer(usable, dtype=np.int8 if signed else np.uint8).astype(np.float64)
        if signed:
            values /= 128.0
        else:
            values = (values - 128.0) / 128.0
    elif bit_depth in {16, 32}:
        code = {16: "i2" if signed else "u2", 32: "i4" if signed else "u4"}[bit_depth]
        values = np.frombuffer(usable, dtype=("<" if byteorder == "little" else ">") + code).astype(np.float64)
        midpoint = float(1 << (bit_depth - 1))
        values = values / midpoint if signed else (values - midpoint) / midpoint
    else:
        packed = np.frombuffer(usable, dtype=np.uint8).reshape(-1, 3)
        if byteorder == "little":
            integers = packed[:, 0].astype(np.int64) | packed[:, 1].astype(np.int64) << 8 | packed[:, 2].astype(np.int64) << 16
        else:
            integers = packed[:, 2].astype(np.int64) | packed[:, 1].astype(np.int64) << 8 | packed[:, 0].astype(np.int64) << 16
        if signed:
            integers = np.where(integers & 0x800000, integers - 0x1000000, integers)
            values = integers.astype(np.float64) / 8_388_608.0
        else:
            values = (integers.astype(np.float64) - 8_388_608.0) / 8_388_608.0
    return PcmAudio(
        samples=np.clip(values.reshape(-1, channels), -1.0, 1.0),
        sample_rate=sample_rate,
        bit_depth=bit_depth,
        encoding=f"{'signed' if signed else 'unsigned'} PCM {bit_depth}-bit {byteorder}",
        data_offset=0,
        raw_sample_bytes=usable,
    )
