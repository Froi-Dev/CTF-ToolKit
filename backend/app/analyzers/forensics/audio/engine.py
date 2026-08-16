from __future__ import annotations

import base64
import binascii
import hashlib
import io
import mimetypes
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

import numpy as np

from app.analyzers.forensics.audio.context import AudioContext, PcmAudio
from app.analyzers.forensics.audio.dsp import (
    channel_metrics,
    shannon_entropy,
    spectrogram,
    tone_analysis,
    waveform_metrics,
    wav_bytes,
)
from app.analyzers.forensics.audio.riff import decode_raw_pcm, parse_wave
from app.core.analyzers import BaseAnalyzer
from app.core.errors import InvalidArtifactError, ToolExecutionError, ToolNotAvailableError
from app.core.flag_detection import FlagDetector
from app.integrations.audio_tools import AudioToolchain
from app.schemas.audio import (
    AudioAnalysisResponse,
    AudioArtifact,
    AudioFileSummary,
    AudioFinding,
    AudioFlagCandidate,
    AudioHashes,
    AudioLimits,
    EmbeddedAudioFile,
    LsbCandidate,
    SpectrogramReport,
    ToneAnalysis,
)


_SUPPORTED_EXTENSIONS = {"wav", "wave", "mp3", "flac", "ogg", "opus", "m4a", "aac", "aiff", "aif", "au", "raw", "pcm"}
_ASCII_STRINGS = re.compile(rb"[\x20-\x7e]{4,}")
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
_SIGNATURES = (
    (b"PK\x03\x04", "ZIP archive", "application/zip", "zip"),
    (b"\x89PNG\r\n\x1a\n", "PNG image", "image/png", "png"),
    (b"\xff\xd8\xff", "JPEG image", "image/jpeg", "jpg"),
    (b"%PDF-", "PDF document", "application/pdf", "pdf"),
    (b"GIF8", "GIF image", "image/gif", "gif"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive", "application/x-7z-compressed", "7z"),
    (b"Rar!\x1a\x07", "RAR archive", "application/vnd.rar", "rar"),
    (b"\x1f\x8b\x08", "gzip archive", "application/gzip", "gz"),
    (b"SQLite format 3\x00", "SQLite database", "application/vnd.sqlite3", "sqlite"),
    (b"\x7fELF", "ELF executable", "application/x-elf", "elf"),
    (b"MZ", "PE executable candidate", "application/vnd.microsoft.portable-executable", "exe"),
)


@dataclass(frozen=True, slots=True)
class AudioPolicy:
    max_upload_bytes: int = 64 * 1024 * 1024
    max_decoded_seconds: float = 300.0
    max_analysis_samples: int = 12_000_000
    max_generated_artifact_bytes: int = 8 * 1024 * 1024
    max_single_artifact_bytes: int = 2 * 1024 * 1024
    max_lsb_bit_plane: int = 2
    max_strings: int = 200


@dataclass(frozen=True, slots=True)
class RawPcmOptions:
    sample_rate: int
    bit_depth: int
    endianness: str
    channels: int
    signed: bool


@dataclass(frozen=True, slots=True)
class AudioInput:
    path: Path
    original_filename: str
    workspace: Path
    raw_options: RawPcmOptions | None = None
    custom_flag_prefix: str | None = None


@dataclass(frozen=True, slots=True)
class _Identification:
    detected_type: str
    mime_type: str
    container: str
    expected_extensions: tuple[str, ...]


def _identify(data: bytes) -> _Identification:
    if len(data) >= 12 and data[:4] in {b"RIFF", b"RIFX"} and data[8:12] == b"WAVE":
        return _Identification("WAV", "audio/wav", "RIFF/WAVE", ("wav", "wave"))
    if data.startswith(b"fLaC"):
        return _Identification("FLAC", "audio/flac", "FLAC", ("flac",))
    if data.startswith(b"OggS"):
        return _Identification("Ogg", "audio/ogg", "Ogg", ("ogg", "opus"))
    if data.startswith(b"ID3") or (len(data) >= 2 and data[0] == 0xFF and data[1] & 0xE0 == 0xE0):
        return _Identification("MP3/AAC", "audio/mpeg", "MPEG audio", ("mp3", "aac"))
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return _Identification("M4A", "audio/mp4", "ISO Base Media", ("m4a", "mp4"))
    if len(data) >= 12 and data[:4] == b"FORM" and data[8:12] in {b"AIFF", b"AIFC"}:
        return _Identification("AIFF", "audio/aiff", "AIFF", ("aiff", "aif"))
    if data.startswith(b".snd"):
        return _Identification("AU", "audio/basic", "Sun/NeXT AU", ("au",))
    return _Identification("unknown audio/raw data", "application/octet-stream", "unknown", tuple())


def _artifact(kind: str, filename: str, mime: str, description: str, content: bytes, policy: AudioPolicy) -> AudioArtifact:
    included = len(content) <= policy.max_single_artifact_bytes
    return AudioArtifact(
        artifact_id=str(uuid4()),
        filename=filename,
        kind=kind,  # type: ignore[arg-type]
        mime_type=mime,
        description=description,
        size=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        content_base64=base64.b64encode(content).decode("ascii") if included else None,
        truncated=not included,
    )


def _extract_strings(data: bytes, maximum: int) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for match in _ASCII_STRINGS.finditer(data):
        value = match.group(0)[:2048].decode("ascii", errors="replace")
        if value not in seen:
            seen.add(value)
            values.append(value)
        if len(values) >= maximum:
            break
    return values


def _decoded_candidates(strings: list[str]) -> list[tuple[str, bytes]]:
    candidates: list[tuple[str, bytes]] = []
    for text in strings:
        for match in _BASE64.finditer(text):
            token = match.group(0)
            try:
                decoded = base64.b64decode(token, validate=True)
            except (binascii.Error, ValueError):
                continue
            if decoded and len(decoded) <= 1024 * 1024:
                candidates.append(("Base64 string", decoded))
        for match in _HEX.finditer(text):
            try:
                decoded = bytes.fromhex(match.group(0))
            except ValueError:
                continue
            if decoded and len(decoded) <= 1024 * 1024:
                candidates.append(("hex string", decoded))
    return candidates[:50]


def _probe_values(probe: dict[str, Any]) -> tuple[dict[str, str], dict[str, Any]]:
    metadata: dict[str, str] = {}
    details: dict[str, Any] = {}
    format_data = probe.get("format") if isinstance(probe.get("format"), dict) else {}
    streams = probe.get("streams") if isinstance(probe.get("streams"), list) else []
    audio = next((item for item in streams if isinstance(item, dict) and item.get("codec_type") == "audio"), {})
    for source in (format_data.get("tags", {}), audio.get("tags", {})):
        if isinstance(source, dict):
            for key, value in source.items():
                metadata[str(key)] = str(value)[:4096]
    details.update(
        codec=str(audio.get("codec_name") or "unknown"),
        encoding=str(audio.get("codec_long_name") or audio.get("codec_name") or "unknown"),
        container=str(format_data.get("format_long_name") or format_data.get("format_name") or "unknown"),
        duration=float(format_data["duration"]) if format_data.get("duration") else None,
        sample_rate=int(audio["sample_rate"]) if audio.get("sample_rate") else None,
        bit_rate=int(audio["bit_rate"]) if audio.get("bit_rate") else None,
        bit_depth=int(audio.get("bits_per_raw_sample") or audio.get("bits_per_sample") or 0) or None,
        channels=int(audio["channels"]) if audio.get("channels") else None,
        channel_layout=str(audio.get("channel_layout")) if audio.get("channel_layout") else None,
    )
    return metadata, details


def _raw_sample_values(pcm: PcmAudio) -> np.ndarray | None:
    raw = pcm.raw_sample_bytes
    if pcm.bit_depth == 8:
        values = np.frombuffer(raw, dtype=np.uint8).astype(np.uint32)
    elif pcm.bit_depth == 16:
        values = np.frombuffer(raw, dtype="<u2").astype(np.uint32)
    elif pcm.bit_depth == 24:
        packed = np.frombuffer(raw, dtype=np.uint8).reshape(-1, 3)
        values = packed[:, 0].astype(np.uint32) | packed[:, 1].astype(np.uint32) << 8 | packed[:, 2].astype(np.uint32) << 16
    elif pcm.bit_depth == 32 and "float" not in pcm.encoding.lower():
        values = np.frombuffer(raw, dtype="<u4")
    else:
        return None
    return values.reshape(-1, pcm.channels)


def _recognized_type(data: bytes) -> str | None:
    for magic, name, _, _ in _SIGNATURES:
        if data.startswith(magic):
            return name
    return None


def _lsb_analysis(
    pcm: PcmAudio,
    detector: FlagDetector,
    policy: AudioPolicy,
) -> tuple[list[LsbCandidate], list[AudioFlagCandidate], list[AudioArtifact]]:
    values = _raw_sample_values(pcm)
    if values is None:
        return [], [], []
    names = ["left", "right"] + [f"channel-{index + 1}" for index in range(2, pcm.channels)]
    streams = [("all-interleaved", values.reshape(-1))] + [(names[index], values[:, index]) for index in range(pcm.channels)]
    candidates: list[LsbCandidate] = []
    flags: list[AudioFlagCandidate] = []
    artifacts: list[AudioArtifact] = []
    for channel_name, samples in streams:
        for plane in range(policy.max_lsb_bit_plane + 1):
            bits = ((samples >> plane) & 1).astype(np.uint8)
            for bit_order in ("big", "little"):
                recovered = np.packbits(bits[: policy.max_analysis_samples], bitorder=bit_order).tobytes()
                detected_flags = detector.detect(recovered)
                recognized = _recognized_type(recovered)
                sample = recovered[: min(len(recovered), 32_768)]
                printable = sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in sample) / max(1, len(sample))
                interesting = bool(detected_flags or recognized or printable >= 0.78)
                if not interesting:
                    continue
                artifact = _artifact(
                    "lsb-extraction",
                    f"lsb_{channel_name}_bit{plane}_{'msb' if bit_order == 'big' else 'lsb'}.bin",
                    "application/octet-stream",
                    f"PCM bit-plane {plane} extracted from {channel_name} samples.",
                    recovered,
                    policy,
                )
                artifacts.append(artifact)
                preview = sample[:160].decode("utf-8", errors="replace") if printable >= 0.5 else None
                candidates.append(
                    LsbCandidate(
                        channel=channel_name,
                        bit_plane=plane,
                        bit_order="msb-first" if bit_order == "big" else "lsb-first",
                        printable_ratio=round(printable, 4),
                        entropy=shannon_entropy(sample),
                        recognized_type=recognized,
                        preview=preview,
                        artifact_id=artifact.artifact_id,
                    )
                )
                for found in detected_flags:
                    flags.append(
                        AudioFlagCandidate(
                            value=found.value,
                            confidence=0.99,
                            source="lsb_analysis",
                            extraction_method=f"{channel_name} bit {plane}, {'MSB' if bit_order == 'big' else 'LSB'}-first",
                            offset=found.offset,
                            channel=channel_name,
                            bit_plane=plane,
                            context=found.context,
                        )
                    )
    return candidates[:12], flags, artifacts[:12]


def _find_embedded(data: bytes, start: int, policy: AudioPolicy) -> tuple[list[EmbeddedAudioFile], list[AudioArtifact]]:
    results: list[EmbeddedAudioFile] = []
    artifacts: list[AudioArtifact] = []
    for magic, name, mime, extension in _SIGNATURES:
        offset = data.find(magic, start)
        if offset < 0:
            continue
        content = data[offset:]
        if not content:
            continue
        artifact = _artifact("embedded-file", f"embedded_{offset:08x}.{extension}", mime, f"Carved {name} beginning at file offset 0x{offset:x}.", content, policy)
        artifacts.append(artifact)
        results.append(EmbeddedAudioFile(offset=offset, detected_type=name, size=len(content), artifact_id=artifact.artifact_id))
    return results[:16], artifacts[:16]


def _inspect_embedded_archive(data: bytes, offset: int) -> list[tuple[str, bytes]]:
    """Read small regular ZIP members in memory without writing or executing them."""
    if not data[offset:].startswith(b"PK\x03\x04"):
        return []
    discovered: list[tuple[str, bytes]] = []
    expanded = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data[offset:])) as archive:
            for member in archive.infolist()[:100]:
                normalized = member.filename.replace("\\", "/")
                parts = [part for part in normalized.split("/") if part not in {"", "."}]
                if member.is_dir() or not parts or ".." in parts or normalized.startswith("/"):
                    continue
                if member.flag_bits & 0x1 or member.file_size > 1024 * 1024:
                    continue
                ratio = member.file_size / max(1, member.compress_size)
                if ratio > 100 or expanded + member.file_size > 4 * 1024 * 1024:
                    continue
                payload = archive.read(member)
                expanded += len(payload)
                discovered.append(("/".join(parts), payload))
    except (zipfile.BadZipFile, RuntimeError, OSError, ValueError):
        return []
    return discovered


class AudioAnalysisEngine(BaseAnalyzer[AudioInput, AudioAnalysisResponse]):
    name = "audio_forensics"
    category = "forensics"

    def __init__(self, policy: AudioPolicy | None = None, tools: AudioToolchain | None = None) -> None:
        self.policy = policy or AudioPolicy()
        self.tools = tools or AudioToolchain()

    def supports(self, value: object) -> bool:
        if not isinstance(value, AudioInput) or not value.path.is_file():
            return False
        extension = Path(value.original_filename).suffix.lower().lstrip(".")
        return extension in _SUPPORTED_EXTENSIONS or _identify(value.path.read_bytes()[:64]).container != "unknown"

    def analyze(self, value: AudioInput) -> AudioAnalysisResponse:
        if not isinstance(value, AudioInput) or not value.path.is_file():
            raise InvalidArtifactError("Audio analysis requires a regular uploaded file.")
        data = value.path.read_bytes()
        if not data:
            raise InvalidArtifactError("An empty file cannot be analyzed as audio.")
        if len(data) > self.policy.max_upload_bytes:
            raise InvalidArtifactError("The audio artifact exceeds the analyzer size limit.")
        identification = _identify(data)
        extension = Path(value.original_filename).suffix.lower().lstrip(".") or None
        if not self.supports(value):
            raise InvalidArtifactError("The uploaded file is not a recognized or supported audio artifact.")

        context = AudioContext(value.path, value.path, value.workspace, value.original_filename, data)
        tools = self.tools.availability()
        probe_details: dict[str, Any] = {}
        if tools["ffprobe"]:
            try:
                probe = self.tools.probe(value.path, cwd=value.workspace)
                context.metadata, probe_details = _probe_values(probe)
            except ToolExecutionError:
                context.errors.append("ffprobe failed; container-native identification continued.")
        else:
            context.errors.append("ffprobe unavailable; container-native identification continued.")

        riff_chunks = []
        container_end = len(data)
        if identification.container == "RIFF/WAVE":
            parsed = parse_wave(data)
            context.pcm = parsed.pcm
            context.metadata.update(parsed.metadata)
            context.errors.extend(parsed.warnings)
            riff_chunks = parsed.chunks
            container_end = parsed.container_end
        elif extension in {"raw", "pcm"}:
            if value.raw_options is None:
                raise InvalidArtifactError("RAW/PCM uploads require sample rate, bit depth, endianness, channel count, and signedness.")
            context.pcm = decode_raw_pcm(
                data,
                sample_rate=value.raw_options.sample_rate,
                bit_depth=value.raw_options.bit_depth,
                channels=value.raw_options.channels,
                endianness=value.raw_options.endianness,
                signed=value.raw_options.signed,
            )
            identification = _Identification("RAW PCM", "audio/L16", "raw PCM", ("raw", "pcm"))
        elif tools["ffmpeg"]:
            normalized = value.workspace / "normalized-analysis.wav"
            try:
                self.tools.normalize(value.path, normalized, cwd=value.workspace, seconds=self.policy.max_decoded_seconds)
                normalized_data = normalized.read_bytes()
                parsed = parse_wave(normalized_data)
                context.working_path = normalized
                context.pcm = parsed.pcm
                context.errors.extend(parsed.warnings)
            except (ToolExecutionError, InvalidArtifactError, OSError):
                context.errors.append("FFmpeg normalization failed; signal-domain analyzers were skipped.")
        else:
            context.errors.append("FFmpeg unavailable; compressed audio signal analysis was skipped.")

        if context.pcm and context.pcm.frames > self.policy.max_analysis_samples:
            context.pcm.samples = context.pcm.samples[: self.policy.max_analysis_samples]
            frame_bytes = context.pcm.channels * (context.pcm.bit_depth // 8)
            context.pcm.raw_sample_bytes = context.pcm.raw_sample_bytes[: self.policy.max_analysis_samples * frame_bytes]
            context.errors.append("Decoded signal analysis was truncated at the configured sample limit.")
        if context.pcm and context.pcm.duration_seconds > self.policy.max_decoded_seconds:
            frames = int(self.policy.max_decoded_seconds * context.pcm.sample_rate)
            context.pcm.samples = context.pcm.samples[:frames]
            frame_bytes = context.pcm.channels * (context.pcm.bit_depth // 8)
            context.pcm.raw_sample_bytes = context.pcm.raw_sample_bytes[: frames * frame_bytes]
            context.errors.append("Decoded signal analysis was truncated at the configured duration limit.")

        prefixes = ["flag", "FLAG", "CTF", "picoCTF", "HTB", "H4G"]
        if value.custom_flag_prefix:
            prefixes.append(value.custom_flag_prefix)
        detector = FlagDetector(list(dict.fromkeys(prefixes)))
        strings = _extract_strings(data, self.policy.max_strings)
        flag_candidates: list[AudioFlagCandidate] = []
        seen_flags: set[tuple[str, str]] = set()

        def add_flags(source: str, method: str, candidate_data: bytes, confidence: float) -> None:
            for found in detector.detect(candidate_data):
                key = (found.value, source)
                if key in seen_flags:
                    continue
                seen_flags.add(key)
                flag_candidates.append(
                    AudioFlagCandidate(
                        value=found.value,
                        confidence=confidence,
                        source=source,
                        extraction_method=method,
                        offset=found.offset,
                        context=found.context,
                    )
                )

        add_flags("original_file", "direct byte scan", data, 0.97)
        for source, decoded in _decoded_candidates(strings + list(context.metadata.values())):
            add_flags("metadata_or_strings", f"safe {source} decoding", decoded, 0.99)

        artifacts: list[AudioArtifact] = []
        embedded_files, embedded_artifacts = _find_embedded(data, container_end, self.policy)
        artifacts.extend(embedded_artifacts)
        for item, artifact in zip(embedded_files, embedded_artifacts):
            if artifact.content_base64:
                carved = base64.b64decode(artifact.content_base64)
                add_flags(f"embedded_file@0x{item.offset:x}", "carve and string scan", carved, 0.98)
                if item.detected_type == "ZIP archive":
                    for member_name, payload in _inspect_embedded_archive(data, item.offset):
                        add_flags(
                            f"embedded_zip:{member_name}",
                            "bounded ZIP member extraction and string scan",
                            payload,
                            0.99,
                        )

        waveform = None
        channels = []
        correlation = None
        spectrum_report = None
        tones = ToneAnalysis()
        lsb_candidates: list[LsbCandidate] = []
        findings: list[AudioFinding] = []
        recommendations: list[str] = []

        expected = identification.expected_extensions
        extension_matches = extension in expected if expected else extension in {"raw", "pcm"}
        if not extension_matches:
            findings.append(AudioFinding(severity="high", title="Filename extension does not match detected audio", confidence=0.98, description=f"The file uses .{extension or '(none)'} but its header identifies {identification.container} content.", method="magic bytes and container header comparison", recommendation="Treat the extension as untrusted and continue with the detected container."))

        unknown_chunks = [chunk for chunk in riff_chunks if not chunk.known]
        for chunk in unknown_chunks:
            severity = "high" if chunk.preview and detector.detect(chunk.preview.encode()) else "medium"
            findings.append(AudioFinding(severity=severity, title=f"Unexpected RIFF chunk {chunk.chunk_id!r}", confidence=0.95 if severity == "high" else 0.8, description="A non-standard chunk is present inside the WAV container and may carry challenge data.", location=f"file offset 0x{chunk.offset:x}", method="bounded RIFF chunk parser", recommendation="Inspect the chunk preview and extracted strings.", evidence={"size": chunk.size, "preview": chunk.preview}))
            if chunk.preview:
                add_flags(f"RIFF_chunk_{chunk.chunk_id}", "RIFF chunk parsing", chunk.preview.encode(), 0.99)

        if embedded_files:
            first = embedded_files[0]
            findings.append(AudioFinding(severity="high", title="Data embedded after the audio container", confidence=0.98, description=f"A {first.detected_type} begins after the legitimate audio boundary.", location=f"file offset 0x{first.offset:x}", method="container boundary and magic-signature scanning", recommendation="Download and inspect the carved artifact; extracted files were never executed."))

        if context.pcm:
            pcm = context.pcm
            waveform = waveform_metrics(pcm)
            channels, correlation = channel_metrics(pcm)
            if waveform.clipping_ratio > 0.05:
                findings.append(AudioFinding(severity="low", title="Substantial waveform clipping", confidence=0.9, description=f"{waveform.clipping_ratio:.1%} of analyzed samples are at full scale.", method="sample amplitude distribution", recommendation="Inspect clipped regions; deliberate saturation can obscure low-bit signals."))
            if abs(waveform.dc_offset) > 0.05:
                findings.append(AudioFinding(severity="low", title="Unusual DC offset", confidence=0.85, description=f"The mean normalized amplitude is {waveform.dc_offset:.4f}.", method="waveform mean", recommendation="Remove DC offset before manual amplification or filtering."))
            if correlation is not None and correlation < 0.5:
                findings.append(AudioFinding(severity="medium", title="Low stereo channel correlation", confidence=min(0.95, 0.7 + (0.5 - correlation) * 0.4), description=f"Left/right correlation is {correlation:.3f}; one channel may contain independent evidence.", method="Pearson correlation of decoded channels", recommendation="Inspect and listen to the left, right, and difference-channel artifacts separately."))
            try:
                spectrum = spectrogram(pcm)
                spec_artifact = _artifact("spectrogram", "spectrogram.png", "image/png", "Forensic 80 dB STFT spectrogram of the analyzed signal.", spectrum.png, self.policy)
                artifacts.append(spec_artifact)
                spectrum_report = SpectrogramReport(fft_size=spectrum.fft_size, hop_size=spectrum.hop_size, dynamic_range_db=80, maximum_frequency_hz=pcm.sample_rate / 2, duration_seconds=round(pcm.duration_seconds, 4), frequency_band_energy=spectrum.band_energy, artifact_id=spec_artifact.artifact_id)
                tones = tone_analysis(pcm, ultrasonic_peak=spectrum.ultrasonic_peak_hz, ultrasonic_ratio=spectrum.ultrasonic_ratio)
            except (ValueError, MemoryError):
                context.errors.append("Spectrogram generation was skipped because the decoded signal was too short or exceeded resources.")
            if tones.ultrasonic_energy_ratio >= 0.02 and tones.ultrasonic_peak_hz:
                findings.append(AudioFinding(severity="medium", title="Structured high-frequency energy", confidence=min(0.95, 0.65 + tones.ultrasonic_energy_ratio * 2), description=f"{tones.ultrasonic_energy_ratio:.2%} of spectral energy lies above 16 kHz, peaking near {tones.ultrasonic_peak_hz:.1f} Hz.", location="16 kHz to Nyquist", method="STFT frequency-band energy comparison", recommendation="Inspect the high-frequency portion of the generated spectrogram."))
                recommendations.append(f"Inspect the spectrogram around {tones.ultrasonic_peak_hz:.0f} Hz for structured ultrasonic content.")
            if tones.dtmf_events:
                findings.append(AudioFinding(severity="high", title="DTMF sequence detected", confidence=min(event.confidence for event in tones.dtmf_events), description=f"Decoded telephone-tone sequence: {tones.dtmf_sequence}", location=f"{tones.dtmf_events[0].start_seconds:.3f}s–{tones.dtmf_events[-1].end_seconds:.3f}s", method="windowed dual-frequency correlation", recommendation="Treat the sequence as a PIN, numeric key, or encoded lead and correlate it with other findings."))
            if tones.morse_text:
                findings.append(AudioFinding(severity="medium", title="Possible Morse-code signal", confidence=tones.morse_confidence or 0.5, description=f"Decoded candidate: {tones.morse_text}", method="dominant-carrier pulse-duration analysis", recommendation="Verify the generated symbols manually; unresolved symbols are shown as '?'.", evidence={"symbols": tones.morse_symbols, "carrier_hz": tones.carrier_hz}))

            lsb_candidates, lsb_flags, lsb_artifacts = _lsb_analysis(pcm, detector, self.policy)
            flag_candidates.extend(lsb_flags)
            artifacts.extend(lsb_artifacts)
            if lsb_flags:
                best = lsb_flags[0]
                findings.append(AudioFinding(severity="critical", title="Potential flag recovered from PCM bit plane", confidence=best.confidence, description=f"Recovered {best.value} from {best.extraction_method}.", method="PCM LSB extraction and centralized flag matching", recommendation="Review and submit only after corroborating the candidate with the challenge context."))
            elif lsb_candidates:
                best = lsb_candidates[0]
                findings.append(AudioFinding(severity="medium", title="Structured PCM bit-plane data", confidence=0.75 if best.recognized_type else 0.6, description=f"Bit plane {best.bit_plane} in {best.channel} produced {'a ' + best.recognized_type if best.recognized_type else f'{best.printable_ratio:.1%} printable data'}.", method="PCM bit-plane extraction and content scoring", recommendation="Inspect the highest-ranked LSB extraction artifact; this is supporting evidence, not proof of steganography."))

            excerpt_frames = min(pcm.frames, pcm.sample_rate * 10)
            if pcm.channels >= 2 and (correlation is None or correlation < 0.95):
                for index, label in ((0, "left"), (1, "right")):
                    artifacts.append(_artifact("channel", f"{label}_channel_excerpt.wav", "audio/wav", f"First ten seconds of the isolated {label} channel.", wav_bytes(pcm.samples[:excerpt_frames, index], pcm.sample_rate), self.policy))
                difference = np.clip(pcm.samples[:excerpt_frames, 0] - pcm.samples[:excerpt_frames, 1], -1, 1)
                artifacts.append(_artifact("difference-channel", "difference_channel_excerpt.wav", "audio/wav", "First ten seconds of L-R phase-cancellation analysis.", wav_bytes(difference, pcm.sample_rate), self.policy))
            artifacts.append(_artifact("reversed", "reversed_excerpt.wav", "audio/wav", "First ten seconds of analyzed audio reversed for manual listening.", wav_bytes(pcm.samples[:excerpt_frames][::-1], pcm.sample_rate), self.policy))

        for candidate in flag_candidates:
            if not any(item.title.startswith("Potential flag") for item in findings):
                findings.append(AudioFinding(severity="critical", title="Potential flag recovered", confidence=candidate.confidence, description=f"Recovered {candidate.value} using {candidate.extraction_method}.", method="centralized candidate extraction and flag matching", recommendation="Review the candidate before treating it as confirmed."))
                break

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda item: (severity_order[item.severity], -item.confidence))
        unique_flags: list[AudioFlagCandidate] = []
        flag_keys: set[tuple[str, str, str | None, int | None]] = set()
        for candidate in flag_candidates:
            key = (candidate.value, candidate.source, candidate.channel, candidate.bit_plane)
            if key not in flag_keys:
                flag_keys.add(key)
                unique_flags.append(candidate)
        total_artifact_bytes = 0
        bounded_artifacts: list[AudioArtifact] = []
        for artifact in artifacts:
            if total_artifact_bytes + artifact.size > self.policy.max_generated_artifact_bytes:
                context.errors.append("Additional generated artifacts were omitted at the aggregate artifact limit.")
                break
            total_artifact_bytes += artifact.size
            bounded_artifacts.append(artifact)

        duration = context.pcm.duration_seconds if context.pcm else probe_details.get("duration")
        sample_rate = context.pcm.sample_rate if context.pcm else probe_details.get("sample_rate")
        bit_depth = context.pcm.bit_depth if context.pcm else probe_details.get("bit_depth")
        channel_count = context.pcm.channels if context.pcm else probe_details.get("channels")
        codec = context.pcm.encoding if context.pcm else probe_details.get("codec", "unknown")
        encoding = context.pcm.encoding if context.pcm else probe_details.get("encoding", "unknown")
        summary = (
            f"Recovered {len(unique_flags)} potential flag candidate(s). The strongest evidence is {findings[0].title.lower()}."
            if unique_flags and findings
            else f"No direct flag was recovered. The strongest lead is {findings[0].title.lower()}."
            if findings
            else "No direct flag or high-confidence anomaly was recovered from the available analysis stages."
        )
        if not recommendations and spectrum_report:
            recommendations.append("Inspect the generated full-spectrum spectrogram and correlate visible structures with channel and tone results.")

        file_summary = AudioFileSummary(
            name=value.original_filename,
            size=len(data),
            hashes=AudioHashes(md5=hashlib.md5(data, usedforsecurity=False).hexdigest(), sha256=hashlib.sha256(data).hexdigest()),
            detected_type=identification.detected_type,
            mime_type=identification.mime_type or mimetypes.guess_type(value.original_filename)[0] or "application/octet-stream",
            extension=extension,
            extension_matches=extension_matches,
            container=probe_details.get("container", identification.container),
            codec=str(codec),
            encoding=str(encoding),
            duration_seconds=round(float(duration), 6) if duration is not None else None,
            sample_rate=sample_rate,
            bit_rate=probe_details.get("bit_rate"),
            bit_depth=bit_depth,
            channels=channel_count,
            channel_layout=probe_details.get("channel_layout") or ({1: "mono", 2: "stereo"}.get(channel_count) if channel_count else None),
        )
        return AudioAnalysisResponse(
            analysis_id=str(uuid4()),
            file=file_summary,
            metadata=context.metadata,
            strings=strings,
            riff_chunks=riff_chunks,
            waveform=waveform,
            channels=channels,
            channel_correlation=correlation,
            spectrogram=spectrum_report,
            tones=tones,
            lsb_candidates=lsb_candidates,
            embedded_files=embedded_files,
            flags=unique_flags,
            findings=findings,
            artifacts=bounded_artifacts,
            tools=tools,
            errors=context.errors,
            recommendations=recommendations,
            summary=summary,
            limits=AudioLimits(
                max_upload_bytes=self.policy.max_upload_bytes,
                max_decoded_seconds=self.policy.max_decoded_seconds,
                max_analysis_samples=self.policy.max_analysis_samples,
                max_generated_artifact_bytes=self.policy.max_generated_artifact_bytes,
                max_lsb_bit_plane=self.policy.max_lsb_bit_plane,
            ),
        )
