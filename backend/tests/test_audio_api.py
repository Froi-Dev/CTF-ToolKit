from __future__ import annotations

import base64
import io
import math
import struct
import wave
import zipfile

import numpy as np
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def _chunk(chunk_id: bytes, payload: bytes) -> bytes:
    return chunk_id + struct.pack("<I", len(payload)) + payload + (b"\x00" if len(payload) & 1 else b"")


def _wav_bytes(samples: np.ndarray, sample_rate: int = 8_000, extra_chunks: bytes = b"") -> bytes:
    values = np.asarray(samples)
    if values.ndim == 1:
        values = values[:, None]
    pcm = np.clip(values, -32768, 32767).astype("<i2").tobytes()
    fmt = struct.pack("<HHIIHH", 1, values.shape[1], sample_rate, sample_rate * values.shape[1] * 2, values.shape[1] * 2, 16)
    body = b"WAVE" + _chunk(b"fmt ", fmt) + extra_chunks + _chunk(b"data", pcm)
    return b"RIFF" + struct.pack("<I", len(body)) + body


def _analyze(data: bytes, filename: str = "challenge.wav"):
    return client.post(
        "/api/v1/forensics/audio/analyze",
        files={"file": (filename, data, "audio/wav")},
    )


def test_normal_wav_produces_real_signal_report_without_high_alerts() -> None:
    rate = 8_000
    time = np.arange(rate) / rate
    samples = np.rint(np.sin(2 * np.pi * 440 * time) * 8_000).astype(np.int16)

    response = _analyze(_wav_bytes(samples))

    assert response.status_code == 200
    result = response.json()
    assert result["file"]["container"] == "RIFF/WAVE"
    assert result["file"]["sample_rate"] == rate
    assert result["waveform"]["rms"] > 0
    assert result["spectrogram"]["artifact_id"]
    assert any(item["kind"] == "spectrogram" for item in result["artifacts"])
    assert result["flags"] == []
    assert not any(item["severity"] in {"critical", "high"} for item in result["findings"])


def test_base64_flag_in_riff_metadata_is_decoded() -> None:
    encoded = base64.b64encode(b"picoCTF{metadata_audio}") + b"\x00"
    info_payload = b"INFO" + _chunk(b"ICMT", encoded)
    wav = _wav_bytes(np.zeros(4_000, dtype=np.int16), extra_chunks=_chunk(b"LIST", info_payload))

    response = _analyze(wav)

    assert response.status_code == 200
    result = response.json()
    assert result["metadata"]["RIFF_INFO_ICMT"].startswith("cGljb0NUR")
    assert any(item["value"] == "picoCTF{metadata_audio}" for item in result["flags"])


def test_custom_riff_chunk_is_reported_with_offset_and_flag() -> None:
    wav = _wav_bytes(
        np.zeros(1_000, dtype=np.int16),
        extra_chunks=_chunk(b"FLAG", b"CTF{riff_chunk_evidence}"),
    )

    response = _analyze(wav)

    result = response.json()
    assert response.status_code == 200
    chunk = next(item for item in result["riff_chunks"] if item["chunk_id"] == "FLAG")
    assert chunk["offset"] > 0
    assert any(item["title"].startswith("Unexpected RIFF chunk") for item in result["findings"])
    assert any(item["value"] == "CTF{riff_chunk_evidence}" for item in result["flags"])


def test_appended_zip_is_carved_and_safe_members_are_scanned_for_flags() -> None:
    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("evidence/flag.txt", "HTB{appended_archive}")
    wav = _wav_bytes(np.zeros(1_000, dtype=np.int16)) + archive_buffer.getvalue()

    response = _analyze(wav)

    result = response.json()
    assert response.status_code == 200
    assert result["embedded_files"][0]["detected_type"] == "ZIP archive"
    assert any(item["kind"] == "embedded-file" for item in result["artifacts"])
    recovered = next(item for item in result["flags"] if item["value"] == "HTB{appended_archive}")
    assert recovered["source"] == "embedded_zip:evidence/flag.txt"


def test_pcm_lsb_flag_is_recovered_from_stereo_channel() -> None:
    message = b"picoCTF{right_channel_lsb}"
    bits = np.unpackbits(np.frombuffer(message, dtype=np.uint8), bitorder="big")
    frames = max(5_000, len(bits))
    samples = np.zeros((frames, 2), dtype=np.int16)
    samples[:, 0] = np.rint(np.sin(2 * np.pi * 220 * np.arange(frames) / 8_000) * 2_000).astype(np.int16)
    samples[: len(bits), 1] = bits

    response = _analyze(_wav_bytes(samples))

    result = response.json()
    assert response.status_code == 200
    candidate = next(item for item in result["flags"] if item["value"] == message.decode())
    assert candidate["source"] == "lsb_analysis"
    assert candidate["channel"] == "right"
    assert candidate["bit_plane"] == 0
    assert any(item["severity"] == "critical" for item in result["findings"])


def test_dtmf_sequence_is_detected_with_timestamps() -> None:
    rate = 8_000
    frequencies = {"7": (852, 1209), "4": (770, 1209), "2": (697, 1336)}
    parts: list[np.ndarray] = []
    for symbol in "742":
        count = round(rate * 0.18)
        time = np.arange(count) / rate
        low, high = frequencies[symbol]
        tone = (np.sin(2 * np.pi * low * time) + np.sin(2 * np.pi * high * time)) * 7_000
        parts.extend([tone.astype(np.int16), np.zeros(round(rate * 0.08), dtype=np.int16)])

    response = _analyze(_wav_bytes(np.concatenate(parts), rate))

    result = response.json()
    assert response.status_code == 200
    assert result["tones"]["dtmf_sequence"] == "742"
    assert len(result["tones"]["dtmf_events"]) == 3
    assert any(item["title"] == "DTMF sequence detected" for item in result["findings"])


def test_high_frequency_and_channel_anomalies_are_ranked_without_claiming_a_flag() -> None:
    rate = 44_100
    count = rate
    time = np.arange(count) / rate
    left = np.sin(2 * np.pi * 440 * time) * 5_000
    right = np.sin(2 * np.pi * 18_700 * time) * 12_000
    samples = np.stack([left, right], axis=1).astype(np.int16)

    response = _analyze(_wav_bytes(samples, rate))

    result = response.json()
    assert response.status_code == 200
    assert result["channel_correlation"] < 0.1
    assert result["tones"]["ultrasonic_peak_hz"] is not None
    assert abs(result["tones"]["ultrasonic_peak_hz"] - 18_700) < 50
    assert any(item["title"] == "Structured high-frequency energy" for item in result["findings"])
    assert result["flags"] == []


def test_raw_pcm_requires_explicit_format_parameters() -> None:
    response = _analyze(b"\x00" * 100, "challenge.raw")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_ARTIFACT"

