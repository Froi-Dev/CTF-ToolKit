from __future__ import annotations

import io
import math
import wave
from collections import Counter
from dataclasses import dataclass

import numpy as np
from PIL import Image

from app.analyzers.forensics.audio.context import PcmAudio
from app.schemas.audio import ChannelMetrics, DtmfEvent, ToneAnalysis, WaveformMetrics


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return round(-sum((count / length) * math.log2(count / length) for count in counts.values()), 4)


def waveform_metrics(pcm: PcmAudio) -> WaveformMetrics:
    values = pcm.samples
    mono = values.mean(axis=1) if values.size else np.empty(0)
    if not mono.size:
        return WaveformMetrics(peak=0, rms=0, dc_offset=0, clipping_ratio=0, silence_ratio=1, zero_crossing_rate=0, analyzed_samples=0)
    peak = float(np.max(np.abs(mono)))
    rms = float(np.sqrt(np.mean(np.square(mono))))
    crossings = float(np.mean(np.signbit(mono[1:]) != np.signbit(mono[:-1]))) if len(mono) > 1 else 0.0
    return WaveformMetrics(
        peak=round(peak, 6),
        rms=round(rms, 6),
        dc_offset=round(float(np.mean(mono)), 6),
        clipping_ratio=round(float(np.mean(np.abs(mono) >= 0.999)), 6),
        silence_ratio=round(float(np.mean(np.abs(mono) < 0.001)), 6),
        zero_crossing_rate=round(crossings, 6),
        analyzed_samples=len(mono),
    )


def _frequency_ratio(samples: np.ndarray, sample_rate: int, threshold_hz: float = 16_000) -> float:
    if len(samples) < 64 or sample_rate / 2 <= threshold_hz:
        return 0.0
    maximum = min(len(samples), 262_144)
    signal = samples[:maximum] - np.mean(samples[:maximum])
    spectrum = np.square(np.abs(np.fft.rfft(signal * np.hanning(len(signal)))))
    total = float(np.sum(spectrum))
    if total <= 0:
        return 0.0
    frequencies = np.fft.rfftfreq(len(signal), 1 / sample_rate)
    return min(1.0, float(np.sum(spectrum[frequencies >= threshold_hz]) / total))


def channel_metrics(pcm: PcmAudio) -> tuple[list[ChannelMetrics], float | None]:
    names = ["left", "right"] + [f"channel-{index + 1}" for index in range(2, pcm.channels)]
    results: list[ChannelMetrics] = []
    for index in range(pcm.channels):
        values = pcm.samples[:, index]
        quantized = np.clip(np.rint((values + 1.0) * 127.5), 0, 255).astype(np.uint8).tobytes()
        results.append(
            ChannelMetrics(
                channel=names[index],
                rms=round(float(np.sqrt(np.mean(np.square(values)))) if values.size else 0.0, 6),
                peak=round(float(np.max(np.abs(values))) if values.size else 0.0, 6),
                dc_offset=round(float(np.mean(values)) if values.size else 0.0, 6),
                entropy=shannon_entropy(quantized),
                high_frequency_ratio=round(_frequency_ratio(values, pcm.sample_rate), 6),
            )
        )
    correlation = None
    if pcm.channels >= 2 and pcm.frames > 1:
        left, right = pcm.samples[:, 0], pcm.samples[:, 1]
        if np.std(left) > 1e-12 and np.std(right) > 1e-12:
            correlation = round(float(np.corrcoef(left, right)[0, 1]), 6)
        elif np.allclose(left, right):
            correlation = 1.0
        else:
            correlation = 0.0
    return results, correlation


@dataclass(frozen=True, slots=True)
class SpectrogramData:
    png: bytes
    fft_size: int
    hop_size: int
    band_energy: dict[str, float]
    ultrasonic_peak_hz: float | None
    ultrasonic_ratio: float


def spectrogram(pcm: PcmAudio, *, width: int = 1200, height: int = 520) -> SpectrogramData:
    samples = pcm.samples.mean(axis=1)
    if len(samples) < 64:
        raise ValueError("Not enough decoded samples for a spectrogram.")
    fft_size = 4096 if pcm.sample_rate >= 32_000 else 2048
    fft_size = min(fft_size, 1 << int(math.floor(math.log2(len(samples)))))
    fft_size = max(64, fft_size)
    hop = max(1, fft_size // 4)
    frame_count = max(1, 1 + (len(samples) - fft_size) // hop)
    if frame_count > width:
        hop = max(hop, (len(samples) - fft_size) // width + 1)
        frame_count = max(1, 1 + (len(samples) - fft_size) // hop)
    starts = np.arange(frame_count) * hop
    frames = np.stack([samples[start : start + fft_size] for start in starts])
    power = np.square(np.abs(np.fft.rfft(frames * np.hanning(fft_size), axis=1)))
    aggregate = np.sum(power, axis=0)
    total = float(np.sum(aggregate)) or 1.0
    frequencies = np.fft.rfftfreq(fft_size, 1 / pcm.sample_rate)
    boundaries = [(0, 4_000), (4_000, 8_000), (8_000, 16_000), (16_000, pcm.sample_rate / 2 + 1)]
    bands: dict[str, float] = {}
    for low, high in boundaries:
        if low >= pcm.sample_rate / 2:
            continue
        mask = (frequencies >= low) & (frequencies < high)
        bands[f"{int(low)}-{int(min(high, pcm.sample_rate / 2))} Hz"] = round(float(np.sum(aggregate[mask]) / total), 6)
    ultrasonic_mask = frequencies >= 16_000
    ultrasonic_ratio = float(np.sum(aggregate[ultrasonic_mask]) / total) if np.any(ultrasonic_mask) else 0.0
    ultrasonic_peak = None
    if np.any(ultrasonic_mask) and np.max(aggregate[ultrasonic_mask]) > 0:
        ultrasonic_peak = float(frequencies[ultrasonic_mask][np.argmax(aggregate[ultrasonic_mask])])

    db = 10.0 * np.log10(power.T + 1e-12)
    ceiling = float(np.percentile(db, 99.7))
    normalized = np.clip((db - (ceiling - 80.0)) / 80.0, 0.0, 1.0)
    # A high-contrast inferno-like palette without a plotting dependency.
    red = np.clip(normalized * 3.0, 0, 1)
    green = np.clip(normalized * 3.0 - 1.0, 0, 1)
    blue = np.clip(normalized * 3.0 - 2.0, 0, 1)
    rgb = (np.stack([red, green, blue], axis=2)[::-1] * 255).astype(np.uint8)
    image = Image.fromarray(rgb, mode="RGB").resize((width, height), Image.Resampling.BILINEAR)
    output = io.BytesIO()
    image.save(output, format="PNG", optimize=True)
    return SpectrogramData(output.getvalue(), fft_size, hop, bands, ultrasonic_peak, round(ultrasonic_ratio, 6))


_DTMF_ROWS = [697.0, 770.0, 852.0, 941.0]
_DTMF_COLS = [1209.0, 1336.0, 1477.0, 1633.0]
_DTMF_SYMBOLS = [
    ["1", "2", "3", "A"],
    ["4", "5", "6", "B"],
    ["7", "8", "9", "C"],
    ["*", "0", "#", "D"],
]


def _tone_power(frame: np.ndarray, sample_rate: int, frequency: float) -> float:
    phase = 2 * np.pi * frequency * np.arange(len(frame)) / sample_rate
    value = abs(np.dot(frame, np.exp(-1j * phase))) ** 2
    return float(value) / max(1, len(frame) ** 2)


def detect_dtmf(pcm: PcmAudio) -> list[DtmfEvent]:
    mono = pcm.samples.mean(axis=1)
    frame_size = max(128, round(pcm.sample_rate * 0.04))
    hop = max(64, round(pcm.sample_rate * 0.02))
    labels: list[tuple[str | None, float, float]] = []
    for start in range(0, max(0, len(mono) - frame_size + 1), hop):
        frame = mono[start : start + frame_size]
        energy = float(np.mean(np.square(frame)))
        if energy < 1e-5:
            labels.append((None, 0.0, start / pcm.sample_rate))
            continue
        windowed = (frame - np.mean(frame)) * np.hanning(frame_size)
        rows = [_tone_power(windowed, pcm.sample_rate, frequency) for frequency in _DTMF_ROWS]
        cols = [_tone_power(windowed, pcm.sample_rate, frequency) for frequency in _DTMF_COLS]
        row_order = np.argsort(rows)[::-1]
        col_order = np.argsort(cols)[::-1]
        row_ratio = rows[row_order[0]] / max(rows[row_order[1]], 1e-12)
        col_ratio = cols[col_order[0]] / max(cols[col_order[1]], 1e-12)
        tone_fraction = (rows[row_order[0]] + cols[col_order[0]]) / max(energy, 1e-12)
        if row_ratio >= 3.0 and col_ratio >= 3.0 and tone_fraction >= 0.12:
            confidence = min(0.99, 0.55 + min(row_ratio, col_ratio) / 30 + min(tone_fraction, 1) * 0.2)
            labels.append((_DTMF_SYMBOLS[row_order[0]][col_order[0]], confidence, start / pcm.sample_rate))
        else:
            labels.append((None, 0.0, start / pcm.sample_rate))

    events: list[DtmfEvent] = []
    index = 0
    while index < len(labels):
        symbol = labels[index][0]
        if symbol is None:
            index += 1
            continue
        end = index + 1
        confidences = [labels[index][1]]
        while end < len(labels) and labels[end][0] == symbol:
            confidences.append(labels[end][1])
            end += 1
        duration = (end - index - 1) * hop / pcm.sample_rate + frame_size / pcm.sample_rate
        if duration >= 0.06:
            events.append(
                DtmfEvent(
                    symbol=symbol,
                    start_seconds=round(labels[index][2], 4),
                    end_seconds=round(labels[index][2] + duration, 4),
                    confidence=round(float(np.mean(confidences)), 4),
                )
            )
        index = end
    return events


_MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}


def detect_morse(pcm: PcmAudio) -> tuple[str | None, str | None, float | None, float | None]:
    mono = pcm.samples.mean(axis=1)
    if len(mono) < pcm.sample_rate // 2:
        return None, None, None, None
    sample = mono[: min(len(mono), pcm.sample_rate * 60)]
    spectrum = np.abs(np.fft.rfft(sample * np.hanning(len(sample))))
    frequencies = np.fft.rfftfreq(len(sample), 1 / pcm.sample_rate)
    mask = (frequencies >= 300) & (frequencies <= min(3000, pcm.sample_rate / 2))
    if not np.any(mask):
        return None, None, None, None
    peak_index = np.flatnonzero(mask)[np.argmax(spectrum[mask])]
    carrier = float(frequencies[peak_index])
    window = max(64, round(pcm.sample_rate * 0.01))
    envelope = []
    for start in range(0, len(sample) - window + 1, window):
        envelope.append(_tone_power(sample[start : start + window] * np.hanning(window), pcm.sample_rate, carrier))
    values = np.asarray(envelope)
    if not values.size or np.percentile(values, 95) < 1e-6:
        return None, None, None, None
    active = values > max(np.percentile(values, 65), np.max(values) * 0.15)
    runs: list[tuple[bool, int]] = []
    for state in active:
        if runs and runs[-1][0] == bool(state):
            runs[-1] = (runs[-1][0], runs[-1][1] + 1)
        else:
            runs.append((bool(state), 1))
    on_lengths = [length for state, length in runs if state]
    if len(on_lengths) < 3:
        return None, None, None, None
    dot = float(np.percentile(on_lengths, 30))
    if dot <= 0:
        return None, None, None, None
    symbols: list[str] = []
    current = ""
    for state, length in runs:
        units = length / dot
        if state:
            current += "-" if units >= 2.1 else "."
        elif units >= 6.0:
            if current:
                symbols.append(current)
                current = ""
            symbols.append("/")
        elif units >= 2.1 and current:
            symbols.append(current)
            current = ""
    if current:
        symbols.append(current)
    decoded = "".join(" " if item == "/" else _MORSE.get(item, "?") for item in symbols)
    unknown_ratio = decoded.count("?") / max(1, len(decoded.replace(" ", "")))
    confidence = max(0.0, min(0.9, 0.82 - unknown_ratio * 0.7))
    if len(decoded.replace(" ", "")) < 2 or confidence < 0.35:
        return None, None, None, None
    return " ".join(symbols), decoded, round(confidence, 4), round(carrier, 2)


def tone_analysis(pcm: PcmAudio, *, ultrasonic_peak: float | None, ultrasonic_ratio: float) -> ToneAnalysis:
    dtmf = detect_dtmf(pcm)
    morse_symbols, morse_text, morse_confidence, carrier = detect_morse(pcm)
    return ToneAnalysis(
        dtmf_sequence="".join(event.symbol for event in dtmf),
        dtmf_events=dtmf,
        morse_symbols=morse_symbols,
        morse_text=morse_text,
        morse_confidence=morse_confidence,
        carrier_hz=carrier,
        ultrasonic_peak_hz=round(ultrasonic_peak, 2) if ultrasonic_peak is not None else None,
        ultrasonic_energy_ratio=ultrasonic_ratio,
    )


def wav_bytes(samples: np.ndarray, sample_rate: int) -> bytes:
    values = np.clip(samples, -1.0, 1.0)
    pcm16 = np.rint(values * 32767).astype("<i2")
    output = io.BytesIO()
    with wave.open(output, "wb") as writer:
        writer.setnchannels(1 if pcm16.ndim == 1 else pcm16.shape[1])
        writer.setsampwidth(2)
        writer.setframerate(sample_rate)
        writer.writeframes(pcm16.tobytes())
    return output.getvalue()
