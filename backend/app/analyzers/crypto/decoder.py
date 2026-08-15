from __future__ import annotations

import re
import time
from dataclasses import dataclass

from app.analyzers.crypto.transforms import (
    TransformOutput,
    decode_base32,
    decode_base64,
    decode_base85,
    decode_binary,
    decode_hex,
    decode_url,
    generate_transformations,
    parse_xor_key,
)
from app.core.analyzers import BaseAnalyzer
from app.core.flag_detection import DetectedFlag, FlagDetector
from app.core.scoring import ScoredBytes, score_bytes
from app.schemas.crypto import (
    DecodeRequest,
    DecodeResponse,
    DecodingCandidate,
    EncodingDetection,
    FlagCandidate,
    ScoreBreakdown,
    SearchMetadata,
    TransformationStep,
)

_BASE85_MARKERS = re.compile(rb"[!#$%&()*+;<=>?@^_`{|}~]")
_OUTPUT_PREVIEW_BYTES = 8_192


@dataclass(frozen=True, slots=True)
class _Step:
    transform: str
    parameter: str | None
    family: str


@dataclass(frozen=True, slots=True)
class _State:
    data: bytes
    chain: tuple[_Step, ...]
    scored: ScoredBytes
    flags: tuple[DetectedFlag, ...]


def detect_encodings(data: bytes) -> list[EncodingDetection]:
    detections: list[EncodingDetection] = []
    compact = b"".join(data.split())
    base64_decoded = decode_base64(data)
    if decode_binary(data) is not None:
        detections.append(
            EncodingDetection(
                name="Binary", confidence=0.98, evidence="Only complete 8-bit groups were found."
            )
        )
    if decode_hex(data) is not None:
        detections.append(
            EncodingDetection(
                name="Hex", confidence=0.94, evidence="The input is an even-length hexadecimal byte sequence."
            )
        )
    if base64_decoded is not None:
        confidence = 0.92 if b"=" in compact or len(compact) % 4 == 0 else 0.78
        detections.append(
            EncodingDetection(
                name="Base64",
                confidence=confidence,
                evidence="The alphabet and padding are valid Base64.",
            )
        )
    if decode_base32(data) is not None:
        detections.append(
            EncodingDetection(
                name="Base32", confidence=0.86, evidence="The alphabet and padding are valid Base32."
            )
        )
    if decode_url(data) is not None:
        detections.append(
            EncodingDetection(
                name="URL", confidence=0.99, evidence="One or more percent-encoded bytes were found."
            )
        )
    if decode_base85(data) and (
        compact.startswith(b"<~")
        or (
            base64_decoded is None
            and len(compact) >= 10
            and _BASE85_MARKERS.search(compact) is not None
        )
    ):
        detections.append(
            EncodingDetection(
                name="Base85",
                confidence=0.62,
                evidence="The input uses a valid Base85 alphabet and length.",
            )
        )
    detections.sort(key=lambda item: item.confidence, reverse=True)
    return detections


def _schema_steps(chain: tuple[_Step, ...]) -> list[TransformationStep]:
    return [
        TransformationStep(transform=step.transform, parameter=step.parameter)
        for step in chain
    ]


def _schema_flag(flag: DetectedFlag, chain: tuple[_Step, ...]) -> FlagCandidate:
    return FlagCandidate(
        value=flag.value,
        matched_pattern=flag.matched_pattern,
        offset=flag.offset,
        confidence=flag.confidence,
        context=flag.context,
        chain=_schema_steps(chain),
    )


def _render_output(data: bytes) -> tuple[str, str, bool]:
    preview = data[:_OUTPUT_PREVIEW_BYTES]
    truncated = len(data) > len(preview)
    try:
        text = preview.decode("utf-8")
    except UnicodeDecodeError:
        return preview.hex(), "hex", truncated
    printable = (
        sum(character.isprintable() or character in "\r\n\t" for character in text) / len(text)
        if text
        else 1.0
    )
    if printable < 0.7:
        return preview.hex(), "hex", truncated
    return text, "utf-8", truncated


def _syntax_bonus(state: _State) -> float:
    """Reward chains that begin with a syntax-validated encoding transform."""
    if not state.chain:
        return 0.0
    return {
        "binary": 0.12,
        "url": 0.12,
        "hex": 0.10,
        "base64": 0.10,
        "base32": 0.09,
        "base85": 0.05,
    }.get(state.chain[0].family, 0.0)


def _ranked_score(state: _State) -> float:
    depth_penalty = max(0, len(state.chain) - 1) * 0.04
    return max(0.0, min(1.0, state.scored.total + _syntax_bonus(state) - depth_penalty))


def _candidate_schema(state: _State) -> DecodingCandidate:
    output, output_format, truncated = _render_output(state.data)
    components = state.scored.components
    depth_penalty = max(0, len(state.chain) - 1) * 0.04
    syntax_bonus = _syntax_bonus(state)
    return DecodingCandidate(
        output=output,
        output_format=output_format,
        output_bytes=len(state.data),
        output_truncated=truncated,
        chain=_schema_steps(state.chain),
        score=round(_ranked_score(state), 4),
        score_breakdown=ScoreBreakdown(
            printable=components.printable,
            utf8=components.utf8,
            language=components.language,
            structure=components.structure,
            flag_bonus=components.flag_bonus,
            entropy=components.entropy,
            depth_penalty=depth_penalty,
            syntax_bonus=syntax_bonus,
        ),
        flags=[_schema_flag(flag, state.chain) for flag in state.flags],
    )


class RecursiveDecoder(BaseAnalyzer[DecodeRequest, DecodeResponse]):
    name = "recursive_decoder"
    category = "crypto"

    def supports(self, value: object) -> bool:
        return isinstance(value, DecodeRequest) and bool(value.input)

    def analyze(self, value: DecodeRequest) -> DecodeResponse:
        if not self.supports(value):
            raise TypeError("RecursiveDecoder requires a non-empty DecodeRequest")

        # Parse keys before beginning the timed search so malformed options fail clearly.
        for xor_key in value.xor_keys:
            parse_xor_key(xor_key)

        started = time.monotonic()
        deadline = started + value.timeout_ms / 1_000
        source = value.input.encode("utf-8")
        detector = FlagDetector(value.flag_prefixes)
        root_flags = detector.detect(source)
        root = _State(source, (), score_bytes(source, root_flags), tuple(root_flags))

        frontier = [root]
        ranked_states: list[_State] = [root] if root_flags else []
        seen: dict[bytes, int] = {source: 0}
        explored_states = 0
        max_depth_reached = 0
        truncated = False

        for depth in range(1, value.max_depth + 1):
            if time.monotonic() >= deadline:
                truncated = True
                break
            next_states: list[_State] = []
            for state in frontier:
                if time.monotonic() >= deadline:
                    truncated = True
                    break
                previous_family = state.chain[-1].family if state.chain else None
                transformed = generate_transformations(
                    state.data,
                    xor_keys=value.xor_keys,
                    deadline=deadline,
                    previous_family=previous_family,
                )
                for output in transformed:
                    if time.monotonic() >= deadline:
                        truncated = True
                        break
                    if seen.get(output.data, value.max_depth + 1) <= depth:
                        continue
                    seen[output.data] = depth
                    chain = state.chain + (
                        _Step(output.transform, output.parameter, output.family),
                    )
                    flags = detector.detect(output.data)
                    scored = score_bytes(output.data, flags)
                    child = _State(output.data, chain, scored, tuple(flags))
                    next_states.append(child)
                    ranked_states.append(child)
                    explored_states += 1
                    max_depth_reached = depth

            if not next_states:
                break

            def expansion_rank(state: _State) -> tuple[float, float, int]:
                encoding_hint = max(
                    (item.confidence for item in detect_encodings(state.data)),
                    default=0.0,
                )
                # Syntax-validated decoders deserve search priority even when their
                # intermediate output is another encoded (and therefore odd-looking)
                # string. Base85 is deliberately weaker because its alphabet is broad.
                family_prior = {
                    "binary": 0.50,
                    "url": 0.48,
                    "hex": 0.45,
                    "base64": 0.42,
                    "base32": 0.38,
                    "base85": 0.12,
                }.get(state.chain[-1].family, 0.0)
                return (
                    state.scored.total + encoding_hint * 0.10 + family_prior,
                    state.scored.components.printable,
                    -len(state.chain),
                )

            next_states.sort(key=expansion_rank, reverse=True)
            if len(next_states) > value.beam_width:
                truncated = True
            frontier = next_states[: value.beam_width]

        def result_rank(state: _State) -> tuple[float, bool, int, float]:
            return (
                _ranked_score(state),
                bool(state.flags),
                -len(state.chain),
                state.scored.components.printable,
            )

        ranked_states.sort(
            key=result_rank,
            reverse=True,
        )

        unique_results: list[_State] = []
        emitted: set[bytes] = set()
        for state in ranked_states:
            if state.data in emitted:
                continue
            emitted.add(state.data)
            unique_results.append(state)
            if len(unique_results) >= value.max_results:
                break

        aggregate_flags: list[FlagCandidate] = []
        flag_values: set[tuple[str, int]] = set()
        for state in ranked_states:
            for flag in state.flags:
                identity = (flag.value, flag.offset)
                if identity in flag_values:
                    continue
                flag_values.add(identity)
                aggregate_flags.append(_schema_flag(flag, state.chain))

        elapsed_ms = max(0, round((time.monotonic() - started) * 1_000))
        return DecodeResponse(
            analyzer=self.name,
            detected_encodings=detect_encodings(source),
            results=[_candidate_schema(state) for state in unique_results],
            flags=aggregate_flags,
            search=SearchMetadata(
                explored_states=explored_states,
                elapsed_ms=elapsed_ms,
                max_depth_reached=max_depth_reached,
                truncated=truncated,
            ),
        )
