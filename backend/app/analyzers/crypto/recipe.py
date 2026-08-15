from __future__ import annotations

import base64

from app.analyzers.crypto.artifacts import analyze_bytes, detect_artifacts
from app.analyzers.crypto.transforms import (
    apply_xor,
    decode_base32,
    decode_base58,
    decode_base64,
    decode_base85,
    decode_binary,
    decode_decimal_ascii,
    decode_escaped_bytes,
    decode_gzip,
    decode_hex,
    decode_html_entities,
    decode_morse,
    decode_octal,
    decode_unicode_escapes,
    decode_url,
    decode_utf16,
    parse_xor_key,
    rotate47,
    rotate_ascii,
)
from app.core.errors import DecoderInputError
from app.core.flag_detection import FlagDetector
from app.schemas.crypto import (
    FlagCandidate,
    RecipeIntermediate,
    RecipeOperation,
    RecipeRequest,
    RecipeResponse,
    TransformationStep,
)


def _render(data: bytes) -> tuple[str, str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data.hex(), "hex"
    printable = sum(character.isprintable() or character in "\r\n\t" for character in text) / len(text) if text else 1.0
    return (text, "utf-8") if printable >= 0.7 else (data.hex(), "hex")


def _required(result: bytes | None, operation: str) -> bytes:
    if result is None:
        raise DecoderInputError(f"{operation} could not decode the current recipe value.")
    return result


def _apply(data: bytes, item: RecipeOperation) -> bytes:
    operation = item.operation
    if operation in {"hex", "base16"}:
        return _required(decode_hex(data), operation)
    if operation == "base64":
        return _required(decode_base64(data), operation)
    if operation == "base32":
        return _required(decode_base32(data), operation)
    if operation == "base58":
        return _required(decode_base58(data), operation)
    if operation in {"base85", "ascii85"}:
        outputs = decode_base85(data)
        preferred = "Ascii85" if operation == "ascii85" else "RFC 1924"
        match = next((output.data for output in outputs if output.parameter == preferred), None)
        return _required(match, operation)
    if operation == "binary":
        return _required(decode_binary(data), operation)
    if operation == "octal":
        return _required(decode_octal(data), operation)
    if operation == "decimal-ascii":
        return _required(decode_decimal_ascii(data), operation)
    if operation == "url":
        return _required(decode_url(data), operation)
    if operation == "html-entities":
        return _required(decode_html_entities(data), operation)
    if operation == "unicode-escapes":
        return _required(decode_unicode_escapes(data), operation)
    if operation == "escaped-bytes":
        return _required(decode_escaped_bytes(data), operation)
    if operation == "morse":
        return _required(decode_morse(data), operation)
    if operation == "rot13":
        return rotate_ascii(data, 13)
    if operation == "rot47":
        return rotate47(data)
    if operation == "caesar":
        try:
            shift = int(item.parameter or "")
        except ValueError as exc:
            raise DecoderInputError("Caesar requires an integer shift between 1 and 25.") from exc
        if not 1 <= shift <= 25:
            raise DecoderInputError("Caesar requires an integer shift between 1 and 25.")
        return rotate_ascii(data, shift)
    if operation == "utf-16":
        return _required(decode_utf16(data), operation)
    if operation == "utf-8":
        try:
            return data.decode("utf-8").encode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecoderInputError("The current recipe value is not valid UTF-8.") from exc
    if operation == "ascii":
        if any(byte > 0x7F for byte in data):
            raise DecoderInputError("The current recipe value is not valid ASCII.")
        return data
    if operation == "gunzip":
        return _required(decode_gzip(data), operation)
    if operation == "xor":
        if not item.parameter:
            raise DecoderInputError("XOR requires an ASCII, hex, or integer key.")
        if item.parameter.lower().startswith("buffer-hex:"):
            try:
                other = bytes.fromhex(item.parameter[11:].replace(" ", ""))
            except ValueError as exc:
                raise DecoderInputError("The XOR byte buffer is not valid hexadecimal.") from exc
            if len(other) != len(data):
                raise DecoderInputError("XOR byte buffers must have the same length.")
            return bytes(left ^ right for left, right in zip(data, other, strict=True))
        return apply_xor(data, parse_xor_key(item.parameter))
    raise DecoderInputError(f"Unsupported recipe operation: {operation}")


def _input_bytes(request: RecipeRequest) -> bytes:
    if request.input_encoding == "text":
        return request.input.encode("utf-8")
    if request.input_encoding == "hex":
        return _required(decode_hex(request.input.encode("ascii", errors="ignore")), "input hex")
    return _required(decode_base64(request.input.encode("ascii", errors="ignore")), "input Base64")


def run_recipe(request: RecipeRequest) -> RecipeResponse:
    data = _input_bytes(request)
    detector = FlagDetector(request.flag_prefixes)
    steps: list[RecipeIntermediate] = []
    chain: list[TransformationStep] = []
    for index, operation in enumerate(request.operations):
        if not operation.enabled:
            continue
        data = _apply(data, operation)
        chain.append(TransformationStep(transform=operation.operation, parameter=operation.parameter))
        output, output_format = _render(data)
        artifacts = detect_artifacts(data)
        flags = [
            FlagCandidate(
                value=flag.value,
                matched_pattern=flag.matched_pattern,
                offset=flag.offset,
                confidence=flag.confidence,
                context=flag.context,
                chain=chain.copy(),
            )
            for flag in detector.detect(data)
        ]
        steps.append(
            RecipeIntermediate(
                index=index,
                operation=operation.operation,
                parameter=operation.parameter,
                output=output,
                output_format=output_format,
                output_base64=base64.b64encode(data).decode("ascii"),
                output_bytes=len(data),
                artifacts=artifacts,
                analysis=analyze_bytes(data, artifacts),
                flags=flags,
            )
        )
    if not steps:
        raise DecoderInputError("The recipe must contain at least one enabled operation.")
    return RecipeResponse(steps=steps, result=steps[-1])
