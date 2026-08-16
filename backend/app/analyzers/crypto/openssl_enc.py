from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.analyzers.crypto.artifacts import analyze_bytes, detect_artifacts
from app.analyzers.crypto.transforms import decode_base64, decode_hex
from app.core.errors import CryptoInputError
from app.core.flag_detection import FlagDetector
from app.schemas.crypto import (
    FlagCandidate,
    OpenSslAnalyzeRequest,
    OpenSslAnalyzeResponse,
    OpenSslDecryptCandidate,
    OpenSslDecryptRequest,
    OpenSslDecryptResponse,
    OpenSslEncryptedMaterial,
    ResolvedOpenSslCipher,
    ResolvedOpenSslDigest,
    ResolvedOpenSslKdf,
    TransformationStep,
)

OPENSSL_SALTED_MAGIC = b"Salted__"
MAX_ENCRYPTED_BYTES = 2 * 1024 * 1024
REJECTION_CAUSES = [
    "Incorrect password",
    "Incorrect cipher",
    "Incorrect digest",
    "Incorrect KDF",
    "Corrupted ciphertext",
]


@dataclass(frozen=True, slots=True)
class CipherSpec:
    key_length: int
    iv_length: int
    block_size: int
    label: str


_CIPHERS: dict[ResolvedOpenSslCipher, CipherSpec] = {
    "des-cbc": CipherSpec(8, 8, 8, "DES-CBC"),
    "des-ede3-cbc": CipherSpec(24, 8, 8, "DES-EDE3-CBC / 3DES"),
    "aes-128-cbc": CipherSpec(16, 16, 16, "AES-128-CBC"),
    "aes-192-cbc": CipherSpec(24, 16, 16, "AES-192-CBC"),
    "aes-256-cbc": CipherSpec(32, 16, 16, "AES-256-CBC"),
}


def decode_encrypted_material(material: OpenSslEncryptedMaterial) -> bytes:
    source = material.value.encode("utf-8")
    if material.encoding == "text":
        decoded = source
    elif material.encoding == "hex":
        decoded = decode_hex(source)
        if decoded is None:
            raise CryptoInputError("The encrypted input is not valid hexadecimal data.")
    elif material.encoding == "base64":
        decoded = decode_base64(source)
        if decoded is None:
            raise CryptoInputError("The encrypted input is not valid Base64 data.")
    else:
        if source.startswith(OPENSSL_SALTED_MAGIC):
            decoded = source
        else:
            decoded = decode_hex(source) or decode_base64(source) or source
    if len(decoded) > MAX_ENCRYPTED_BYTES:
        raise CryptoInputError(
            f"The decoded encrypted input exceeds the {MAX_ENCRYPTED_BYTES}-byte analysis limit."
        )
    return decoded


def _payload_analysis(data: bytes, password_supplied: bool) -> OpenSslAnalyzeResponse:
    detected = data.startswith(OPENSSL_SALTED_MAGIC)
    structure_valid = not detected or len(data) >= 16
    salt = data[8:16] if detected and structure_valid else None
    ciphertext_bytes = len(data) - 16 if detected and structure_valid else (len(data) if not detected else 0)
    if not structure_valid:
        status = "invalid-payload"
        message = "The Salted__ header is present, but the required 8-byte salt is incomplete."
    elif not password_supplied:
        status = "password-required"
        message = (
            "OpenSSL encrypted payload detected. Enter a password to continue."
            if detected
            else "Raw encrypted bytes loaded. Enter a password and select or auto-detect parameters."
        )
    else:
        status = "ready-for-decryption"
        message = "Ready for decryption."
    return OpenSslAnalyzeResponse(
        detected=detected,
        format="openssl-enc" if detected else "raw",
        header="Salted__" if detected else None,
        salt_hex=salt.hex() if salt is not None else None,
        total_bytes=len(data),
        encrypted_payload_bytes=max(0, ciphertext_bytes),
        structure_valid=structure_valid,
        password_supplied=password_supplied,
        password_status="provided" if password_supplied else "not-supplied",
        status=status,
        message=message,
    )


def analyze_openssl_enc(request: OpenSslAnalyzeRequest) -> OpenSslAnalyzeResponse:
    data = decode_encrypted_material(request.encrypted)
    return _payload_analysis(data, request.password is not None)


def _password_bytes(value: str, encoding: str) -> bytes:
    if encoding == "utf-8":
        return value.encode("utf-8")
    if encoding == "ascii":
        try:
            return value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise CryptoInputError("The password contains characters that cannot be encoded as ASCII.") from exc
    if encoding == "hex":
        try:
            decoded = bytes.fromhex("".join(value.split()))
        except ValueError as exc:
            raise CryptoInputError("The password is not valid hexadecimal data.") from exc
        if not decoded:
            raise CryptoInputError("The decoded hexadecimal password must not be empty.")
        return decoded
    compact = "".join(value.split())
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CryptoInputError("The password is not valid Base64 data.") from exc
    if not decoded:
        raise CryptoInputError("The decoded Base64 password must not be empty.")
    return decoded


def evp_bytes_to_key(
    password: bytes,
    salt: bytes | None,
    key_length: int,
    iv_length: int,
    digest: ResolvedOpenSslDigest,
) -> tuple[bytes, bytes]:
    """Implement the single-iteration legacy OpenSSL EVP_BytesToKey expansion."""

    output = bytearray()
    previous = b""
    seed = password + (salt or b"")
    while len(output) < key_length + iv_length:
        previous = hashlib.new(digest, previous + seed).digest()
        output.extend(previous)
    return bytes(output[:key_length]), bytes(output[key_length : key_length + iv_length])


def _derive_key_iv(
    password: bytes,
    salt: bytes | None,
    spec: CipherSpec,
    kdf: ResolvedOpenSslKdf,
    digest: ResolvedOpenSslDigest,
    iterations: int,
) -> tuple[bytes, bytes]:
    if kdf == "evp-bytes-to-key":
        return evp_bytes_to_key(password, salt, spec.key_length, spec.iv_length, digest)
    derived = hashlib.pbkdf2_hmac(
        digest,
        password,
        salt or b"",
        iterations,
        dklen=spec.key_length + spec.iv_length,
    )
    return derived[: spec.key_length], derived[spec.key_length :]


def _decrypt_cbc(cipher_name: ResolvedOpenSslCipher, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    algorithm = algorithms.AES(key) if cipher_name.startswith("aes-") else TripleDES(key)
    decryptor = Cipher(algorithm, modes.CBC(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def _pkcs7_unpad(data: bytes, block_size: int) -> bytes | None:
    if not data:
        return None
    padding_length = data[-1]
    if padding_length < 1 or padding_length > block_size:
        return None
    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        return None
    return data[:-padding_length]


def _plaintext_view(data: bytes) -> tuple[str, str, bool]:
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return data.hex(), "hex", False
    printable = sum(character.isprintable() or character in "\r\n\t" for character in decoded)
    ratio = printable / len(decoded) if decoded else 1.0
    return (decoded, "utf-8", True) if ratio >= 0.7 else (data.hex(), "hex", True)


def _command(
    cipher_name: ResolvedOpenSslCipher,
    kdf: ResolvedOpenSslKdf,
    digest: ResolvedOpenSslDigest,
    iterations: int,
    password: str,
    password_encoding: str,
    salted: bool,
) -> str | None:
    if password_encoding not in {"utf-8", "ascii"}:
        return None
    cipher_flag = {
        "des-cbc": "des",
        "des-ede3-cbc": "des3",
        "aes-128-cbc": "aes-128-cbc",
        "aes-192-cbc": "aes-192-cbc",
        "aes-256-cbc": "aes-256-cbc",
    }[cipher_name]
    quoted_password = "'" + password.replace("'", "'\"'\"'") + "'"
    parts = ["openssl", cipher_flag, "-d", "-salt" if salted else "-nosalt", "-md", digest]
    if kdf == "pbkdf2":
        parts.extend(["-pbkdf2", "-iter", str(iterations)])
    parts.extend(["-in", "encrypted.bin", "-out", "plaintext.bin", "-k", quoted_password])
    return " ".join(parts)


def _choices(request: OpenSslDecryptRequest) -> tuple[
    list[ResolvedOpenSslCipher], list[ResolvedOpenSslKdf], list[ResolvedOpenSslDigest]
]:
    ciphers: list[ResolvedOpenSslCipher] = (
        ["des-ede3-cbc", "des-cbc", "aes-128-cbc", "aes-192-cbc", "aes-256-cbc"]
        if request.cipher == "auto"
        else [request.cipher]
    )
    # Salted__ identifies a container, not a KDF. PBKDF2 is only tried when selected.
    kdfs: list[ResolvedOpenSslKdf] = (
        ["evp-bytes-to-key"] if request.kdf == "auto" else [request.kdf]
    )
    digests: list[ResolvedOpenSslDigest] = (
        ["sha256", "md5"] if request.digest == "auto" else [request.digest]
    )
    return ciphers, kdfs, digests


def decrypt_openssl_enc(request: OpenSslDecryptRequest) -> OpenSslDecryptResponse:
    raw = decode_encrypted_material(request.encrypted)
    payload = _payload_analysis(raw, True)
    if not payload.structure_valid:
        raise CryptoInputError(payload.message)
    salt = raw[8:16] if payload.detected else None
    ciphertext = raw[16:] if payload.detected else raw
    if not ciphertext:
        raise CryptoInputError("The encrypted payload does not contain any ciphertext bytes.")

    password = _password_bytes(request.password, request.password_encoding)
    cipher_choices, kdf_choices, digest_choices = _choices(request)
    variants = [
        (cipher_name, kdf, digest)
        for cipher_name in cipher_choices
        for kdf in kdf_choices
        for digest in digest_choices
    ]
    detector = FlagDetector(request.flag_prefixes)
    candidates: list[OpenSslDecryptCandidate] = []
    any_aligned = False

    for cipher_name, kdf, digest in variants:
        spec = _CIPHERS[cipher_name]
        if len(ciphertext) % spec.block_size:
            continue
        any_aligned = True
        key, iv = _derive_key_iv(password, salt, spec, kdf, digest, request.iterations)
        plaintext = _pkcs7_unpad(
            _decrypt_cbc(cipher_name, key, iv, ciphertext), spec.block_size
        )
        if plaintext is None:
            continue

        artifacts = detect_artifacts(plaintext)
        analysis = analyze_bytes(plaintext, artifacts)
        step = TransformationStep(
            transform="OpenSSL enc Decrypt", parameter=f"{spec.label}, {kdf}, {digest}"
        )
        flags = [
            FlagCandidate(
                value=flag.value,
                matched_pattern=flag.matched_pattern,
                source="decryptor.plaintext",
                offset=flag.offset,
                confidence=flag.confidence,
                context=flag.context,
                chain=[step],
            )
            for flag in detector.detect(plaintext)
        ]
        score = min(
            1.0,
            0.5
            + analysis.printable * 0.2
            + (0.1 if analysis.utf8 else 0.0)
            + (0.15 if artifacts else 0.0)
            + (0.2 if flags else 0.0),
        )
        if score >= 0.9:
            confidence = "VERY HIGH"
        elif score >= 0.75:
            confidence = "HIGH"
        elif score >= 0.6:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        rendered, output_format, utf8_valid = _plaintext_view(plaintext)
        candidates.append(
            OpenSslDecryptCandidate(
                rank=1,
                cipher=cipher_name,
                cipher_label=spec.label,
                kdf=kdf,
                digest=digest,
                iterations=request.iterations if kdf == "pbkdf2" else None,
                key_hex=key.hex(),
                iv_hex=iv.hex(),
                printable_percentage=round(analysis.printable * 100, 2),
                utf8_valid=utf8_valid,
                file_magic=analysis.magic,
                confidence=confidence,
                score=round(score, 4),
                plaintext=rendered,
                plaintext_format=output_format,
                plaintext_base64=base64.b64encode(plaintext).decode("ascii"),
                artifacts=artifacts,
                flags=flags,
                equivalent_command=_command(
                    cipher_name,
                    kdf,
                    digest,
                    request.iterations,
                    request.password,
                    request.password_encoding,
                    payload.detected,
                ),
            )
        )

    candidates.sort(key=lambda candidate: candidate.score, reverse=True)
    ranked = [candidate.model_copy(update={"rank": index}) for index, candidate in enumerate(candidates, 1)]
    if ranked:
        return OpenSslDecryptResponse(
            status="success",
            payload=payload,
            attempted_variants=len(variants),
            candidates=ranked,
        )
    reason = (
        "Invalid block padding."
        if any_aligned
        else "Ciphertext length is not aligned to any selected cipher block size."
    )
    return OpenSslDecryptResponse(
        status="rejected",
        payload=payload,
        attempted_variants=len(variants),
        candidates=[],
        rejection_reason=reason,
        possible_causes=REJECTION_CAUSES,
    )
