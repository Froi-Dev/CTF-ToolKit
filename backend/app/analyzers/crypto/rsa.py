from __future__ import annotations

import base64
from collections import deque

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.analyzers.crypto.artifacts import detect_artifacts
from app.analyzers.crypto.transforms import decode_base64, decode_hex
from app.core.errors import CryptoInputError
from app.core.flag_detection import FlagDetector
from app.schemas.crypto import (
    CryptoAnalyzeRequest,
    CryptoAnalyzeResponse,
    CryptoFinding,
    CryptoMaterial,
    FlagCandidate,
    RsaDecryptRequest,
    RsaDecryptResponse,
    RsaKeyInfo,
    TransformationStep,
)


RsaKey = rsa.RSAPrivateKey | rsa.RSAPublicKey


def _material_bytes(material: CryptoMaterial) -> bytes:
    raw = material.value.encode("utf-8")
    if material.encoding == "text":
        return raw
    if material.encoding == "hex":
        decoded = decode_hex(raw)
        if decoded is None:
            raise CryptoInputError("The supplied value is not valid hexadecimal data.")
        return decoded
    if material.encoding == "base64":
        decoded = decode_base64(raw)
        if decoded is None:
            raise CryptoInputError("The supplied value is not valid Base64 data.")
        return decoded
    return raw


def decode_ciphertext(material: CryptoMaterial) -> bytes:
    raw = _material_bytes(material)
    if material.encoding != "auto":
        return raw
    text = material.value.encode("utf-8")
    decoded = decode_hex(text)
    if decoded is not None:
        return decoded
    decoded = decode_base64(text)
    return decoded if decoded is not None else raw


def _load_key_data(data: bytes, password: bytes | None) -> tuple[RsaKey, str] | None:
    pem = data.lstrip().startswith(b"-----BEGIN")
    loaders = (
        (lambda: serialization.load_pem_private_key(data, password=password)) if pem else (lambda: serialization.load_der_private_key(data, password=password)),
        (lambda: serialization.load_pem_public_key(data)) if pem else (lambda: serialization.load_der_public_key(data)),
        (lambda: x509.load_pem_x509_certificate(data).public_key()) if pem else (lambda: x509.load_der_x509_certificate(data).public_key()),
    )
    for loader in loaders:
        try:
            key = loader()
        except (TypeError, ValueError):
            continue
        if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
            return key, "PEM" if pem else "DER"
    return None


def load_rsa_key(material: CryptoMaterial, password: str | None = None) -> tuple[RsaKey, str, bytes]:
    source = _material_bytes(material)
    password_bytes = password.encode("utf-8") if password is not None else None
    queue: deque[tuple[bytes, int]] = deque([(source, 0)])
    seen: set[bytes] = set()
    while queue:
        data, depth = queue.popleft()
        if data in seen:
            continue
        seen.add(data)
        loaded = _load_key_data(data, password_bytes)
        if loaded is not None:
            return loaded[0], loaded[1], data
        if material.encoding == "auto" and depth < 4:
            for decoder in (decode_hex, decode_base64):
                decoded = decoder(data)
                if decoded is not None and decoded != data and len(decoded) <= 131_072:
                    queue.append((decoded, depth + 1))
    raise CryptoInputError(
        "No RSA PEM, DER, public key, private key, or certificate could be parsed from the supplied key material."
    )


def _key_info(key: RsaKey, format_name: str) -> RsaKeyInfo:
    public = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
    numbers = public.public_numbers()
    return RsaKeyInfo(
        key_type="private" if isinstance(key, rsa.RSAPrivateKey) else "public",
        format=format_name,
        modulus_bits=public.key_size,
        public_exponent=numbers.e,
    )


def analyze_crypto(request: CryptoAnalyzeRequest) -> CryptoAnalyzeResponse:
    key, format_name, key_data = load_rsa_key(request.key)
    info = _key_info(key, format_name)
    findings: list[CryptoFinding] = []
    recommendations: list[str] = []
    if info.public_exponent == 3:
        findings.append(
            CryptoFinding(
                title="Small RSA public exponent",
                severity="high",
                confidence=0.98,
                description="e = 3 can enable integer-root or broadcast attacks when padding or message reuse is weak.",
            )
        )
        recommendations.append("Inspect padding and related ciphertexts before selecting a small-exponent attack.")
    if info.modulus_bits < 2048:
        findings.append(
            CryptoFinding(
                title="RSA modulus below 2048 bits",
                severity="medium",
                confidence=1.0,
                description=f"The parsed RSA modulus is {info.modulus_bits} bits; factorization feasibility depends on its structure and size.",
            )
        )
        recommendations.append("Analyze the modulus for weak factors; do not run every factorization method blindly.")

    cipher_artifacts = []
    cipher_bytes: int | None = None
    compatible: bool | None = None
    if request.ciphertext is not None:
        ciphertext = decode_ciphertext(request.ciphertext)
        cipher_bytes = len(ciphertext)
        cipher_artifacts = detect_artifacts(ciphertext)
        expected = (info.modulus_bits + 7) // 8
        compatible = cipher_bytes == expected
        findings.append(
            CryptoFinding(
                title="Ciphertext length matches RSA modulus" if compatible else "Ciphertext length does not match one RSA block",
                severity="info" if compatible else "low",
                confidence=0.99,
                description=f"The ciphertext is {cipher_bytes} bytes and one RSA block for this key is {expected} bytes.",
            )
        )
        if compatible and info.key_type == "private":
            recommendations.insert(0, "Try direct RSA decryption with the challenge-specified padding.")
        elif compatible:
            recommendations.insert(0, "A matching private key or a justified RSA weakness is required for decryption.")
    if not findings:
        findings.append(
            CryptoFinding(
                title="RSA key parsed",
                severity="info",
                confidence=1.0,
                description="No obvious weakness can be established from the supplied key alone.",
            )
        )
    return CryptoAnalyzeResponse(
        key=info,
        key_artifacts=detect_artifacts(key_data),
        ciphertext_artifacts=cipher_artifacts,
        ciphertext_bytes=cipher_bytes,
        compatible=compatible,
        findings=findings,
        recommended_actions=recommendations,
    )


def _plaintext_view(data: bytes) -> tuple[str, str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data.hex(), "hex"
    printable = sum(character.isprintable() or character in "\r\n\t" for character in text) / len(text) if text else 1.0
    return (text, "utf-8") if printable >= 0.7 else (data.hex(), "hex")


def decrypt_rsa(request: RsaDecryptRequest) -> RsaDecryptResponse:
    key, format_name, _key_data = load_rsa_key(request.private_key, request.password)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise CryptoInputError("RSA decryption requires a private key; the supplied material contains only a public key.")
    ciphertext = decode_ciphertext(request.ciphertext)
    modulus_bytes = (key.key_size + 7) // 8
    if len(ciphertext) != modulus_bytes:
        raise CryptoInputError(
            f"Ciphertext is {len(ciphertext)} bytes, but this RSA key requires exactly {modulus_bytes} bytes per block."
        )
    try:
        if request.padding == "pkcs1v15":
            plaintext = key.decrypt(ciphertext, padding.PKCS1v15())
        elif request.padding.startswith("oaep-"):
            algorithm = hashes.SHA1() if request.padding == "oaep-sha1" else hashes.SHA256()
            label = request.label.encode("utf-8") if request.label is not None else None
            plaintext = key.decrypt(
                ciphertext,
                padding.OAEP(mgf=padding.MGF1(algorithm=algorithm), algorithm=algorithm, label=label),
            )
        else:
            private = key.private_numbers()
            value = int.from_bytes(ciphertext, "big")
            if value >= private.public_numbers.n:
                raise CryptoInputError("The raw ciphertext integer must be smaller than the RSA modulus.")
            decoded = pow(value, private.d, private.public_numbers.n)
            plaintext = decoded.to_bytes(modulus_bytes, "big").lstrip(b"\x00")
    except ValueError as exc:
        raise CryptoInputError(
            "RSA decryption failed. Verify the key, ciphertext encoding, padding, OAEP hash, and label."
        ) from exc

    rendered, output_format = _plaintext_view(plaintext)
    flag_detector = FlagDetector(request.flag_prefixes)
    step = TransformationStep(transform="RSA Decrypt", parameter=request.padding)
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
        for flag in flag_detector.detect(plaintext)
    ]
    return RsaDecryptResponse(
        key=_key_info(key, format_name),
        padding=request.padding,
        ciphertext_bytes=len(ciphertext),
        plaintext=rendered,
        plaintext_format=output_format,
        plaintext_base64=base64.b64encode(plaintext).decode("ascii"),
        artifacts=detect_artifacts(plaintext),
        flags=flags,
    )
