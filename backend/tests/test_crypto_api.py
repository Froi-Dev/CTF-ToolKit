import base64
import hashlib

from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.main import app

client = TestClient(app)


def _openssl_key_iv(
    password: bytes,
    salt: bytes,
    key_length: int,
    iv_length: int,
    digest: str,
) -> tuple[bytes, bytes]:
    output = bytearray()
    previous = b""
    while len(output) < key_length + iv_length:
        previous = hashlib.new(digest, previous + password + salt).digest()
        output.extend(previous)
    return bytes(output[:key_length]), bytes(output[key_length : key_length + iv_length])


def _openssl_encrypt(
    plaintext: bytes,
    password: bytes,
    salt: bytes,
    *,
    cipher_name: str = "des-ede3-cbc",
    digest: str = "md5",
    pbkdf2: bool = False,
    iterations: int = 10_000,
) -> bytes:
    cipher_parameters = {
        "des-cbc": (8, 8, 8),
        "des-ede3-cbc": (24, 8, 8),
        "aes-256-cbc": (32, 16, 16),
    }
    key_length, iv_length, block_size = cipher_parameters[cipher_name]
    if pbkdf2:
        derived = hashlib.pbkdf2_hmac(
            digest, password, salt, iterations, dklen=key_length + iv_length
        )
        key, iv = derived[:key_length], derived[key_length:]
    else:
        key, iv = _openssl_key_iv(password, salt, key_length, iv_length, digest)
    padding_length = block_size - len(plaintext) % block_size
    padded = plaintext + bytes([padding_length]) * padding_length
    algorithm = algorithms.AES(key) if cipher_name.startswith("aes-") else TripleDES(key)
    encryptor = Cipher(algorithm, modes.CBC(iv)).encryptor()
    return b"Salted__" + salt + encryptor.update(padded) + encryptor.finalize()


def test_recursive_chain_is_ranked_and_flag_is_a_candidate() -> None:
    plaintext = b"CTF{recursive_decoder}"
    xored = bytes(byte ^ 0x17 for byte in plaintext)
    encoded = base64.b64encode(xored.hex().encode()).decode()

    response = client.post(
        "/api/v1/crypto/decode",
        json={
            "input": encoded,
            "max_depth": 3,
            "max_results": 20,
            "xor_keys": ["0x17"],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    matching = next(result for result in payload["results"] if result["output"] == plaintext.decode())
    assert [step["transform"] for step in matching["chain"]] == ["Base64", "Hex", "XOR"]
    assert matching["flags"][0]["state"] == "candidate"
    assert payload["flags"][0]["value"] == plaintext.decode()
    assert payload["flags"][0]["source"] == "request.input"


def test_nested_base64_chain_detection() -> None:
    plaintext = b"the secret message"
    encoded = base64.b64encode(base64.b64encode(plaintext)).decode()
    response = client.post(
        "/api/v1/crypto/decode",
        json={"input": encoded, "max_depth": 2, "max_results": 20},
    )
    assert response.status_code == 200
    payload = response.json()
    matching = next(result for result in payload["results"] if result["output"] == plaintext.decode())
    assert [step["transform"] for step in matching["chain"]] == ["Base64", "Base64"]


def test_plain_flag_is_detected_without_claiming_confirmation() -> None:
    response = client.post("/api/v1/crypto/decode", json={"input": "H4G{review_me}"})
    assert response.status_code == 200
    flag = response.json()["flags"][0]
    assert flag["state"] == "candidate"
    assert flag["chain"] == []


def test_validation_errors_have_standard_envelope() -> None:
    response = client.post("/api/v1/crypto/decode", json={"input": "", "max_depth": 99})
    assert response.status_code == 422
    payload = response.json()
    assert payload["error"]["code"] == "VALIDATION_ERROR"
    assert payload["error"]["details"]["fields"]


def test_invalid_xor_key_has_standard_envelope() -> None:
    response = client.post(
        "/api/v1/crypto/decode", json={"input": "hello", "xor_keys": ["0x1234"]}
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_DECODER_OPTION"


def test_non_ascii_input_does_not_break_rot_detection() -> None:
    response = client.post(
        "/api/v1/crypto/decode",
        json={"input": "A" * 100 + "é", "max_depth": 1, "timeout_ms": 500},
    )
    assert response.status_code == 200


def test_simple_base64_plaintext_is_the_best_result() -> None:
    response = client.post(
        "/api/v1/crypto/decode", json={"input": "SWxvdmV5b3U="}
    )
    assert response.status_code == 200
    result = response.json()["results"][0]
    assert result["output"] == "Iloveyou"
    assert result["chain"] == [{"transform": "Base64", "parameter": None}]


def test_local_frontend_ports_are_allowed_by_cors() -> None:
    response = client.options(
        "/api/v1/crypto/decode",
        headers={
            "Origin": "http://127.0.0.1:4173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://127.0.0.1:4173"


def test_recipe_returns_intermediates_and_detects_rsa_key() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    response = client.post(
        "/api/v1/crypto/recipes/run",
        json={"input": pem.hex(), "operations": [{"operation": "hex"}]},
    )
    assert response.status_code == 200
    result = response.json()["result"]
    assert result["output_base64"] == base64.b64encode(pem).decode()
    assert result["artifacts"][0]["kind"] == "rsa-private-key"
    assert result["artifacts"][0]["send_to_decryptor"] is True


def test_recipe_failure_has_decoder_error_envelope() -> None:
    response = client.post(
        "/api/v1/crypto/recipes/run",
        json={"input": "not hex", "operations": [{"operation": "hex"}]},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_DECODER_OPTION"


def test_rsa_analysis_and_pkcs1_decryption_with_hex_encoded_pem() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    plaintext = b"picoCTF{real_rsa_result}"
    ciphertext = key.public_key().encrypt(plaintext, padding.PKCS1v15())

    analysis = client.post(
        "/api/v1/crypto/decrypt/analyze",
        json={
            "key": {"value": pem.hex(), "encoding": "auto"},
            "ciphertext": {"value": base64.b64encode(ciphertext).decode(), "encoding": "base64"},
        },
    )
    assert analysis.status_code == 200
    assert analysis.json()["key"]["key_type"] == "private"
    assert analysis.json()["compatible"] is True

    decrypted = client.post(
        "/api/v1/crypto/decrypt/rsa",
        json={
            "private_key": {"value": pem.hex(), "encoding": "auto"},
            "ciphertext": {"value": ciphertext.hex(), "encoding": "hex"},
            "padding": "pkcs1v15",
        },
    )
    assert decrypted.status_code == 200
    payload = decrypted.json()
    assert payload["plaintext"] == plaintext.decode()
    assert payload["flags"][0]["state"] == "candidate"
    assert payload["flags"][0]["source"] == "decryptor.plaintext"


def test_rsa_oaep_sha256_and_wrong_ciphertext_length() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    plaintext = b"OAEP works"
    ciphertext = key.public_key().encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    response = client.post(
        "/api/v1/crypto/decrypt/rsa",
        json={
            "private_key": {"value": pem, "encoding": "text"},
            "ciphertext": {"value": base64.b64encode(ciphertext).decode(), "encoding": "base64"},
            "padding": "oaep-sha256",
        },
    )
    assert response.status_code == 200
    assert response.json()["plaintext"] == plaintext.decode()

    invalid = client.post(
        "/api/v1/crypto/decrypt/rsa",
        json={
            "private_key": {"value": pem, "encoding": "text"},
            "ciphertext": {"value": "00", "encoding": "hex"},
        },
    )
    assert invalid.status_code == 400
    assert invalid.json()["error"]["code"] == "INVALID_CRYPTO_INPUT"


def test_openssl_salted_3des_analysis_does_not_require_password() -> None:
    encrypted = _openssl_encrypt(
        b"picoCTF{openssl_des3_md5}",
        b"supersecretpassword123",
        bytes.fromhex("8fd312ab70e41c99"),
    )
    response = client.post(
        "/api/v1/crypto/decrypt/openssl/analyze",
        json={"encrypted": {"value": encrypted.hex(), "encoding": "hex"}},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["detected"] is True
    assert payload["header"] == "Salted__"
    assert payload["salt_hex"] == "8fd312ab70e41c99"
    assert payload["encrypted_payload_bytes"] == len(encrypted) - 16
    assert payload["password_status"] == "not-supplied"
    assert payload["status"] == "password-required"


def test_openssl_auto_detects_3des_evp_md5_and_scores_flag() -> None:
    password = "supersecretpassword123"
    encrypted = _openssl_encrypt(
        b"picoCTF{openssl_des3_md5}",
        password.encode(),
        bytes.fromhex("8fd312ab70e41c99"),
    )
    response = client.post(
        "/api/v1/crypto/decrypt/openssl",
        json={
            "encrypted": {
                # Reconstructed TCP stream bytes are transported losslessly as Base64.
                "value": base64.b64encode(encrypted).decode(),
                "encoding": "base64",
            },
            "password": password,
            "cipher": "auto",
            "kdf": "auto",
            "digest": "auto",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["attempted_variants"] == 10
    candidate = payload["candidates"][0]
    assert candidate["cipher"] == "des-ede3-cbc"
    assert candidate["kdf"] == "evp-bytes-to-key"
    assert candidate["digest"] == "md5"
    assert candidate["padding_valid"] is True
    assert candidate["flags"][0]["value"] == "picoCTF{openssl_des3_md5}"
    assert candidate["confidence"] == "VERY HIGH"
    assert "openssl des3 -d -salt -md md5" in candidate["equivalent_command"]


def test_openssl_salted_des_sha256_and_artifact_detection() -> None:
    encrypted = _openssl_encrypt(
        b"CTF{single_des_compatibility}",
        b"des-password",
        bytes.fromhex("a1a2a3a4a5a6a7a8"),
        cipher_name="des-cbc",
        digest="sha256",
    )
    detected = client.post(
        "/api/v1/crypto/recipes/run",
        json={"input": encrypted.hex(), "operations": [{"operation": "hex"}]},
    )
    assert detected.status_code == 200
    artifact = detected.json()["result"]["artifacts"][0]
    assert artifact["kind"] == "openssl-enc"
    assert artifact["send_to_decryptor"] is True
    assert artifact["details"]["salt"] == "a1a2a3a4a5a6a7a8"

    response = client.post(
        "/api/v1/crypto/decrypt/openssl",
        json={
            "encrypted": {"value": base64.b64encode(encrypted).decode(), "encoding": "auto"},
            "password": "des-password",
            "cipher": "des-cbc",
            "kdf": "evp-bytes-to-key",
            "digest": "sha256",
        },
    )
    assert response.status_code == 200
    candidate = response.json()["candidates"][0]
    assert candidate["cipher"] == "des-cbc"
    assert candidate["digest"] == "sha256"
    assert candidate["plaintext"] == "CTF{single_des_compatibility}"


def test_openssl_pbkdf2_aes_and_binary_file_magic() -> None:
    plaintext = b"\x89PNG\r\n\x1a\n" + b"binary image bytes"
    encrypted = _openssl_encrypt(
        plaintext,
        b"70617373776f7264",
        bytes.fromhex("0102030405060708"),
        cipher_name="aes-256-cbc",
        digest="sha256",
        pbkdf2=True,
        iterations=12_345,
    )
    response = client.post(
        "/api/v1/crypto/decrypt/openssl",
        json={
            "encrypted": {"value": encrypted.hex(), "encoding": "hex"},
            "password": "NzA2MTczNzM3NzZmNzI2NA==",
            "password_encoding": "base64",
            "cipher": "aes-256-cbc",
            "kdf": "pbkdf2",
            "digest": "sha256",
            "iterations": 12_345,
        },
    )

    assert response.status_code == 200
    candidate = response.json()["candidates"][0]
    assert candidate["kdf"] == "pbkdf2"
    assert candidate["iterations"] == 12_345
    assert candidate["file_magic"] == "PNG image"
    assert base64.b64decode(candidate["plaintext_base64"]) == plaintext
    assert candidate["equivalent_command"] is None


def test_openssl_wrong_password_is_rejected_without_success() -> None:
    encrypted = _openssl_encrypt(
        b"CTF{padding_must_validate}", b"correct-password", b"12345678"
    )
    response = client.post(
        "/api/v1/crypto/decrypt/openssl",
        json={
            "encrypted": {"value": encrypted.hex(), "encoding": "hex"},
            "password": "wrong-password",
            "cipher": "des-ede3-cbc",
            "kdf": "evp-bytes-to-key",
            "digest": "md5",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "rejected"
    assert payload["candidates"] == []
    assert payload["rejection_reason"] == "Invalid block padding."
    assert "Incorrect password" in payload["possible_causes"]


def test_openssl_truncated_header_has_structured_crypto_error_on_decrypt() -> None:
    analysis = client.post(
        "/api/v1/crypto/decrypt/openssl/analyze",
        json={"encrypted": {"value": b"Salted__tiny".hex(), "encoding": "hex"}},
    )
    assert analysis.status_code == 200
    assert analysis.json()["status"] == "invalid-payload"

    decrypted = client.post(
        "/api/v1/crypto/decrypt/openssl",
        json={
            "encrypted": {"value": b"Salted__tiny".hex(), "encoding": "hex"},
            "password": "anything",
        },
    )
    assert decrypted.status_code == 400
    assert decrypted.json()["error"]["code"] == "INVALID_CRYPTO_INPUT"
