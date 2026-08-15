import base64

from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.main import app

client = TestClient(app)


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
