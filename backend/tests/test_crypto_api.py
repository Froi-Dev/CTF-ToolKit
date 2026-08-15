import base64

from fastapi.testclient import TestClient

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
