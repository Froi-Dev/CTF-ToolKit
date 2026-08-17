import base64
from fastapi.testclient import TestClient

def test_analyze_symmetric(client: TestClient) -> None:
    # 16-byte block repeated 5 times -> ECB leak
    block = b"A" * 16
    ciphertext = block * 5
    response = client.post("/api/v1/crypto/analyze/symmetric", json={"ciphertext": ciphertext.hex()}) # Fastapi parses hex strings automatically? Wait, no, SymmetricAnalyzeInput has `ciphertext: bytes` which Pydantic might decode from base64 or utf-8 depending on config. Let's use string encoding. Wait, Pydantic's default `bytes` parser expects base64 encoded strings in v2 or utf-8 strings. Let's send a base64 encoded string.
    import base64
    b64_cipher = base64.b64encode(ciphertext).decode("ascii")
    response = client.post("/api/v1/crypto/analyze/symmetric", json={"ciphertext": b64_cipher})
    assert response.status_code == 200
    data = response.json()
    assert data["block_size_detected"] == 16
    assert any("ECB Mode Pattern Leakage" in f["title"] for f in data["findings"])

def test_analyze_stream(client: TestClient) -> None:
    # Small test
    c1 = base64.b64encode(b"hello world!").decode("ascii")
    crib = base64.b64encode(b"hello").decode("ascii")
    response = client.post("/api/v1/crypto/analyze/stream", json={"ciphertexts": [c1], "cribs": [crib]})
    assert response.status_code == 200

def test_analyze_hash(client: TestClient) -> None:
    response = client.post("/api/v1/crypto/analyze/hash", json={"hash_str": "5f4dcc3b5aa765d61d8327deb882cf99"})
    assert response.status_code == 200
    data = response.json()
    assert data["algorithm"] == "MD5"
    assert data["cracked_plaintext"] == "password"

def test_analyze_custom(client: TestClient) -> None:
    code = "KEY = b'supersecret'\nIV = 12345\n"
    response = client.post("/api/v1/crypto/analyze/custom", json={"source_code": code})
    assert response.status_code == 200
    data = response.json()
    assert data["extracted_constants"]["KEY"] == "b'supersecret'"
    assert data["extracted_constants"]["IV"] == "12345"
    assert "solve" in data["proposed_solver"]
