from __future__ import annotations

import io
import zipfile

from fastapi.testclient import TestClient
from PIL import Image

from app.analyzers.stego import ImageStegoAnalyzer, StegoPolicy
from app.analyzers.stego.structures import parse_png
from app.api.v1.routes import stego as stego_route
from app.main import app
from app.services.stego import StegoAnalysisService

client = TestClient(app)


def _png(width: int = 16, height: int = 16) -> bytes:
    output = io.BytesIO()
    Image.new("RGB", (width, height), (100, 120, 140)).save(output, format="PNG")
    return output.getvalue()


def _jpeg(width: int = 16, height: int = 16) -> bytes:
    output = io.BytesIO()
    Image.new("RGB", (width, height), (180, 110, 70)).save(output, format="JPEG")
    return output.getvalue()


def _zip(entries: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return output.getvalue()


def _png_with_red_lsb(payload: bytes) -> bytes:
    image = Image.new("RGB", (16, 16), (100, 120, 140))
    raw_pixels = image.tobytes()
    pixels = [
        (raw_pixels[index], raw_pixels[index + 1], raw_pixels[index + 2])
        for index in range(0, len(raw_pixels), 3)
    ]
    bits = [int(bit) for byte in payload for bit in f"{byte:08b}"]
    assert len(bits) <= len(pixels)
    encoded = []
    for index, (red, green, blue) in enumerate(pixels):
        red = (red & 0xFE) | bits[index] if index < len(bits) else red & 0xFE
        encoded.append((red, green, blue))
    image.putdata(encoded)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def test_png_metadata_structure_channels_bitplanes_lsb_and_flags() -> None:
    image = _png_with_red_lsb(b"CTF{lsb_secret}")

    response = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("hidden.png", image, "image/png")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["category"] == "steganography"
    assert payload["image"]["format"] == "PNG"
    assert payload["image"]["width"] == 16
    assert payload["image"]["height"] == 16
    assert [chunk["chunk_type"] for chunk in payload["png_chunks"]][:3] == ["IHDR", "IDAT", "IEND"]
    assert all(chunk["crc_valid"] for chunk in payload["png_chunks"])
    assert {channel["channel"] for channel in payload["channels"]} == {"R", "G", "B"}
    assert len(payload["bit_planes"]) == 24
    red_stream = next(item for item in payload["lsb"] if item["stream"] == "R")
    assert red_stream["flags"][0]["value"] == "CTF{lsb_secret}"
    assert red_stream["suspicious"] is True
    assert payload["flags"][0]["source"] == "lsb:R"


def test_png_trailing_zip_is_detected_and_carved() -> None:
    image = _png()
    archive = _zip({"flag.txt": b"CTF{zip_tail}"})

    response = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("tail.png", image + archive, "image/png")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["trailing_bytes"]["present"] is True
    assert payload["trailing_bytes"]["offset"] == len(image)
    assert payload["trailing_bytes"]["detected_type"] == "zip"
    candidate = next(item for item in payload["signatures"] if item["detected_type"] == "zip")
    assert candidate["offset"] == len(image)
    assert candidate["source"] == "trailing-bytes"
    assert candidate["carved_artifact_id"]
    carved = next(item for item in payload["carved_artifacts"] if item["artifact_id"] == candidate["carved_artifact_id"])
    assert carved["parent_artifact_id"] == payload["artifact_id"]
    assert carved["detected_type"] == "zip"
    assert carved["retained"] is False


def test_jpeg_structure_and_trailing_pdf_carving() -> None:
    image = _jpeg()
    pdf = b"%PDF-1.7\nbody\n%%EOF"

    response = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("tail.jpg", image + pdf, "image/jpeg")},
    )

    assert response.status_code == 200
    payload = response.json()
    markers = {segment["marker"] for segment in payload["jpeg_segments"]}
    assert {"FFD8", "FFDA", "FFD9"}.issubset(markers)
    assert payload["trailing_bytes"]["offset"] == len(image)
    assert payload["trailing_bytes"]["detected_type"] == "pdf"
    pdf_candidate = next(item for item in payload["signatures"] if item["detected_type"] == "pdf")
    assert pdf_candidate["source"] == "trailing-bytes"
    assert any(item["artifact_id"] == pdf_candidate["carved_artifact_id"] for item in payload["carved_artifacts"])


def test_invalid_upload_uses_structured_error() -> None:
    response = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("fake.png", b"not an image", "image/png")},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_ARTIFACT"


def test_upload_limit_uses_structured_error(monkeypatch) -> None:
    limited = StegoAnalysisService(ImageStegoAnalyzer(StegoPolicy(max_upload_bytes=8)))
    monkeypatch.setattr(stego_route, "service", limited)

    response = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("large.png", _png(), "image/png")},
    )

    assert response.status_code == 413
    assert response.json()["error"]["details"] == {"max_bytes": 8}


def test_pixel_limit_rejects_oversized_decoded_image(monkeypatch) -> None:
    limited = StegoAnalysisService(ImageStegoAnalyzer(StegoPolicy(max_pixels=4)))
    monkeypatch.setattr(stego_route, "service", limited)

    response = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("too-many-pixels.png", _png(width=3, height=3), "image/png")},
    )

    assert response.status_code == 400
    assert "pixel limit" in response.json()["error"]["message"]


def test_missing_file_has_standard_validation_envelope() -> None:
    response = client.post("/api/v1/stego/analyze")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_png_parser_reports_bad_crc_without_needing_decode() -> None:
    image = bytearray(_png())
    chunk_type = image.find(b"IDAT")
    length = int.from_bytes(image[chunk_type - 4 : chunk_type], "big")
    crc_offset = chunk_type + 4 + length
    image[crc_offset] ^= 0xFF

    chunks, structure = parse_png(bytes(image), max_results=8)

    assert any(chunk.chunk_type == "IDAT" and not chunk.crc_valid for chunk in chunks)
    assert any("invalid CRC" in warning for warning in structure.warnings)
