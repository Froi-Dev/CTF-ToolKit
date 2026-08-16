from __future__ import annotations

import io
import base64
import gzip
import struct
import zipfile
import zlib

from fastapi.testclient import TestClient
from PIL import Image, PngImagePlugin

from app.analyzers.stego import ImageStegoAnalyzer, StegoPolicy
from app.analyzers.stego.structures import parse_png
from app.api.v1.routes import stego as stego_route
from app.core.tool_runner import ToolExecution
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


def _image_with_payload(
    payload: bytes,
    *,
    channel: int = 2,
    bit_plane: int = 0,
    traversal: str = "xy",
    image_format: str = "PNG",
) -> bytes:
    image = Image.new("RGB", (32, 24), (100, 120, 140))
    raw = image.tobytes()
    pixels = [tuple(raw[index : index + 3]) for index in range(0, len(raw), 3)]
    bits = [int(bit) for byte in payload for bit in f"{byte:08b}"]
    coordinates = [(x, y) for y in range(image.height) for x in range(image.width)]
    if traversal == "yx":
        coordinates = [(x, y) for x in range(image.width) for y in range(image.height)]
    elif traversal == "reverse-xy":
        coordinates.reverse()
    elif traversal == "reverse-yx":
        coordinates = [(x, y) for x in range(image.width) for y in range(image.height)][::-1]
    assert len(bits) <= len(coordinates)
    for index, bit in enumerate(bits):
        x, y = coordinates[index]
        position = y * image.width + x
        values = list(pixels[position])
        values[channel] = (values[channel] & ~(1 << bit_plane)) | (bit << bit_plane)
        pixels[position] = tuple(values)
    image.putdata(pixels)
    output = io.BytesIO()
    image.save(output, format=image_format)
    return output.getvalue()


def _png_with_two_red_bits(payload: bytes) -> bytes:
    image = Image.new("RGB", (32, 24), (100, 120, 140))
    raw = image.tobytes()
    pixels = [tuple(raw[index : index + 3]) for index in range(0, len(raw), 3)]
    bits = [int(bit) for byte in payload for bit in f"{byte:08b}"]
    assert len(bits) <= len(pixels) * 2
    encoded = []
    for index, (red, green, blue) in enumerate(pixels):
        first = bits[index * 2] if index * 2 < len(bits) else 0
        second = bits[index * 2 + 1] if index * 2 + 1 < len(bits) else 0
        encoded.append(((red & 0xFC) | first | (second << 1), green, blue))
    image.putdata(encoded)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _png_with_custom_chunk(payload: bytes) -> bytes:
    image = _png()
    iend = image.rfind(b"\x00\x00\x00\x00IEND")
    assert iend > 0
    chunk_type = b"ruSt"
    chunk = (
        struct.pack(">I", len(payload))
        + chunk_type
        + payload
        + struct.pack(">I", zlib.crc32(chunk_type + payload) & 0xFFFFFFFF)
    )
    return image[:iend] + chunk + image[iend:]


def _png_with_encoded_metadata() -> bytes:
    output = io.BytesIO()
    info = PngImagePlugin.PngInfo()
    info.add_text("Comment", base64.b64encode(b"CTF{metadata_decode}").decode(), zip=True)
    Image.new("RGB", (16, 16), (100, 120, 140)).save(output, format="PNG", pnginfo=info)
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


def test_advanced_blue_lsb_scan_ranks_generalized_flag_and_visuals() -> None:
    image = _image_with_payload(b"ACME{blue_lsb_ranked}")

    response = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("blue.png", image, "image/png")},
    )

    assert response.status_code == 200
    payload = response.json()
    finding = next(item for item in payload["findings"] if item["flags"])
    assert finding["severity"] == "critical"
    assert finding["flags"][0]["value"] == "ACME{blue_lsb_ranked}"
    assert finding["method"]["notation"] == "b1,b,lsb,xy"
    assert finding["method"]["channels"] == "B"
    assert finding["method"]["bit_plane"] == 0
    assert finding["method"]["byte_bit_order"] == "msb-first"
    assert len(payload["bit_plane_visuals"]) == 24
    assert base64.b64decode(payload["bit_plane_visuals"][0]["png_base64"]).startswith(
        b"\x89PNG"
    )
    assert payload["pixel_scan"]["candidates_evaluated"] > 100
    assert payload["pixel_scan"]["noise_hidden"] > 0


def test_bit_one_and_yx_traversal_are_enumerated() -> None:
    image = _image_with_payload(
        b"CTF{column_major_bit_one}", channel=0, bit_plane=1, traversal="yx"
    )

    response = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("yx.png", image, "image/png")},
    )

    assert response.status_code == 200
    finding = next(
        item
        for item in response.json()["findings"]
        if any(flag["value"] == "CTF{column_major_bit_one}" for flag in item["flags"])
    )
    assert finding["method"]["bit_plane"] == 1
    assert finding["method"]["traversal"] == "yx"
    assert finding["method"]["notation"] == "b1,r,bit1,yx"


def test_recursive_decoder_chain_recovers_base64_flag() -> None:
    encoded = base64.b64encode(b"picoCTF{decoded_from_pixels}")
    image = _image_with_payload(encoded)

    response = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("encoded.png", image, "image/png")},
    )

    assert response.status_code == 200
    finding = next(
        item
        for item in response.json()["findings"]
        if any(flag["value"] == "picoCTF{decoded_from_pixels}" for flag in item["flags"])
    )
    assert finding["severity"] == "critical"
    assert any(step["operation"] == "decode" for step in finding["analysis_chain"])


def test_bmp_lossless_pixels_are_supported() -> None:
    image = _image_with_payload(b"FLAG{bmp_pixels}", image_format="BMP")

    response = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("hidden.bmp", image, "image/bmp")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["image"]["format"] == "BMP"
    assert any(flag["value"] == "FLAG{bmp_pixels}" for flag in payload["flags"])


def test_unknown_png_chunk_is_explained_and_ranked() -> None:
    image = _png_with_custom_chunk(b"custom forensic note")

    response = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("custom.png", image, "image/png")},
    )

    assert response.status_code == 200
    payload = response.json()
    custom = next(chunk for chunk in payload["png_chunks"] if chunk["chunk_type"] == "ruSt")
    assert custom["known"] is False
    assert custom["suspicious"] is True
    assert "custom chunk" in custom["explanation"]
    assert any(item["source"] == "png_structure" for item in payload["findings"])


def test_show_all_is_bounded_and_explicit() -> None:
    response = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("plain.png", _png(), "image/png")},
        data={"show_all": "true"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["noise_included"] is True
    assert len(payload["findings"]) <= payload["limits"]["max_candidates"]


def test_multi_bit_and_reverse_traversal_extractions() -> None:
    two_bit_response = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("two.png", _png_with_two_red_bits(b"CTF{two_bits}"), "image/png")},
    )
    reverse_response = client.post(
        "/api/v1/stego/analyze",
        files={
            "file": (
                "reverse.png",
                _image_with_payload(b"HTB{reverse_order}", traversal="reverse-xy"),
                "image/png",
            )
        },
    )

    assert two_bit_response.status_code == reverse_response.status_code == 200
    two_bit = next(
        item
        for item in two_bit_response.json()["findings"]
        if any(flag["value"] == "CTF{two_bits}" for flag in item["flags"])
    )
    reverse = next(
        item
        for item in reverse_response.json()["findings"]
        if any(flag["value"] == "HTB{reverse_order}" for flag in item["flags"])
    )
    assert two_bit["method"]["notation"] == "b2,r,lsb,xy"
    assert reverse["method"]["traversal"] == "reverse-xy"


def test_gzip_stream_is_bounded_decompressed_and_flagged() -> None:
    compressed = gzip.compress(b"THM{compressed_pixel_stream}")
    image = _image_with_payload(compressed)

    response = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("gzip.png", image, "image/png")},
    )

    assert response.status_code == 200
    finding = next(
        item
        for item in response.json()["findings"]
        if any(flag["value"] == "THM{compressed_pixel_stream}" for flag in item["flags"])
    )
    assert finding["severity"] == "critical"
    assert any(step["operation"] == "decompress" for step in finding["analysis_chain"])


def test_compressed_png_metadata_is_decoded_recursively() -> None:
    response = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("metadata.png", _png_with_encoded_metadata(), "image/png")},
    )

    assert response.status_code == 200
    finding = next(
        item
        for item in response.json()["findings"]
        if any(flag["value"] == "CTF{metadata_decode}" for flag in item["flags"])
    )
    assert finding["source"] == "metadata"
    assert any(step["operation"] == "decode" for step in finding["analysis_chain"])


def test_qr_payloads_reenter_flag_pipeline(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.analyzers.stego.pixel._detect_codes",
        lambda _image: [("QR_CODE", "CTF{visual_qr}")],
    )

    response = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("qr.png", _png(), "image/png")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["barcodes"][0]["payload"] == "CTF{visual_qr}"
    assert any(
        item["source"] == "qr_barcode"
        and any(flag["value"] == "CTF{visual_qr}" for flag in item["flags"])
        for item in payload["findings"]
    )


def test_zsteg_is_optional_validation_not_native_backend(monkeypatch) -> None:
    class FakeRunner:
        def available(self, tool: str) -> bool:
            return tool == "zsteg"

        def run(self, *_args, **_kwargs) -> ToolExecution:
            return ToolExecution(
                tool="zsteg",
                returncode=0,
                duration_ms=12,
                stdout=b'b1,b,lsb,xy .. text: "CTF{external_validation}"\n',
                stderr=b"",
            )

    analyzer = ImageStegoAnalyzer(tool_runner=FakeRunner())  # type: ignore[arg-type]
    monkeypatch.setattr(stego_route, "service", StegoAnalysisService(analyzer))

    response = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("external.png", _png(), "image/png")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["external_validation"][0]["executed"] is True
    assert any(
        item["source"] == "external_tool"
        and any(flag["value"] == "CTF{external_validation}" for flag in item["flags"])
        for item in payload["findings"]
    )


def test_analyzer_failure_is_structured_and_cors_visible(monkeypatch) -> None:
    class BrokenAnalyzer(ImageStegoAnalyzer):
        def analyze(self, artifact):  # type: ignore[no-untyped-def]
            del artifact
            raise RuntimeError("internal detail must stay server-side")

    monkeypatch.setattr(stego_route, "service", StegoAnalysisService(BrokenAnalyzer()))

    response = client.post(
        "/api/v1/stego/analyze",
        headers={"Origin": "http://localhost:5173"},
        files={"file": ("broken.png", _png(), "image/png")},
    )

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "ANALYSIS_FAILED"
    assert "internal detail" not in response.text
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_analyzer_memory_failure_has_resource_limit_error(monkeypatch) -> None:
    class MemoryLimitedAnalyzer(ImageStegoAnalyzer):
        def analyze(self, artifact):  # type: ignore[no-untyped-def]
            del artifact
            raise MemoryError

    monkeypatch.setattr(
        stego_route,
        "service",
        StegoAnalysisService(MemoryLimitedAnalyzer()),
    )

    response = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("large.png", _png(), "image/png")},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "ANALYSIS_RESOURCE_LIMIT"


def test_quick_scan_is_default_and_deep_scan_is_explicit() -> None:
    image = _png()
    quick = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("quick.png", image, "image/png")},
    )
    deep = client.post(
        "/api/v1/stego/analyze",
        files={"file": ("deep.png", image, "image/png")},
        data={"deep_scan": "true"},
    )

    assert quick.status_code == deep.status_code == 200
    assert quick.json()["pixel_scan"]["mode"] == "quick"
    assert deep.json()["pixel_scan"]["mode"] == "deep"
    assert (
        quick.json()["pixel_scan"]["candidates_evaluated"]
        < deep.json()["pixel_scan"]["candidates_evaluated"]
    )


def test_busy_analyzer_rejects_instead_of_queueing(monkeypatch) -> None:
    busy_service = StegoAnalysisService()
    assert busy_service._request_slot.acquire(blocking=False)  # noqa: SLF001
    monkeypatch.setattr(stego_route, "service", busy_service)
    try:
        response = client.post(
            "/api/v1/stego/analyze",
            files={"file": ("queued.png", _png(), "image/png")},
        )
    finally:
        busy_service._request_slot.release()  # noqa: SLF001

    assert response.status_code == 429
    assert response.json()["error"]["code"] == "ANALYSIS_BUSY"
