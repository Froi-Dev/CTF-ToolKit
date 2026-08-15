from __future__ import annotations

import io
import struct

from fastapi.testclient import TestClient
from PIL import Image

from app.analyzers.forensics import FileTriageAnalyzer, TriagePolicy
from app.analyzers.network import NetworkPcapAnalyzer
from app.api.v1.routes import autotriage as autotriage_route
from app.core.errors import ToolNotAvailableError
from app.main import app
from app.services.autotriage import AutoTriageService

client = TestClient(app)


def _png_with_red_lsb(payload: bytes) -> bytes:
    image = Image.new("RGB", (16, 16), (100, 120, 140))
    raw_pixels = image.tobytes()
    pixels = [
        (raw_pixels[index], raw_pixels[index + 1], raw_pixels[index + 2])
        for index in range(0, len(raw_pixels), 3)
    ]
    bits = [int(bit) for byte in payload for bit in f"{byte:08b}"]
    encoded = [
        (((red & 0xFE) | bits[index]) if index < len(bits) else red & 0xFE, green, blue)
        for index, (red, green, blue) in enumerate(pixels)
    ]
    image.putdata(encoded)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def test_auto_triage_runs_baseline_and_lsb_for_png() -> None:
    image = _png_with_red_lsb(b"CTF{auto_lsb}")

    response = client.post(
        "/api/v1/auto-triage/analyze",
        files={"file": ("hidden.png", image, "image/png")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["detected_type"] == "png"
    assert payload["forensics"]["artifact_id"] == payload["artifact_id"]
    assert payload["steganography"]["artifact_id"] == payload["artifact_id"]
    assert payload["network"] is None
    runs = {item["category"]: item for item in payload["analyzer_runs"]}
    assert runs["forensics"]["status"] == "completed"
    assert runs["steganography"]["status"] == "completed"
    assert runs["network"]["status"] == "skipped"
    capabilities = {item["key"]: item for item in payload["capabilities"]}
    assert capabilities["strings"]["status"] == "completed"
    assert capabilities["metadata"]["result_count"] > 0
    assert capabilities["lsb"]["status"] == "completed"
    assert any(
        flag["value"] == "CTF{auto_lsb}"
        for stream in payload["steganography"]["lsb"]
        for flag in stream["flags"]
    )


def test_auto_triage_skips_specialists_for_plain_text() -> None:
    response = client.post(
        "/api/v1/auto-triage/analyze",
        files={"file": ("notes.txt", b"hello CTF{baseline_flag}", "text/plain")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["detected_type"] == "text"
    assert payload["steganography"] is None
    assert payload["network"] is None
    assert payload["forensics"]["flags"][0]["value"] == "CTF{baseline_flag}"
    runs = {item["category"]: item["status"] for item in payload["analyzer_runs"]}
    assert runs == {
        "forensics": "completed",
        "steganography": "skipped",
        "network": "skipped",
    }


class _MissingTShark:
    def analyze(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise ToolNotAvailableError("tshark")


def test_pcap_keeps_baseline_result_when_tshark_is_unavailable(monkeypatch) -> None:
    service = AutoTriageService(
        network=NetworkPcapAnalyzer(tshark=_MissingTShark()),  # type: ignore[arg-type]
    )
    monkeypatch.setattr(autotriage_route, "service", service)
    pcap = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65_535, 1)

    response = client.post(
        "/api/v1/auto-triage/analyze",
        files={"file": ("capture.pcap", pcap, "application/octet-stream")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["forensics"]["magic"]["detected_type"] == "pcap"
    assert payload["network"] is None
    network_run = next(item for item in payload["analyzer_runs"] if item["category"] == "network")
    assert network_run["status"] == "unavailable"
    assert "tshark" in network_run["message"].lower()


def test_auto_triage_upload_limit_and_missing_file_use_structured_errors(monkeypatch) -> None:
    limited = AutoTriageService(
        forensics=FileTriageAnalyzer(TriagePolicy(max_upload_bytes=8))
    )
    monkeypatch.setattr(autotriage_route, "service", limited)

    too_large = client.post(
        "/api/v1/auto-triage/analyze",
        files={"file": ("large.bin", b"123456789", "application/octet-stream")},
    )
    missing = client.post("/api/v1/auto-triage/analyze")

    assert too_large.status_code == 413
    assert too_large.json()["error"]["details"] == {"max_bytes": 8}
    assert missing.status_code == 422
    assert missing.json()["error"]["code"] == "VALIDATION_ERROR"


def test_auto_triage_rejects_empty_artifacts() -> None:
    response = client.post(
        "/api/v1/auto-triage/analyze",
        files={"file": ("empty.bin", b"", "application/octet-stream")},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_ARTIFACT"


def test_auto_triage_keeps_only_the_uploaded_filename_basename() -> None:
    response = client.post(
        "/api/v1/auto-triage/analyze",
        files={"file": ("../../evidence.txt", b"bounded input", "text/plain")},
    )

    assert response.status_code == 200
    assert response.json()["original_filename"] == "evidence.txt"
