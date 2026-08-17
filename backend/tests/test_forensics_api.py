import hashlib
import io
import json
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.analyzers.forensics import FileTriageAnalyzer, TriagePolicy
from app.analyzers.forensics.metadata import DeepMetadataAnalyzer
from app.api.v1.routes import forensics as forensics_route
from app.main import app
from app.services.forensics import ForensicsTriageService
from app.core.tool_runner import ToolExecution

client = TestClient(app)


def _zip(entries: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return output.getvalue()


def test_png_magic_mime_hashes_metadata_strings_entropy_and_embedded_detection() -> None:
    png = (
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\x0dIHDR"
        + (2).to_bytes(4, "big")
        + (3).to_bytes(4, "big")
        + b"\x08\x02\x00\x00\x00"
        + b"fake-crc"
        + b"\x00\x00\x00\x00IENDfake"
        + b"notes CTF{byte_offsets_work} "
        + b"%PDF-1.7\nbody\n%%EOF"
    )

    response = client.post(
        "/api/v1/forensics/triage",
        files={"file": ("evidence.txt", png, "text/plain")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["magic"]["detected_type"] == "png"
    assert payload["magic"]["mime_type"] == "image/png"
    assert payload["extension"]["mismatch"] is True
    assert payload["hashes"]["sha256"] == hashlib.sha256(png).hexdigest()
    assert payload["entropy"]["sample_size"] == len(png)
    assert {item["key"]: item["value"] for item in payload["metadata"]}["width"] == 2
    assert any("notes CTF{" in item["value"] for item in payload["strings"])
    assert payload["flags"][0]["value"] == "CTF{byte_offsets_work}"
    embedded_pdf = next(item for item in payload["embedded_files"] if item["detected_type"] == "pdf")
    assert embedded_pdf["extracted_artifact_id"]
    assert any(
        artifact["artifact_id"] == embedded_pdf["extracted_artifact_id"]
        and artifact["parent_artifact_id"] == payload["artifact_id"]
        and artifact["extraction_method"] == "embedded-carve"
        for artifact in payload["extracted_artifacts"]
    )


def test_zip_discovery_extracts_safe_members_and_preserves_provenance() -> None:
    archive_bytes = _zip(
        {
            "evidence/flag.txt": b"picoCTF{inside_archive}",
            "../escape.txt": b"must not escape",
        }
    )

    response = client.post(
        "/api/v1/forensics/triage",
        files={"file": ("challenge.zip", archive_bytes, "application/octet-stream")},
    )

    assert response.status_code == 200
    payload = response.json()
    archive = payload["archives"][0]
    assert archive["format"] == "zip"
    safe = next(item for item in archive["members"] if item["path"] == "evidence/flag.txt")
    unsafe = next(item for item in archive["members"] if item["path"] == "../escape.txt")
    assert safe["extractable"] is True
    assert safe["extracted_artifact_id"]
    assert unsafe["extractable"] is False
    assert "unsafe" in unsafe["skipped_reason"]
    assert payload["flags"][0]["source"] == "evidence/flag.txt"
    child = next(
        item for item in payload["extracted_artifacts"] if item["artifact_id"] == safe["extracted_artifact_id"]
    )
    assert child["parent_artifact_id"] == payload["artifact_id"]
    assert child["hashes"]["sha256"] == hashlib.sha256(b"picoCTF{inside_archive}").hexdigest()
    assert child["retained"] is False


def test_zip_symlink_and_high_compression_ratio_are_not_extracted() -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "target")
        archive.writestr("bomb.txt", b"A" * 200_000)

    response = client.post(
        "/api/v1/forensics/triage",
        files={"file": ("hostile.zip", output.getvalue(), "application/zip")},
    )

    assert response.status_code == 200
    members = {item["path"]: item for item in response.json()["archives"][0]["members"]}
    assert members["link"]["kind"] == "symlink"
    assert members["link"]["extractable"] is False
    assert members["bomb.txt"]["extractable"] is False
    assert "compression ratio" in members["bomb.txt"]["skipped_reason"]


def test_compressed_tar_bomb_ratio_is_not_extracted() -> None:
    output = io.BytesIO()
    content = b"A" * 500_000
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        info = tarfile.TarInfo("large.txt")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))

    response = client.post(
        "/api/v1/forensics/triage",
        files={"file": ("hostile.tar.gz", output.getvalue(), "application/gzip")},
    )

    assert response.status_code == 200
    member = response.json()["archives"][0]["members"][0]
    assert member["extractable"] is False
    assert "compression ratio" in member["skipped_reason"]
    assert response.json()["extracted_artifacts"] == []


def test_upload_limit_uses_structured_error(monkeypatch) -> None:
    limited = ForensicsTriageService(
        FileTriageAnalyzer(TriagePolicy(max_upload_bytes=8))
    )
    monkeypatch.setattr(forensics_route, "service", limited)

    response = client.post(
        "/api/v1/forensics/triage",
        files={"file": ("large.bin", b"123456789", "application/octet-stream")},
    )

    assert response.status_code == 413
    assert response.json() == {
        "error": {
            "code": "ARTIFACT_TOO_LARGE",
            "message": "Artifact exceeds the 8-byte upload limit.",
            "details": {"max_bytes": 8},
        }
    }


def test_missing_file_has_standard_validation_envelope() -> None:
    response = client.post("/api/v1/forensics/triage")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_flag_offsets_are_bytes_not_decoded_character_positions() -> None:
    data = "é".encode() + b"CTF{offset}"
    response = client.post(
        "/api/v1/forensics/triage",
        files={"file": ("offset.bin", data, "application/octet-stream")},
    )
    assert response.status_code == 200
    assert response.json()["flags"][0]["offset"] == 2


class _ExifRunner:
    def available(self, tool: str) -> bool:
        return tool == "exiftool"

    def run(self, tool: str, arguments: list[str], **_kwargs: object) -> ToolExecution:
        if arguments == ["-ver"]:
            output = b"13.25\n"
        else:
            output = json.dumps([{
                "SourceFile": "/tmp/random/artifact",
                "System:FileName": "artifact-random",
                "System:FileCreateDate": "2026:04:01 12:00:00",
                "EXIF:DateTimeOriginal": "2019:08:13 12:00:00",
                "EXIF:GPSLatitude": 14.5995,
                "EXIF:GPSLongitude": 120.9842,
                "PNG:Comment": "cGljb0NURnttZXRhZGF0YV9mbGFnfQ==",
                "XMP:Author": "admin_backup",
            }]).encode()
        return ToolExecution(tool="exiftool", returncode=0, duration_ms=1, stdout=output, stderr=b"")


def test_deep_metadata_decodes_flags_builds_timeline_and_normalizes_identity(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"evidence")
    analysis = DeepMetadataAnalyzer(_ExifRunner()).analyze(artifact, "challenge.png")  # type: ignore[arg-type]

    assert analysis.tool_available is True
    assert analysis.tool_version == "13.25"
    assert analysis.gps is not None
    assert (analysis.gps.latitude, analysis.gps.longitude) == (14.5995, 120.9842)
    assert analysis.timestamp_anomalies
    decoded = next(item for item in analysis.decoded if item.field == "PNG:Comment")
    assert decoded.decoded == "picoCTF{metadata_flag}"
    assert decoded.flags == ["picoCTF{metadata_flag}"]
    assert any(item.severity == "critical" for item in analysis.notable)
    filename = next(item for item in analysis.all_metadata if item.tag == "FileName")
    assert filename.display_value == "challenge.png"


def test_qr_recovery_never_claims_payload_from_blank_image() -> None:
    from PIL import Image

    output = io.BytesIO()
    Image.new("RGB", (32, 32), "white").save(output, "PNG")
    response = client.post(
        "/api/v1/forensics/triage",
        files={"file": ("blank.png", output.getvalue(), "image/png")},
    )

    assert response.status_code == 200
    recovery = response.json()["qr_barcode"]
    assert recovery["findings"] == []
    assert recovery["variants"]
    assert all(not item["success"] for item in recovery["attempts"])


def test_file_analysis_decodes_real_qr_and_promotes_flag() -> None:
    cv2 = pytest.importorskip("cv2")
    qr = cv2.QRCodeEncoder_create().encode("CTF{file_analysis_qr}")
    qr = cv2.copyMakeBorder(qr, 4, 4, 4, 4, cv2.BORDER_CONSTANT, value=255)
    qr = cv2.resize(qr, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    encoded, png = cv2.imencode(".png", qr)
    assert encoded

    response = client.post(
        "/api/v1/forensics/triage",
        files={"file": ("code.png", png.tobytes(), "image/png")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert any(item["decoded_value"] == "CTF{file_analysis_qr}" for item in payload["qr_barcode"]["findings"])
    assert any(item["value"] == "CTF{file_analysis_qr}" for item in payload["flags"])


def test_file_analysis_qr_pipeline_includes_image_bit_planes() -> None:
    from PIL import Image
    from app.analyzers.forensics.qr_barcode import QRBarcodeRecoveryAnalyzer

    variants = QRBarcodeRecoveryAnalyzer._variants(
        Image.new("RGB", (8, 8), "white"), include_bit_planes=True
    )
    labels = {label for label, _image, _steps in variants}

    assert "R bit-plane 0" in labels
    assert "G bit-plane 7" in labels
    assert "B bit-plane 3" in labels
