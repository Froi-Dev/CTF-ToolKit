import hashlib
import io
import stat
import tarfile
import zipfile

from fastapi.testclient import TestClient

from app.analyzers.forensics import FileTriageAnalyzer, TriagePolicy
from app.api.v1.routes import forensics as forensics_route
from app.main import app
from app.services.forensics import ForensicsTriageService

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
