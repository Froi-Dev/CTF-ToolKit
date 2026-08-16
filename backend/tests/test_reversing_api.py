import struct
from pathlib import Path

from fastapi.testclient import TestClient

from app.analyzers.reversing import ReversePolicy, StaticReverseAnalyzer
from app.api.v1.routes import reversing as reversing_route
from app.core.errors import ToolExecutionError
from app.main import app
from app.services.reversing import ReverseAnalysisService

client = TestClient(app)


class MissingToolRunner:
    def available(self, tool: str) -> bool:
        assert tool == "objdump"
        return False

    def run(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("A missing disassembler must not be invoked.")


class FailingToolRunner:
    def available(self, tool: str) -> bool:
        return True

    def run(self, *args: object, **kwargs: object) -> object:
        raise ToolExecutionError("objdump", "bounded disassembler failure")


def _minimal_elf(*extra: bytes) -> bytes:
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\0" * 8
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        2, 62, 1, 0x401000, 64, 0, 0, 64, 56, 1, 64, 0, 0,
    )
    gnu_stack = struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 16)
    return ident + header + gnu_stack + b"\0".join(extra)


def test_script_analysis_reports_evidence_without_confirming_flag() -> None:
    script = b'#!/usr/bin/python\nprint("Correct! CTF{evidence_only}")\n'

    response = client.post(
        "/api/v1/reversing/analyze",
        files={"file": ("challenge.py", script, "application/octet-stream")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["file"]["format"] == "Script"
    assert payload["file"]["hashes"]["sha256"]
    assert payload["flags"][0]["value"] == "CTF{evidence_only}"
    assert payload["flags"][0]["state"] == "candidate"
    assert payload["recovered_values"] == {}
    assert any(item["kind"] == "success-path string" for item in payload["validation_leads"])


def test_elf_header_protection_and_extension_mismatch_without_objdump(monkeypatch) -> None:
    analyzer = StaticReverseAnalyzer(tool_runner=MissingToolRunner())
    monkeypatch.setattr(reversing_route, "service", ReverseAnalysisService(analyzer))
    artifact = _minimal_elf(b"Enter password:", b"Wrong password!", b"flag.txt")

    response = client.post(
        "/api/v1/reversing/analyze",
        files={"file": ("challenge.jpg", artifact, "image/jpeg")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["file"]["format"] == "ELF"
    assert payload["file"]["architecture"] == "x86-64"
    assert payload["file"]["bits"] == 64
    assert payload["file"]["entry_point"] == 0x401000
    assert payload["file"]["extension_matches"] is False
    assert next(item for item in payload["protections"] if item["name"] == "NX")["status"] == "enabled"
    assert payload["tools"]["objdump"] is False
    assert payload["disassembly"] == []
    assert any(item["title"] == "Extension mismatch" for item in payload["findings"])


def test_custom_flag_prefix_is_bounded_and_detected() -> None:
    response = client.post(
        "/api/v1/reversing/analyze",
        files={"file": ("challenge.js", b'console.log("ACME{custom_prefix}")', "text/javascript")},
        data={"custom_flag_prefix": "ACME"},
    )
    assert response.status_code == 200
    assert response.json()["flags"][0]["value"] == "ACME{custom_prefix}"

    invalid = client.post(
        "/api/v1/reversing/analyze",
        files={"file": ("challenge.js", b"data", "text/javascript")},
        data={"custom_flag_prefix": "ACME.*"},
    )
    assert invalid.status_code == 400
    assert invalid.json()["error"]["code"] == "INVALID_ARTIFACT"


def test_utf16_flag_uses_original_byte_offset() -> None:
    artifact = b"prefix" + "CTF{wide_flag}".encode("utf-16le") + b"suffix"
    response = client.post(
        "/api/v1/reversing/analyze",
        files={"file": ("wide.bin", artifact, "application/octet-stream")},
    )
    assert response.status_code == 200
    flag = response.json()["flags"][0]
    assert flag["value"] == "CTF{wide_flag}"
    assert flag["offset"] == 6


def test_disassembler_failure_degrades_to_warning(monkeypatch) -> None:
    analyzer = StaticReverseAnalyzer(tool_runner=FailingToolRunner())
    monkeypatch.setattr(reversing_route, "service", ReverseAnalysisService(analyzer))
    response = client.post(
        "/api/v1/reversing/analyze",
        files={"file": ("challenge.elf", _minimal_elf(b"Correct!"), "application/octet-stream")},
    )
    assert response.status_code == 200
    assert response.json()["disassembly"] == []
    assert "failed safely" in response.json()["warnings"][0]


def test_malformed_pe_and_empty_artifact_use_structured_errors() -> None:
    malformed = client.post(
        "/api/v1/reversing/analyze",
        files={"file": ("broken.exe", b"MZ" + b"\0" * 20, "application/octet-stream")},
    )
    assert malformed.status_code == 400
    assert malformed.json()["error"]["code"] == "INVALID_ARTIFACT"

    empty = client.post(
        "/api/v1/reversing/analyze",
        files={"file": ("empty.bin", b"", "application/octet-stream")},
    )
    assert empty.status_code == 400
    assert empty.json()["error"]["code"] == "INVALID_ARTIFACT"


def test_upload_limit_is_enforced(monkeypatch) -> None:
    analyzer = StaticReverseAnalyzer(
        policy=ReversePolicy(max_upload_bytes=8),
        tool_runner=MissingToolRunner(),
    )
    monkeypatch.setattr(reversing_route, "service", ReverseAnalysisService(analyzer))

    response = client.post(
        "/api/v1/reversing/analyze",
        files={"file": ("large.bin", b"123456789", "application/octet-stream")},
    )

    assert response.status_code == 413
    assert response.json()["error"]["details"] == {"max_bytes": 8}


def test_uploaded_script_is_never_executed(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    script = f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n".encode()

    response = client.post(
        "/api/v1/reversing/analyze",
        files={"file": ("hostile.py", script, "text/x-python")},
    )

    assert response.status_code == 200
    assert not marker.exists()
