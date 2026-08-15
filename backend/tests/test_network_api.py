from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.analyzers.network import NetworkPcapAnalyzer, NetworkPolicy
from app.api.v1.routes import network as network_route
from app.core.errors import ToolNotAvailableError
from app.core.tool_runner import ToolExecution
from app.integrations.tshark import (
    ExportedObject,
    ReconstructedStream,
    TSharkIntegration,
    TSharkResult,
)
from app.main import app
from app.services.network import NetworkAnalysisService

client = TestClient(app)
PCAP_HEADER = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20


def _row(**values: str) -> dict[str, str]:
    base = {
        "frame.number": "1",
        "frame.time_epoch": "1700000000.000000",
        "frame.len": "100",
        "frame.cap_len": "100",
        "frame.protocols": "eth:ethertype:ip:tcp",
        "eth.src": "00:00:00:00:00:01",
        "eth.dst": "00:00:00:00:00:02",
        "ip.src": "10.0.0.1",
        "ip.dst": "10.0.0.2",
        "ipv6.src": "",
        "ipv6.dst": "",
        "tcp.srcport": "40000",
        "tcp.dstport": "21",
        "udp.srcport": "",
        "udp.dstport": "",
        "tcp.stream": "0",
        "tcp.flags.syn": "0",
        "tcp.flags.fin": "0",
        "tcp.flags.reset": "0",
        "_ws.col.Protocol": "TCP",
        "_ws.col.Info": "",
        "dns.id": "",
        "dns.flags.response": "",
        "dns.qry.name": "",
        "dns.qry.type": "",
        "dns.a": "",
        "dns.aaaa": "",
        "dns.cname": "",
        "http.request.method": "",
        "http.host": "",
        "http.request.uri": "",
        "http.response.code": "",
        "http.content_type": "",
        "http.content_length": "",
        "http.user_agent": "",
        "http.authorization": "",
        "ftp.request.command": "",
        "ftp.request.arg": "",
        "ftp.response.code": "",
        "ftp.response.arg": "",
    }
    base.update(values)
    return base


class FixtureTShark:
    def analyze(self, capture_path: Path, workspace: Path, **options: object) -> TSharkResult:
        del capture_path, options
        exported_path = workspace / "exports" / "http" / "proof.txt"
        exported_path.parent.mkdir(parents=True)
        exported_path.write_bytes(b"downloaded CTF{exported_object}")
        rows = (
            _row(
                **{
                    "frame.protocols": "eth:ethertype:ip:tcp:ftp",
                    "_ws.col.Protocol": "FTP",
                    "ftp.request.command": "USER",
                    "ftp.request.arg": "alice",
                }
            ),
            _row(
                **{
                    "frame.number": "2",
                    "frame.time_epoch": "1700000000.100000",
                    "frame.protocols": "eth:ethertype:ip:tcp:ftp",
                    "_ws.col.Protocol": "FTP",
                    "ftp.request.command": "PASS",
                    "ftp.request.arg": "wonderland",
                }
            ),
            _row(
                **{
                    "frame.number": "3",
                    "frame.time_epoch": "1700000001.000000",
                    "frame.protocols": "eth:ethertype:ip:udp:dns",
                    "_ws.col.Protocol": "DNS",
                    "tcp.srcport": "",
                    "tcp.dstport": "",
                    "tcp.stream": "",
                    "udp.srcport": "53000",
                    "udp.dstport": "53",
                    "dns.id": "0x1234",
                    "dns.flags.response": "0",
                    "dns.qry.name": "challenge.test",
                    "dns.qry.type": "1",
                }
            ),
            _row(
                **{
                    "frame.number": "4",
                    "frame.time_epoch": "1700000002.000000",
                    "frame.protocols": "eth:ethertype:ip:tcp:http",
                    "_ws.col.Protocol": "HTTP",
                    "tcp.srcport": "41000",
                    "tcp.dstport": "80",
                    "tcp.stream": "1",
                    "http.request.method": "POST",
                    "http.host": "challenge.test",
                    "http.request.uri": "/login",
                    "http.authorization": "Basic Ym9iOnNlY3JldA==",
                }
            ),
            _row(
                **{
                    "frame.number": "5",
                    "frame.time_epoch": "1700000002.500000",
                    "frame.protocols": "eth:ethertype:ip:tcp:http",
                    "_ws.col.Protocol": "HTTP",
                    "ip.src": "10.0.0.2",
                    "ip.dst": "10.0.0.1",
                    "tcp.srcport": "80",
                    "tcp.dstport": "41000",
                    "tcp.stream": "1",
                    "http.response.code": "200",
                    "http.content_type": "text/plain",
                    "http.content_length": "12",
                }
            ),
        )
        streams = (
            ReconstructedStream(
                0,
                b"USER alice\r\nPASS wonderland\r\nflag{stream_flag}\r\n",
                (("a_to_b", 0, 50),),
                False,
            ),
            ReconstructedStream(
                1,
                b"POST /login HTTP/1.1\r\n\r\nusername=carol&password=swordfish",
                (("a_to_b", 0, 59),),
                False,
            ),
        )
        execution = ToolExecution("tshark", 0, 4, b"", b"")
        return TSharkResult(
            rows=rows,
            streams=streams,
            exported_objects=(ExportedObject("http", "proof.txt", exported_path),),
            executions=(("packet-decode", execution),),
            warnings=(),
        )


def test_network_analysis_covers_protocols_streams_files_credentials_flags_and_timeline(
    monkeypatch,
) -> None:
    analyzer = NetworkPcapAnalyzer(tshark=FixtureTShark())  # type: ignore[arg-type]
    monkeypatch.setattr(network_route, "service", NetworkAnalysisService(analyzer))

    response = client.post(
        "/api/v1/network/analyze",
        files={"file": ("capture.pcap", PCAP_HEADER, "application/vnd.tcpdump.pcap")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["capture"]["format"] == "pcap"
    assert payload["capture"]["packet_count"] == 5
    assert payload["capture"]["unique_hosts"] == 2
    assert len(payload["packets"]) == 5
    assert payload["protocol_hierarchy"][0]["protocol"] == "eth"
    assert len(payload["conversations"]) == 3
    assert payload["dns"][0]["name"] == "challenge.test"
    assert payload["http"][0]["uri"] == "/login"
    assert payload["ftp"][1]["command"] == "PASS"
    assert payload["tcp_streams"][0]["reconstructed_bytes"] > 0
    assert payload["tcp_streams"][0]["reconstructed_base64"]
    assert payload["transferred_files"][0]["source_name"] == "proof.txt"
    assert payload["transferred_files"][0]["parent_artifact_id"] == payload["capture"]["artifact_id"]
    credentials = {(item["protocol"], item["username"], item["secret"]) for item in payload["plaintext_credentials"]}
    assert ("ftp", "alice", "wonderland") in credentials
    assert ("http-basic", "bob", "secret") in credentials
    assert ("http-form", "carol", "swordfish") in credentials
    assert {(item["transport"], item["port"]) for item in payload["interesting_ports"]} >= {
        ("tcp", 21),
        ("udp", 53),
        ("tcp", 80),
    }
    assert {item["value"] for item in payload["flags"]} == {
        "flag{stream_flag}",
        "CTF{exported_object}",
    }
    assert {item["event_type"] for item in payload["timeline"]} >= {
        "dns.query",
        "http.request",
        "http.response",
        "ftp.request",
    }


def test_non_capture_is_rejected_before_external_tool_execution() -> None:
    response = client.post(
        "/api/v1/network/analyze",
        files={"file": ("fake.pcap", b"not a capture", "application/octet-stream")},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_ARTIFACT"


class MissingTShark(TSharkIntegration):
    def analyze(self, *args: object, **kwargs: object) -> TSharkResult:
        del args, kwargs
        raise ToolNotAvailableError("tshark")


def test_missing_tshark_has_structured_service_unavailable_error(monkeypatch) -> None:
    analyzer = NetworkPcapAnalyzer(tshark=MissingTShark())
    monkeypatch.setattr(network_route, "service", NetworkAnalysisService(analyzer))
    response = client.post(
        "/api/v1/network/analyze",
        files={"file": ("capture.pcap", PCAP_HEADER, "application/octet-stream")},
    )
    assert response.status_code == 503
    assert response.json() == {
        "error": {
            "code": "TOOL_NOT_AVAILABLE",
            "message": "tshark is not installed or is not available on PATH.",
            "details": {"tool": "tshark"},
        }
    }


def test_network_upload_limit_is_enforced(monkeypatch) -> None:
    analyzer = NetworkPcapAnalyzer(
        policy=NetworkPolicy(max_upload_bytes=8),
        tshark=FixtureTShark(),  # type: ignore[arg-type]
    )
    monkeypatch.setattr(network_route, "service", NetworkAnalysisService(analyzer))
    response = client.post(
        "/api/v1/network/analyze",
        files={"file": ("large.pcap", PCAP_HEADER, "application/octet-stream")},
    )
    assert response.status_code == 413
    assert response.json()["error"]["details"] == {"max_bytes": 8}


def test_follow_stream_parser_preserves_direction_and_truncates() -> None:
    reconstructed = TSharkIntegration._parse_follow(
        7,
        b"Header\n48656c6c6f\n\t776f726c64\n",
        8,
    )
    assert reconstructed.data == b"Hellowor"
    assert reconstructed.chunks == (("a_to_b", 0, 5), ("b_to_a", 5, 3))
    assert reconstructed.truncated is True


class RecordingRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str]]] = []

    def run(self, tool: str, arguments: list[str], **options: object) -> ToolExecution:
        del options
        self.calls.append((tool, arguments))
        return ToolExecution(tool, 0, 1, b"", b"")


def test_tshark_integration_is_offline_file_analysis_only(tmp_path: Path) -> None:
    capture = tmp_path / "challenge.pcap"
    capture.write_bytes(PCAP_HEADER)
    runner = RecordingRunner()
    integration = TSharkIntegration(runner=runner)  # type: ignore[arg-type]

    integration.analyze(
        capture,
        tmp_path,
        max_packets=100,
        max_streams=10,
        max_stream_bytes=1024,
        max_exported_files=10,
        max_exported_bytes=4096,
        timeout_seconds=5,
    )

    assert runner.calls
    for tool, arguments in runner.calls:
        assert tool == "tshark"
        assert "-r" in arguments
        assert arguments[arguments.index("-r") + 1] == str(capture)
        assert "-i" not in arguments
