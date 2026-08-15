from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from pathlib import Path

from app.core.errors import InvalidArtifactError, ToolExecutionError
from app.core.tool_runner import ToolExecution, ToolRunner


PACKET_FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.cap_len",
    "frame.protocols",
    "frame.interface_id",
    "frame.interface_name",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.stream",
    "tcp.flags.syn",
    "tcp.flags.fin",
    "tcp.flags.reset",
    "_ws.col.Protocol",
    "_ws.col.Info",
    "dns.id",
    "dns.flags.response",
    "dns.qry.name",
    "dns.qry.type",
    "dns.a",
    "dns.aaaa",
    "dns.cname",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.response.code",
    "http.content_type",
    "http.content_length",
    "http.user_agent",
    "http.authorization",
    "ftp.request.command",
    "ftp.request.arg",
    "ftp.response.code",
    "ftp.response.arg",
)

_HEX_LINE = re.compile(r"^[0-9a-fA-F]+$")


@dataclass(frozen=True, slots=True)
class ReconstructedStream:
    stream_id: int
    data: bytes
    chunks: tuple[tuple[str, int, int], ...]
    truncated: bool


@dataclass(frozen=True, slots=True)
class ExportedObject:
    protocol: str
    source_name: str
    path: Path


@dataclass(frozen=True, slots=True)
class TSharkResult:
    rows: tuple[dict[str, str], ...]
    streams: tuple[ReconstructedStream, ...]
    exported_objects: tuple[ExportedObject, ...]
    executions: tuple[tuple[str, ToolExecution], ...]
    warnings: tuple[str, ...]


class TSharkIntegration:
    """Delegate packet decoding, stream following, and object export to TShark."""

    def __init__(self, runner: ToolRunner | None = None) -> None:
        self._runner = runner or ToolRunner({"tshark"})

    def analyze(
        self,
        capture_path: Path,
        workspace: Path,
        *,
        max_packets: int,
        max_streams: int,
        max_stream_bytes: int,
        max_exported_files: int,
        max_exported_bytes: int,
        timeout_seconds: float,
    ) -> TSharkResult:
        executions: list[tuple[str, ToolExecution]] = []
        warnings: list[str] = []
        field_arguments = [
            "-n",
            "-r",
            str(capture_path),
            "-c",
            str(max_packets),
            "-o",
            "tcp.desegment_tcp_streams:TRUE",
            "-o",
            "http.desegment_body:TRUE",
            "-T",
            "fields",
            "-E",
            "header=n",
            "-E",
            "separator=/t",
            "-E",
            "quote=d",
            "-E",
            "escape=y",
            "-E",
            "occurrence=a",
            "-E",
            "aggregator=,",
        ]
        for field in PACKET_FIELDS:
            field_arguments.extend(("-e", field))
        packet_execution = self._runner.run(
            "tshark",
            field_arguments,
            cwd=workspace,
            timeout_seconds=timeout_seconds,
            output_limit=64 * 1024 * 1024,
        )
        executions.append(("packet-decode", packet_execution))
        if packet_execution.returncode != 0:
            detail = packet_execution.stderr.decode("utf-8", errors="replace").strip()
            raise InvalidArtifactError(
                "TShark could not decode this capture."
                + (f" {detail[:500]}" if detail else "")
            )
        rows = self._parse_rows(packet_execution.stdout)

        stream_ids = sorted(
            {
                int(row["tcp.stream"])
                for row in rows
                if row.get("tcp.stream", "").isdigit()
            }
        )
        if len(stream_ids) > max_streams:
            warnings.append(
                f"TCP reconstruction was limited to the first {max_streams} of {len(stream_ids)} streams."
            )
        streams: list[ReconstructedStream] = []
        for stream_id in stream_ids[:max_streams]:
            try:
                follow = self._runner.run(
                    "tshark",
                    [
                        "-n",
                        "-r",
                        str(capture_path),
                        "-q",
                        "-z",
                        f"follow,tcp,raw,{stream_id}",
                    ],
                    cwd=workspace,
                    timeout_seconds=timeout_seconds,
                    output_limit=max(1_048_576, max_stream_bytes * 3),
                )
            except ToolExecutionError as exc:
                warnings.append(f"TCP stream {stream_id} reconstruction stopped safely: {exc}")
                continue
            executions.append((f"follow-tcp-{stream_id}", follow))
            if follow.returncode != 0:
                warnings.append(f"TShark could not reconstruct TCP stream {stream_id}.")
                continue
            streams.append(self._parse_follow(stream_id, follow.stdout, max_stream_bytes))

        exported: list[ExportedObject] = []
        exported_total = 0
        for protocol in ("http", "ftp-data"):
            export_root = workspace / "exports" / protocol
            export_root.mkdir(parents=True, exist_ok=True)
            try:
                execution = self._runner.run(
                    "tshark",
                    [
                        "-n",
                        "-r",
                        str(capture_path),
                        "--export-objects",
                        f"{protocol},{export_root}",
                    ],
                    cwd=workspace,
                    timeout_seconds=timeout_seconds,
                    output_limit=4 * 1024 * 1024,
                )
            except ToolExecutionError as exc:
                warnings.append(f"{protocol} object export stopped safely: {exc}")
                continue
            executions.append((f"export-{protocol}", execution))
            if execution.returncode != 0:
                warnings.append(f"TShark {protocol} object export was unavailable or failed.")
                continue
            root_resolved = export_root.resolve()
            for candidate in sorted(export_root.iterdir(), key=lambda item: item.name):
                if len(exported) >= max_exported_files:
                    warnings.append(
                        f"Transferred-file results were limited to {max_exported_files} objects."
                    )
                    break
                try:
                    resolved = candidate.resolve(strict=True)
                    size = candidate.stat().st_size
                except OSError:
                    warnings.append("An unreadable exported object was skipped.")
                    continue
                if (
                    candidate.is_symlink()
                    or not candidate.is_file()
                    or resolved.parent != root_resolved
                ):
                    warnings.append("An unsafe exported-object path was skipped.")
                    continue
                if exported_total + size > max_exported_bytes:
                    warnings.append(
                        f"Transferred-file results reached the {max_exported_bytes}-byte expanded-data limit."
                    )
                    break
                exported.append(ExportedObject(protocol, candidate.name[:255], candidate))
                exported_total += size

        return TSharkResult(
            rows=tuple(rows),
            streams=tuple(streams),
            exported_objects=tuple(exported),
            executions=tuple(executions),
            warnings=tuple(dict.fromkeys(warnings)),
        )

    @staticmethod
    def _parse_rows(output: bytes) -> list[dict[str, str]]:
        text = output.decode("utf-8", errors="replace")
        reader = csv.reader(io.StringIO(text), delimiter="\t", quotechar='"')
        rows: list[dict[str, str]] = []
        for values in reader:
            if not values or not any(values):
                continue
            padded = values[: len(PACKET_FIELDS)] + [""] * max(0, len(PACKET_FIELDS) - len(values))
            rows.append(dict(zip(PACKET_FIELDS, padded, strict=True)))
        return rows

    @staticmethod
    def _parse_follow(stream_id: int, output: bytes, maximum: int) -> ReconstructedStream:
        data = bytearray()
        chunks: list[tuple[str, int, int]] = []
        truncated = False
        for raw_line in output.decode("ascii", errors="ignore").splitlines():
            direction = "b_to_a" if raw_line[:1].isspace() else "a_to_b"
            line = raw_line.strip()
            if not line or len(line) % 2 or _HEX_LINE.fullmatch(line) is None:
                continue
            try:
                decoded = bytes.fromhex(line)
            except ValueError:
                continue
            remaining = maximum - len(data)
            if remaining <= 0:
                truncated = True
                break
            accepted = decoded[:remaining]
            chunks.append((direction, len(data), len(accepted)))
            data.extend(accepted)
            if len(accepted) < len(decoded):
                truncated = True
                break
        return ReconstructedStream(stream_id, bytes(data), tuple(chunks), truncated)
