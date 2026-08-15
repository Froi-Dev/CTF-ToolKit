from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

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
    "ip.id",
    "ip.ttl",
    "ip.len",
    "ipv6.src",
    "ipv6.dst",
    "ipv6.hlim",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "udp.stream",
    "tcp.stream",
    "tcp.seq",
    "tcp.ack",
    "tcp.flags",
    "tcp.window_size",
    "tcp.len",
    "tcp.payload",
    "udp.length",
    "udp.payload",
    "data.data",
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
    "dns.txt",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.response.code",
    "http.content_type",
    "http.content_length",
    "http.user_agent",
    "http.authorization",
    "http.cookie",
    "http.file_data",
    "ftp.request.command",
    "ftp.request.arg",
    "ftp.response.code",
    "ftp.response.arg",
)

_HEX_LINE = re.compile(r"^[0-9a-fA-F]+$")
_PACKET_OUTPUT_LIMIT_BYTES = 64 * 1024 * 1024
_TCP_FOLLOW_BATCH_SIZE = 8
ProgressCallback = Callable[[str, str | None], None]


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
    udp_streams: tuple[ReconstructedStream, ...] = ()


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
        max_udp_streams: int | None = None,
        progress: ProgressCallback | None = None,
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
        _progress(progress, "tshark.packet-decode", "Decoding packet fields in one capture pass")
        packet_execution = self._runner.run(
            "tshark",
            field_arguments,
            cwd=workspace,
            timeout_seconds=timeout_seconds,
            output_limit=_PACKET_OUTPUT_LIMIT_BYTES,
        )
        executions.append(("packet-decode", packet_execution))
        if packet_execution.returncode != 0:
            detail = packet_execution.stderr.decode("utf-8", errors="replace").strip()
            raise InvalidArtifactError(
                "TShark could not decode this capture."
                + (f" {detail[:500]}" if detail else "")
            )
        rows = self._parse_rows(packet_execution.stdout, PACKET_FIELDS)
        udp_streams, udp_warnings = self._reconstruct_udp_streams(
            rows,
            max_streams=max_udp_streams if max_udp_streams is not None else max_streams,
            max_stream_bytes=max_stream_bytes,
        )
        warnings.extend(udp_warnings)

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
        selected_stream_ids = stream_ids[:max_streams]
        for batch_start in range(0, len(selected_stream_ids), _TCP_FOLLOW_BATCH_SIZE):
            batch = selected_stream_ids[batch_start : batch_start + _TCP_FOLLOW_BATCH_SIZE]
            _progress(
                progress,
                "tshark.tcp-reconstruction",
                f"Reconstructing TCP streams {batch_start + 1}-{batch_start + len(batch)} of {len(selected_stream_ids)}",
            )
            arguments = ["-n", "-r", str(capture_path), "-q"]
            for stream_id in batch:
                arguments.extend(("-z", f"follow,tcp,raw,{stream_id}"))
            try:
                follow = self._runner.run(
                    "tshark",
                    arguments,
                    cwd=workspace,
                    timeout_seconds=timeout_seconds,
                    output_limit=max(1_048_576, max_stream_bytes * 3 * len(batch)),
                )
            except ToolExecutionError as exc:
                warnings.append(
                    f"TCP stream batch {batch[0]}-{batch[-1]} reconstruction stopped safely: {exc}"
                )
                continue
            executions.append((f"follow-tcp-batch-{batch[0]}-{batch[-1]}", follow))
            if follow.returncode != 0:
                warnings.append(f"TShark could not reconstruct TCP streams {batch[0]}-{batch[-1]}.")
                continue
            parsed = self._parse_follow_many(follow.stdout, max_stream_bytes)
            for stream_id in batch:
                stream = parsed.get(stream_id)
                if stream is None:
                    warnings.append(f"TShark returned no reconstruction for TCP stream {stream_id}.")
                else:
                    streams.append(stream)

        exported: list[ExportedObject] = []
        exported_total = 0
        export_protocols: list[str] = []
        if any(
            "http" in row.get("frame.protocols", "").lower().split(":")
            or row.get("http.request.method")
            or row.get("http.response.code")
            or row.get("http.file_data")
            for row in rows
        ):
            export_protocols.append("http")
        if any(
            "ftp-data" in row.get("frame.protocols", "").lower().split(":")
            or "ftp_data" in row.get("frame.protocols", "").lower().split(":")
            for row in rows
        ):
            export_protocols.append("ftp-data")
        for protocol in export_protocols:
            _progress(progress, "tshark.object-export", f"Exporting observed {protocol} objects")
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
            udp_streams=udp_streams,
        )

    @staticmethod
    def _parse_rows(
        output: bytes,
        fields: tuple[str, ...] = PACKET_FIELDS,
    ) -> list[dict[str, str]]:
        # The default CPython CSV field limit is 128 KiB, while a legitimate
        # reassembled HTTP body or packet byte field can be larger. TShark's
        # complete stdout is already capped at this same 64 MiB boundary by
        # ToolRunner, so allowing one field up to that bound remains finite.
        if csv.field_size_limit() < _PACKET_OUTPUT_LIMIT_BYTES:
            csv.field_size_limit(_PACKET_OUTPUT_LIMIT_BYTES)
        text = output.decode("utf-8", errors="replace")
        reader = csv.reader(io.StringIO(text), delimiter="\t", quotechar='"')
        rows: list[dict[str, str]] = []
        for values in reader:
            if not values or not any(values):
                continue
            padded = values[: len(fields)] + [""] * max(0, len(fields) - len(values))
            rows.append(dict(zip(fields, padded, strict=True)))
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

    @classmethod
    def _parse_follow_many(
        cls,
        output: bytes,
        maximum: int,
    ) -> dict[int, ReconstructedStream]:
        text = output.decode("ascii", errors="ignore")
        matches = list(re.finditer(r"(?m)^Filter:\s*tcp\.stream\s+eq\s+(\d+)\s*$", text))
        parsed: dict[int, ReconstructedStream] = {}
        for index, match in enumerate(matches):
            stream_id = int(match.group(1))
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            parsed[stream_id] = cls._parse_follow(
                stream_id,
                text[match.start() : end].encode("ascii"),
                maximum,
            )
        return parsed

    @staticmethod
    def _reconstruct_udp_streams(
        rows: tuple[dict[str, str], ...] | list[dict[str, str]],
        *,
        max_streams: int,
        max_stream_bytes: int,
    ) -> tuple[tuple[ReconstructedStream, ...], tuple[str, ...]]:
        grouped: dict[int, list[dict[str, str]]] = {}
        for row in rows:
            value = row.get("udp.stream", "").split(",", 1)[0]
            if not value.isdigit():
                continue
            grouped.setdefault(int(value), []).append(row)

        warnings: list[str] = []
        stream_ids = sorted(grouped)
        if len(stream_ids) > max_streams:
            warnings.append(
                f"UDP reconstruction was limited to the first {max_streams} of {len(stream_ids)} streams."
            )

        reconstructed: list[ReconstructedStream] = []
        for stream_id in stream_ids[:max_streams]:
            data = bytearray()
            chunks: list[tuple[str, int, int]] = []
            packets = sorted(
                grouped[stream_id],
                key=lambda row: (
                    _float_value(row.get("frame.time_epoch", "")),
                    _integer_value(row.get("frame.number", "")),
                ),
            )
            first = packets[0]
            endpoint_a = _row_endpoint(first, source=True)
            truncated = False
            for row in packets:
                payload = _decode_field_bytes(
                    row.get("udp.payload", "") or row.get("data.data", "")
                )
                if not payload:
                    continue
                remaining = max_stream_bytes - len(data)
                if remaining <= 0:
                    truncated = True
                    break
                accepted = payload[:remaining]
                direction = "a_to_b" if _row_endpoint(row, source=True) == endpoint_a else "b_to_a"
                chunks.append((direction, len(data), len(accepted)))
                data.extend(accepted)
                if len(accepted) < len(payload):
                    truncated = True
                    break
            reconstructed.append(
                ReconstructedStream(stream_id, bytes(data), tuple(chunks), truncated)
            )
        return tuple(reconstructed), tuple(warnings)


def _integer_value(value: str) -> int:
    try:
        return int(value.split(",", 1)[0])
    except ValueError:
        return -1


def _float_value(value: str) -> float:
    try:
        return float(value.split(",", 1)[0])
    except ValueError:
        return 0.0


def _row_endpoint(row: dict[str, str], *, source: bool) -> str:
    side = "src" if source else "dst"
    address = row.get(f"ip.{side}") or row.get(f"ipv6.{side}") or row.get(f"eth.{side}") or "unknown"
    port = row.get(f"udp.{side}port", "").split(",", 1)[0]
    return f"{address.split(',', 1)[0]}:{port}"


def _decode_field_bytes(value: str) -> bytes:
    decoded = bytearray()
    for occurrence in value.split(","):
        compact = occurrence.replace(":", "").strip()
        if not compact or len(compact) % 2:
            continue
        try:
            decoded.extend(bytes.fromhex(compact))
        except ValueError:
            continue
    return bytes(decoded)


def _progress(callback: ProgressCallback | None, stage: str, detail: str | None = None) -> None:
    if callback is not None:
        callback(stage, detail)
