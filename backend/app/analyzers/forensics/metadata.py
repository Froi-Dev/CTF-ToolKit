from __future__ import annotations

import base64
import codecs
import json
import re
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from app.analyzers.crypto.decoder import RecursiveDecoder, detect_encodings
from app.core.flag_detection import FlagDetector
from app.core.errors import ToolExecutionError
from app.core.tool_runner import ToolRunner
from app.schemas.crypto import DecodeRequest
from app.schemas.forensics import (
    DecodeStep,
    DecodedMetadataValue,
    DeepMetadataEntry,
    EmbeddedMetadataObject,
    ForensicFinding,
    GPSMetadata,
    MetadataAnalysis,
    MetadataTimelineEvent,
)

_FLAG_PREFIXES = ["flag", "CTF", "picoCTF", "HTB", "THM", "hack", "H4G"]
_HIGH_VALUE_TAGS = {
    "comment", "usercomment", "description", "imagedescription", "subject", "title",
    "keywords", "caption", "notes", "instructions", "xpcomment", "xpkeywords",
}
_IDENTITY_TAGS = {
    "author", "creator", "artist", "owner", "lastmodifiedby", "producer", "company",
    "copyright", "username", "computername", "software", "cameraownername", "model",
}
_BASIC_TAGS = {
    "filename", "filetype", "filetypeextension", "mimetype", "filesize", "imagewidth",
    "imageheight", "imagesize", "bitdepth", "compression", "duration", "encoding",
    "pagecount", "imagecount", "streamcount",
}
_TIMESTAMP_TAGS = {
    "filemodifydate": "File modified",
    "fileaccessdate": "File accessed",
    "filecreatedate": "File created",
    "createdate": "Content created",
    "modifydate": "Content modified",
    "datetimeoriginal": "Original media created",
    "metadatadate": "Metadata modified",
}
_GPS_TAGS = {
    "gpslatitude", "gpslongitude", "gpsaltitude", "gpsdatetime", "gpstimestamp",
    "gpsimgdirection", "location", "city", "state", "country",
}
_EMBEDDED_TAGS = {
    "thumbnailimage": ("thumbnail", "image/jpeg"),
    "previewimage": ("preview", "image/jpeg"),
    "coverart": ("cover art", None),
    "xmp": ("XMP packet", "application/rdf+xml"),
    "icc_profile": ("ICC profile", "application/vnd.iccprofile"),
}
_SENSITIVE = re.compile(
    r"\b(flag|password|passwd|secret|token|key|credential|backup|admin|private|cmd|powershell|/tmp/|\\users\\)\b",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[^\s@]+@[^\s@]+\.[A-Za-z]{2,}\b")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]+-----")
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.IGNORECASE)
_HASH = re.compile(r"\b(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\b", re.IGNORECASE)
_PATH = re.compile(r"(?:[A-Za-z]:\\[^\r\n]+|/(?:tmp|home|var|etc|Users)/[^\r\n]+)")
_COORDINATES = re.compile(r"(?<!\d)-?(?:[0-8]?\d(?:\.\d+)?|90(?:\.0+)?)[, ]+\s*-?(?:1[0-7]\d(?:\.\d+)?|\d?\d(?:\.\d+)?|180(?:\.0+)?)")
_BINARY_DESCRIPTION = re.compile(r"Binary data\s+(\d+)\s+bytes", re.IGNORECASE)


def _display(value: object, limit: int = 8_192) -> str:
    if isinstance(value, (dict, list)):
        rendered = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    elif value is None:
        rendered = "null"
    else:
        rendered = str(value)
    return rendered[:limit] + ("…" if len(rendered) > limit else "")


def _parts(key: str) -> tuple[str, str]:
    if ":" in key:
        return tuple(key.split(":", 1))  # type: ignore[return-value]
    return "Other", key


def _category(tag: str, group: str) -> str:
    normalized = tag.lower().replace(" ", "")
    if normalized in _BASIC_TAGS:
        return "Basic File Information"
    if normalized in _TIMESTAMP_TAGS or "date" in normalized or "time" in normalized:
        return "Timestamp Information"
    if normalized in _IDENTITY_TAGS:
        return "Author / Identity Information"
    if normalized in _GPS_TAGS or normalized.startswith("gps"):
        return "GPS / Location Metadata"
    if normalized in _HIGH_VALUE_TAGS:
        return "Comments and Descriptions"
    if group.upper().startswith("ICC"):
        return "ICC Profile"
    if group.upper().startswith("XMP"):
        return "XMP"
    if group.upper().startswith("PDF"):
        return "PDF Metadata"
    if group.upper() in {"EXIF", "IFD0", "EXIFIFD", "GPS"}:
        return "EXIF"
    return "Application / Other"


def _parse_timestamp(value: str) -> datetime | None:
    candidate = value.strip().replace("Z", "+00:00")
    for pattern in ("%Y:%m:%d %H:%M:%S%z", "%Y:%m:%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(candidate, pattern)
        except ValueError:
            continue
    return None


def _custom_flags(text: str, pattern: str | None) -> list[str]:
    if not pattern:
        return []
    try:
        compiled = re.compile(pattern)
    except re.error:
        return []
    return [match.group(0)[:512] for match in compiled.finditer(text)][:20]


def _strong_encoding_names(value: str) -> set[str]:
    """Reject syntactically possible but ordinary values such as dimensions and paths."""
    compact = "".join(value.split())
    names: set[str] = set()
    if len(compact) >= 12 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) and (
        compact.endswith("=") or len(compact) >= 20
    ):
        names.add("Base64")
    if len(compact) >= 16 and re.fullmatch(r"[A-Z2-7]+={0,6}", compact, re.IGNORECASE):
        names.add("Base32")
    if len(value) >= 8 and not any(character.isspace() for character in value) and re.fullmatch(r"[0-9a-fA-F]+", value) and re.search(r"[a-fA-F]", value):
        names.add("Hex")
    if len(compact) >= 16 and re.fullmatch(r"[01]+", compact):
        names.add("Binary")
    if re.search(r"%[0-9a-fA-F]{2}", value):
        names.add("URL")
    if re.search(r"&(?:#\d+|#x[0-9a-f]+|[a-z]+);", value, re.IGNORECASE):
        names.add("HTML Entities")
    if re.search(r"(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2})", value):
        names.update({"Unicode Escapes", "Escaped Bytes"})
    return names


class DeepMetadataAnalyzer:
    """ExifTool-backed metadata normalization and bounded CTF intelligence."""

    def __init__(self, runner: ToolRunner | None = None) -> None:
        self._runner = runner or ToolRunner(
            {"exiftool"}, default_timeout_seconds=15.0, default_output_limit=8 * 1024 * 1024
        )
        self._decoder = RecursiveDecoder()
        self._flags = FlagDetector(_FLAG_PREFIXES)

    def analyze(self, path: Path, filename: str, custom_flag_regex: str | None = None) -> MetadataAnalysis:
        if not self._runner.available("exiftool"):
            return MetadataAnalysis(
                tool_available=False,
                summary="ExifTool is unavailable; only the baseline format metadata was collected.",
                warnings=["Install ExifTool or set CTFKIT_EXIFTOOL_PATH to enable deep metadata analysis."],
            )
        execution = self._runner.run(
            "exiftool",
            ["-json", "-G1", "-a", "-u", "-n", "-api", "LargeFileSupport=1", str(path)],
            cwd=path.parent,
        )
        if execution.returncode not in {0, 1}:
            return MetadataAnalysis(
                tool_available=True,
                summary="ExifTool could not parse this artifact.",
                raw_exiftool=execution.stdout.decode("utf-8", errors="replace"),
                warnings=[execution.stderr.decode("utf-8", errors="replace")[:1000]],
            )
        raw = execution.stdout.decode("utf-8", errors="replace")
        try:
            records = json.loads(raw)
            record = records[0] if records else {}
        except (json.JSONDecodeError, TypeError, IndexError):
            return MetadataAnalysis(
                tool_available=True,
                summary="ExifTool returned output that could not be normalized.",
                raw_exiftool=raw,
                warnings=["Structured ExifTool JSON parsing failed."],
            )

        entries: list[DeepMetadataEntry] = []
        categories: dict[str, list[DeepMetadataEntry]] = {}
        notable: list[ForensicFinding] = []
        decoded: list[DecodedMetadataValue] = []
        timeline: list[MetadataTimelineEvent] = []
        timestamp_values: dict[str, tuple[str, datetime]] = {}
        direct_flags: set[str] = set()

        for key, value in record.items():
            group, tag = _parts(key)
            normalized = tag.lower().replace(" ", "")
            display = (
                filename if tag in {"SourceFile", "FileName"}
                else "<temporary analysis workspace>" if tag == "Directory"
                else _display(value)
            )
            category = _category(tag, group)
            importance = "info"
            reason: str | None = None
            severity = "low"

            value_flags = [item.value for item in self._flags.detect(display.encode("utf-8", errors="replace"))]
            value_flags.extend(_custom_flags(display, custom_flag_regex))
            if value_flags:
                direct_flags.update(value_flags)
                importance, severity = "critical", "critical"
                reason = "A configured flag pattern appears directly in this metadata value."
            elif normalized in _HIGH_VALUE_TAGS and display:
                importance, severity = "high", "high"
                reason = "Comments and description fields are common CTF hiding locations."
            elif _SENSITIVE.search(display):
                importance, severity = "high", "high"
                reason = "The value contains security-sensitive or CTF-relevant terminology."
            elif normalized in _IDENTITY_TAGS and display:
                importance, severity = "medium", "medium"
                reason = "Identity and software attribution may reveal the challenge origin or a credential clue."
            elif normalized.startswith("gps"):
                importance, severity = "medium", "medium"
                reason = "Location metadata is forensically notable."
            elif len(display) > 512:
                importance, severity = "high", "high"
                reason = "This unusually long textual metadata value may conceal encoded or embedded data."
            elif _URL.search(display) or _EMAIL.search(display) or _IP.search(display):
                importance, severity = "medium", "medium"
                reason = "The value contains a network or identity indicator worth investigating."
            elif _JWT.search(display) or _PEM.search(display):
                importance, severity = "high", "high"
                reason = "The value contains a JWT-like token or cryptographic material."
            elif _UUID.search(display) or _HASH.search(display):
                importance, severity = "medium", "medium"
                reason = "The value contains a structured identifier or cryptographic hash."
            elif _PATH.search(display):
                importance, severity = "medium", "medium"
                reason = "The value exposes a filesystem path that may identify a user or staging directory."
            elif _COORDINATES.search(display) and not normalized.startswith("gps"):
                importance, severity = "medium", "medium"
                reason = "The value resembles geographic coordinates."
            elif group.lower().startswith("unknown") or tag.lower().startswith("unknown"):
                importance, severity = "medium", "medium"
                reason = "ExifTool exposed an unknown or uncommon metadata tag."

            entry = DeepMetadataEntry(
                group=group, tag=tag, key=key, category=category, value=value,
                display_value=display, importance=importance,
            )
            entries.append(entry)
            categories.setdefault(category, []).append(entry)
            if reason:
                notable.append(ForensicFinding(
                    finding_id=str(uuid4()), severity=severity, title=f"Notable metadata: {key}",
                    reason=reason, analyzer="metadata", section="notable", field=key,
                    value=display[:1024],
                ))

            if normalized in _TIMESTAMP_TAGS:
                parsed = _parse_timestamp(display)
                timeline.append(MetadataTimelineEvent(
                    field=key, timestamp=display,
                    normalized_timestamp=parsed.isoformat() if parsed else None,
                    description=_TIMESTAMP_TAGS[normalized],
                ))
                if parsed:
                    timestamp_values[normalized] = (key, parsed)

            if isinstance(value, str) and 4 <= len(value) <= 32_768 and len(decoded) < 24:
                strong_names = _strong_encoding_names(value)
                if normalized in _HIGH_VALUE_TAGS and len(value) >= 16 and re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", value):
                    strong_names.add("Base58")
                detections = [
                    item for item in detect_encodings(value.encode())
                    if item.confidence >= 0.78 and item.name in strong_names
                ]
                if detections:
                    result = self._decoder.analyze(DecodeRequest(
                        input=value, max_depth=4, max_results=4, beam_width=12,
                        timeout_ms=750, flag_prefixes=_FLAG_PREFIXES,
                    ))
                    candidate = next((item for item in result.results if item.chain and item.output != value), None)
                    printable = sum(character.isprintable() or character in "\r\n\t" for character in candidate.output) / max(1, len(candidate.output)) if candidate else 0
                    if candidate and (candidate.flags or (candidate.score >= 0.55 and printable >= 0.8 and candidate.output.strip())):
                        chain: list[DecodeStep] = []
                        for index, step in enumerate(candidate.chain):
                            output = candidate.output if index == len(candidate.chain) - 1 else "intermediate value"
                            chain.append(DecodeStep(transform=step.transform, parameter=step.parameter, output=output))
                        found = list(dict.fromkeys(item.value for item in candidate.flags))
                        decoded.append(DecodedMetadataValue(
                            field=key, original=value, detected_encoding=detections[0].name,
                            confidence=detections[0].confidence, chain=chain,
                            decoded=candidate.output, flags=found,
                        ))
                        notable.append(ForensicFinding(
                            finding_id=str(uuid4()), severity="critical" if found else "high",
                            title=f"Encoded metadata: {key}",
                            reason="A strongly matched encoding produced a meaningful decoded value.",
                            analyzer="metadata", section="decoded", field=key,
                            value=candidate.output[:1024],
                        ))
                        direct_flags.update(found)
                if normalized in _HIGH_VALUE_TAGS and len(decoded) < 24:
                    rot13 = codecs.decode(value, "rot_13")
                    rot_flags = [item.value for item in self._flags.detect(rot13.encode("utf-8", errors="replace"))]
                    if rot_flags:
                        decoded.append(DecodedMetadataValue(
                            field=key, original=value, detected_encoding="ROT13", confidence=0.98,
                            chain=[DecodeStep(transform="rot13", output=rot13)], decoded=rot13,
                            flags=rot_flags,
                        ))
                        notable.append(ForensicFinding(
                            finding_id=str(uuid4()), severity="critical", title=f"ROT13 flag in metadata: {key}",
                            reason="ROT13 decoding of a high-priority metadata field produced a configured flag pattern.",
                            analyzer="metadata", section="decoded", field=key, value=rot13[:1024],
                        ))
                        direct_flags.update(rot_flags)

        timeline.sort(key=lambda item: item.normalized_timestamp or item.timestamp)
        anomalies: list[str] = []
        original = timestamp_values.get("datetimeoriginal") or timestamp_values.get("createdate")
        filesystem = timestamp_values.get("filecreatedate") or timestamp_values.get("filemodifydate")
        if original and filesystem:
            left = original[1].replace(tzinfo=None)
            right = filesystem[1].replace(tzinfo=None)
            days = abs((right - left).days)
            if days >= 365:
                message = f"{original[0]} and {filesystem[0]} differ by approximately {days // 365} year(s)."
                anomalies.append(message)
                notable.append(ForensicFinding(
                    finding_id=str(uuid4()), severity="low", title="Timestamp anomaly",
                    reason=message + " This may indicate copying, export, or later editing.",
                    analyzer="metadata", section="timeline",
                ))
        created = timestamp_values.get("createdate")
        modified = timestamp_values.get("modifydate")
        if created and modified and modified[1].replace(tzinfo=None) < created[1].replace(tzinfo=None):
            message = f"{modified[0]} predates {created[0]}."
            anomalies.append(message)
            notable.append(ForensicFinding(
                finding_id=str(uuid4()), severity="medium", title="Timestamp conflict",
                reason=message + " The editing history is internally inconsistent.",
                analyzer="metadata", section="timeline",
            ))

        gps = self._gps(entries)
        embedded = self._embedded(path, entries)
        if embedded:
            notable.append(ForensicFinding(
                finding_id=str(uuid4()), severity="medium", title="Embedded metadata objects",
                reason=f"ExifTool identified {len(embedded)} embedded preview, profile, or packet object(s).",
                analyzer="metadata", section="embedded",
            ))
        attention = len([item for item in notable if item.severity != "info"])
        summary = (
            f"ExifTool extracted {len(entries)} fields. {attention} field or relationship"
            f"{'s' if attention != 1 else ''} deserve attention."
        )
        if direct_flags:
            summary += f" {len(direct_flags)} flag candidate(s) were directly supported by metadata or its decoding chain."
        stderr = execution.stderr.decode("utf-8", errors="replace").strip()
        return MetadataAnalysis(
            tool_available=True, tool_version=self._version(path), summary=summary,
            categories=categories, notable=notable, decoded=decoded, timeline=timeline,
            timestamp_anomalies=anomalies, gps=gps, embedded_objects=embedded,
            all_metadata=entries, raw_exiftool=raw,
            warnings=[stderr[:1000]] if stderr else [],
        )

    def _version(self, path: Path) -> str | None:
        try:
            result = self._runner.run("exiftool", ["-ver"], cwd=path.parent, timeout_seconds=3)
        except ToolExecutionError:
            return None
        return result.stdout.decode("ascii", errors="replace").strip() or None

    @staticmethod
    def _gps(entries: list[DeepMetadataEntry]) -> GPSMetadata | None:
        values = {item.tag.lower().replace(" ", ""): item.display_value for item in entries}
        try:
            latitude = float(values["gpslatitude"])
            longitude = float(values["gpslongitude"])
        except (KeyError, ValueError):
            return None
        try:
            altitude = float(values["gpsaltitude"].split()[0])
        except (KeyError, ValueError):
            altitude = None
        location = ", ".join(values[key] for key in ("city", "state", "country", "location") if values.get(key)) or None
        return GPSMetadata(
            latitude=round(latitude, 7), longitude=round(longitude, 7), altitude=altitude,
            timestamp=values.get("gpsdatetime") or values.get("gpstimestamp"),
            direction=values.get("gpsimgdirection"), location=location,
        )

    def _embedded(self, path: Path, entries: list[DeepMetadataEntry]) -> list[EmbeddedMetadataObject]:
        objects: list[EmbeddedMetadataObject] = []
        for entry in entries:
            normalized = entry.tag.lower().replace(" ", "").replace("_", "")
            match = next(((tag, spec) for tag, spec in _EMBEDDED_TAGS.items() if normalized == tag.replace("_", "")), None)
            binary = _BINARY_DESCRIPTION.search(entry.display_value)
            if not match and not binary:
                continue
            kind, mime = match[1] if match else ("binary metadata", None)
            payload: str | None = None
            size = int(binary.group(1)) if binary else None
            if match and kind in {"thumbnail", "preview"} and (size is None or size <= 2 * 1024 * 1024):
                try:
                    result = self._runner.run(
                        "exiftool", ["-b", f"-{entry.tag}", str(path)], cwd=path.parent,
                        timeout_seconds=5, output_limit=2 * 1024 * 1024,
                    )
                except ToolExecutionError:
                    result = None
                if result is not None and result.returncode == 0 and result.stdout:
                    payload = base64.b64encode(result.stdout).decode("ascii")
                    size = len(result.stdout)
            objects.append(EmbeddedMetadataObject(
                tag=entry.key, kind=kind, description=entry.display_value[:500],
                byte_size=size, mime_type=mime, data_base64=payload,
            ))
        return objects[:16]
