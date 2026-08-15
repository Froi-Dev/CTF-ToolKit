from __future__ import annotations

import tempfile
from functools import partial
from pathlib import Path
from uuid import uuid4

from anyio import to_thread
from fastapi import UploadFile

from app.analyzers.network import NetworkPcapAnalyzer, PcapInput
from app.analyzers.network.parsing import capture_format
from app.core.errors import ArtifactTooLargeError, InvalidArtifactError
from app.schemas.network import NetworkAnalysisResponse

_UPLOAD_CHUNK_BYTES = 1024 * 1024


def _safe_display_name(filename: str | None) -> str:
    if not filename or "\x00" in filename:
        raise InvalidArtifactError("A non-empty, valid filename is required.")
    normalized = filename.replace("\\", "/")
    basename = normalized.rsplit("/", 1)[-1].strip()
    if not basename or basename in {".", ".."}:
        raise InvalidArtifactError("A non-empty, valid filename is required.")
    return basename[:255]


class NetworkAnalysisService:
    def __init__(self, analyzer: NetworkPcapAnalyzer | None = None) -> None:
        self._analyzer = analyzer or NetworkPcapAnalyzer()

    async def analyze(self, upload: UploadFile) -> NetworkAnalysisResponse:
        original_filename = _safe_display_name(upload.filename)
        artifact_id = str(uuid4())
        maximum = self._analyzer.policy.max_upload_bytes

        try:
            with tempfile.TemporaryDirectory(prefix="ctfkit-pcap-") as temporary:
                workspace = Path(temporary)
                artifact_path = workspace / f"capture-{artifact_id}"
                size = 0
                header = bytearray()
                with artifact_path.open("xb") as destination:
                    while chunk := await upload.read(_UPLOAD_CHUNK_BYTES):
                        size += len(chunk)
                        if size > maximum:
                            raise ArtifactTooLargeError(maximum)
                        if len(header) < 4:
                            header.extend(chunk[: 4 - len(header)])
                        destination.write(chunk)

                detected_format = capture_format(bytes(header))
                if detected_format is None:
                    raise InvalidArtifactError(
                        "The upload is not a PCAP or PCAPNG capture based on its file signature."
                    )
                pcap_input = PcapInput(
                    path=artifact_path,
                    original_filename=original_filename,
                    artifact_id=artifact_id,
                    workspace=workspace,
                    capture_format=detected_format,
                )
                return await to_thread.run_sync(
                    partial(self._analyzer.analyze, pcap_input)
                )
        finally:
            await upload.close()
