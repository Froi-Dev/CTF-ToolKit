from __future__ import annotations

import base64
import hashlib
from pathlib import PurePath

from app.analyzers.network.investigation.packet_scoring import entropy, payload_reasons, score_from
from app.analyzers.network.investigation.recommendations import recommendations_for
from app.schemas.network import InvestigationTarget, SuspicionReason, TransferredFile


def score_artifacts(artifacts: list[TransferredFile]) -> list[InvestigationTarget]:
    targets: list[InvestigationTarget] = []
    for artifact in artifacts:
        content = base64.b64decode(artifact.content_base64) if artifact.content_base64 else b""
        reasons = payload_reasons(content)
        suffix = PurePath(artifact.source_name).suffix.lower()
        if suffix in {".exe", ".dll", ".elf", ".bin", ".ps1", ".sh"}:
            reasons.append(SuspicionReason(category="artifact-type", description=f"Transferred object has executable or script extension {suffix}", score=14, evidence={"extension": suffix}))
        if artifact.size >= 32 and content and entropy(content) >= 7.2:
            reasons.append(SuspicionReason(category="artifact-entropy", description="Transferred object preview has high entropy and may be compressed or encrypted", score=12, evidence={"entropy": round(entropy(content), 3), "preview_bytes": len(content)}))
        if artifact.content_truncated:
            reasons.append(SuspicionReason(category="bounded-preview", description=f"Only a bounded preview of the {artifact.size}-byte object was retained in the response", score=2, evidence={"artifact_bytes": artifact.size, "preview_bytes": len(content)}))
        score = score_from(reasons)
        target = InvestigationTarget(
            id=f"artifact-{hashlib.sha256(artifact.artifact_id.encode()).hexdigest()[:16]}",
            target_type="artifact",
            title=f"Transferred File: {artifact.source_name}",
            suspicion=score,
            interpretation=None,
            protocol=artifact.protocol,
            related_artifacts=[artifact.artifact_id],
            hypotheses=["The object deserves file-level inspection; CTFKit has not inferred its purpose."] if reasons else [],
            wireshark_filter=(
                "http" if artifact.protocol == "http"
                else "ftp-data" if artifact.protocol == "ftp-data"
                else artifact.protocol
            ),
            categories=["files"],
        )
        target.recommended_actions = recommendations_for(target)
        targets.append(target)
    return targets
