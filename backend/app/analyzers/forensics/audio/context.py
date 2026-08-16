from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import numpy as np


@dataclass(slots=True)
class PcmAudio:
    samples: np.ndarray
    sample_rate: int
    bit_depth: int
    encoding: str
    data_offset: int
    raw_sample_bytes: bytes

    @property
    def channels(self) -> int:
        return int(self.samples.shape[1])

    @property
    def frames(self) -> int:
        return int(self.samples.shape[0])

    @property
    def duration_seconds(self) -> float:
        return self.frames / self.sample_rate


@dataclass(slots=True)
class AudioContext:
    source_path: Path
    working_path: Path
    workspace: Path
    original_filename: str
    original_data: bytes
    pcm: PcmAudio | None = None
    metadata: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

