from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.core.errors import ToolExecutionError
from app.core.tool_runner import ToolRunner


class AudioToolchain:
    """Bounded FFmpeg/ffprobe access for audio identification and normalization."""

    def __init__(self, runner: ToolRunner | None = None) -> None:
        self._runner = runner or ToolRunner(
            {"ffmpeg", "ffprobe"},
            default_timeout_seconds=30,
            default_output_limit=2 * 1024 * 1024,
        )

    def availability(self) -> dict[str, bool]:
        return {
            "ffmpeg": self._runner.available("ffmpeg"),
            "ffprobe": self._runner.available("ffprobe"),
        }

    def probe(self, source: Path, *, cwd: Path) -> dict[str, Any]:
        execution = self._runner.run(
            "ffprobe",
            [
                "-v",
                "error",
                "-show_format",
                "-show_streams",
                "-of",
                "json",
                str(source),
            ],
            cwd=cwd,
            timeout_seconds=15,
            output_limit=2 * 1024 * 1024,
        )
        if execution.returncode != 0:
            raise ToolExecutionError("ffprobe", "ffprobe could not identify the audio stream.")
        try:
            return json.loads(execution.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ToolExecutionError("ffprobe", "ffprobe returned malformed JSON.") from exc

    def normalize(self, source: Path, destination: Path, *, cwd: Path, seconds: float) -> None:
        execution = self._runner.run(
            "ffmpeg",
            [
                "-v",
                "error",
                "-nostdin",
                "-y",
                "-i",
                str(source),
                "-t",
                f"{seconds:g}",
                "-map_metadata",
                "-1",
                "-c:a",
                "pcm_s16le",
                str(destination),
            ],
            cwd=cwd,
            timeout_seconds=30,
            output_limit=512 * 1024,
        )
        if execution.returncode != 0 or not destination.is_file():
            raise ToolExecutionError("ffmpeg", "FFmpeg could not create the analysis WAV copy.")

