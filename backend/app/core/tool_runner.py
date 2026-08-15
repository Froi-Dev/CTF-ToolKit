from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from app.core.errors import ToolExecutionError, ToolNotAvailableError


@dataclass(frozen=True, slots=True)
class ToolExecution:
    tool: str
    returncode: int
    duration_ms: int
    stdout: bytes
    stderr: bytes
    output_truncated: bool = False


class ToolRunner:
    """Run allowlisted tools without a shell and with bounded captured output."""

    def __init__(
        self,
        allowlist: set[str] | None = None,
        *,
        default_timeout_seconds: float = 30.0,
        default_output_limit: int = 32 * 1024 * 1024,
    ) -> None:
        self._allowlist = {name.lower() for name in (allowlist or {"tshark"})}
        self._default_timeout = default_timeout_seconds
        self._default_output_limit = default_output_limit

    def available(self, tool: str) -> bool:
        return self._resolve_executable(tool) is not None

    def _resolve_executable(self, tool: str) -> str | None:
        """Resolve an allowlisted executable without accepting arbitrary tool names."""
        normalized = tool.lower()
        if normalized not in self._allowlist:
            return None

        override_name = {"tshark": "CTFKIT_TSHARK_PATH"}.get(normalized)
        if override_name:
            override = os.environ.get(override_name)
            if override:
                candidate = Path(override).expanduser()
                if candidate.is_file():
                    return str(candidate.resolve())

        discovered = shutil.which(tool)
        if discovered is not None:
            return discovered

        if os.name == "nt" and normalized == "tshark":
            installation_roots = (
                os.environ.get("ProgramFiles"),
                os.environ.get("ProgramFiles(x86)"),
                r"C:\Program Files",
                r"C:\Program Files (x86)",
            )
            for root in dict.fromkeys(root for root in installation_roots if root):
                candidate = Path(root) / "Wireshark" / "tshark.exe"
                if candidate.is_file():
                    return str(candidate.resolve())
        return None

    def run(
        self,
        tool: str,
        arguments: Sequence[str],
        *,
        cwd: Path,
        timeout_seconds: float | None = None,
        output_limit: int | None = None,
    ) -> ToolExecution:
        normalized = tool.lower()
        if normalized not in self._allowlist:
            raise ToolNotAvailableError(tool)
        executable = self._resolve_executable(tool)
        if executable is None:
            raise ToolNotAvailableError(tool)
        if not cwd.is_dir():
            raise ToolExecutionError(tool, "The external-tool working directory is invalid.")
        if any("\x00" in argument or len(argument) > 32_768 for argument in arguments):
            raise ToolExecutionError(tool, "An external-tool argument is invalid.")

        limit = output_limit or self._default_output_limit
        timeout = timeout_seconds or self._default_timeout
        command = [executable, *arguments]
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        started = time.monotonic()
        process = subprocess.Popen(
            command,
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            creationflags=creationflags,
        )
        output_exceeded = threading.Event()
        stdout = bytearray()
        stderr = bytearray()

        def read_bounded(pipe: object, destination: bytearray) -> None:
            try:
                while True:
                    chunk = pipe.read(65_536)  # type: ignore[attr-defined]
                    if not chunk:
                        break
                    remaining = limit - len(destination)
                    if remaining > 0:
                        destination.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        output_exceeded.set()
            finally:
                pipe.close()  # type: ignore[attr-defined]

        threads = [
            threading.Thread(target=read_bounded, args=(process.stdout, stdout), daemon=True),
            threading.Thread(target=read_bounded, args=(process.stderr, stderr), daemon=True),
        ]
        for thread in threads:
            thread.start()

        deadline = started + timeout
        timed_out = False
        while process.poll() is None:
            if output_exceeded.wait(0.05):
                process.kill()
                break
            if time.monotonic() >= deadline:
                timed_out = True
                process.kill()
                break
        process.wait()
        for thread in threads:
            thread.join(timeout=2.0)
        duration_ms = max(0, round((time.monotonic() - started) * 1_000))

        if timed_out:
            raise ToolExecutionError(
                tool,
                f"{tool} exceeded the {timeout:g}-second execution limit.",
                timed_out=True,
            )
        if output_exceeded.is_set():
            raise ToolExecutionError(tool, f"{tool} exceeded the captured-output limit.")
        return ToolExecution(
            tool=tool,
            returncode=process.returncode,
            duration_ms=duration_ms,
            stdout=bytes(stdout),
            stderr=bytes(stderr),
        )
