from pathlib import Path

from app.core.tool_runner import ToolRunner


def test_explicit_tshark_path_is_resolved_when_path_lookup_fails(
    monkeypatch, tmp_path: Path
) -> None:
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"fixture")
    monkeypatch.setenv("CTFKIT_TSHARK_PATH", str(executable))
    monkeypatch.setattr("app.core.tool_runner.shutil.which", lambda tool: None)

    runner = ToolRunner({"tshark"})

    assert runner.available("tshark") is True
    assert runner._resolve_executable("tshark") == str(executable.resolve())


def test_unallowlisted_executable_override_is_ignored(
    monkeypatch, tmp_path: Path
) -> None:
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"fixture")
    monkeypatch.setenv("CTFKIT_TSHARK_PATH", str(executable))

    runner = ToolRunner({"tshark"})

    assert runner.available("python") is False
    assert runner._resolve_executable("python") is None
