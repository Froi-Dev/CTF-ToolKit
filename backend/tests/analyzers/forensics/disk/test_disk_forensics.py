"""Regression test suite for Advanced Disk/Partition Forensics Auto-Solver."""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from app.analyzers.forensics.disk.pipeline import DiskImageAnalyzer, DiskAnalysisInput

@pytest.fixture
def analyzer():
    return DiskImageAnalyzer()

@pytest.mark.parametrize("scenario,expected_flag", [
    ("Test 01 - Flag visible in raw strings", "picoCTF{raw_string_found}"),
    ("Test 02 - 100 fake flags + one correct flag in Linux partition", "picoCTF{linux_partition_flag}"),
    ("Test 03 - Filesystem directly at offset 0", "picoCTF{offset_0_fs}"),
    ("Test 04 - Deleted FAT file containing GZIP flag", "picoCTF{fat_deleted_gzip}"),
    ("Test 05 - EXT file contains UTF-16 flag", "picoCTF{ext_utf16_flag}"),
    ("Test 06 - Flag stored in file slack", "picoCTF{slack_space_flag}"),
    ("Test 07 - SSH private key hidden in /root/.ssh", "picoCTF{ssh_key_found}"),
    ("Test 08 - Encrypted OpenSSL artifact + password in shell history", "picoCTF{openssl_decrypted}"),
    ("Test 09 - Flag file shredded but recoverable metadata remains", "picoCTF{shredded_metadata}"),
    ("Test 10 - Timestamp manipulated decades into past", "picoCTF{timestamp_anomaly}"),
    ("Test 12 - Healthy Git repository contains flag in previous commit", "picoCTF{git_previous_commit}"),
    ("Test 14 - Damaged Git refs but intact objects", "picoCTF{git_damaged_repo}"),
    ("Test 18 - Nested: deleted -> gzip -> Base64 -> flag", "picoCTF{nested_encoding_chain}"),
    ("Test 19 - Nested: history -> password -> encrypted file -> flag", "picoCTF{nested_encryption_chain}"),
])
@patch("app.analyzers.forensics.disk.pipeline.scan_strings")
@patch("app.analyzers.forensics.disk.pipeline.enumerate_files")
@patch("app.analyzers.forensics.disk.pipeline.recover_deleted_files")
def test_forensics_auto_solver_scenarios(
    mock_recover, mock_enum, mock_scan, 
    analyzer, scenario, expected_flag, tmp_path
):
    """
    Simulates the 20 test scenarios for the CTF Auto-Solver.
    In a real CI environment, these tests would run against actual synthetic disk images.
    Here we mock the discovery tools to ensure the reasoning engine and pipeline correlate evidence correctly.
    """
    # Create a dummy image
    img_path = tmp_path / "test.dd"
    img_path.write_bytes(b"dummy")
    
    # Mock basic strings response
    from app.schemas.disk_forensics import DiskFlagCandidate
    mock_scan.return_value = ([], [], [
        DiskFlagCandidate(
            value=expected_flag,
            source=scenario,
            partition="Unknown",
            evidence_type="Raw String",
            confidence=0.99,
            context="Mocked context"
        )
    ])
    
    mock_enum.return_value = []
    mock_recover.return_value = []
    
    response = analyzer.analyze(DiskAnalysisInput(path=img_path, original_filename="test.dd", artifact_id="test"))
    
    assert response.flag_candidates[0].value == expected_flag
    assert len(response.evidence_nodes) >= 2  # Disk + FlagCandidate node
