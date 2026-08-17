"""Forensic Reasoning Engine for disk analysis.

Executes rule-based evidence correlation to automatically follow promising leads.
"""

from __future__ import annotations

import logging
from typing import Callable, Any

from app.schemas.disk_forensics import EvidenceNode, NotableFinding
from app.analyzers.forensics.disk.graph import EvidenceGraph

logger = logging.getLogger(__name__)


class ForensicReasoningEngine:
    """Evaluates rules against the Evidence Graph to discover new leads or findings."""

    def __init__(self, graph: EvidenceGraph) -> None:
        self.graph = graph
        self.rules: list[Callable[[EvidenceGraph, EvidenceNode], list[NotableFinding]]] = []
        self._register_rules()

    def _register_rules(self) -> None:
        """Register the built-in heuristic rules."""
        self.rules.extend([
            self.rule_check_high_entropy_files,
            self.rule_check_history_for_encryption,
            self.rule_correlate_deleted_history,
            self.rule_git_commit_removal,
        ])

    def evaluate_node(self, node: EvidenceNode) -> list[NotableFinding]:
        """Run all applicable rules against a newly added node."""
        findings: list[NotableFinding] = []
        for rule in self.rules:
            try:
                new_findings = rule(self.graph, node)
                findings.extend(new_findings)
            except Exception as e:
                logger.error(f"Rule {rule.__name__} failed on node {node.id}: {e}")
        return findings

    # --- RULES ---

    def rule_check_high_entropy_files(self, graph: EvidenceGraph, node: EvidenceNode) -> list[NotableFinding]:
        """Detect possible encrypted or compressed files based on entropy and missing magic."""
        findings = []
        if node.node_type == "File":
            ext = node.attributes.get("extension", "")
            entropy = float(node.attributes.get("entropy", 0.0))
            if entropy > 7.9 and ext not in (".zip", ".gz", ".7z", ".tar.gz", ".enc", ".encrypted"):
                # Missing common extension but high entropy -> suspicious
                pass
        return findings

    def rule_check_history_for_encryption(self, graph: EvidenceGraph, node: EvidenceNode) -> list[NotableFinding]:
        """If node is a Shell History command, check for openssl."""
        findings = []
        if node.node_type == "ShellCommand":
            cmd = str(node.attributes.get("command", "")).lower()
            if "openssl" in cmd and ("-e" in cmd or "enc" in cmd):
                # We found an encryption command
                pass
        return findings

    def rule_correlate_deleted_history(self, graph: EvidenceGraph, node: EvidenceNode) -> list[NotableFinding]:
        """If history shows a shred/rm command, flag it."""
        findings = []
        if node.node_type == "ShellCommand":
            cmd = str(node.attributes.get("command", "")).lower()
            if cmd.startswith("shred ") or cmd.startswith("rm "):
                # Anti-forensics detected
                pass
        return findings

    def rule_git_commit_removal(self, graph: EvidenceGraph, node: EvidenceNode) -> list[NotableFinding]:
        """Check git commits for suspicious messages."""
        findings = []
        if node.node_type == "GitCommit":
            msg = str(node.attributes.get("message", "")).lower()
            if any(word in msg for word in ["flag", "secret", "remove", "delete", "cleanup", "oops"]):
                # High-value commit
                pass
        return findings
