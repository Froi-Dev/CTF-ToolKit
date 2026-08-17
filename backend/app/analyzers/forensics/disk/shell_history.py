"""Shell history analyzer for tracking user actions and finding passwords/encryption."""

import re
import logging
from app.schemas.disk_forensics import EvidenceNode, NotableFinding
from app.analyzers.forensics.disk.graph import EvidenceGraph

logger = logging.getLogger(__name__)

def parse_shell_history(
    graph: EvidenceGraph,
    history_content: str,
    file_path: str,
    partition_id: str
) -> list[EvidenceNode]:
    """Parse shell history and generate ShellCommand nodes."""
    nodes = []
    lines = history_content.splitlines()
    
    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
            
        # Create a node for the command
        cmd_node = graph.add_node(
            node_type="ShellCommand",
            label=f"Command: {line[:30]}...",
            attributes={
                "command": line,
                "source_file": file_path,
                "line_number": i + 1,
            }
        )
        graph.add_edge(partition_id, cmd_node.id, "contains")
        nodes.append(cmd_node)
        
        # Check for openssl encryption
        if "openssl" in line and ("-enc" in line or "-e" in line):
            # Try to extract password if passed via -k or -pass
            # e.g., openssl aes-256-cbc -e -in flag.txt -out flag.enc -k supersecret
            pass_match = re.search(r'-k\s+([^\s]+)', line)
            if pass_match:
                pwd = pass_match.group(1)
                pwd_node = graph.add_node(
                    node_type="PasswordCandidate",
                    label=f"Password: {pwd}",
                    attributes={"password": pwd, "source": "shell_history"}
                )
                graph.add_edge(cmd_node.id, pwd_node.id, "produces")
                nodes.append(pwd_node)

    return nodes
