"""Evidence Transformation Graph for disk forensics."""

from __future__ import annotations

import uuid
from typing import Any

from app.schemas.disk_forensics import EvidenceNode, EvidenceEdge


class EvidenceGraph:
    """Tracks the lineage of forensic evidence."""

    def __init__(self) -> None:
        self.nodes: dict[str, EvidenceNode] = {}
        self.edges: list[EvidenceEdge] = []

    def add_node(
        self,
        node_type: str,
        label: str,
        attributes: dict[str, Any] | None = None,
        confidence: float = 1.0,
        node_id: str | None = None,
    ) -> EvidenceNode:
        """Create and add a new node to the graph."""
        nid = node_id or str(uuid.uuid4())
        
        # Ensure attributes are JSON serializable types allowed by the schema
        safe_attrs: dict[str, str | int | float | bool | None] = {}
        if attributes:
            for k, v in attributes.items():
                if isinstance(v, (str, int, float, bool, type(None))):
                    safe_attrs[k] = v
                else:
                    safe_attrs[k] = str(v)

        node = EvidenceNode(
            id=nid,
            node_type=node_type,
            label=label,
            attributes=safe_attrs,
            confidence=confidence,
        )
        self.nodes[nid] = node
        return node

    def add_edge(self, source_id: str, target_id: str, relation: str) -> EvidenceEdge | None:
        """Add a directional edge between two nodes."""
        if source_id not in self.nodes or target_id not in self.nodes:
            return None
            
        edge = EvidenceEdge(source_id=source_id, target_id=target_id, relation=relation)
        self.edges.append(edge)
        return edge

    def get_nodes(self) -> list[EvidenceNode]:
        """Return all nodes."""
        return list(self.nodes.values())

    def get_edges(self) -> list[EvidenceEdge]:
        """Return all edges."""
        return list(self.edges)
