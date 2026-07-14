from __future__ import annotations
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import uuid

class AssetMetadata(BaseModel):
    tech_stack: Optional[str] = None
    criticality: str = "Medium"
    owner: Optional[str] = None
    contains_pii: bool = False
    contains_phi: bool = False
    internet_facing: bool = False
    custom_tags: Dict[str, Any] = Field(default_factory=dict)

from enum import Enum

class NodeAnalysisState(str, Enum):
    NEVER_ANALYZED = "Never Analyzed"
    ANALYZED = "Analyzed"
    NEEDS_REANALYSIS = "Needs Reanalysis"
    PROTECTED = "Protected"
    OUT_OF_SCOPE = "Out of Scope"
    INHERITED_CONTEXT_CHANGED = "Inherited Context Changed"
    CONTROL_ADDED = "Control Added"
    CONTROL_REMOVED = "Control Removed"

class Node(BaseModel):
    id: str
    name: str
    type: str  # e.g., "Service", "Database", "Actor", "Browser"
    trust_zone: str = "Internal"
    metadata: AssetMetadata = Field(default_factory=AssetMetadata)
    analysis_state: NodeAnalysisState = NodeAnalysisState.NEVER_ANALYZED

class Edge(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str
    target_id: str
    protocol: Optional[str] = None
    authenticated: bool = False
    data_flow_types: List[str] = Field(default_factory=list)  # e.g., ["PII", "Credentials"]
    security_controls: List[str] = Field(default_factory=list)  # List of Control IDs

class ArchitectureGraph(BaseModel):
    """
    Represents the unified Tri-Graph (Component, Trust, and Data flows).
    Provides methods to query neighborhoods and relationships.
    """
    nodes: Dict[str, Node] = Field(default_factory=dict)
    edges: List[Edge] = Field(default_factory=list)

    def add_node(self, node: Node):
        """Add a component node to the graph."""
        self.nodes[node.id] = node

    def add_edge(self, edge: Edge, bidirectional: bool = False):
        """
        Add a data flow edge.
        If bidirectional is True, it automatically splits it into two directed edges.
        """
        self.edges.append(edge)
        if bidirectional:
            reverse_edge = Edge(
                source_id=edge.target_id,
                target_id=edge.source_id,
                protocol=edge.protocol,
                authenticated=edge.authenticated,
                data_flow_types=edge.data_flow_types.copy(),
                security_controls=edge.security_controls.copy()
            )
            self.edges.append(reverse_edge)

    def get_node(self, node_id: str) -> Optional[Node]:
        return self.nodes.get(node_id)

    def get_outbound_edges(self, node_id: str) -> List[Edge]:
        return [e for e in self.edges if e.source_id == node_id]

    def get_inbound_edges(self, node_id: str) -> List[Edge]:
        return [e for e in self.edges if e.target_id == node_id]

    def get_neighborhood(self, edge_id: str) -> Dict[str, Any]:
        """
        Extracts a localized sub-graph (A -> B -> C) centered around a specific edge.
        This keeps the LLM context extremely small.
        """
        edge = next((e for e in self.edges if e.id == edge_id), None)
        if not edge:
            return {}

        source_node = self.get_node(edge.source_id)
        target_node = self.get_node(edge.target_id)
        
        # Get downstream edges from target to represent 'C' in A->B->C
        downstream_edges = self.get_outbound_edges(edge.target_id)
        
        return {
            "focus_edge": edge.model_dump(),
            "source_node": source_node.model_dump() if source_node else None,
            "target_node": target_node.model_dump() if target_node else None,
            "downstream_flows": [e.model_dump() for e in downstream_edges]
        }
        
    def get_component_graph(self) -> ArchitectureGraph:
        """Returns the physical/logical topology excluding trust boundaries and data types."""
        g = ArchitectureGraph()
        g.nodes = {k: v.model_copy() for k, v in self.nodes.items()}
        for edge in self.edges:
            e_copy = edge.model_copy()
            e_copy.data_flow_types = []
            g.edges.append(e_copy)
        return g

    def get_trust_graph(self) -> ArchitectureGraph:
        """Returns only nodes and edges that cross trust boundaries."""
        g = ArchitectureGraph()
        for edge in self.edges:
            src = self.get_node(edge.source_id)
            tgt = self.get_node(edge.target_id)
            if src and tgt and src.trust_zone != tgt.trust_zone:
                g.nodes[src.id] = src.model_copy()
                g.nodes[tgt.id] = tgt.model_copy()
                g.edges.append(edge.model_copy())
        return g

    def get_data_graph(self, target_data_tags: List[str] = ["PII", "PHI", "Credentials"]) -> ArchitectureGraph:
        """Returns only nodes and edges that carry the specified sensitive data tags."""
        g = ArchitectureGraph()
        target_tags_lower = {t.lower() for t in target_data_tags}
        for edge in self.edges:
            edge_tags = {t.lower() for t in edge.data_flow_types}
            if edge_tags.intersection(target_tags_lower):
                src = self.get_node(edge.source_id)
                tgt = self.get_node(edge.target_id)
                if src: g.nodes[src.id] = src.model_copy()
                if tgt: g.nodes[tgt.id] = tgt.model_copy()
                g.edges.append(edge.model_copy())
        return g
