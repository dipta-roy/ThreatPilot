"""DFD Conversion module for ThreatPilot.

Converts the detected architectural components, flows, and boundaries into
a Data Flow Diagram (DFD) structure suitable for threat analysis.
"""

from __future__ import annotations
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field
from threatpilot.core.domain_models import Component, Flow, TrustBoundary, Asset

class DFDNode(BaseModel):
    """Represents a discrete functional entity within the Data Flow Diagram."""
    id: str
    name: str
    type: str
    element_type: str = ""
    asset_type: str = ""
    trust_boundary: Optional[str] = None
    parent_trust_boundary: Optional[str] = None
    description: str = ""
    component_id: Optional[str] = None

class DFDEdge(BaseModel):
    """Represents a communication channel or data movement between DFD nodes."""
    id: str
    name: str
    source_id: str
    target_id: str
    protocol: str = "HTTPS"
    is_bidirectional: bool = False
    trust_boundary: Optional[str] = None
    flow_id: Optional[str] = None

class DFDAsset(BaseModel):
    """Represents a protected information or physical asset within the system."""
    name: str
    type: str
    criticality: str
    description: str = ""
    is_out_of_scope: bool = False
    out_of_scope_justification: str = ""

class DFDBoundary(BaseModel):
    """Represents a trust boundary within the Data Flow Diagram."""
    name: str
    type: str
    description: str = ""
    parent_boundary: Optional[str] = None

class DFDModel(BaseModel):
    """Aggregates all nodes, edges, and assets into a complete architectural model."""
    nodes: List[DFDNode] = Field(default_factory=list)
    edges: List[DFDEdge] = Field(default_factory=list)
    assets: List[DFDAsset] = Field(default_factory=list)
    boundaries: List[DFDBoundary] = Field(default_factory=list)

def convert_to_dfd(
    components: List[Component],
    flows: List[Flow],
    boundaries: List[TrustBoundary] = None,
    assets: List[Asset] = None
) -> DFDModel:
    """Transforms domain-specific architectural elements into a standardized DFD structure."""
    dfd = DFDModel()
    boundaries = boundaries or []; assets = assets or []

    for a in assets:
        dfd.assets.append(DFDAsset(
            name=a.name, 
            type=a.type.value, 
            criticality=a.criticality, 
            description=a.description,
            is_out_of_scope=a.is_out_of_scope, 
            out_of_scope_justification=a.out_of_scope_justification
        ))

    for b in boundaries:
        parent_name = None
        if b.parent_boundary_id:
            parent = next((pb for pb in boundaries if pb.boundary_id == b.parent_boundary_id), None)
            if parent:
                parent_name = parent.name
        dfd.boundaries.append(DFDBoundary(
            name=b.name,
            type=b.type,
            description=b.description,
            parent_boundary=parent_name
        ))

    def get_containing_boundary(x: float, y: float, w: float = 0, h: float = 0) -> Optional[TrustBoundary]:
        cx, cy = x + w/2, y + h/2
        for b in boundaries:
            if b.x <= cx <= b.x + b.width and b.y <= cy <= b.y + b.height: return b
        return None

    for comp in components:
        if comp.is_out_of_scope: continue

        tb_name = "None (External)"; parent_tb_name = None; tb = None
        if comp.trust_boundary_id: tb = next((b for b in boundaries if b.boundary_id == comp.trust_boundary_id), None)
        if not tb: tb = get_containing_boundary(comp.x, comp.y, comp.width, comp.height)
        
        if tb:
            tb_name = tb.name
            if tb.parent_boundary_id:
                if (parent := next((b for b in boundaries if b.boundary_id == tb.parent_boundary_id), None)): parent_tb_name = parent.name

        dfd.nodes.append(DFDNode(id=comp.component_id, name=comp.name, type=comp.type, element_type=comp.element_type.value, trust_boundary=tb_name, parent_trust_boundary=parent_tb_name, description=comp.description, component_id=comp.component_id))

    # Pre-calculate component centers to optimize Euclidean distance math (O(F * C))
    comp_centers = {}
    for c in components:
        comp_centers[c.component_id] = (c.x + c.width/2, c.y + c.height/2)

    for flow in flows:
        if flow.is_out_of_scope: continue

        src_id, dst_id = flow.source_id, flow.target_id
        if not src_id or not dst_id:
            best_src = best_dst = None; min_src_dist = min_dst_dist = 150.0  
            for c_id, (cx, cy) in comp_centers.items():
                if not src_id:
                    if (d := ((cx - flow.start_x)**2 + (cy - flow.start_y)**2)**0.5) < min_src_dist: min_src_dist, best_src = d, c_id
                if not dst_id:
                    if (d := ((cx - flow.end_x)**2 + (cy - flow.end_y)**2)**0.5) < min_dst_dist: min_dst_dist, best_dst = d, c_id
            if not src_id: src_id = best_src or ""
            if not dst_id: dst_id = best_dst or ""

        tb_name = "Internal"
        src_node = next((n for n in dfd.nodes if n.id == src_id), None)
        dst_node = next((n for n in dfd.nodes if n.id == dst_id), None)
        if src_node and dst_node:
            tb_name = f"Cross-Boundary ({src_node.trust_boundary} -> {dst_node.trust_boundary})" if src_node.trust_boundary != dst_node.trust_boundary else src_node.trust_boundary

        dfd.edges.append(DFDEdge(id=flow.flow_id, name=flow.name, source_id=src_id, target_id=dst_id, protocol=flow.protocol, is_bidirectional=flow.is_bidirectional, trust_boundary=tb_name, flow_id=flow.flow_id))

    return dfd

def generate_deterministic_narrative(dfd: DFDModel) -> str:
    """Generates a deterministic plain-text Architecture Narrative story for the entire model."""
    lines = []
    
    nodes_by_id = {n.id: n for n in dfd.nodes}
    
    if not dfd.edges:
        return "No data flows have been defined for this architecture."
        
    for edge in dfd.edges:
        source = nodes_by_id.get(edge.source_id)
        target = nodes_by_id.get(edge.target_id)
        
        src_name = source.name if source else "Unknown origin"
        dst_name = target.name if target else "Unknown destination"
        
        sentence = f"✓ {src_name} sends data to {dst_name}"
        if edge.protocol and str(edge.protocol).strip().lower() not in ('none', 'unknown', ''):
            sentence += f" over {edge.protocol}"
            
        if source and target:
            src_tb = source.trust_boundary or "an external trust boundary"
            dst_tb = target.trust_boundary or "an external trust boundary"
            if src_tb != dst_tb:
                sentence += f", crossing from the {src_tb} into the {dst_tb}"
            else:
                sentence += f", remaining within the {src_tb}"
        
        sentence += "."
        lines.append(sentence)
        
        if edge.is_bidirectional:
            ret_sentence = f"✓ {dst_name} returns data to {src_name}"
            if edge.protocol and str(edge.protocol).strip().lower() not in ('none', 'unknown', ''):
                ret_sentence += f" over {edge.protocol}"
            
            if source and target:
                if src_tb != dst_tb:
                    ret_sentence += f", crossing from the {dst_tb} into the {src_tb}"
                else:
                    ret_sentence += f", remaining within the {dst_tb}"
            ret_sentence += "."
            lines.append(ret_sentence)
            
    if dfd.assets:
        lines.append("\n### Key Assets")
        for asset in dfd.assets:
            if asset.is_out_of_scope:
                continue
            lines.append(f"- **{asset.name}** ({asset.type}): {asset.description or 'No description provided.'}")
            
    return "\n\n".join(lines)
