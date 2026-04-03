"""DFD Conversion module for ThreatPilot.

Converts the detected architectural components, flows, and boundaries into
a Data Flow Diagram (DFD) structure suitable for threat analysis.
"""

from __future__ import annotations
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field
from threatpilot.core.domain_models import Component, Flow, TrustBoundary

class DFDNodeType(str, Enum):
    """The standard DFD element types."""
    PROCESS = "Process"
    DATA_STORE = "DataStore"
    EXTERNAL_ENTITY = "ExternalEntity"

class DFDNode(BaseModel):
    """A node in the Data Flow Diagram."""

    id: str
    name: str
    type: str
    element_classification: str = ""
    asset_classification: str = ""
    description: str = ""
    component_id: Optional[str] = None

class DFDEdge(BaseModel):
    """A directed edge in the Data Flow Diagram representing data-in-transit."""

    id: str
    name: str
    source_id: str
    target_id: str
    protocol: str = "HTTPS"
    flow_id: Optional[str] = None

class DFDModel(BaseModel):
    """The complete DFD representation of the system."""

    nodes: List[DFDNode] = Field(default_factory=list)
    edges: List[DFDEdge] = Field(default_factory=list)

def convert_to_dfd(
    components: List[Component],
    flows: List[Flow]
) -> DFDModel:
    """Map detected domain objects to a DFD structure with auto-linking."""
    dfd = DFDModel()

    for comp in components:
        node = DFDNode(
            id=comp.component_id,
            name=comp.name,
            type=comp.type,
            element_classification=comp.element_classification,
            asset_classification=comp.asset_classification,
            description=comp.description,
            component_id=comp.component_id
        )
        dfd.nodes.append(node)

    for flow in flows:
        src_id = flow.source_id
        dst_id = flow.target_id
        
        if not src_id or not dst_id:
            best_src = None
            best_dst = None
            min_src_dist = 150.0  
            min_dst_dist = 150.0
            
            for c in components:
                cx, cy = c.x + c.width/2, c.y + c.height/2
                
                if not src_id:
                    d = ((cx - flow.start_x)**2 + (cy - flow.start_y)**2)**0.5
                    if d < min_src_dist:
                        min_src_dist = d
                        best_src = c.component_id
                
                if not dst_id:
                    d = ((cx - flow.end_x)**2 + (cy - flow.end_y)**2)**0.5
                    if d < min_dst_dist:
                        min_dst_dist = d
                        best_dst = c.component_id
            
            if not src_id: src_id = best_src or ""
            if not dst_id: dst_id = best_dst or ""

        edge = DFDEdge(
            id=flow.flow_id,
            name=flow.name,
            source_id=src_id,
            target_id=dst_id,
            protocol=flow.protocol,
            flow_id=flow.flow_id
        )
        dfd.edges.append(edge)

    return dfd
