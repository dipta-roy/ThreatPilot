"""Core domain models for Threat Modeling.

Defines the ``Component``, ``Flow``, and ``TrustBoundary`` models that
represent the final structure of the analyzed system.
"""

from __future__ import annotations
import uuid
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field

class ElementType(str, Enum):
    """The standard DFD element types."""
    PROCESS = "Process"
    DATA_STORE = "Data Store"
    DATA_FLOW = "Data Flow"
    ENTITY = "Entity"
    NONE = "None"

class AssetType(str, Enum):
    """Broad classification for assets."""
    PHYSICAL = "Physical"
    INFORMATIONAL = "Informational"
    NONE = "None"

class Asset(BaseModel):
    """A high-value asset that may reside within components or flows."""
    asset_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    name: str = "New Asset"
    type: AssetType = AssetType.INFORMATIONAL
    description: str = ""
    criticality: str = "Medium"
    is_out_of_scope: bool = False
    out_of_scope_justification: str = ""

class Component(BaseModel):
    """A logical or physical component in the arch diagram (DFD Node)."""

    component_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    name: str = "New Component"
    type: str = "Service"
    element_type: ElementType = ElementType.PROCESS
    asset_type: AssetType = AssetType.INFORMATIONAL
    trust_boundary_id: Optional[str] = None
    description: str = ""
    is_out_of_scope: bool = False
    out_of_scope_justification: str = ""
    x: float = 0.0
    y: float = 0.0
    width: float = 100.0
    height: float = 100.0

class Flow(BaseModel):
    """A data flow between two components."""

    flow_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    name: str = "Data Flow"
    source_id: str = ""
    target_id: str = ""
    protocol: str = "HTTPS"
    description: str = ""
    is_out_of_scope: bool = False
    out_of_scope_justification: str = ""
    is_bidirectional: bool = False
    trust_boundary_id: Optional[str] = None
    start_x: float = 0.0
    start_y: float = 0.0
    end_x: float = 0.0
    end_y: float = 0.0

class TrustBoundary(BaseModel):
    """A trust boundary encompassing multiple components."""

    boundary_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    name: str = "Trust Boundary"
    type: str = "Internal"
    description: str = ""
    parent_boundary_id: Optional[str] = None
    x: float = 0.0
    y: float = 0.0
    width: float = 200.0
    height: float = 200.0