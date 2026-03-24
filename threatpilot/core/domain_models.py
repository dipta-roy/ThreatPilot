"""Core domain models for Threat Modeling.

Defines the ``Component``, ``Flow``, and ``TrustBoundary`` models that
represent the final structure of the analyzed system.
"""

from __future__ import annotations

import uuid
from typing import Any
from pydantic import BaseModel, Field


class Component(BaseModel):
    """A logical or physical component in the arch diagram."""

    component_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    name: str = "New Component"
    type: str = "Service"
    description: str = ""
    is_high_value_asset: bool = False
    criticality_description: str = ""
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
    x: float = 0.0
    y: float = 0.0
    width: float = 200.0
    height: float = 200.0
