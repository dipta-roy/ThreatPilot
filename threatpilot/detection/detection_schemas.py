"""Structured schemas for AI vision object detection in ThreatPilot.

Defines Pydantic models for native structured output validation.
"""

from __future__ import annotations
from typing import List, Optional
from pydantic import BaseModel, Field

class VisionComponent(BaseModel):
    """Schema representing an identified system component."""
    name: str = Field(description="Name of the component as labeled in the diagram.")
    type: str = Field(description="Subtype of the component (e.g. Service, Web App, Database, API Gateway).")
    element_type: str = Field(description="Standard DFD class: 'Process', 'Data Store', or 'Entity'.")
    trust_boundary: Optional[str] = Field(None, description="Name of the trust boundary container this component resides in.")
    bounding_box: List[int] = Field(description="Bounding box [ymin, xmin, ymax, xmax] normalized to range 0-1000.")

class VisionFlow(BaseModel):
    """Schema representing an identified data flow/connection between components."""
    name: str = Field(description="Name of the data flow or protocol.")
    source: str = Field(description="Name of the source component.")
    target: str = Field(description="Name of the target component.")
    protocol: str = Field(description="Protocol being used (e.g. HTTPS, gRPC, JDBC, AMQP).")
    bounding_box: List[int] = Field(description="Flow path start/end coordinates [ys, xs, ye, xe] normalized to 0-1000.")

class VisionBoundary(BaseModel):
    """Schema representing a trust boundary container."""
    name: str = Field(description="Name of the trust boundary.")
    bounding_box: List[int] = Field(description="Bounding box [ymin, xmin, ymax, xmax] normalized to range 0-1000.")

class VisionAsset(BaseModel):
    """Schema representing a valuable asset requiring protection."""
    name: str = Field(description="Name of the data asset, credential, key, or secret.")
    type: str = Field(description="Asset classification type: 'Physical' or 'Informational'.")
    description: str = Field(description="Reasoning / explanation of why this item requires protection and what it contains.")

class VisionResponse(BaseModel):
    """Consolidated response schema containing all extracted architectural elements."""
    c: List[VisionComponent] = Field(description="List of detected logical architectural components.")
    f: List[VisionFlow] = Field(description="List of detected data flows between components.")
    tb: List[VisionBoundary] = Field(description="List of detected trust boundary containers.")
    a: List[VisionAsset] = Field(description="List of identified assets (data, secrets, credentials).")

def get_vision_response_schema() -> dict:
    """Generates a fully-inlined (dereferenced) schema dict suitable for the Gemini API."""
    return {
        "type": "OBJECT",
        "properties": {
            "c": {
                "type": "ARRAY",
                "description": "List of detected logical architectural components.",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "name": {"type": "STRING", "description": "Name of the component as labeled in the diagram."},
                        "type": {"type": "STRING", "description": "Subtype of the component (e.g. Service, Web App, Database, API Gateway)."},
                        "element_type": {"type": "STRING", "description": "Standard DFD class: 'Process', 'Data Store', or 'Entity'."},
                        "trust_boundary": {"type": "STRING", "description": "Name of the trust boundary container this component resides in."},
                        "bounding_box": {
                            "type": "ARRAY",
                            "items": {"type": "INTEGER"},
                            "description": "Bounding box [ymin, xmin, ymax, xmax] normalized to range 0-1000."
                        }
                    },
                    "required": ["name", "type", "element_type", "bounding_box"]
                }
            },
            "f": {
                "type": "ARRAY",
                "description": "List of detected data flows between components.",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "name": {"type": "STRING", "description": "Name of the data flow or protocol."},
                        "source": {"type": "STRING", "description": "Name of the source component."},
                        "target": {"type": "STRING", "description": "Name of the target component."},
                        "protocol": {"type": "STRING", "description": "Protocol being used (e.g. HTTPS, gRPC, JDBC, AMQP)."},
                        "bounding_box": {
                            "type": "ARRAY",
                            "items": {"type": "INTEGER"},
                            "description": "Flow path start/end coordinates [ys, xs, ye, xe] normalized to 0-1000."
                        }
                    },
                    "required": ["name", "source", "target", "protocol", "bounding_box"]
                }
            },
            "tb": {
                "type": "ARRAY",
                "description": "List of detected trust boundary containers.",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "name": {"type": "STRING", "description": "Name of the trust boundary."},
                        "bounding_box": {
                            "type": "ARRAY",
                            "items": {"type": "INTEGER"},
                            "description": "Bounding box [ymin, xmin, ymax, xmax] normalized to range 0-1000."
                        }
                    },
                    "required": ["name", "bounding_box"]
                }
            },
            "a": {
                "type": "ARRAY",
                "description": "List of identified assets (data, secrets, credentials).",
                "items": {
                    "type": "OBJECT",
                    "properties": {
                        "name": {"type": "STRING", "description": "Name of the data asset, credential, key, or secret."},
                        "type": {"type": "STRING", "description": "Asset classification type: 'Physical' or 'Informational'."},
                        "description": {"type": "STRING", "description": "Reasoning / explanation of why this item requires protection and what it contains."}
                    },
                    "required": ["name", "type", "description"]
                }
            }
        },
        "required": ["c", "f", "tb", "a"]
    }
