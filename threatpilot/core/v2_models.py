from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
import uuid

class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class ThreatState(str, Enum):
    NEW = "New"
    EXISTING = "Existing"
    UPDATED = "Updated"
    MITIGATED = "Mitigated"
    RESOLVED = "Resolved"
    ACCEPTED_RISK = "Accepted Risk"
    FALSE_POSITIVE = "False Positive"

class ThreatCategory(str, Enum):
    COMPONENT = "Component Threat"
    DATA_FLOW = "Data Flow Threat"
    ATTACK_PATH = "Attack Path Threat"

class SecurityControl(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: str
    strength: str
    scope: str
    mitigates: List[str] = Field(default_factory=list)
    verified: bool = False

class ThreatContextStatic(BaseModel):
    origin: str
    business_criticality: str
    data_classification: List[str]
    asset_type: str
    trust_zone: str

class ThreatContextDynamic(BaseModel):
    authenticated: bool = False
    current_privileges: str = "None"
    tokens_obtained: List[str] = Field(default_factory=list)
    active_controls: List[SecurityControl] = Field(default_factory=list)
    risk_score: float = 0.0

class ThreatContext(BaseModel):
    """The security context that mutates as we traverse the graph."""
    static: ThreatContextStatic
    dynamic: ThreatContextDynamic

class EventLogEntry(BaseModel):
    event_id: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    description: str
    node_id: Optional[str] = None
    edge_id: Optional[str] = None
    context_snapshot: Optional[Dict[str, Any]] = None

class AttackMemory(BaseModel):
    """Chronological event log tracking the attacker's path."""
    events: List[EventLogEntry] = Field(default_factory=list)

    def add_event(self, description: str, node_id: str = None, edge_id: str = None, context: ThreatContext = None):
        event = EventLogEntry(
            event_id=len(self.events) + 1,
            description=description,
            node_id=node_id,
            edge_id=edge_id,
            context_snapshot=context.model_dump() if context else None
        )
        self.events.append(event)

class ThreatSession(BaseModel):
    """Master container for a threat modeling run, ensuring absolute reproducibility."""
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user: str
    architecture_version: str  # e.g., git commit hash
    execution_time_ms: int = 0
    prompt_versions: Dict[str, str] = Field(default_factory=dict)  # Maps agent to prompt version

class Risk(BaseModel):
    score: float
    level: RiskLevel
    justification: str

class Evidence(BaseModel):
    traversal_path: List[str]  # List of node/edge IDs
    description: str

class Threat(BaseModel):
    """The foundational Threat Reasoning Object."""
    id: str  # e.g. TP-000124
    category: ThreatCategory
    state: ThreatState
    title: str
    reason: str
    evidence: Evidence
    missing_controls: List[str]
    recommended_mitigation: str
    verification_method: str
    references: List[str]  # CWE, ASVS, etc.
    risk: Optional[Risk] = None
