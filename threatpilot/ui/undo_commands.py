"""Undo/Redo command implementations for ThreatPilot."""

from __future__ import annotations
from typing import TYPE_CHECKING, List, Any
from PySide6.QtGui import QUndoCommand

if TYPE_CHECKING:
    from threatpilot.core.project_manager import Project
    from threatpilot.core.domain_models import Component, Flow, TrustBoundary, Asset

class AddComponentCommand(QUndoCommand):
    def __init__(self, project: Project, component: Component, description: str = "Add Component", parent: QUndoCommand = None):
        super().__init__(description, parent)
        self.project = project
        self.component = component

    def redo(self):
        if self.component not in self.project.components:
            self.project.components.append(self.component)

    def undo(self):
        if self.component in self.project.components:
            self.project.components.remove(self.component)

class DeleteComponentCommand(QUndoCommand):
    def __init__(self, project: Project, component: Component, description: str = "Delete Component", parent: QUndoCommand = None):
        super().__init__(description, parent)
        self.project = project
        self.component = component
        self.index = -1

    def redo(self):
        if self.component in self.project.components:
            self.index = self.project.components.index(self.component)
            self.project.components.remove(self.component)

    def undo(self):
        if self.index >= 0:
            self.project.components.insert(self.index, self.component)

class AddFlowCommand(QUndoCommand):
    def __init__(self, project: Project, flow: Flow, description: str = "Add Data Flow", parent: QUndoCommand = None):
        super().__init__(description, parent)
        self.project = project
        self.flow = flow

    def redo(self):
        if self.flow not in self.project.flows:
            self.project.flows.append(self.flow)

    def undo(self):
        if self.flow in self.project.flows:
            self.project.flows.remove(self.flow)

class DeleteFlowCommand(QUndoCommand):
    def __init__(self, project: Project, flow: Flow, description: str = "Delete Data Flow", parent: QUndoCommand = None):
        super().__init__(description, parent)
        self.project = project
        self.flow = flow
        self.index = -1

    def redo(self):
        if self.flow in self.project.flows:
            self.index = self.project.flows.index(self.flow)
            self.project.flows.remove(self.flow)

    def undo(self):
        if self.index >= 0:
            self.project.flows.insert(self.index, self.flow)
class PropertyUpdateCommand(QUndoCommand):
    """Generic command for updating a property of any object."""
    def __init__(self, target_obj: Any, field: str, old_val: Any, new_val: Any, description: str = "Update Property", parent: QUndoCommand = None):
        super().__init__(f"{description} ({field})", parent)
        self.target_obj = target_obj
        self.field = field
        self.old_val = old_val
        self.new_val = new_val

    def redo(self):
        setattr(self.target_obj, self.field, self.new_val)

    def undo(self):
        setattr(self.target_obj, self.field, self.old_val)

class AddTrustBoundaryCommand(QUndoCommand):
    def __init__(self, project: Project, boundary: TrustBoundary, description: str = "Add Trust Boundary", parent: QUndoCommand = None):
        super().__init__(description, parent)
        self.project = project
        self.boundary = boundary

    def redo(self):
        if self.boundary not in self.project.boundaries:
            self.project.boundaries.append(self.boundary)

    def undo(self):
        if self.boundary in self.project.boundaries:
            self.project.boundaries.remove(self.boundary)

class DeleteTrustBoundaryCommand(QUndoCommand):
    def __init__(self, project: Project, boundary: TrustBoundary, description: str = "Delete Trust Boundary", parent: QUndoCommand = None):
        super().__init__(description, parent)
        self.project = project
        self.boundary = boundary
        self.index = -1

    def redo(self):
        if self.boundary in self.project.boundaries:
            self.index = self.project.boundaries.index(self.boundary)
            self.project.boundaries.remove(self.boundary)

    def undo(self):
        if self.index >= 0:
            self.project.boundaries.insert(self.index, self.boundary)

class AddAssetCommand(QUndoCommand):
    def __init__(self, project: Project, asset: Asset, description: str = "Add Asset", parent: QUndoCommand = None):
        super().__init__(description, parent)
        self.project = project
        self.asset = asset

    def redo(self):
        if self.asset not in self.project.assets:
            self.project.assets.append(self.asset)

    def undo(self):
        if self.asset in self.project.assets:
            self.project.assets.remove(self.asset)

class DeleteAssetCommand(QUndoCommand):
    def __init__(self, project: Project, asset: Asset, description: str = "Delete Asset", parent: QUndoCommand = None):
        super().__init__(description, parent)
        self.project = project
        self.asset = asset
        self.index = -1

    def redo(self):
        if self.asset in self.project.assets:
            self.index = self.project.assets.index(self.asset)
            self.project.assets.remove(self.asset)

    def undo(self):
        if self.index >= 0:
            self.project.assets.insert(self.index, self.asset)

class DeleteThreatCommand(QUndoCommand):
    def __init__(self, project: Project, threat_id: str, description: str = "Delete Threat", parent: QUndoCommand = None):
        super().__init__(description, parent)
        self.project = project
        self.threat_id = threat_id
        self.threat = None
        self.index = -1

    def redo(self):
        if self.project.threat_register:
            threat = next((t for t in self.project.threat_register.threats if t.threat_id == self.threat_id), None)
            if threat:
                self.threat = threat
                self.index = self.project.threat_register.threats.index(threat)
                self.project.threat_register.remove_threat(self.threat_id)

    def undo(self):
        if self.threat and self.index >= 0:
            self.project.threat_register.threats.insert(self.index, self.threat)

class DeleteVulnerabilityCommand(QUndoCommand):
    def __init__(self, project: Project, vulnerability_id: str, description: str = "Delete Vulnerability", parent: QUndoCommand = None):
        super().__init__(description, parent)
        self.project = project
        self.vulnerability_id = vulnerability_id
        self.vulnerability = None
        self.index = -1
        self.affected_threats = [] # (threat_id, index_in_threat_vulnerability_ids)

    def redo(self):
        reg = self.project.vulnerability_register
        if reg:
            vuln = reg.get_vulnerability(self.vulnerability_id)
            if vuln:
                self.vulnerability = vuln
                self.index = reg.vulnerabilities.index(vuln)
                
                # Track where this vulnerability was used in threats
                self.affected_threats = []
                for threat in self.project.threat_register.threats:
                    if self.vulnerability_id in threat.vulnerability_ids:
                        idx = threat.vulnerability_ids.index(self.vulnerability_id)
                        self.affected_threats.append((threat.threat_id, idx))
                        threat.vulnerability_ids.remove(self.vulnerability_id)
                
                reg.vulnerabilities.remove(vuln)

    def undo(self):
        if self.vulnerability and self.index >= 0:
            self.project.vulnerability_register.vulnerabilities.insert(self.index, self.vulnerability)
            
            # Restore references in threats
            for tid, idx in self.affected_threats:
                threat = next((t for t in self.project.threat_register.threats if t.threat_id == tid), None)
                if threat:
                    threat.vulnerability_ids.insert(idx, self.vulnerability_id)
