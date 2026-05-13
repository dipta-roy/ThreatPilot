"""Undo/Redo command implementations for ThreatPilot."""

from __future__ import annotations
from typing import TYPE_CHECKING, List, Any
from PySide6.QtGui import QUndoCommand

if TYPE_CHECKING:
    from threatpilot.core.project_manager import Project
    from threatpilot.core.domain_models import Component, Flow, TrustBoundary, Asset

class AddComponentCommand(QUndoCommand):
    def __init__(self, project: Project, component: Component, description: str = "Add Component"):
        super().__init__(description)
        self.project = project
        self.component = component

    def redo(self):
        if self.component not in self.project.components:
            self.project.components.append(self.component)

    def undo(self):
        if self.component in self.project.components:
            self.project.components.remove(self.component)

class DeleteComponentCommand(QUndoCommand):
    def __init__(self, project: Project, component: Component, description: str = "Delete Component"):
        super().__init__(description)
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
    def __init__(self, project: Project, flow: Flow, description: str = "Add Data Flow"):
        super().__init__(description)
        self.project = project
        self.flow = flow

    def redo(self):
        if self.flow not in self.project.flows:
            self.project.flows.append(self.flow)

    def undo(self):
        if self.flow in self.project.flows:
            self.project.flows.remove(self.flow)

class DeleteFlowCommand(QUndoCommand):
    def __init__(self, project: Project, flow: Flow, description: str = "Delete Data Flow"):
        super().__init__(description)
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
    def __init__(self, target_obj: Any, field: str, old_val: Any, new_val: Any, description: str = "Update Property"):
        super().__init__(f"{description} ({field})")
        self.target_obj = target_obj
        self.field = field
        self.old_val = old_val
        self.new_val = new_val

    def redo(self):
        setattr(self.target_obj, self.field, self.new_val)

    def undo(self):
        setattr(self.target_obj, self.field, self.old_val)

class AddTrustBoundaryCommand(QUndoCommand):
    def __init__(self, project: Project, boundary: TrustBoundary, description: str = "Add Trust Boundary"):
        super().__init__(description)
        self.project = project
        self.boundary = boundary

    def redo(self):
        if self.boundary not in self.project.boundaries:
            self.project.boundaries.append(self.boundary)

    def undo(self):
        if self.boundary in self.project.boundaries:
            self.project.boundaries.remove(self.boundary)

class DeleteTrustBoundaryCommand(QUndoCommand):
    def __init__(self, project: Project, boundary: TrustBoundary, description: str = "Delete Trust Boundary"):
        super().__init__(description)
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
    def __init__(self, project: Project, asset: Asset, description: str = "Add Asset"):
        super().__init__(description)
        self.project = project
        self.asset = asset

    def redo(self):
        if self.asset not in self.project.assets:
            self.project.assets.append(self.asset)

    def undo(self):
        if self.asset in self.project.assets:
            self.project.assets.remove(self.asset)

class DeleteAssetCommand(QUndoCommand):
    def __init__(self, project: Project, asset: Asset, description: str = "Delete Asset"):
        super().__init__(description)
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
