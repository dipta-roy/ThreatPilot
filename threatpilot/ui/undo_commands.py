"""Undo/Redo command implementations for ThreatPilot."""

from __future__ import annotations
from typing import TYPE_CHECKING, List, Any
from PySide6.QtGui import QUndoCommand

if TYPE_CHECKING:
    from threatpilot.core.project_manager import Project
    from threatpilot.core.domain_models import Component, Flow

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
