"""Project explorer panel for ThreatPilot.

Provides a tree view of project elements:
- Project root
- Diagrams folder (with individual diagrams)
- Analysis elements (threat register, config - placeholders for now)

Supports diagram management: rename, double-click to view.
"""

from __future__ import annotations

from typing import cast

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import (
    QInputDialog,
    QMessageBox,
    QMenu,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from threatpilot.core.diagram_model import Diagram
from threatpilot.core.project_manager import Project


class ProjectExplorer(QWidget):
    """Tree view explorer for ThreatPilot projects.

    Signals:
        diagram_activated: Emitted when a diagram is double-clicked or selected
            to be displayed. Carries the ``Diagram`` object.
    """

    diagram_activated: Signal = Signal(object)  # Diagram
    diagram_deleted: Signal = Signal(object)    # Diagram
    tool_activated: Signal = Signal(str)        # Action string
    project_modified: Signal = Signal()

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._project: Project | None = None

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Initialise the tree widget and layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.itemDoubleClicked.connect(self._on_item_double_clicked)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._on_context_menu)

        layout.addWidget(self._tree)

    # ------------------------------------------------------------------
    # Project lifecycle
    # ------------------------------------------------------------------

    def set_project(self, project: Project | None) -> None:
        """Update the explorer to display the given project.

        Args:
            project: The ``Project`` model to display, or ``None`` to clear.
        """
        self._project = project
        self.refresh()

    def refresh(self) -> None:
        """Rebuild the tree structure from the current project model."""
        self._tree.clear()
        if not self._project:
            return

        # --- Root Project Item ---
        root = QTreeWidgetItem(self._tree, [self._project.project_name])
        # root.setIcon(0, QIcon.fromTheme("project-development")) # optional
        root.setExpanded(True)

        # --- Diagrams Folder ---
        self._diagrams_root = QTreeWidgetItem(root, ["Diagrams"])
        # self._diagrams_root.setIcon(0, QIcon.fromTheme("folder-images"))
        self._diagrams_root.setExpanded(True)

        for diag in self._project.diagrams:
            item = QTreeWidgetItem(self._diagrams_root, [diag.original_name])
            item.setData(0, Qt.ItemDataRole.UserRole, diag)
            # item.setIcon(0, QIcon.fromTheme("image-x-generic"))

        # --- Architecture Folder ---
        arch_root = QTreeWidgetItem(root, ["Architecture"])
        arch_root.setExpanded(True)
        i0 = QTreeWidgetItem(arch_root, ["Entities and Nodes"])
        i0.setData(0, Qt.ItemDataRole.UserRole, "action_edit_components")
        i0b = QTreeWidgetItem(arch_root, ["Data Flow"])
        i0b.setData(0, Qt.ItemDataRole.UserRole, "action_edit_flows")

        # --- Analysis Folder ---
        analysis_root = QTreeWidgetItem(root, ["Analysis"])
        analysis_root.setExpanded(True)
        i1 = QTreeWidgetItem(analysis_root, ["Threat Register"])
        i1.setData(0, Qt.ItemDataRole.UserRole, "action_view_threats")
        i2 = QTreeWidgetItem(analysis_root, ["Risk Matrix"])
        i2.setData(0, Qt.ItemDataRole.UserRole, "action_view_risk_matrix")

        # --- Configuration Folder ---
        config_root = QTreeWidgetItem(root, ["Configuration"])
        config_root.setExpanded(True)
        i3 = QTreeWidgetItem(config_root, ["AI Settings"])
        i3.setData(0, Qt.ItemDataRole.UserRole, "action_ai_settings")
        i4 = QTreeWidgetItem(config_root, ["Business Context"])
        i4.setData(0, Qt.ItemDataRole.UserRole, "action_prompt_config")

    # ------------------------------------------------------------------
    # Event Handlers
    # ------------------------------------------------------------------

    def _on_item_double_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        """Handle double-click (or single click via mapping) on a tree item."""
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if isinstance(data, Diagram):
            self.diagram_activated.emit(data)
        elif isinstance(data, str):
            self.tool_activated.emit(data)

    def _on_context_menu(self, pos) -> None:
        """Show context menu for selected item."""
        item = self._tree.itemAt(pos)
        if not item:
            return

        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not isinstance(data, Diagram):
            return

        menu = QMenu(self)
        
        rename_action = QAction("Rename", self)
        rename_action.triggered.connect(lambda: self._rename_diagram(item))
        menu.addAction(rename_action)

        delete_action = QAction("Delete", self)
        delete_action.triggered.connect(lambda: self._delete_diagram(item))
        menu.addAction(delete_action)

        menu.exec(self._tree.mapToGlobal(pos))

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _rename_diagram(self, item: QTreeWidgetItem) -> None:
        """Rename a diagram entry."""
        diag = cast(Diagram, item.data(0, Qt.ItemDataRole.UserRole))
        
        new_name, ok = QInputDialog.getText(
            self, "Rename Diagram", "New name:",
            text=diag.original_name
        )
        if ok and new_name.strip():
            diag.original_name = new_name.strip()
            item.setText(0, diag.original_name)
            self.project_modified.emit()
            
            # Note: We typically need to save the project after this metadata change
            # but that is usually handled by the owner Main Window.

    def _delete_diagram(self, item: QTreeWidgetItem) -> None:
        """Remove a diagram from the project."""
        diag = cast(Diagram, item.data(0, Qt.ItemDataRole.UserRole))
        
        reply = QMessageBox.question(
            self, "Delete Diagram",
            f"Are you sure you want to delete '{diag.original_name}'?\n"
            "This will permanently delete the image file from your project folder.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            if self._project and diag in self._project.diagrams:
                # Physically delete the file
                from pathlib import Path
                full_path = Path(self._project.project_path) / diag.file_path
                if full_path.exists():
                    try:
                        full_path.unlink()
                    except Exception as e:
                        print(f"Failed to delete file: {e}")

                self._project.diagrams.remove(diag)
                item.parent().removeChild(item)
                self.diagram_deleted.emit(diag)
                self.project_modified.emit()
