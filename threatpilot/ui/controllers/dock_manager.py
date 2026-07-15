"""Dock management utility for ThreatPilot's main window."""

from PySide6.QtWidgets import QDockWidget, QWidget
from PySide6.QtCore import Qt, QTimer

class DockManager:
    """Handles the creation and conditional visibility of dock widgets."""
    
    def __init__(self, main_window):
        self._main_window = main_window

    def create_dock(self, title: str, widget: QWidget, area: Qt.DockWidgetArea, *, min_width: int = 0, min_height: int = 0) -> QDockWidget:
        """Helper to create and dock a QDockWidget with specified parameters."""
        dock = QDockWidget(title, self._main_window)
        dock.setObjectName(f"dock_{title.lower().replace(' ', '_')}")
        dock.setWidget(widget)
        dock.setAllowedAreas(Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea | Qt.DockWidgetArea.BottomDockWidgetArea)
        dock.setFeatures(QDockWidget.DockWidgetFeature.DockWidgetClosable | QDockWidget.DockWidgetFeature.DockWidgetMovable | QDockWidget.DockWidgetFeature.DockWidgetFloatable)
        if min_width: widget.setMinimumWidth(min_width)
        if min_height: widget.setMinimumHeight(min_height)
        self._main_window.addDockWidget(area, dock)
        return dock

    def on_tab_changed(self, index: int, central_tabs, properties_panel_dock) -> None:
        """Conditionally shows or hides the Attributes dock based on the active workspace tab."""
        if not properties_panel_dock:
            return
            
        # Only show Attributes for STRIDE (1) and LINDDUN (2) tabs
        show_attributes = (index in (1, 2))
        properties_panel_dock.setVisible(show_attributes)
        
        # Refresh the newly activated tab dynamically if it supports it
        current_widget = central_tabs.widget(index)
        if hasattr(current_widget, "refresh"):
            QTimer.singleShot(0, current_widget.refresh)
