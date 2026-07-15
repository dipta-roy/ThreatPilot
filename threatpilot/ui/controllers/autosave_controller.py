"""Autosave controller for ThreatPilot's main window."""

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QMessageBox

class AutosaveController:
    """Manages auto-save and debounced saving logic."""

    def __init__(self, main_window, project_accessor, status_bar):
        self._main_window = main_window
        self._get_project = project_accessor
        self._status_bar = status_bar
        
        self.save_debounce_timer = QTimer(self._main_window)
        self.save_debounce_timer.setSingleShot(True)
        self.save_debounce_timer.setInterval(2000)
        self.save_debounce_timer.timeout.connect(self.on_autosave)

    def trigger_debounced_save(self) -> None:
        """Starts or restarts the debounce timer for auto-saving."""
        if self._get_project():
            self.save_debounce_timer.start()

    def on_save_project(self, silent: bool = False, central_tabs=None) -> None:
        """Save the current project to disk."""
        project = self._get_project()
        if project is None:
            if not silent:
                QMessageBox.information(self._main_window, "Save", "No project is open.")
            return

        try:
            from threatpilot.core.project_manager import save_project
            save_project(project)
            
            # Lazy refresh: only refresh the active tab to prevent UI stutter
            if central_tabs:
                current_widget = central_tabs.currentWidget()
                if hasattr(current_widget, "refresh"):
                    current_widget.refresh()
            
            if not silent:
                self._status_bar.showMessage("Project saved.")
        except (ValueError, OSError) as exc:
            if not silent:
                QMessageBox.critical(self._main_window, "Error", f"Could not save project:\n{exc}")

    def on_autosave(self) -> None:
        """Automatically save the active project periodically without UX intrusion."""
        if self._get_project() is not None:
            self.on_save_project(silent=True)
            self._status_bar.showMessage("Project auto-saved.", 2000)
