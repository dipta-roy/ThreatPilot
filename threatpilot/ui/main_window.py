"""Main application window for ThreatPilot."""

from __future__ import annotations
import asyncio
from datetime import datetime
from pathlib import Path
from PySide6.QtCore import Qt, QSize, QTimer, QUrl, QThread, Signal, QRectF, QPointF, QBuffer, QIODevice
from PySide6.QtGui import QAction, QKeySequence, QFont, QPixmap, QImage, QIcon, QUndoStack, QUndoCommand, QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QDockWidget,
    QFileDialog,
    QInputDialog,
    QLabel,
    QMainWindow,
    QMenuBar,
    QMessageBox,
    QStatusBar,
    QToolBar,
    QHBoxLayout,
    QPushButton,
    QVBoxLayout,
    QWidget,
    QProgressDialog,
    QWizard,
    QWizardPage,
    QDialog,
    QTabWidget,
    QTextEdit,
)
from threatpilot.core.diagram_model import Diagram
from threatpilot.core.threat_model import Threat
from threatpilot.core.project_manager import (
    Project,
    create_project,
    load_project,
    save_project,
)
from threatpilot.core.domain_models import Component, Flow, TrustBoundary
from threatpilot.core.dfd_converter import convert_to_dfd, DFDModel, DFDNode, DFDEdge
from threatpilot.detection.image_loader import import_diagram_file
from threatpilot.ui.diagram_canvas import DiagramCanvas
from threatpilot.ui.project_explorer import ProjectExplorer
from threatpilot.ui.ai_settings_dialog import AISettingsDialog
from threatpilot.ui.prompt_settings_dialog import PromptSettingsDialog
from threatpilot.ui.properties_panel import PropertiesPanel
from threatpilot.ui.threat_panel import ThreatPanel
from threatpilot.ui.architecture_dialog import EntitiesDialog, DataFlowDialog
from threatpilot.ui.risk_matrix_dialog import RiskMatrixDialog
from threatpilot.ui.risk_assessment_panel import RiskAssessmentPanel
from threatpilot.config.ai_config import AIConfig
from threatpilot.ui.about_dialog import AboutDialog
from threatpilot.ui.quick_start_wizard import QuickStartWizard
from threatpilot.export.excel_exporter import export_to_excel
from threatpilot.export.markdown_exporter import export_to_markdown
from threatpilot.export.html_exporter import export_to_html
from threatpilot.export.mitigation_exporter import export_mitigation_checklist, export_mitigation_checklist_html
from threatpilot.export.diagram_exporter import export_scene_to_image
from threatpilot.ai.factory import create_ai_provider
from threatpilot.ai.prompt_builder import PromptBuilder
from threatpilot.ai.analyzer import ThreatAnalyzer
from threatpilot.ai.response_parser import extract_json
from threatpilot.core.constants import (
    APP_NAME, WINDOW_WIDTH_PERCENT, WINDOW_HEIGHT_PERCENT, 
    MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT
)
from threatpilot.ui.workers import AnalysisWorker, AIVisionWorker, ReasoningWorker
from threatpilot.ui.dialogs import ReasoningDisplayDialog, PlaceholderPanel
from threatpilot.ui.worker_manager import WorkerManager
from threatpilot.ui.menu_manager import MenuManager
from threatpilot.utils.paths import get_resource_path, get_app_icon_path, get_recent_project_file, PROJECT_ROOT, CONFIG_FILE
from threatpilot.utils.logger import setup_logging, LOG_DIR, sanitize_text, get_logger
logger = get_logger(__name__)

class MainWindow(QMainWindow):
    """Primary application window for project management and threat modeling."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._project: Project | None = None
        self._current_diagram: Diagram | None = None
        self._undo_stack = QUndoStack(self)
        self._undo_action = self._undo_stack.createUndoAction(self, "&Undo")
        self._redo_action = self._undo_stack.createRedoAction(self, "&Redo")
        self._undo_action.setShortcut(QKeySequence.StandardKey.Undo)
        self._redo_action.setShortcut(QKeySequence.StandardKey.Redo)

        self._worker_mgr = WorkerManager(self)
        self._menu_mgr = MenuManager(self)

        self._setup_window()
        self._setup_central_widget()
        self._setup_docks()
        self._menu_mgr.setup_menus()
        self._menu_mgr.setup_toolbar()
        self._setup_status_bar()
        self._connect_actions()
        
        self._undo_stack.indexChanged.connect(self._on_undo_redo_happened)
        self._is_dark_theme = False
        self._load_stylesheet()
        self._load_recent_project()
        
        self._save_debounce_timer = QTimer(self)
        self._save_debounce_timer.setSingleShot(True)
        self._save_debounce_timer.setInterval(2000) # Save 2 seconds after the last modification
        self._save_debounce_timer.timeout.connect(lambda: self._on_save_project(silent=True))

        config = AIConfig.load()
        self._autosave_timer = QTimer(self)
        self._autosave_timer.timeout.connect(self._on_autosave)
        self._autosave_timer.start(config.autosave_interval * 60000)
        self._analysis_new_threats = 0

    def _load_stylesheet(self) -> None:
        """Applies the professional application theme (Dark/Light)."""
        theme_file = "style.qss" if self._is_dark_theme else "style_light.qss"
        resource_dir = get_resource_path("")
        style_path = resource_dir / theme_file
        if style_path.exists():
            QApplication.instance().setStyleSheet(style_path.read_text())
        else:
            fallback_path = resource_dir / "style.qss"
            if fallback_path.exists():
                QApplication.instance().setStyleSheet(fallback_path.read_text())
                
        if hasattr(self, "_risk_assessment_panel"):
            self._risk_assessment_panel.set_theme(self._is_dark_theme)
        if hasattr(self, "_threat_panel"):
            self._threat_panel.set_theme(self._is_dark_theme)
        if hasattr(self, "_full_threat_ledger"):
            self._full_threat_ledger.set_theme(self._is_dark_theme)
        if hasattr(self, "_properties_panel"):
            self._properties_panel.set_theme(self._is_dark_theme)
        if hasattr(self, "_canvas"):
            self._canvas.set_theme(self._is_dark_theme)
        if hasattr(self, "_vulnerability_panel"):
            self._vulnerability_panel.set_theme(self._is_dark_theme)

    def _on_toggle_theme(self) -> None:
        """Switches the application theme between dark and light modes."""
        self._is_dark_theme = not self._is_dark_theme
        self._load_stylesheet()
        self.statusBar().showMessage(f"Theme switched to {'Dark' if self._is_dark_theme else 'Light'}")

    def _on_toggle_full_screen(self) -> None:
        """Toggles between full screen and windowed states."""
        if self.isFullScreen():
            self.showMaximized()
        else:
            self.showFullScreen()

    def _load_recent_project(self) -> None:
        """Reloads the last opened project from the recent history file."""
        recent_file = get_recent_project_file()
        if recent_file.exists():
            path = recent_file.read_text().strip()
            if path and Path(path).exists():
                try:
                    self._open_project_from_path(path)
                except Exception:
                    pass

    def _setup_window(self) -> None:
        """Configures the top-level window properties and geometry."""
        self._update_title()
        icon_path = get_app_icon_path()
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
        
        # Calculate initial size based on screen percentages
        screen = QApplication.primaryScreen().availableGeometry()
        w = int(screen.width() * WINDOW_WIDTH_PERCENT)
        h = int(screen.height() * WINDOW_HEIGHT_PERCENT)
        self.resize(w, h)
        
        # Center the window on screen
        self.move(screen.center() - self.rect().center())
        
        self.setMinimumSize(QSize(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT))
        self.setDockNestingEnabled(True)
        self.setDockOptions(
            QMainWindow.DockOption.AnimatedDocks | 
            QMainWindow.DockOption.AllowNestedDocks | 
            QMainWindow.DockOption.AllowTabbedDocks | 
            QMainWindow.DockOption.GroupedDragging
        )

    def _update_title(self) -> None:
        """Updates the window title to reflect the current project and diagram."""
        title = APP_NAME
        if self._project:
            title += f" - {self._project.project_name}"
            if self._current_diagram:
                title += f" [{self._current_diagram.original_name}]"
        self.setWindowTitle(title)

    def _setup_central_widget(self) -> None:
        """Initializes the central workspace tabs for diagrams and analysis reports."""
        self._central_tabs = QTabWidget()
        self._central_tabs.setObjectName("central_tabs_container")
        self._central_tabs.setDocumentMode(True)
        
        self._canvas = DiagramCanvas(self)
        self._canvas.setMinimumWidth(200)
        self._central_tabs.addTab(self._canvas, "System Architecture")
        
        self._stride_threat_ledger = ThreatPanel(self, filter_mode="STRIDE")
        self._stride_threat_ledger.setMinimumWidth(200)
        self._central_tabs.addTab(self._stride_threat_ledger, "STRIDE Security")
        
        self._linddun_threat_ledger = ThreatPanel(self, filter_mode="LINDDUN")
        self._linddun_threat_ledger.setMinimumWidth(200)
        self._central_tabs.addTab(self._linddun_threat_ledger, "LINDDUN Privacy")

        from threatpilot.ui.vulnerability_panel import VulnerabilityPanel
        self._vulnerability_panel = VulnerabilityPanel(self)
        self._vulnerability_panel.setMinimumWidth(200)
        self._vulnerability_panel.vulnerability_changed.connect(self._on_save_project)
        self._vulnerability_panel.vulnerability_changed.connect(
            lambda: self._properties_panel.set_item(self._properties_panel._current_item)
        )
        self._central_tabs.addTab(self._vulnerability_panel, "Vulnerabilities")

        self._risk_assessment_panel = RiskAssessmentPanel(self)
        self._risk_assessment_panel.setMinimumWidth(200)
        self._risk_assessment_panel.threat_edited.connect(self._on_save_project)
        self._central_tabs.addTab(self._risk_assessment_panel, "Risk Assessment")
        
        self._central_tabs.currentChanged.connect(self._on_tab_changed)
        self.setCentralWidget(self._central_tabs)

    def _setup_docks(self) -> None:
        """Initializes and positions the application's dockable panels."""
        self._properties_panel = PropertiesPanel(self, undo_stack=self._undo_stack)
        self._properties_panel.property_changed.connect(
            lambda obj: self._on_project_modified(obj, refresh_properties=False)
        )
        self._properties_panel.reasoning_requested.connect(self._on_reasoning_requested)
        
        def _sync_labels(obj):
            if isinstance(obj, Threat):
                QTimer.singleShot(0, self._stride_threat_ledger.refresh)
                QTimer.singleShot(0, self._linddun_threat_ledger.refresh)
        
        self._properties_panel.property_changed.connect(_sync_labels)
        self._properties_panel_dock = self._create_dock("Attributes", self._properties_panel, Qt.DockWidgetArea.RightDockWidgetArea, min_width=150)

        self._project_explorer = ProjectExplorer(self)
        self._project_explorer.diagram_activated.connect(self._on_diagram_activated)
        self._project_explorer.diagram_deleted.connect(self._on_diagram_deleted)
        self._project_explorer.tool_activated.connect(self._on_explorer_tool_activated)
        self._project_explorer.project_modified.connect(self._on_save_project)
        self._project_explorer_dock = self._create_dock("Project Map", self._project_explorer, Qt.DockWidgetArea.LeftDockWidgetArea, min_width=180)

        self._ai_log_view = QTextEdit()
        self._ai_log_view.setReadOnly(True)
        self._ai_log_view.setObjectName("ai_log_view")
        self._ai_log_view.setPlaceholderText("AI transaction logs will appear here during detection or analysis...")

        self._stride_threat_ledger.threat_selected.connect(self._properties_panel.set_item)
        self._linddun_threat_ledger.threat_selected.connect(self._properties_panel.set_item)
        self._stride_threat_ledger.reasoning_requested.connect(self._on_reasoning_requested)
        self._linddun_threat_ledger.reasoning_requested.connect(self._on_reasoning_requested)
        self._vulnerability_panel.reasoning_requested.connect(self._on_reasoning_requested)
        self._stride_threat_ledger.run_analysis_requested.connect(lambda mode, iters: self._on_run_analysis(mode, iters))
        self._stride_threat_ledger.threat_added.connect(self._on_save_project)
        self._stride_threat_ledger.threat_removed.connect(self._on_save_project)
        self._linddun_threat_ledger.run_analysis_requested.connect(lambda mode, iters: self._on_run_analysis(mode, iters))
        self._linddun_threat_ledger.threat_added.connect(self._on_save_project)
        self._linddun_threat_ledger.threat_removed.connect(self._on_save_project)
        self._risk_assessment_panel.threat_edited.connect(self._on_save_project)
        
        self._ai_log_dock = self._create_dock("AI Activity Log", self._ai_log_view, Qt.DockWidgetArea.BottomDockWidgetArea, min_width=400)
        self._ai_log_dock.setVisible(False)
        
        # Initialize visibility based on current tab
        self._on_tab_changed(self._central_tabs.currentIndex())

    def _on_tab_changed(self, index: int) -> None:
        """Conditionally shows or hides the Attributes dock based on the active workspace tab."""
        if not hasattr(self, "_properties_panel_dock"):
            return
            
        # Only show Attributes for STRIDE (1) and LINDDUN (2) tabs
        show_attributes = (index in (1, 2))
        self._properties_panel_dock.setVisible(show_attributes)

    def _create_dock(self, title: str, widget: QWidget, area: Qt.DockWidgetArea, *, min_width: int = 0, min_height: int = 0) -> QDockWidget:
        """Helper to create and dock a QDockWidget with specified parameters."""
        dock = QDockWidget(title, self)
        dock.setObjectName(f"dock_{title.lower().replace(' ', '_')}")
        dock.setWidget(widget)
        dock.setAllowedAreas(Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea | Qt.DockWidgetArea.BottomDockWidgetArea)
        dock.setFeatures(QDockWidget.DockWidgetFeature.DockWidgetClosable | QDockWidget.DockWidgetFeature.DockWidgetMovable | QDockWidget.DockWidgetFeature.DockWidgetFloatable)
        if min_width: widget.setMinimumWidth(min_width)
        if min_height: widget.setMinimumHeight(min_height)
        self.addDockWidget(area, dock)
        return dock



    def _setup_status_bar(self) -> None:
        """Initializes the application status bar."""
        status_bar = QStatusBar(self)
        self.setStatusBar(status_bar)
        status_bar.showMessage("Ready")

    def _connect_actions(self) -> None:
        """Connects UI actions to their respective event handlers."""
        self._action_new_project.triggered.connect(self._on_new_project)
        self._action_open_project.triggered.connect(self._on_open_project)
        self._action_close_project.triggered.connect(self._on_close_project)
        self._action_save_project.triggered.connect(self._on_save_project)
        self._action_import_diagram.triggered.connect(self._on_import_diagram)
        self._action_fit_diagram.triggered.connect(self._on_fit_diagram)
        self._action_ai_settings.triggered.connect(self._on_ai_settings)
        self._action_prompt_config.triggered.connect(self._on_prompt_config)
        self._action_run_analysis.triggered.connect(self._on_run_analysis)
        self._action_export_excel.triggered.connect(self._on_export_excel)
        self._action_export_markdown.triggered.connect(self._on_export_markdown)
        self._action_export_html.triggered.connect(self._on_export_html)
        self._action_export_mitigation.triggered.connect(self._on_export_mitigation_checklist)
        self._action_export_mitigation_html.triggered.connect(self._on_export_mitigation_checklist_html)
        self._action_export_diagram.triggered.connect(self._on_export_diagram)
        self._action_about.triggered.connect(self._on_about)
        self._action_detect_objects.triggered.connect(self._on_detect_objects)
        self._action_edit_elements.triggered.connect(self._on_edit_elements)
        self._action_edit_assets.triggered.connect(self._on_edit_assets)
        self._action_edit_boundaries.triggered.connect(self._on_edit_boundaries)
        self._action_toggle_theme.triggered.connect(self._on_toggle_theme)
        self._action_quickstart.triggered.connect(self._on_quick_start)
        self._action_open_logs.triggered.connect(self._on_open_logs)

    def _on_new_project(self) -> None:
        """Displays a dialog to create a new threat modeling project."""
        name, ok = QInputDialog.getText(self, "New Project", "Project name:")
        if not ok or not name.strip():
            return

        directory = QFileDialog.getExistingDirectory(self, "Select project parent directory")
        if not directory:
            return

        if self._project:
             self._on_close_project()

        try:
            self._project = create_project(name.strip(), parent_dir=directory)
            self._project_explorer.set_project(self._project)
            self._stride_threat_ledger.set_register(self._project.threat_register)
            self._linddun_threat_ledger.set_register(self._project.threat_register)
            self._risk_assessment_panel.set_project(self._project)
            self._vulnerability_panel.set_project(self._project)
            self._properties_panel.set_project(self._project)
            self._current_diagram = None
            self._canvas.clear_diagram()
            self._update_title()
            self.statusBar().showMessage(f"Project '{self._project.project_name}' created.")
            
            recent_file = get_recent_project_file()
            recent_file.write_text(str(self._project.project_path))
                
        except OSError as exc:
            QMessageBox.critical(self, "Error", f"Could not create project:\n{exc}")

    def _on_close_project(self) -> None:
        """Closes the current project and resets the workspace UI."""
        if not self._project:
            return
            
        self._worker_mgr.stop_active_worker()
        if hasattr(self, "_worker_ai_vision") and self._worker_ai_vision.isRunning():
            self._worker_ai_vision.terminate()
            self._worker_ai_vision.wait()
        if hasattr(self, "_reasoning_workers"):
            for w in self._reasoning_workers:
                if w.isRunning():
                    w.terminate()
                    w.wait()

        self._project = None
        self._current_diagram = None
        self._project_explorer.set_project(None)
        self._stride_threat_ledger.set_register(None)
        self._linddun_threat_ledger.set_register(None)
        self._risk_assessment_panel.set_project(None)
        self._vulnerability_panel.set_project(None)
        self._properties_panel.set_item(None)
        self._canvas.clear_diagram()
        self._undo_stack.clear()
        self._ai_log_view.clear()
        self._update_title()
        
        recent_file = get_recent_project_file()
        if recent_file.exists():
            try: recent_file.unlink()
            except Exception: pass
            
        self.statusBar().showMessage("Project closed.")

    def _on_open_project(self) -> None:
        """Opens a project selection dialog."""
        directory = QFileDialog.getExistingDirectory(self, "Open ThreatPilot project")
        if not directory:
            return

        if self._project:
            self._on_close_project()

        try:
            self._open_project_from_path(directory)
        except (FileNotFoundError, ValueError) as exc:
            QMessageBox.critical(self, "Error", f"Could not open project:\n{exc}")

    def _open_project_from_path(self, directory: str) -> None:
        """Loads a project from a filesystem path."""
        self._project = load_project(directory)
        self._project_explorer.set_project(self._project)
        self._stride_threat_ledger.set_register(self._project.threat_register)
        self._linddun_threat_ledger.set_register(self._project.threat_register)
        self._risk_assessment_panel.set_project(self._project)
        self._vulnerability_panel.set_project(self._project)
        self._properties_panel.set_project(self._project)
        self._current_diagram = None
        self._canvas.clear_diagram()
        self._update_title()

        if self._project.diagrams:
            self._on_diagram_activated(self._project.diagrams[0])

        self.statusBar().showMessage(f"Project '{self._project.project_name}' loaded.")
        
        recent_file = get_recent_project_file()
        recent_file.write_text(str(directory))

    def _on_project_modified(self, obj: Any = None, refresh_properties: bool = True) -> None:
        """Refreshes UI components and triggers a debounced save when data changes."""
        if hasattr(self, "_risk_assessment_panel"):
            QTimer.singleShot(0, self._risk_assessment_panel.refresh)
        if hasattr(self, "_stride_threat_ledger"):
            QTimer.singleShot(0, self._stride_threat_ledger.refresh)
        if hasattr(self, "_linddun_threat_ledger"):
            QTimer.singleShot(0, self._linddun_threat_ledger.refresh)
        if hasattr(self, "_vulnerability_panel"):
            QTimer.singleShot(0, self._vulnerability_panel.refresh)
        QTimer.singleShot(0, self._refresh_canvas_overlays)
        self._update_title()
        
        # Trigger debounced auto-save
        if self._project:
            self._save_debounce_timer.start()

    def _on_save_project(self, silent: bool = False) -> None:
        """Save the current project to disk."""
        if self._project is None:
            if not silent:
                QMessageBox.information(self, "Save", "No project is open.")
            return

        try:
            save_project(self._project)
            if hasattr(self, "_risk_assessment_panel"):
                self._risk_assessment_panel.refresh()
            if hasattr(self, "_threat_panel"):
                self._threat_panel.refresh()
            if hasattr(self, "_stride_threat_ledger"):
                self._stride_threat_ledger.refresh()
            if hasattr(self, "_linddun_threat_ledger"):
                self._linddun_threat_ledger.refresh()
            
            if not silent:
                self.statusBar().showMessage("Project saved.")
        except (ValueError, OSError) as exc:
            if not silent:
                QMessageBox.critical(self, "Error", f"Could not save project:\n{exc}")

    def _on_autosave(self) -> None:
        """Automatically save the active project periodically without UX intrusion."""
        if self._project is not None:
            self._on_save_project(silent=True)
            self.statusBar().showMessage("Project auto-saved.", 2000)

    def _on_diagram_deleted(self, diagram: Diagram) -> None:
        """Handle the physical removal of a diagram and cleanup the canvas."""
        if self._current_diagram == diagram:
            self._current_diagram = None
            self._canvas.clear_diagram()
            self._update_title()
            self.statusBar().showMessage(f"Deleted diagram: {diagram.original_name}")

    def _on_import_diagram(self) -> None:
        """Import a PNG / JPG diagram into the current project."""
        if self._project is None:
            QMessageBox.information(
                self, "Import", "Please create or open a project first."
            )
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Diagram",
            "",
            "Images (*.png *.jpg *.jpeg);;All Files (*)",
        )
        if not file_path:
            return

        try:
            diagram = import_diagram_file(file_path, self._project.project_path)
            self._project.diagrams.append(diagram)
            self._project_explorer.refresh()
            self._current_diagram = diagram
            
            image_path = Path(self._project.project_path) / diagram.file_path
            image = QImage(str(image_path))
            pixmap = QPixmap.fromImage(image)
            if not pixmap.isNull():
                self._canvas.set_diagram_pixmap(pixmap)

            save_project(self._project)
            self.statusBar().showMessage(
                f"Imported '{diagram.original_name}' "
                f"({diagram.width}x{diagram.height})"
            )
        except (FileNotFoundError, ValueError, OSError) as exc:
            QMessageBox.critical(
                self, "Import Error", f"Could not import diagram:\n{exc}"
            )

    def _on_diagram_activated(self, diagram: Diagram) -> None:
        """Display the activated diagram on the canvas."""
        if not self._project:
            return

        self._central_tabs.setCurrentIndex(0)
        self._current_diagram = diagram
        image_path = Path(self._project.project_path) / diagram.file_path
        
        image = QImage(str(image_path))
        pixmap = QPixmap.fromImage(image)
        if not pixmap.isNull():
            self._canvas.set_diagram_pixmap(pixmap)
            self._refresh_canvas_overlays()
        
        self.statusBar().showMessage(f"Showing diagram: {diagram.original_name}")

    def _on_ai_settings(self) -> None:
        """Edit the project's AI provider configuration."""
        dialog = AISettingsDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            config = dialog.get_config()
            try:
                config.save()
                
                # Verify the save actually persisted the API key
                reloaded = AIConfig.load()
                saved_key = reloaded.gemini_api_key.get_secret_value()
                entered_key = config.gemini_api_key.get_secret_value()
                
                if entered_key and not saved_key:
                    QMessageBox.warning(
                        self,
                        "Settings Warning",
                        f"Settings were saved but the API key could not be encrypted.\n\n"
                        f"Config file: {CONFIG_FILE.absolute()}\n\n"
                        f"This is usually caused by a missing encryption backend or permission issue in the home directory.\n"
                        f"Check the application logs for details."
                    )
                else:
                    self.statusBar().showMessage(
                        f"Settings updated (Auto-save: {config.autosave_interval} min)."
                    )
                    
            except Exception as exc:
                QMessageBox.critical(
                    self,
                    "Save Error",
                    f"Failed to save AI settings:\n\n{exc}"
                )
                return
            
            self._autosave_timer.setInterval(config.autosave_interval * 60000)

    def _on_prompt_config(self) -> None:
        """Opens the prompt configuration dialog for business context and policy."""
        if not self._project:
            QMessageBox.information(self, "Business Context", "Create or open a project first.")
            return

        dialog = PromptSettingsDialog(self._project.prompt_config, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._project.prompt_config = dialog.get_config()
            save_project(self._project)
            self.statusBar().showMessage("Business Context updated.")

    def _on_explorer_tool_activated(self, action: str) -> None:
        """Dispatches actions triggered from the project explorer tree."""
        if not self._project:
            return

        if action == "action_ai_settings":
            self._on_ai_settings()
        elif action == "action_prompt_config":
            self._on_prompt_config()
        elif action == "action_edit_elements":
            self._on_edit_elements()
        elif action == "action_edit_assets":
            self._on_edit_assets()
        elif action == "action_edit_boundaries":
            self._on_edit_boundaries()
        elif action == "action_edit_flows":
            self._on_edit_flows()
        elif action == "action_view_threats":
            self._central_tabs.setCurrentIndex(1)
            self._stride_threat_ledger.clear_filter()
            self._linddun_threat_ledger.clear_filter()
        elif action == "action_view_risk_matrix" and self._project:
            from threatpilot.ui.risk_matrix_dialog import RiskMatrixDialog
            component_names = [c.name for c in self._project.components]
            component_names.extend([f.name for f in self._project.flows])
            dialog = RiskMatrixDialog(self._project.threat_register.threats, component_names=component_names, is_dark=self._is_dark_theme, project=self._project, parent=self)
            dialog.exec()

    def _on_run_analysis(self, analysis_mode: str | None = None, iterations: int = 1) -> None:
        """Initiates AI-driven threat analysis for the current system architecture."""
        if not self._project: return
        
        if analysis_mode == "CHECKLIST":
            self._on_export_mitigation_checklist()
            return

        mode = analysis_mode if analysis_mode and analysis_mode != "ALL" else None
        dfd = convert_to_dfd(self._project.components, self._project.flows, self._project.boundaries)
        if not dfd.nodes:
            QMessageBox.warning(self, "Analysis", "No components detected to analyze. Please add or detect components first.")
            return

        try:
            config = AIConfig.load()
            if mode: config.analysis_mode = mode
            
            if config.provider_type == "gemini":
                reply = QMessageBox.warning(
                    self, "Data Privacy Acknowledgement",
                    "You are using Google Gemini (Cloud AI). Architecture data will be sent to Google. Proceed?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.No: return

            provider = create_ai_provider(config)
        except Exception as exc:
            QMessageBox.critical(self, "AI Error", f"Could not create AI provider:\n{exc}")
            return

        iter_label = f" ({iterations} iterations)" if iterations > 1 else ""
        if hasattr(self._stride_threat_ledger, "_btn_run"): self._stride_threat_ledger._btn_run.setEnabled(False)
        if hasattr(self._linddun_threat_ledger, "_btn_run"): self._linddun_threat_ledger._btn_run.setEnabled(False)

        self._ai_log_dock.show()
        self._analysis_new_threats = 0
        self._worker_mgr.start_analysis(
            AnalysisWorker, "AI Threat Analysis", f"Analyzing system architecture{iter_label}...",
            provider, self._project.prompt_config, dfd, self._project.project_name, iterations=iterations
        )

    def _on_reasoning_requested(self, item: Any) -> None:
        """Triggers AI reasoning generation for a specific threat or vulnerability."""
        if not self._project: return
        
        existing_reasoning = getattr(item, "reasoning", "")
        if existing_reasoning and existing_reasoning.strip():
            dialog = ReasoningDisplayDialog("AI Technical Reasoning", existing_reasoning, parent=self, show_regenerate=True)
            dialog.exec()
            if not dialog.regenerate_clicked:
                return

        self.statusBar().showMessage("Generating technical reasoning...")
        try:
            config = AIConfig.load()
            
            # Determine correct mode based on the item's category
            from threatpilot.core.threat_model import Threat, STRIDECategory
            mode = config.analysis_mode
            if isinstance(item, Threat):
                if item.category.value in STRIDECategory.get_linddun_values():
                    mode = "LINDDUN"
                else:
                    mode = "STRIDE"
            
            provider = create_ai_provider(config)
            self._worker_mgr.start_analysis(
                ReasoningWorker, "XAI Reasoning", "Generating technical reasoning...",
                provider, self._project.prompt_config, item, mode
            )
        except Exception as exc:
            QMessageBox.critical(self, "Reasoning Error", f"Failed to initialize AI provider:\n{exc}")

    def _on_reasoning_finished(self, reasoning: str, item: Any) -> None:
        """Updates the workspace with generated AI reasoning."""
        from threatpilot.ai.response_parser import convert_reasoning_to_markdown
        logger.info(f"MainWindow: Reasoning finished. item_id={getattr(item, 'threat_id', 'N/A')}, raw_len={len(reasoning)}")
        formatted_reasoning = convert_reasoning_to_markdown(reasoning)
        logger.info(f"MainWindow: Formatted reasoning length: {len(formatted_reasoning)}")
        
        item.reasoning = formatted_reasoning
        if self._project:
            save_project(self._project)

        from threatpilot.core.threat_model import Threat, Vulnerability
        if isinstance(item, Threat):
            self._stride_threat_ledger.refresh()
            self._linddun_threat_ledger.refresh()
            
            # Explicitly refresh properties panel if this item (or one with same ID) is currently selected
            current_item = getattr(self._properties_panel, "_current_item", None)
            is_selected = False
            if current_item:
                if current_item is item:
                    is_selected = True
                elif hasattr(current_item, "threat_id") and hasattr(item, "threat_id"):
                    is_selected = (current_item.threat_id == item.threat_id)
            
            if is_selected:
                self._properties_panel.set_item(item)
        elif isinstance(item, Vulnerability):
            self._vulnerability_panel.refresh()
            
        self.statusBar().showMessage("Reasoning generated successfully.")
        ReasoningDisplayDialog("AI Technical Reasoning", formatted_reasoning, parent=self).exec()

    def _on_reasoning_failed(self, error_msg: str) -> None:
        """Handles failures during reasoning generation."""
        self.statusBar().showMessage("Reasoning generation failed.")
        self._show_concise_error("XAI Error", "Reasoning generation failed:", error_msg)

    def _on_partial_analysis_result(self, partial_register, origin_project: Project | None = None) -> None:
        """Integrates partial analysis results into the live project view."""
        if not self._project or (origin_project and self._project is not origin_project): 
            return
            
        for t in partial_register.threats:
            if self._project.threat_register.add_threat(t):
                self._analysis_new_threats += 1
            
        if hasattr(partial_register, "new_vulnerabilities"):
            for v in partial_register.new_vulnerabilities:
                self._project.vulnerability_register.add_vulnerability(v)

        self._stride_threat_ledger.refresh()
        self._linddun_threat_ledger.refresh()
        self._risk_assessment_panel.refresh()
        self._vulnerability_panel.refresh()
        self.statusBar().showMessage(f"Incremental update: {len(partial_register.threats)} threats added from segment.")

    def _on_request_continuation(self, current, total):
        """Displays a confirmation dialog to proceed with segmented analysis passes."""
        if current == 0:
            title, msg = "Large Architecture Detected", "The architecture will be analyzed in segments. Proceed?"
        else:
            title, msg = "Segmented Analysis", f"Segment {current}/{total} complete. Proceed to next?"

        reply = QMessageBox.question(self, title, msg, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.Yes)
        if self._worker_mgr._worker:
            self._worker_mgr._worker.continue_analysis(reply == QMessageBox.StandardButton.Yes)

    def _on_iteration_progress(self, current_iter: int, total_iters: int, current_seg: int, total_segs: int) -> None:
        """Updates progress tracking for multi-pass analysis."""
        label = f"Iteration {current_iter}/{total_iters}: "
        label += f"Starting segments..." if current_seg == 0 else f"Segment {current_seg}/{total_segs} complete."
        
        if hasattr(self, "_progress") and self._progress:
            self._progress.setLabelText(label)
        self.statusBar().showMessage(label)

    def _on_analysis_finished(self, new_register, raw_resp: str = "", usage: Any = None, origin_project: Project | None = None) -> None:
        """Finalizes the analysis run and persists all discovered threats."""
        if hasattr(self._stride_threat_ledger, "_btn_run"): self._stride_threat_ledger._btn_run.setEnabled(True)
        if hasattr(self._linddun_threat_ledger, "_btn_run"): self._linddun_threat_ledger._btn_run.setEnabled(True)

        if not self._project or (origin_project and self._project is not origin_project):
            return

        # Merge any remaining threats (most already handled via partial results)
        for t in new_register.threats:
            if self._project.threat_register.add_threat(t):
                self._analysis_new_threats += 1
        if hasattr(new_register, "new_vulnerabilities"):
            for v in new_register.new_vulnerabilities:
                self._project.vulnerability_register.add_vulnerability(v)

        self.statusBar().showMessage(f"Analysis complete: {self._analysis_new_threats} new threats added.")
        self._stride_threat_ledger.refresh()
        self._linddun_threat_ledger.refresh()
        self._risk_assessment_panel.refresh()
        self._vulnerability_panel.refresh()

        save_project(self._project)
        QMessageBox.information(self, "Analysis Complete", f"{self._analysis_new_threats} new threats identified.")

    def _on_analysis_failed(self, error_msg: str) -> None:
        """Handles overall analysis failures."""
        if hasattr(self._stride_threat_ledger, "_btn_run"): self._stride_threat_ledger._btn_run.setEnabled(True)
        if hasattr(self._linddun_threat_ledger, "_btn_run"): self._linddun_threat_ledger._btn_run.setEnabled(True)
        if "cancelled by user" in error_msg.lower():
            self.statusBar().showMessage("Analysis cancelled.")
            return
        self.statusBar().showMessage("Analysis failed.")
        self._show_concise_error("Analysis Error", "The AI analysis failed:", error_msg)

    def _show_concise_error(self, title: str, prefix: str, error_msg: str) -> None:
        """Displays categorized, user-friendly error messages for AI/API failures."""
        config = AIConfig.load()
        msg = str(error_msg).lower()
        
        if "timeout" in msg or "deadline" in msg:
            explanation = "🕒 **Request Timeout**: Try increasing the 'Request Timeout' in AI Settings."
        elif "connection" in msg or "connect_error" in msg:
            explanation = "🔌 **Connection Failed**: Check your internet connection or Ollama service."
        elif "model" in msg and "not found" in msg:
            explanation = f"🤖 **Model Not Found**: Verify model name '{config.model_name}' in Settings."
        elif "api_key" in msg or "401" in msg or "unauthorized" in msg:
            explanation = "🔑 **Authentication Failed**: Verify your API Key in AI Settings."
        elif "quota" in msg or "429" in msg:
            explanation = "⏳ **Rate Limit Exceeded**: Wait 60 seconds before retrying."
        else:
            explanation = f"❓ **Unexpected Error**: {error_msg[:200]}..."

        if config.api_key:
            explanation = explanation.replace(config.api_key, "[HIDDEN]")
            error_msg = error_msg.replace(config.api_key, "[HIDDEN]")
            
        QMessageBox.critical(self, title, f"{prefix}\n\n{explanation}")

    def _on_fit_diagram(self) -> None:
        """Fits the diagram image to the current canvas viewport."""
        self._canvas.fit_to_screen()

    def _update_title(self) -> None:
        """Update the window title to reflect the current project."""
        if self._project:
            self.setWindowTitle(f"ThreatPilot - {self._project.project_name}")
        else:
            self.setWindowTitle("ThreatPilot")

    @property
    def project(self) -> Project | None:
        """Return the currently open project, or ``None``."""
        return self._project

    @property
    def current_diagram(self) -> Diagram | None:
        """Return the currently displayed diagram, or ``None``."""
        return self._current_diagram

    @property
    def canvas(self) -> DiagramCanvas:
        """Return the central diagram canvas."""
        return self._canvas

    @property
    def project_explorer_dock(self) -> QDockWidget:
        """Return the Project Explorer dock widget."""
        return self._project_explorer_dock

    @property
    def properties_panel_dock(self) -> QDockWidget:
        """Return the Properties Panel dock widget."""
        return self._properties_panel_dock

    def _on_export_excel(self) -> None:
        """Export the current threat register to a Microsoft Excel file."""
        if not self._project or not self._project.threat_register.threats:
            QMessageBox.information(
                self, "Export", "No threats found to export."
            )
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export to Excel", "", "Excel Files (*.xlsx);;All Files (*)"
        )
        if not file_path:
            return

        if not file_path.endswith(".xlsx"):
            file_path += ".xlsx"

        try:
            export_to_excel(self._project, file_path)
            self.statusBar().showMessage(f"Exported to {file_path}")
            QMessageBox.information(self, "Export Success", f"File saved to {file_path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", f"Could not export to Excel:\n{exc}")

    def _on_detect_objects(self) -> None:
        """Run OpenCV object detection on the current diagram."""
        if not self._project or not self._current_diagram:
            QMessageBox.information(self, "Detection", "Import and open a diagram first.")
            return

        image_path = Path(self._project.project_path) / self._current_diagram.file_path
        if not image_path.exists():
            return

        self.statusBar().showMessage("Running computer vision detection...")
        
        config = AIConfig.load()
        prov_type = config.provider_type.lower()
        model_name = config.model_name.lower()
        
        is_vision_model = (
            "llava" in model_name or 
            "vl" in model_name or 
            "vision" in model_name or 
            "paligemma" in model_name or 
            "gemma" in model_name or      # User indicated gemma4 supports vision
            "moondream" in model_name or
            "minicpm" in model_name or
            "pixtral" in model_name or
            prov_type == "gemini"
        )
        
        has_valid_config = (
            (prov_type == "ollama" and config.endpoint_url and is_vision_model)
            or (prov_type == "gemini" and config.api_key)
        )
        if has_valid_config:
            # Safely stop existing worker if running
            if hasattr(self, "_worker_ai_vision") and self._worker_ai_vision.isRunning():
                try:
                    self._worker_ai_vision.finished.disconnect()
                    self._worker_ai_vision.failed.disconnect()
                except Exception:
                    pass
                self._worker_ai_vision.terminate()
                self._worker_ai_vision.wait()

            self.statusBar().showMessage(f"Using AI Vision ({prov_type.capitalize()}) to detect components...")
            provider = create_ai_provider(config)
            self._worker_ai_vision = AIVisionWorker(
                provider, str(image_path), self._project.project_name, self._project.prompt_config
            )
            self._worker_ai_vision.finished.connect(lambda data: self._on_ai_detection_finished(data, self._project))
            self._worker_ai_vision.failed.connect(lambda msg: self._show_concise_error("AI Detection Failed", "Computer Vision detection failed:", msg))
            self._worker_ai_vision.prompt_ready.connect(lambda p: self.append_ai_log(p, "PROMPT"))
            self._worker_ai_vision.response_ready.connect(lambda r: self.append_ai_log(r, "RESPONSE"))

            if prov_type == "ollama" or (prov_type == "gemini"):
                self._central_tabs.setCurrentIndex(0) 
                self._ai_log_dock.show() 
                self._ai_log_dock.raise_()
                self._worker_ai_vision.start()
        else:
            reason = "The selected model does not appear to support vision." if prov_type == "ollama" else "The provider is not correctly configured."
            QMessageBox.warning(self, "Vision Detection Unavailable", 
                f"{reason}\n\n"
                "Ensure:\n"
                "1. You have selected a vision-capable model (e.g., llava, qwen2-vl).\n"
                "2. Your AI provider is reachable.")

    def _on_ai_detection_finished(self, data: Any, origin_project: Project | None = None) -> None:
        """Processes results from AI vision detection and updates project elements."""
        if not self._project or (origin_project and self._project is not origin_project):
             return

        if not isinstance(data, dict):
            if isinstance(data, list):
                data = {"c": data, "f": [], "tb": [], "a": []}
            else: return

        self._project.components.clear()
        self._project.flows.clear()
        self._project.boundaries.clear()
        self._project.assets.clear()

        comp_list = data.get("c", data.get("components", []))
        flow_list = data.get("f", data.get("flows", []))
        tb_list = data.get("tb", data.get("trust_boundaries", []))

        img_w, img_h = 1920, 1080 
        if self._current_diagram:
            image_path = Path(self._project.project_path) / self._current_diagram.file_path
            pix = QPixmap(str(image_path))
            if not pix.isNull():
                img_w, img_h = pix.width(), pix.height()

        for dtb in tb_list:
            bbox = dtb.get("b", dtb.get("bounding_box"))
            if isinstance(bbox, list) and len(bbox) >= 4:
                final_x = (float(bbox[0]) / 1000.0) * img_w
                final_y = (float(bbox[1]) / 1000.0) * img_h
                final_w = (float(bbox[2]) / 1000.0) * img_w
                final_h = (float(bbox[3]) / 1000.0) * img_h
            else:
                final_x, final_y, final_w, final_h = 10, 10, img_w - 20, img_h - 20
            
            b = TrustBoundary(
                name=str(dtb.get("n", dtb.get("name", "Trust Boundary")) or "Trust Boundary"),
                x=final_x, y=final_y, width=final_w, height=final_h
            )
            self._project.boundaries.append(b)

        from threatpilot.core.domain_models import Asset, AssetType
        asset_list = data.get("a", [])
        for ad in asset_list:
             a_name = str(ad.get("n", ad.get("name", "Unknown Asset")) or "Unknown Asset")
             a_type_raw = str(ad.get("t", ad.get("type", "Informational")) or "Informational")
             a_type = AssetType.PHYSICAL if "phys" in a_type_raw.lower() else AssetType.INFORMATIONAL
             a_desc = str(ad.get("d", ad.get("description", "")) or "")
             self._project.assets.append(Asset(name=a_name, type=a_type, description=a_desc))

        comp_count = 0
        for dc in comp_list:
            bbox = dc.get("b", dc.get("bounding_box"))
            if isinstance(bbox, list) and len(bbox) >= 4:
                final_x = (float(bbox[0]) / 1000.0) * img_w
                final_y = (float(bbox[1]) / 1000.0) * img_h
                final_w = (float(bbox[2]) / 1000.0) * img_w
                final_h = (float(bbox[3]) / 1000.0) * img_h
            else:
                final_x = 50 + (comp_count % 5) * 120
                final_y = 50 + (comp_count // 5) * 120
                final_w = final_h = 100
                comp_count += 1

            comp_type = str(dc.get("t", dc.get("type", "Service")) or "Service")
            name = str(dc.get("n", dc.get("name", "Unknown Item")) or "Unknown Item")

            from threatpilot.ai.response_parser import map_element_type
            et_raw = str(dc.get("et", dc.get("element_type", "Process")) or "Process")
            et = map_element_type(et_raw)

            if not any(a.name == name for a in self._project.assets):
                self._project.assets.append(Asset(name=name, type=AssetType.PHYSICAL, description=f"Identified component ({comp_type})"))

            tb_id = None
            tb_name = dc.get("tb", dc.get("trust_boundary"))
            if tb_name:
                tb_match = next((b for b in self._project.boundaries if b.name == tb_name), None)
                if tb_match: tb_id = tb_match.boundary_id

            if not tb_id:
                comp_rect = QRectF(final_x, final_y, final_w, final_h)
                comp_center = comp_rect.center()
                for b in self._project.boundaries:
                    if QRectF(b.x, b.y, b.width, b.height).contains(comp_center):
                        tb_id = b.boundary_id
                        break

            try:
                self._project.components.append(Component(
                    name=name, type=comp_type, element_type=et,
                    trust_boundary_id=tb_id, x=final_x, y=final_y, width=final_w, height=final_h
                ))
            except Exception as exc:
                from threatpilot.utils.logger import get_logger
                get_logger(__name__).error(f"Failed to create component {name}: {exc}")

        for df in flow_list:
            try:
                bbox = df.get("b", df.get("bounding_box", [0, 0, 10, 10]))
                final_x = (float(bbox[0]) / 1000.0) * img_w
                final_y = (float(bbox[1]) / 1000.0) * img_h

                src_name = str(df.get("s", df.get("source", ""))).strip().lower()
                dst_name = str(df.get("d", df.get("target", ""))).strip().lower()

                def _find_id(sn: str) -> str:
                    if not sn: return ""
                    for c in self._project.components:
                        cn = c.name.strip().lower()
                        if cn == sn or sn in cn or cn in sn: return c.component_id
                    return ""

                self._project.flows.append(Flow(
                    name=str(df.get("n", df.get("name", "Data Flow")) or "Data Flow"),
                    protocol=str(df.get("p", df.get("protocol", "HTTPS")) or "HTTPS"),
                    source_id=_find_id(src_name), target_id=_find_id(dst_name),
                    start_x=final_x, start_y=final_y,
                    end_x=final_x + (float(bbox[2])/1000.0)*img_w,
                    end_y=final_y + (float(bbox[3])/1000.0)*img_h
                ))
            except Exception as exc:
                from threatpilot.utils.logger import get_logger
                get_logger(__name__).error(f"Failed to create flow: {exc}")

        self._refresh_canvas_overlays()
        save_project(self._project)
        self.statusBar().showMessage(f"AI Detection complete: {len(self._project.components)} components found.")

    def _refresh_canvas_overlays(self) -> None:
        """Redraws all detected architectural elements as overlays on the diagram canvas."""
        if not self._project: return
        self._canvas.clear_overlays()

        for b in self._project.boundaries:
            self._canvas.add_trust_boundary(QRectF(b.x, b.y, b.width, b.height), label=b.name, data=b)
        for c in self._project.components:
            self._canvas.add_component_box(QRectF(c.x, c.y, c.width, c.height), label=c.name, data=c)
        for f in self._project.flows:
            if any([f.start_x, f.start_y, f.end_x, f.end_y]):
                self._canvas.add_flow_arrow(QPointF(f.start_x, f.start_y), QPointF(f.end_x, f.end_y), label=f.name, data=f)

    def _on_edit_elements(self) -> None:
        """Opens the management dialog for architectural components."""
        if not self._project: return
        from threatpilot.ui.architecture_dialog import ElementsDialog
        dialog = ElementsDialog(self._project, self._undo_stack, self)
        dialog.project_modified.connect(self._refresh_canvas_overlays)
        dialog.project_modified.connect(self._on_project_modified)
        dialog.exec()
        self._refresh_canvas_overlays()
        save_project(self._project)

    def _on_edit_assets(self) -> None:
        """Opens the management dialog for system assets."""
        if not self._project: return
        from threatpilot.ui.architecture_dialog import AssetsDialog
        dialog = AssetsDialog(self._project, self._undo_stack, self)
        dialog.project_modified.connect(self._on_project_modified)
        dialog.exec()
        save_project(self._project)

    def _on_edit_boundaries(self) -> None:
        """Opens the management dialog for trust boundaries."""
        if not self._project: return
        from threatpilot.ui.architecture_dialog import TrustBoundaryDialog
        dialog = TrustBoundaryDialog(self._project, self._undo_stack, self)
        dialog.project_modified.connect(self._refresh_canvas_overlays)
        dialog.project_modified.connect(self._on_project_modified)
        dialog.exec()
        self._refresh_canvas_overlays()
        save_project(self._project)

    def _on_edit_flows(self) -> None:
        """Opens the management dialog for data flows."""
        if not self._project: return
        from threatpilot.ui.architecture_dialog import DataFlowDialog
        dialog = DataFlowDialog(self._project, self._undo_stack, self)
        dialog.project_modified.connect(self._on_project_modified)
        dialog.exec()
        self._refresh_canvas_overlays()
        save_project(self._project)

    def _on_export_markdown(self) -> None:
        """Exports the current threat model to a Markdown report file."""
        if not self._project: return
        file_path, _ = QFileDialog.getSaveFileName(self, "Export to Markdown", "", "Markdown Files (*.md);;All Files (*)")
        if not file_path: return
        if not file_path.endswith(".md"): file_path += ".md"
        try:
            export_to_markdown(self._project, file_path)
            self.statusBar().showMessage(f"Report exported to {file_path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", f"Markdown export failed:\n{exc}")

    def _on_export_html(self) -> None:
        """Exports the current threat model to an HTML report file."""
        if not self._project: return
        file_path, _ = QFileDialog.getSaveFileName(self, "Export to HTML", "", "HTML Files (*.html *.htm);;All Files (*)")
        if not file_path: return
        if not file_path.endswith(".html") and not file_path.endswith(".htm"): file_path += ".html"
        try:
            export_to_html(self._project, file_path)
            self.statusBar().showMessage(f"Report exported to {file_path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", f"HTML export failed:\n{exc}")

    def _on_export_mitigation_checklist(self) -> None:
        """Exports a consolidated mitigation checklist to a Markdown file."""
        if not self._project or not self._project.threat_register.threats:
            QMessageBox.information(self, "Export", "No threats found to generate a checklist.")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Export Mitigation Checklist", "", "Markdown Files (*.md);;All Files (*)")
        if not file_path: return
        if not file_path.endswith(".md"): file_path += ".md"
        
        try:
            export_mitigation_checklist(self._project, file_path)
            self.statusBar().showMessage(f"Checklist exported to {file_path}")
            QMessageBox.information(self, "Export Success", f"Mitigation checklist saved to {file_path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", f"Checklist export failed:\n{exc}")

    def _on_export_mitigation_checklist_html(self) -> None:
        """Exports a consolidated mitigation checklist to a premium HTML file."""
        if not self._project or not self._project.threat_register.threats:
            QMessageBox.information(self, "Export", "No threats found to generate a checklist.")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Export Mitigation Checklist to HTML", "", "HTML Files (*.html *.htm);;All Files (*)")
        if not file_path: return
        if not file_path.endswith(".html") and not file_path.endswith(".htm"): file_path += ".html"
        
        try:
            export_mitigation_checklist_html(self._project, file_path)
            self.statusBar().showMessage(f"Checklist exported to {file_path}")
            QMessageBox.information(self, "Export Success", f"Mitigation checklist saved to {file_path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", f"Checklist export failed:\n{exc}")

    def _on_export_diagram(self) -> None:
        """Exports the annotated architecture diagram as an image file."""
        scene = self._canvas.scene()
        if not scene or scene.itemsBoundingRect().isEmpty(): return
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Diagram Image", "", "PNG Image (*.png);;JPEG Image (*.jpg);;All Files (*)")
        if not file_path: return
        try:
            export_scene_to_image(scene, file_path)
            self.statusBar().showMessage(f"Diagram exported to {file_path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", f"Diagram export failed:\n{exc}")

    def _on_about(self) -> None:
        """Displays the application information dialog."""
        AboutDialog(self, is_dark=self._is_dark_theme).exec()

    def _on_quick_start(self) -> None:
        """Launches the user quick-start wizard."""
        QuickStartWizard(self, is_dark=self._is_dark_theme).exec()

    def _on_open_logs(self) -> None:
        """Opens the application log directory in the system file explorer."""
        if LOG_DIR.exists(): QDesktopServices.openUrl(QUrl.fromLocalFile(str(LOG_DIR)))
        else: QMessageBox.warning(self, "Logs", "Log directory not found.")

    def _on_undo_redo_happened(self, index: int) -> None:
        """Refreshes the UI after an undo/redo operation, preserving panel state if needed."""
        panel_was_editing = hasattr(self, "_properties_panel") and self._properties_panel._is_panel_editing
        QTimer.singleShot(0, lambda: self._perform_undo_redo_refresh(skip_panel=panel_was_editing))

    def _perform_undo_redo_refresh(self, skip_panel: bool = False) -> None:
        """Executes a full UI refresh after project state changes."""
        self._on_project_modified()
        if not skip_panel and hasattr(self, "_properties_panel"):
            item = self._properties_panel._current_item
            if item: self._properties_panel.set_item(item)
        if hasattr(self, "_threat_panel"): self._threat_panel.refresh()
        if hasattr(self, "_stride_threat_ledger"): self._stride_threat_ledger.refresh()
        if hasattr(self, "_linddun_threat_ledger"): self._linddun_threat_ledger.refresh()
        if hasattr(self, "_risk_assessment_panel"): self._risk_assessment_panel.refresh()
        if hasattr(self, "_vulnerability_panel"): self._vulnerability_panel.refresh()

    def append_ai_log(self, text: str, category: str = "INFO") -> None:
        """Appends a timestamped entry to the AI Activity Log dock."""
        time_str = datetime.now().strftime("%H:%M:%S")
        is_dark = getattr(self, "_is_dark_theme", True)
        color = ("#58a6ff" if is_dark else "#0969da") if "PROMPT" in category else ("#7ee787" if is_dark else "#1a7f37") if "RESPONSE" in category else ("#8b949e" if is_dark else "#57606a")
        time_color = "#484f58" if is_dark else "#8b949e"
        
        entry = f"<span style='color: {time_color};'>[{time_str}]</span> <b style='color: {color};'>{category}</b>: {sanitize_text(text)}<br>"
        self._ai_log_view.append(entry)
        self._ai_log_view.verticalScrollBar().setValue(self._ai_log_view.verticalScrollBar().maximum())
