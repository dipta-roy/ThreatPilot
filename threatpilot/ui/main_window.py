"""Main application window for ThreatPilot.

Provides the primary PySide6 QMainWindow with:
- Left dock:   Project Explorer
- Center:      Diagram Canvas
- Right dock:  Threat Panel
- Bottom dock: Properties Panel
- Menu bar:    File | Edit | AI | View | Export
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QAction, QKeySequence, QFont, QPixmap, QImage
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
    QVBoxLayout,
    QWidget,
)

from threatpilot.core.diagram_model import Diagram
from threatpilot.core.threat_model import Threat
from threatpilot.core.project_manager import (
    Project,
    create_project,
    load_project,
    save_project,
)
from threatpilot.detection.image_loader import import_diagram_file
from threatpilot.ui.diagram_canvas import DiagramCanvas
from threatpilot.ui.project_explorer import ProjectExplorer
from threatpilot.ui.ai_settings_dialog import AISettingsDialog
from threatpilot.ui.prompt_settings_dialog import PromptSettingsDialog
from threatpilot.ui.properties_panel import PropertiesPanel
from threatpilot.ui.threat_panel import ThreatPanel
from threatpilot.export.excel_exporter import export_to_excel
from threatpilot.export.markdown_exporter import export_to_markdown
from threatpilot.export.diagram_exporter import export_scene_to_image
from threatpilot.ai.factory import create_ai_provider
from threatpilot.ai.prompt_builder import PromptBuilder
from threatpilot.ai.analyzer import ThreatAnalyzer
from threatpilot.ai.response_parser import extract_json
from threatpilot.core.dfd_converter import convert_to_dfd
from threatpilot.core.dfd_converter import convert_to_dfd
from threatpilot.core.domain_models import Component, Flow, TrustBoundary
from threatpilot.ui.architecture_dialog import ArchitectureDialog
from threatpilot.ui.risk_matrix_dialog import RiskMatrixDialog
from PySide6.QtWidgets import QDialog
from PySide6.QtCore import QThread, Signal, QRectF, QPointF
import asyncio
import json
import re


class AnalysisWorker(QThread):
    """Background worker for running AI analysis without blocking the UI.
    
    Signals:
        finished: Emitted when analysis completes successfully.
        failed: Emitted when an error occurs.
    """
    finished = Signal(object)  # ThreatRegister
    failed = Signal(str)      # Error message
    prompt_ready = Signal(str)
    response_ready = Signal(str)

    def __init__(self, provider, prompt_config, dfd, system_name, parent=None):
        super().__init__(parent)
        self.provider = provider
        self.prompt_config = prompt_config
        self.dfd = dfd
        self.system_name = system_name

    def run(self):
        """Execute the async analysis within a new event loop."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            analyzer = ThreatAnalyzer(self.provider, self.prompt_config)
            
            # Capture the prompt for logging
            system_p = analyzer.builder.build_system_prompt()
            user_p = analyzer.builder.build_user_prompt(self.dfd, self.system_name)
            self.prompt_ready.emit(f"SYSTEM: {system_p}\n\nUSER: {user_p}")

            register, raw_resp, usage = loop.run_until_complete(
                analyzer.analyze(self.dfd, self.system_name)
            )
            
            # Log the raw response and usage
            self.response_ready.emit(raw_resp)
            if usage:
                u = usage.get("usage", usage)
                self.response_ready.emit(f"METADATA: Tokens [In: {u.get('prompt_tokens', u.get('promptTokenCount', 0))} | Out: {u.get('completion_tokens', u.get('candidatesTokenCount', 0))} | Total: {u.get('total_tokens', u.get('totalTokenCount', 0))}]")
                
            self.finished.emit(register)
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            loop.close()





class AIVisionWorker(QThread):
    """Background worker for multimodal AI architecture detection.

    Signals:
        finished: Emitted when AI vision detection completes.
        failed: Emitted when an error occurs.
    """
    finished = Signal(dict)
    failed = Signal(str)
    prompt_ready = Signal(str)
    response_ready = Signal(str)

    def __init__(self, provider, image_path, system_name, prompt_config, parent=None):
        super().__init__(parent)
        self.provider = provider
        self.image_path = image_path
        self.system_name = system_name
        self.prompt_config = prompt_config

    def run(self):
        """Execute multimodal AI vision logic within a new event loop."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            with open(self.image_path, "rb") as f:
                image_bytes = f.read()

            builder = PromptBuilder(self.prompt_config)
            prompt = builder.build_vision_detection_prompt(self.system_name)
            self.prompt_ready.emit(prompt)

            async def run_vision():
                return await self.provider.vision_complete(prompt, image_bytes)

            response_text, meta = loop.run_until_complete(run_vision())
            
            usage = meta.get("usage", {})
            self.response_ready.emit(response_text)
            if usage:
                self.response_ready.emit(f"METADATA: Tokens [In: {usage.get('promptTokenCount', 0)} | Out: {usage.get('candidatesTokenCount', 0)} | Total: {usage.get('total_token_count', usage.get('totalTokenCount', 0))}]")
            
            data = extract_json(response_text)
            if data:
                self.finished.emit(data)
            else:
                # Try a last-ditch effort for very messy responses:
                # Look for ANYTHING that looks like a list or dict if the standard extract failed
                self.failed.emit("Failed to parse AI response. Check the Logs tab for details on the raw output structure.")
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            loop.close()


class _PlaceholderPanel(QWidget):
    """A temporary placeholder widget used for dock panels.

    Each panel displays a centred label indicating its purpose.
    These will be replaced by full implementations in later requirements.
    """

    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        label = QLabel(title)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont()
        font.setPointSize(11)
        font.setBold(True)
        label.setFont(font)
        label.setStyleSheet("color: #8899aa;")
        layout.addWidget(label)


class MainWindow(QMainWindow):
    """ThreatPilot main application window.

    Layout
    ------
    - **Left dock** – Project Explorer (tree of project artefacts).
    - **Centre** – Diagram Canvas (``QGraphicsView`` for the architecture diagram).
    - **Right dock** – Threat Panel (generated threats and risk data).
    - **Bottom dock** – Properties Panel (editable properties of selected element).

    Menu bar
    --------
    File | Edit | AI | View | Export
    """

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        # Runtime state
        self._project: Project | None = None
        self._current_diagram: Diagram | None = None

        self._setup_window()
        self._setup_central_widget()
        self._setup_docks()
        self._setup_menu_bar()
        self._setup_toolbar()
        self._setup_status_bar()
        self._connect_actions()
        
        # Load and apply global modern dark-theme stylesheet
        self._load_stylesheet()
        
        self._load_recent_project()

    def _load_stylesheet(self) -> None:
        """Apply a professional dark theme across the entire application."""
        style_path = Path("f:/ThreatPilot/threatpilot/resources/style.qss")
        if style_path.exists():
            with open(style_path, "r") as f:
                self.setStyleSheet(f.read())

    def _load_recent_project(self) -> None:
        """Attempt to automatically reload the last opened project on startup."""
        recent_file = Path("f:/ThreatPilot/.threatpilot_recent")
        if recent_file.exists():
            with open(recent_file, "r") as f:
                path = f.read().strip()
                if path and Path(path).exists():
                    try:
                        self._open_project_from_path(path)
                    except Exception:
                        pass # Silently fail and boot empty if the recent project was deleted or corrupted
    # ------------------------------------------------------------------
    # Window chrome
    # ------------------------------------------------------------------

    def _setup_window(self) -> None:
        """Configure the top-level window properties."""
        self._update_title()
        self.resize(1400, 900)
        self.setMinimumSize(QSize(1000, 650))
        self.setDockNestingEnabled(True)

    def _update_title(self) -> None:
        """Dynamically update window title based on project state."""
        title = "ThreatPilot"
        if self._project:
            title += f" - {self._project.project_name}"
            if self._current_diagram:
                title += f" [{self._current_diagram.original_name}]"
        self.setWindowTitle(title)

    # ------------------------------------------------------------------
    # Central widget – Diagram Canvas
    # ------------------------------------------------------------------

    def _setup_central_widget(self) -> None:
        """Initialise central workspace with tabbed navigation for diagrams and reports."""
        from PySide6.QtWidgets import QTabWidget
        self._central_tabs = QTabWidget()
        self._central_tabs.setDocumentMode(True)  # cleaner tab look
        
        # Tab 1: Diagram Workspace
        self._canvas = DiagramCanvas(self)
        self._central_tabs.addTab(self._canvas, "Infrastructure Blueprint")
        
        # Tab 2: Full Threat Ledger
        from threatpilot.ui.threat_panel import ThreatPanel
        self._full_threat_ledger = ThreatPanel(self)
        self._central_tabs.addTab(self._full_threat_ledger, "System Threat Register")
        
        self.setCentralWidget(self._central_tabs)

    # ------------------------------------------------------------------
    # Dock widgets
    # ------------------------------------------------------------------

    def _setup_docks(self) -> None:
        """Create and position the three dock panels."""
        # --- Right Stack 1: Properties Panel ---
        self._properties_panel = PropertiesPanel(self)
        self._properties_panel.property_changed.connect(self._on_save_project)
        
        def _sync_labels(obj):
            if isinstance(obj, Threat):
                self._threat_panel.refresh()
                self._full_threat_ledger.refresh()
        self._properties_panel.property_changed.connect(_sync_labels)
        self._properties_panel_dock = self._create_dock(
            "Attributes",
            self._properties_panel,
            Qt.DockWidgetArea.RightDockWidgetArea,
            min_width=320,
        )

        # --- Left: Project Explorer ---
        self._project_explorer = ProjectExplorer(self)
        self._project_explorer.diagram_activated.connect(self._on_diagram_activated)
        self._project_explorer.diagram_deleted.connect(self._on_diagram_deleted)
        self._project_explorer.tool_activated.connect(self._on_explorer_tool_activated)
        self._project_explorer.project_modified.connect(self._on_save_project)
        self._project_explorer_dock = self._create_dock(
            "Project Map",
            self._project_explorer,
            Qt.DockWidgetArea.LeftDockWidgetArea,
            min_width=220,
        )

        # --- Right Stack 2: Threat Entry List (Compact) ---
        self._threat_panel = ThreatPanel(self)
        self._threat_panel.threat_selected.connect(self._properties_panel.set_item)
        self._threat_panel.threat_added.connect(self._on_save_project)
        self._threat_panel.threat_removed.connect(self._on_save_project)
        self._threat_panel.run_analysis_requested.connect(self._on_run_analysis)
        self._threat_panel_dock = self._create_dock(
            "Threat Ledger",
            self._threat_panel,
            Qt.DockWidgetArea.RightDockWidgetArea,
            min_width=280,
        )
        self._threat_panel_dock.setVisible(False)
        
        # Synchronise the full ledger in central view too
        self._threat_panel.threat_selected.connect(self._properties_panel.set_item)
        self._full_threat_ledger.threat_selected.connect(self._properties_panel.set_item)

        self._full_threat_ledger.run_analysis_requested.connect(self._on_run_analysis)
        self._full_threat_ledger.threat_added.connect(self._on_save_project)
        self._full_threat_ledger.threat_removed.connect(self._on_save_project)

    def _create_dock(
        self,
        title: str,
        widget: QWidget,
        area: Qt.DockWidgetArea,
        *,
        min_width: int = 0,
        min_height: int = 0,
    ) -> QDockWidget:
        """Create a ``QDockWidget``, attach *widget*, and dock it.

        Args:
            title: Dock window title.
            widget: The widget to embed inside the dock.
            area: Dock area to attach the widget to.
            min_width: Optional minimum width.
            min_height: Optional minimum height.

        Returns:
            The newly created ``QDockWidget``.
        """
        dock = QDockWidget(title, self)
        dock.setWidget(widget)
        dock.setAllowedAreas(
            Qt.DockWidgetArea.LeftDockWidgetArea
            | Qt.DockWidgetArea.RightDockWidgetArea
            | Qt.DockWidgetArea.BottomDockWidgetArea
        )
        if min_width:
            widget.setMinimumWidth(min_width)
        if min_height:
            widget.setMinimumHeight(min_height)
        self.addDockWidget(area, dock)
        return dock

    # ------------------------------------------------------------------
    # Menu bar
    # ------------------------------------------------------------------

    def _setup_menu_bar(self) -> None:
        """Build the application menu bar with File, Edit, AI, View, Export."""
        menu_bar = self.menuBar()

        # --- File menu ---
        file_menu = menu_bar.addMenu("&File")

        self._action_new_project = QAction("&New Project...", self)
        self._action_new_project.setShortcut(QKeySequence.StandardKey.New)
        file_menu.addAction(self._action_new_project)

        self._action_open_project = QAction("&Open Project...", self)
        self._action_open_project.setShortcut(QKeySequence.StandardKey.Open)
        file_menu.addAction(self._action_open_project)

        self._action_save_project = QAction("&Save Project", self)
        self._action_save_project.setShortcut(QKeySequence.StandardKey.Save)
        file_menu.addAction(self._action_save_project)

        file_menu.addSeparator()

        self._action_import_diagram = QAction("&Import Diagram...", self)
        self._action_import_diagram.setShortcut(QKeySequence("Ctrl+I"))
        file_menu.addAction(self._action_import_diagram)

        file_menu.addSeparator()

        self._action_exit = QAction("E&xit", self)
        self._action_exit.setShortcut(QKeySequence("Alt+F4"))
        self._action_exit.triggered.connect(self.close)
        file_menu.addAction(self._action_exit)

        # --- Architecture menu (formerly Edit) ---
        arch_menu = menu_bar.addMenu("&Architecture")

        self._action_detect_objects = QAction("&Entity Recognition (Capture)", self)
        self._action_detect_objects.setShortcut(QKeySequence("Ctrl+D"))
        arch_menu.addAction(self._action_detect_objects)

        self._action_edit_components = QAction("&Component Inventory (Edit)...", self)
        self._action_edit_components.setShortcut(QKeySequence("Ctrl+E"))
        arch_menu.addAction(self._action_edit_components)

        arch_menu.addSeparator()

        self._action_delete = QAction("&Remove Selected Entity", self)
        self._action_delete.setShortcut(QKeySequence.StandardKey.Delete)
        arch_menu.addAction(self._action_delete)

        # --- Intelligence menu (formerly AI) ---
        intel_menu = menu_bar.addMenu("&Intelligence")

        self._action_run_analysis = QAction("&Run Security Analysis", self)
        self._action_run_analysis.setShortcut(QKeySequence("Ctrl+R"))
        intel_menu.addAction(self._action_run_analysis)

        intel_menu.addSeparator()

        self._action_ai_settings = QAction("&Manage AI Providers...", self)
        intel_menu.addAction(self._action_ai_settings)

        self._action_prompt_config = QAction("&Business Context & Policy...", self)
        intel_menu.addAction(self._action_prompt_config)

        # --- View menu ---
        view_menu = menu_bar.addMenu("&View")
        
        # Workspace layout toggles
        self._action_toggle_explorer = self._project_explorer_dock.toggleViewAction()
        self._action_toggle_explorer.setText("Project &Map")
        view_menu.addAction(self._action_toggle_explorer)

        self._action_toggle_threats = self._threat_panel_dock.toggleViewAction()
        self._action_toggle_threats.setText("&Threat Ledger")
        view_menu.addAction(self._action_toggle_threats)

        self._action_toggle_properties = self._properties_panel_dock.toggleViewAction()
        self._action_toggle_properties.setText("&Element Attributes")
        view_menu.addAction(self._action_toggle_properties)

        view_menu.addSeparator()

        self._action_fit_diagram = QAction("&Center & Fit Diagram", self)
        self._action_fit_diagram.setShortcut(QKeySequence("Ctrl+0"))
        self._action_fit_diagram.triggered.connect(self._canvas.fit_to_screen)
        view_menu.addAction(self._action_fit_diagram)

        # --- Reporting menu (formerly Export) ---
        report_menu = menu_bar.addMenu("&Reporting")

        self._action_export_excel = QAction("Generate &Risk Matrix (Excel)...", self)
        report_menu.addAction(self._action_export_excel)

        self._action_export_markdown = QAction("Generate &Security Report (MD)...", self)
        report_menu.addAction(self._action_export_markdown)

        report_menu.addSeparator()

        self._action_export_diagram = QAction("Export &Annotated Diagram (Image)...", self)
        report_menu.addAction(self._action_export_diagram)

        # --- Help menu ---
        help_menu = menu_bar.addMenu("&Help")
        self._action_about = QAction("&About ThreatPilot...", self)
        help_menu.addAction(self._action_about)

        # Connect actions
        self._action_about.triggered.connect(self._on_about)
        self._action_detect_objects.triggered.connect(self._on_detect_objects)
        self._action_edit_components.triggered.connect(self._on_edit_components)
        self._action_run_analysis.triggered.connect(self._on_run_analysis)
        self._action_ai_settings.triggered.connect(self._on_ai_settings)
        self._action_prompt_config.triggered.connect(self._on_prompt_config)
        self._action_export_excel.triggered.connect(self._on_export_excel)
        self._action_export_markdown.triggered.connect(self._on_export_markdown)
        self._action_export_diagram.triggered.connect(self._on_export_diagram)

    # ------------------------------------------------------------------
    # Toolbar
    # ------------------------------------------------------------------

    def _setup_toolbar(self) -> None:
        """Create a clean, result-oriented master toolbar."""
        toolbar = QToolBar("Performance Controls", self)
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(24, 24))
        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.addToolBar(toolbar)

        # 1. Project Management
        toolbar.addAction(self._action_new_project)
        toolbar.addAction(self._action_open_project)
        
        toolbar.addSeparator()

        # 2. Capture & Detection (The "Build" Phase)
        toolbar.addAction(self._action_import_diagram)
        
        det_act = toolbar.addAction("Extract Security Entities")
        det_act.triggered.connect(self._on_detect_objects)
        
        edit_act = toolbar.addAction("Architecture Inventory")
        edit_act.triggered.connect(self._on_edit_components)
        
        toolbar.addSeparator()

        # 3. Security Analysis (The "Analyze" Phase)
        run_act = toolbar.addAction("Analyze Architecture")
        run_act.setObjectName("btn_run_analysis")
        run_act.triggered.connect(self._on_run_analysis)
        
        toolbar.addSeparator()

        # 4. Global Intelligence settings
        toolbar.addAction(self._action_ai_settings)

    # ------------------------------------------------------------------
    # Status bar
    # ------------------------------------------------------------------

    def _setup_status_bar(self) -> None:
        """Create and configure the status bar."""
        status_bar = QStatusBar(self)
        self.setStatusBar(status_bar)
        status_bar.showMessage("Ready")

    # ------------------------------------------------------------------
    # Signal / slot wiring
    # ------------------------------------------------------------------

    def _connect_actions(self) -> None:
        """Connect menu / toolbar actions to their handler slots."""
        self._action_new_project.triggered.connect(self._on_new_project)
        self._action_open_project.triggered.connect(self._on_open_project)
        self._action_save_project.triggered.connect(self._on_save_project)
        self._action_import_diagram.triggered.connect(self._on_import_diagram)
        self._action_fit_diagram.triggered.connect(self._on_fit_diagram)
        self._action_ai_settings.triggered.connect(self._on_ai_settings)
        self._action_prompt_config.triggered.connect(self._on_prompt_config)
        self._action_run_analysis.triggered.connect(self._on_run_analysis)
        self._action_export_excel.triggered.connect(self._on_export_excel)
        self._action_export_markdown.triggered.connect(self._on_export_markdown)
        self._action_export_diagram.triggered.connect(self._on_export_diagram)

    # ------------------------------------------------------------------
    # Slots – File actions
    # ------------------------------------------------------------------

    def _on_new_project(self) -> None:
        """Create a new project via dialog."""
        name, ok = QInputDialog.getText(
            self, "New Project", "Project name:"
        )
        if not ok or not name.strip():
            return

        directory = QFileDialog.getExistingDirectory(
            self, "Select project parent directory"
        )
        if not directory:
            return

        try:
            self._project = create_project(name.strip(), parent_dir=directory)
            self._project_explorer.set_project(self._project)
            self._threat_panel.set_register(self._project.threat_register)
            self._full_threat_ledger.set_register(self._project.threat_register)
            self._current_diagram = None
            self._canvas.clear_diagram()
            self._update_title()
            self.statusBar().showMessage(
                f"Project '{self._project.project_name}' created."
            )
            
            # Save to recent
            recent_file = Path("f:/ThreatPilot/.threatpilot_recent")
            with open(recent_file, "w") as f:
                f.write(str(self._project.project_path))
                
        except OSError as exc:
            QMessageBox.critical(self, "Error", f"Could not create project:\n{exc}")

    def _on_open_project(self) -> None:
        """Open an existing project directory."""
        directory = QFileDialog.getExistingDirectory(
            self, "Open ThreatPilot project"
        )
        if not directory:
            return

        try:
            self._open_project_from_path(directory)
        except (FileNotFoundError, ValueError) as exc:
            QMessageBox.critical(self, "Error", f"Could not open project:\n{exc}")

    def _open_project_from_path(self, directory: str) -> None:
        """Helper to load a project directly from a directory path."""
        self._project = load_project(directory)
        self._project_explorer.set_project(self._project)
        self._threat_panel.set_register(self._project.threat_register)
        self._full_threat_ledger.set_register(self._project.threat_register)
        self._current_diagram = None
        self._canvas.clear_diagram()
        self._update_title()

        # If the project has diagrams, display the first one by default
        if self._project.diagrams:
            self._on_diagram_activated(self._project.diagrams[0])

        self.statusBar().showMessage(
            f"Project '{self._project.project_name}' loaded."
        )
        
        # Save to recent
        recent_file = Path("f:/ThreatPilot/.threatpilot_recent")
        with open(recent_file, "w") as f:
            f.write(str(directory))

    def _on_save_project(self) -> None:
        """Save the current project to disk."""
        if self._project is None:
            QMessageBox.information(self, "Save", "No project is open.")
            return

        try:
            save_project(self._project)
            self.statusBar().showMessage("Project saved.")
        except (ValueError, OSError) as exc:
            QMessageBox.critical(self, "Error", f"Could not save project:\n{exc}")

    def _on_diagram_deleted(self, diagram: Diagram) -> None:
        """Handle the physical removal of a diagram and cleanup the canvas."""
        if self._current_diagram == diagram:
            self._current_diagram = None
            self._canvas.clear_diagram()
            self._update_title()
            self.statusBar().showMessage(f"Deleted diagram: {diagram.original_name}")

    # ------------------------------------------------------------------
    # Slots – Diagram import
    # ------------------------------------------------------------------

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
            
            # Load pixmap and display via DiagramCanvas (bypassing internal Qt cache)
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

        self._central_tabs.setCurrentIndex(0)  # Switch to Diagram tab
        self._current_diagram = diagram
        image_path = Path(self._project.project_path) / diagram.file_path
        
        # Load via QImage buffer to bypass QPixmap internal path caching
        image = QImage(str(image_path))
        pixmap = QPixmap.fromImage(image)
        if not pixmap.isNull():
            self._canvas.set_diagram_pixmap(pixmap)
            self._refresh_canvas_overlays()
        
        self.statusBar().showMessage(f"Showing diagram: {diagram.original_name}")

    # ------------------------------------------------------------------
    # Slots – AI actions
    # ------------------------------------------------------------------

    def _on_ai_settings(self) -> None:
        """Edit the project's AI provider configuration."""
        if not self._project:
            QMessageBox.information(self, "AI Settings", "Create or open a project first.")
            return
        dialog = AISettingsDialog(self._project.ai_config, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._project.ai_config = dialog.get_config()
            save_project(self._project)
            self.statusBar().showMessage("AI settings updated.")

    def _on_prompt_config(self) -> None:
        """Edit the prompt generation parameters."""
        if not self._project:
            QMessageBox.information(self, "Prompt Config", "Create or open a project first.")
            return

        dialog = PromptSettingsDialog(self._project.prompt_config, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._project.prompt_config = dialog.get_config()
            save_project(self._project)
            self.statusBar().showMessage("Prompt configuration updated.")

    def _on_explorer_tool_activated(self, action: str) -> None:
        """Handle selection of non-diagram tools in the project explorer."""
        if not self._project:
            return

        if action == "action_ai_settings":
            self._on_ai_settings()
        elif action == "action_prompt_config":
            self._on_prompt_config()
        elif action == "action_edit_components":
            self._on_edit_components()
        elif action == "action_view_threats":
            self._central_tabs.setCurrentIndex(1)  # Focus the central threat register
            self._full_threat_ledger.clear_filter()
            self._threat_panel_dock.show()         # Also show the side summary
            self._threat_panel_dock.raise_()
        elif action == "action_view_risk_matrix" and self._project:
            from threatpilot.ui.risk_matrix_dialog import RiskMatrixDialog
            dialog = RiskMatrixDialog(self._project.threat_register.threats, self)
            dialog.exec()

    def _on_run_analysis(self) -> None:
        """Trigger AI-driven threat analysis using the configured provider."""
        if not self._project:
            return

        # 1. Convert Current Architectural State to DFD
        dfd = convert_to_dfd(self._project.components, self._project.flows)
        if not dfd.nodes:
            QMessageBox.warning(self, "Analysis", "No components detected to analyze. Please add or detect components first.")
            return

        # 2. Create AI Provider via Factory
        try:
            provider = create_ai_provider(self._project.ai_config)
        except Exception as exc:
            QMessageBox.critical(self, "AI Error", f"Could not create AI provider:\n{exc}")
            return

        # 3. Launch Background Worker
        self.statusBar().showMessage(f"Running AI Analysis via {self._project.ai_config.provider_type}...")
        self._threat_panel._btn_run.setEnabled(False) # Visual feedback

        self._worker = AnalysisWorker(
            provider, 
            self._project.prompt_config, 
            dfd, 
            self._project.project_name
        )
        self._worker.finished.connect(self._on_analysis_finished)
        self._worker.failed.connect(self._on_analysis_failed)
        self._worker.prompt_ready.connect(lambda p: self._properties_panel.append_log(p, "PROMPT"))
        self._worker.response_ready.connect(lambda r: self._properties_panel.append_log(r, "RESPONSE"))
        
        self._properties_panel._tabs.setCurrentIndex(1) # Switch to Logs
        self._worker.start()

    def _on_analysis_finished(self, new_register) -> None:
        """Merge new threats into the project and refresh UI."""
        self._threat_panel._btn_run.setEnabled(True)
        self.statusBar().showMessage("Analysis complete.")
        
        # Merge threats (simple append or replacement for now)
        for t in new_register.threats:
            self._project.threat_register.add_threat(t)
            
        self._threat_panel.refresh()
        self._full_threat_ledger.refresh()
        save_project(self._project)
        QMessageBox.information(self, "Analysis", f"Analysis complete! {len(new_register.threats)} new threats identified.")

    def _on_analysis_failed(self, error_msg: str) -> None:
        """Handle analysis failure with concise error reporting."""
        self._threat_panel._btn_run.setEnabled(True)
        self.statusBar().showMessage("Analysis failed.")
        self._show_concise_error("Analysis Error", "The AI analysis failed:", error_msg)

    def _show_concise_error(self, title: str, prefix: str, error_msg: str) -> None:
        """Sanitize and display a concise version of technical AI/API errors."""
        # Clean up technical noise (SDK headers, JSON details, stack traces)
        clean_msg = str(error_msg).split("\n")[0]
        
        # Strip common redundant prefix patterns
        clean_msg = clean_msg.replace("google.api_core.exceptions.", "")
        
        if len(clean_msg) > 220:
            clean_msg = clean_msg[:217] + "..."
            
        QMessageBox.critical(self, title, f"{prefix}\n\n{clean_msg}")


    # ------------------------------------------------------------------
    # Slots – View actions
    # ------------------------------------------------------------------

    def _on_fit_diagram(self) -> None:
        """Fit the diagram image to the canvas viewport."""
        self._canvas.fit_to_screen()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _update_title(self) -> None:
        """Update the window title to reflect the current project."""
        if self._project:
            self.setWindowTitle(f"ThreatPilot - {self._project.project_name}")
        else:
            self.setWindowTitle("ThreatPilot")

    # ------------------------------------------------------------------
    # Public accessors (for future requirement modules)
    # ------------------------------------------------------------------

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
    def threat_panel_dock(self) -> QDockWidget:
        """Return the Threat Panel dock widget."""
        return self._threat_panel_dock

    @property
    def properties_panel_dock(self) -> QDockWidget:
        """Return the Properties Panel dock widget."""
        return self._properties_panel_dock

    # ------------------------------------------------------------------
    # Slots – Export actions
    # ------------------------------------------------------------------

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
            export_to_excel(self._project.threat_register, file_path)
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
        
        # Determine if we can use AI Vision (Gemini / Claude)
        prov_type = self._project.ai_config.provider_type.lower()
        if prov_type in ["gemini", "claude"] and self._project.ai_config.api_key:
            self.statusBar().showMessage(f"Using AI Vision ({prov_type.capitalize()}) to detect components...")
            provider = create_ai_provider(self._project.ai_config)
            self._worker_ai_vision = AIVisionWorker(
                provider, str(image_path), self._project.project_name, self._project.prompt_config
            )
            self._worker_ai_vision.finished.connect(self._on_ai_detection_finished)
            self._worker_ai_vision.failed.connect(lambda msg: self._show_concise_error("AI Detection Failed", "Computer Vision detection failed:", msg))
            self._worker_ai_vision.prompt_ready.connect(lambda p: self._properties_panel.append_log(p, "PROMPT"))
            self._worker_ai_vision.response_ready.connect(lambda r: self._properties_panel.append_log(r, "RESPONSE"))

            self._properties_panel._tabs.setCurrentIndex(1) # Switch to Logs
            self._worker_ai_vision.start()
        else:
            QMessageBox.warning(self, "Detection", "Traditional Computer Vision detection is disabled as OpenCV has been removed. Please configure an AI Vision provider in AI Settings.")

    def _on_ai_detection_finished(self, data: dict) -> None:
        """Handle results from multimodal AI vision detection."""
        if not self._project:
             return

        self._project.components.clear()
        self._project.flows.clear()
        self._project.boundaries.clear()

        # Handle if AI returned a direct list instead of a dict with a 'components' key
        if isinstance(data, list):
            comp_list = data
        else:
            comp_list = data.get("components", []) or data.get("elements", [])
        
        # Get actual image dimensions to scale from 0-1000 normalized range
        img_w, img_h = 1920, 1080 # Default
        if self._current_diagram:
             image_path = Path(self._project.project_path) / self._current_diagram.file_path
             pix = QPixmap(str(image_path))
             if not pix.isNull():
                 img_w, img_h = pix.width(), pix.height()

        for dc in comp_list:
            bbox = dc.get("bounding_box", [0, 0, 100, 100])
            # Scale coordinates from 0-1000 back to pixels
            final_x = (bbox[0] / 1000.0) * img_w
            final_y = (bbox[1] / 1000.0) * img_h
            final_w = (bbox[2] / 1000.0) * img_w
            final_h = (bbox[3] / 1000.0) * img_h

            obj_type = str(dc.get("type", "Service")).lower()
            name = dc.get("name", "Unknown AI Item")

            if "flow" in obj_type:
                f = Flow(
                    name=name,
                    start_x=final_x, start_y=final_y,
                    end_x=final_x + final_w, end_y=final_y + final_h # Approximated vector
                )
                self._project.flows.append(f)
            elif "boundary" in obj_type or "trust" in obj_type:
                 b = TrustBoundary(
                     name=name,
                     x=final_x, y=final_y, width=final_w, height=final_h
                 )
                 self._project.boundaries.append(b)
            else:
                c = Component(
                    name=name,
                    type=dc.get("type", "Service"),
                    x=final_x, y=final_y, width=final_w, height=final_h
                )
                self._project.components.append(c)

        self._refresh_canvas_overlays()
        save_project(self._project)
        self.statusBar().showMessage(f"AI Detection complete: {len(self._project.components)} components found.")
        QMessageBox.information(self, "AI Vision", f"AI Vision successfully detected {len(self._project.components)} components.")



    def _refresh_canvas_overlays(self) -> None:
        """Clear and redraw all detected objects as visual overlays on the image."""
        if not self._project:
            return

        self._canvas.clear_overlays()

        # Draw boundaries
        for b in self._project.boundaries:
            rect = QRectF(b.x, b.y, b.width, b.height)
            self._canvas.add_trust_boundary(rect, label=b.name, data=b)

        # Draw components
        for c in self._project.components:
            rect = QRectF(c.x, c.y, c.width, c.height)
            self._canvas.add_component_box(rect, label=c.name, data=c)

        # Draw flow vectors
        for f in self._project.flows:
            if f.start_x or f.start_y or f.end_x or f.end_y:
                start = QPointF(f.start_x, f.start_y)
                end = QPointF(f.end_x, f.end_y)
                self._canvas.add_flow_arrow(start, end, label=f.name, data=f)

    def _on_edit_components(self) -> None:
        """Open the table dialog to manually edit or drop detected components."""
        if not self._project:
            return
            
        dialog = ArchitectureDialog(self._project, self)
        dialog.exec()
        
        # Reload visual overlays to reflect renamed/deleted tables
        self._refresh_canvas_overlays()
        save_project(self._project)

    def _on_export_markdown(self) -> None:
        """Export the current threat model as a detailed Markdown report."""
        if not self._project:
            QMessageBox.information(
                self, "Export", "Open a project first."
            )
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export to Markdown", "", "Markdown Files (*.md);;All Files (*)"
        )
        if not file_path:
            return

        if not file_path.endswith(".md"):
            file_path += ".md"

        try:
            export_to_markdown(self._project, file_path)
            self.statusBar().showMessage(f"Markdown report exported to {file_path}")
            QMessageBox.information(self, "Export Success", f"File saved to {file_path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", f"Could not export to Markdown:\n{exc}")


    def _on_export_diagram(self) -> None:
        """Export the current annotated diagram with all overlays as an image."""
        scene = self._canvas.scene()
        if not scene or scene.itemsBoundingRect().isEmpty():
            QMessageBox.information(
                self, "Export", "No diagram loaded to export."
            )
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Diagram Image", "", "PNG Image (*.png);;JPEG Image (*.jpg);;All Files (*)"
        )
        if not file_path:
            return

        try:
            export_scene_to_image(scene, file_path)
            self.statusBar().showMessage(f"Diagram exported to {file_path}")
            QMessageBox.information(self, "Export Success", f"Diagram saved to {file_path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", f"Could not export diagram:\n{exc}")

    def _on_about(self) -> None:
        """Show the About dialog with project metadata."""
        QMessageBox.about(
            self, 
            "About ThreatPilot",
            "<h3>ThreatPilot</h3>"
            "<p><b>Version:</b> 0.1 Beta</p>"
            "<p><b>Author:</b> Dipta Roy</p>"
            "<p>ThreatPilot is an AI-powered Threat Modeling platform that uses computer vision "
            "and Large Language Models to automatically identify security risks from architectural diagrams.</p>"
            "<p>&copy; 2026 Dipta Roy. All rights reserved.</p>"
        )


