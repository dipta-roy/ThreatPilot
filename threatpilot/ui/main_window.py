"""Main application window for ThreatPilot.

Provides the primary PySide6 QMainWindow with:
- Left dock:   Project Explorer
- Center:      Diagram Canvas
- Right dock:  Threat Panel
- Bottom dock: Properties Panel
- Menu bar:    File | Edit | AI | View | Export
"""

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
from threatpilot.ui.about_dialog import AboutDialog
from threatpilot.ui.quick_start_wizard import QuickStartWizard
from threatpilot.export.excel_exporter import export_to_excel
from threatpilot.export.markdown_exporter import export_to_markdown
from threatpilot.export.diagram_exporter import export_scene_to_image
from threatpilot.ai.factory import create_ai_provider
from threatpilot.ai.prompt_builder import PromptBuilder
from threatpilot.ai.analyzer import ThreatAnalyzer
from threatpilot.ai.response_parser import extract_json
from threatpilot.config.ai_config import AIConfig
from threatpilot.utils.logger import setup_logging, LOG_DIR, sanitize_text

class AnalysisWorker(QThread):
    """Background worker for running AI analysis without blocking the UI.
    
    Signals:
        finished: Emitted when analysis completes successfully.
        failed: Emitted when an error occurs.
    """
    finished = Signal(object)
    failed = Signal(str)
    partial_result_ready = Signal(object)
    prompt_ready = Signal(str)
    response_ready = Signal(str)
    request_segment_continuation = Signal(int, int)

    def __init__(self, provider, prompt_config, dfd, system_name, parent=None):
        super().__init__(parent)
        self.provider = provider
        self.prompt_config = prompt_config
        self.dfd = dfd
        self.system_name = system_name
        
        import threading
        self._continue_event = threading.Event()
        self._should_continue_result = True

    def continue_analysis(self, should_continue: bool):
        """Called by the UI thread to resume analysis."""
        self._should_continue_result = should_continue
        self._continue_event.set()

    def run(self):
        """Execute the async analysis within a new event loop."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            analyzer = ThreatAnalyzer(self.provider, self.prompt_config)

            async def progress_cb(current, total):
                self._continue_event.clear()
                self.request_segment_continuation.emit(current, total)
                self._continue_event.wait()
                return self._should_continue_result

            register, raw_resp, usage = loop.run_until_complete(
                analyzer.analyze(
                    self.dfd, 
                    self.system_name, 
                    progress_callback=progress_cb,
                    result_callback=lambda partial: self.partial_result_ready.emit(partial)
                )
            )
            
            if "Analysis cancelled by user" in raw_resp:
                self.failed.emit("Analysis cancelled by user.")
                return
                
            system_p = analyzer.builder.build_system_prompt()
            user_p = analyzer.builder.build_user_prompt(self.dfd, self.system_name)
            self.prompt_ready.emit(f"SYSTEM: {system_p}\n\nUSER: {user_p}")
            
            self.response_ready.emit(raw_resp)
            if usage:
                u = usage.get("usage", usage)
                in_t = u.get('promptTokenCount') or u.get('prompt_tokens') or u.get('prompt_eval_count') or 0
                out_t = u.get('candidatesTokenCount') or u.get('completion_tokens') or u.get('eval_count') or 0
                total_t = u.get('totalTokenCount') or u.get('total_tokens') or (in_t + out_t)
                
                finish_reason = usage.get("finish_reason", "SUCCESS")
                meta_log = f"METADATA: Tokens [In: {in_t} | Out: {out_t} | Total: {total_t}] | FinishReason: {finish_reason}"
                self.response_ready.emit(meta_log)
                
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
            
            img = QImage(self.image_path)
            if img.isNull():
                raise FileNotFoundError(f"Selected image file at {self.image_path} could not be loaded.")
            
            if img.width() > 1024 or img.height() > 1024:
                img = img.scaled(1024, 1024, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            
            buffer = QBuffer()
            buffer.open(QIODevice.WriteOnly)
            img.save(buffer, "PNG")
            image_bytes = bytes(buffer.data())

            builder = PromptBuilder(self.prompt_config)
            prompt = builder.build_vision_detection_prompt(self.system_name)
            self.prompt_ready.emit(prompt)

            async def run_vision():
                return await self.provider.vision_complete(prompt, image_bytes)

            response_text, meta = loop.run_until_complete(run_vision())
            
            usage = meta.get("usage", {})
            finish_reason = meta.get("finish_reason", "UNKNOWN")
            
            self.response_ready.emit(response_text)
            log_meta = f"METADATA: Tokens [In: {usage.get('promptTokenCount', 0)} | Out: {usage.get('candidatesTokenCount', 0)} | Total: {usage.get('total_token_count', usage.get('totalTokenCount', 0))}]"
            log_meta += f" | FinishReason: {finish_reason}"
            self.response_ready.emit(log_meta)
            
            data = extract_json(response_text)
            if data:
                self.finished.emit(data)
            else:
                self.failed.emit("Failed to parse AI response. Check the Logs tab for details on the raw output structure.")
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            loop.close()


class ReasoningWorker(QThread):
    """Background worker for deep technical reasoning (XAI)."""
    finished = Signal(str, object)
    failed = Signal(str)

    def __init__(self, provider, prompt_config, threat, analysis_mode, parent=None):
        super().__init__(parent)
        self.provider = provider
        self.prompt_config = prompt_config
        self.threat = threat
        self.analysis_mode = analysis_mode

    def run(self):
        """Execute the reasoning AI call in a private event loop."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            analyzer = ThreatAnalyzer(self.provider, self.prompt_config)
            analyzer.builder.analysis_mode = self.analysis_mode
            
            reasoning = loop.run_until_complete(analyzer.analyze_reasoning(self.threat))
            self.finished.emit(reasoning, self.threat)
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
        label.setStyleSheet("color: #8899aa; font-weight: 500;")
        label.setObjectName("placeholder_label")
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

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._project: Project | None = None
        self._current_diagram: Diagram | None = None

        self._undo_stack = QUndoStack(self)
        self._undo_action = self._undo_stack.createUndoAction(self, "&Undo")
        self._redo_action = self._undo_stack.createRedoAction(self, "&Redo")
        self._undo_action.setShortcut(QKeySequence.StandardKey.Undo)
        self._redo_action.setShortcut(QKeySequence.StandardKey.Redo)

        self._setup_window()
        self._setup_central_widget()
        self._setup_docks()
        self._setup_menu_bar()
        self._setup_toolbar()
        self._setup_status_bar()
        self._connect_actions()
        
        self._undo_stack.indexChanged.connect(self._on_undo_redo_happened)
        
        self._is_dark_theme = False
        self._load_stylesheet()
        self._load_recent_project()
        config = AIConfig.load()
        self._autosave_timer = QTimer(self)
        self._autosave_timer.timeout.connect(self._on_autosave)
        self._autosave_timer.start(config.autosave_interval * 60000)

    def _load_stylesheet(self) -> None:
        """Apply a professional dark or light theme across the entire application."""
        theme_file = "style.qss" if self._is_dark_theme else "style_light.qss"
        resource_dir = Path(__file__).parent.parent / "resources"
        style_path = resource_dir / theme_file
        if style_path.exists():
            from PySide6.QtWidgets import QApplication
            QApplication.instance().setStyleSheet(style_path.read_text())
        else:
            fallback_path = resource_dir / "style.qss"
            if fallback_path.exists():
                from PySide6.QtWidgets import QApplication
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

    def _on_toggle_theme(self) -> None:
        """Switch between dark and light modes."""
        self._is_dark_theme = not self._is_dark_theme
        self._load_stylesheet()
        theme_name = "Dark" if self._is_dark_theme else "Light"
        self.statusBar().showMessage(f"Theme switched to {theme_name}")

    def _on_toggle_full_screen(self) -> None:
        """Toggle between full screen and maximized window states."""
        if self.isFullScreen():
            self.showMaximized()
        else:
            self.showFullScreen()

    def _load_recent_project(self) -> None:
        """Attempt to automatically reload the last opened project on startup."""
        project_root = Path(__file__).parent.parent.parent
        recent_file = project_root / ".threatpilot_recent"
        if recent_file.exists():
            path = recent_file.read_text().strip()
            if path and Path(path).exists():
                try:
                    self._open_project_from_path(path)
                except Exception:
                    pass

    def _setup_window(self) -> None:
        """Configure the top-level window properties."""
        self._update_title()
        
        icon_path = Path(__file__).parent.parent / "resources" / "app-icon.png"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
            
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

    def _setup_central_widget(self) -> None:
        """Initialise central workspace with tabbed navigation for diagrams and reports."""
        self._central_tabs = QTabWidget()
        self._central_tabs.setObjectName("central_tabs_container")
        self._central_tabs.setDocumentMode(True)
        
        self._canvas = DiagramCanvas(self)
        self._central_tabs.addTab(self._canvas, "System Architecture")
        
        from threatpilot.ui.threat_panel import ThreatPanel
        self._stride_threat_ledger = ThreatPanel(self, filter_mode="STRIDE")
        self._central_tabs.addTab(self._stride_threat_ledger, "STRIDE Security")
        self._linddun_threat_ledger = ThreatPanel(self, filter_mode="LINDDUN")
        self._central_tabs.addTab(self._linddun_threat_ledger, "LINDDUN Privacy")

        self._risk_assessment_panel = RiskAssessmentPanel(self)
        self._risk_assessment_panel.threat_edited.connect(self._on_save_project)
        self._central_tabs.addTab(self._risk_assessment_panel, "Risk Assessment")
        
        self.setCentralWidget(self._central_tabs)

    def _setup_docks(self) -> None:
        """Create and position the three dock panels."""
        self._properties_panel = PropertiesPanel(self, undo_stack=self._undo_stack)
        self._properties_panel.property_changed.connect(
            lambda obj: self._on_project_modified(obj, refresh_properties=False)
        )
        self._properties_panel.reasoning_requested.connect(self._on_reasoning_requested)
        
        def _sync_labels(obj):
            if isinstance(obj, Threat):
                QTimer.singleShot(0, self._threat_panel.refresh)
                QTimer.singleShot(0, self._stride_threat_ledger.refresh)
                QTimer.singleShot(0, self._linddun_threat_ledger.refresh)
        self._properties_panel.property_changed.connect(_sync_labels)
        self._properties_panel_dock = self._create_dock(
            "Attributes",
            self._properties_panel,
            Qt.DockWidgetArea.RightDockWidgetArea,
            min_width=320,
        )

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
        
        self._threat_panel.threat_selected.connect(self._properties_panel.set_item)
        self._stride_threat_ledger.threat_selected.connect(self._properties_panel.set_item)
        self._linddun_threat_ledger.threat_selected.connect(self._properties_panel.set_item)

        self._stride_threat_ledger.run_analysis_requested.connect(self._on_run_analysis)
        self._stride_threat_ledger.threat_added.connect(self._on_save_project)
        self._stride_threat_ledger.threat_removed.connect(self._on_save_project)
        
        self._linddun_threat_ledger.run_analysis_requested.connect(self._on_run_analysis)
        self._linddun_threat_ledger.threat_added.connect(self._on_save_project)
        self._linddun_threat_ledger.threat_removed.connect(self._on_save_project)

        self._ai_log_view = QTextEdit()
        self._ai_log_view.setReadOnly(True)
        self._ai_log_view.setObjectName("ai_log_view")
        self._ai_log_view.setPlaceholderText("AI transaction logs will appear here during detection or analysis...")
        
        self._ai_log_dock = self._create_dock(
            "AI Activity Log",
            self._ai_log_view,
            Qt.DockWidgetArea.BottomDockWidgetArea,
            min_width=400,
        )
        self._ai_log_dock.setVisible(False)

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

    def _setup_menu_bar(self) -> None:
        """Build the application menu bar with File, Edit, AI, View, Export."""
        menu_bar = self.menuBar()

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

        self._action_close_project = QAction("&Close Project", self)
        file_menu.addAction(self._action_close_project)

        file_menu.addSeparator()

        self._action_exit = QAction("E&xit", self)
        self._action_exit.triggered.connect(self.close)
        file_menu.addAction(self._action_exit)

        edit_menu = menu_bar.addMenu("&Edit")
        edit_menu.addAction(self._undo_action)
        edit_menu.addAction(self._redo_action)
        edit_menu.addSeparator()
        
        self._action_detect_objects = QAction("&Detect Entities", self)
        self._action_detect_objects.setShortcut(QKeySequence("Ctrl+D"))

        self._action_edit_components = QAction("&Component Inventory (Edit)...", self)
        self._action_edit_components.setShortcut(QKeySequence("Ctrl+E"))
        edit_menu.addAction(self._action_detect_objects)
        edit_menu.addAction(self._action_edit_components)

        intel_menu = menu_bar.addMenu("&Intelligence")

        self._action_run_analysis = QAction("&Run Security Analysis", self)
        self._action_run_analysis.setShortcut(QKeySequence("Ctrl+R"))
        intel_menu.addAction(self._action_run_analysis)

        intel_menu.addSeparator()

        self._action_ai_settings = QAction("&AI Settings...", self)
        intel_menu.addAction(self._action_ai_settings)

        self._action_prompt_config = QAction("&Business Context & Policy...", self)
        intel_menu.addAction(self._action_prompt_config)

        view_menu = menu_bar.addMenu("&View")
        
        self._action_toggle_explorer = self._project_explorer_dock.toggleViewAction()
        self._action_toggle_explorer.setText("Project &Map")
        view_menu.addAction(self._action_toggle_explorer)

        self._action_toggle_threats = self._threat_panel_dock.toggleViewAction()
        self._action_toggle_threats.setText("&Threat Ledger")
        view_menu.addAction(self._action_toggle_threats)

        self._action_toggle_properties = self._properties_panel_dock.toggleViewAction()
        self._action_toggle_properties.setText("&Element Attributes")
        view_menu.addAction(self._action_toggle_properties)

        self._action_toggle_ai_log = self._ai_log_dock.toggleViewAction()
        self._action_toggle_ai_log.setText("&AI Activity Log")
        view_menu.addAction(self._action_toggle_ai_log)

        view_menu.addSeparator()

        self._action_fit_diagram = QAction("&Center & Fit Diagram", self)
        self._action_fit_diagram.setShortcut(QKeySequence("Ctrl+0"))
        self._action_fit_diagram.triggered.connect(self._canvas.fit_to_screen)
        view_menu.addAction(self._action_fit_diagram)

        view_menu.addSeparator()
        self._action_toggle_theme = QAction("&Toggle Dark/Light Mode", self)
        self._action_toggle_theme.setShortcut(QKeySequence("Ctrl+T"))
        view_menu.addAction(self._action_toggle_theme)

        self._action_toggle_full_screen = QAction("Toggle &Full Screen", self)
        self._action_toggle_full_screen.setShortcut(QKeySequence("F11"))
        self._action_toggle_full_screen.triggered.connect(self._on_toggle_full_screen)
        view_menu.addAction(self._action_toggle_full_screen)

        report_menu = menu_bar.addMenu("&Reporting")

        self._action_export_excel = QAction("Generate &Risk Matrix (Excel)...", self)
        report_menu.addAction(self._action_export_excel)

        self._action_export_markdown = QAction("Generate &Security Report (MD)...", self)
        report_menu.addAction(self._action_export_markdown)

        report_menu.addSeparator()

        self._action_export_diagram = QAction("Export &Annotated Diagram (Image)...", self)
        report_menu.addAction(self._action_export_diagram)

        help_menu = menu_bar.addMenu("&Help")
        
        self._action_quickstart = QAction("&Quick Start Wizard...", self)
        help_menu.addAction(self._action_quickstart)

        self._action_open_logs = QAction("Open &Log Folder", self)
        help_menu.addAction(self._action_open_logs)
        
        help_menu.addSeparator()
        
        self._action_about = QAction("&About ThreatPilot...", self)
        help_menu.addAction(self._action_about)

    def _setup_toolbar(self) -> None:
        """Create a clean, result-oriented master toolbar."""
        toolbar = QToolBar("Performance Controls", self)
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(24, 24))
        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.addToolBar(toolbar)
        toolbar.addAction(self._action_import_diagram)
        toolbar.addAction(self._action_detect_objects)
        toolbar.addSeparator()
        run_act = toolbar.addAction("Analyze Threats")
        run_act.setObjectName("btn_run_analysis")
        run_act.triggered.connect(self._on_run_analysis)
        toolbar.addSeparator()

    def _setup_status_bar(self) -> None:
        """Create and configure the status bar."""
        status_bar = QStatusBar(self)
        self.setStatusBar(status_bar)
        status_bar.showMessage("Ready")

    def _connect_actions(self) -> None:
        """Connect menu / toolbar actions to their handler slots."""
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
        self._action_export_diagram.triggered.connect(self._on_export_diagram)
        self._action_about.triggered.connect(self._on_about)
        self._action_detect_objects.triggered.connect(self._on_detect_objects)
        self._action_edit_components.triggered.connect(self._on_edit_components)
        self._action_toggle_theme.triggered.connect(self._on_toggle_theme)
        self._action_quickstart.triggered.connect(self._on_quick_start)
        self._action_open_logs.triggered.connect(self._on_open_logs)

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
            self._stride_threat_ledger.set_register(self._project.threat_register)
            self._linddun_threat_ledger.set_register(self._project.threat_register)
            self._risk_assessment_panel.set_project(self._project)
            self._current_diagram = None
            self._canvas.clear_diagram()
            self._update_title()
            self.statusBar().showMessage(
                f"Project '{self._project.project_name}' created."
            )
            
            project_root = Path(__file__).parent.parent.parent
            recent_file = project_root / ".threatpilot_recent"
            recent_file.write_text(str(self._project.project_path))
                
        except OSError as exc:
            QMessageBox.critical(self, "Error", f"Could not create project:\n{exc}")

    def _on_close_project(self) -> None:
        """Clear the current project and reset the UI."""
        if not self._project:
            return
            
        self._project = None
        self._project_explorer.set_project(None)
        self._threat_panel.set_register(None)
        self._stride_threat_ledger.set_register(None)
        self._linddun_threat_ledger.set_register(None)
        self._risk_assessment_panel.set_project(None)
        self._current_diagram = None
        self._canvas.clear_diagram()
        self._update_title()
        
        project_root = Path(__file__).parent.parent.parent
        recent_file = project_root / ".threatpilot_recent"
        if recent_file.exists():
            recent_file.unlink()
            
        self.statusBar().showMessage("Project closed.")

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
        self._stride_threat_ledger.set_register(self._project.threat_register)
        self._linddun_threat_ledger.set_register(self._project.threat_register)
        self._risk_assessment_panel.set_project(self._project)
        self._current_diagram = None
        self._canvas.clear_diagram()
        self._update_title()

        if self._project.diagrams:
            self._on_diagram_activated(self._project.diagrams[0])

        self.statusBar().showMessage(
            f"Project '{self._project.project_name}' loaded."
        )
        
        project_root = Path(__file__).parent.parent.parent
        recent_file = project_root / ".threatpilot_recent"
        recent_file.write_text(str(directory))

    def _on_project_modified(self, obj: Any = None, refresh_properties: bool = True) -> None:
        """Trigger UI updates for panels when a project property changes. Does NOT save to disk."""
        if hasattr(self, "_risk_assessment_panel"):
            QTimer.singleShot(0, self._risk_assessment_panel.refresh)
        if hasattr(self, "_threat_panel"):
            QTimer.singleShot(0, self._threat_panel.refresh)
        if hasattr(self, "_stride_threat_ledger"):
            QTimer.singleShot(0, self._stride_threat_ledger.refresh)
        if hasattr(self, "_linddun_threat_ledger"):
            QTimer.singleShot(0, self._linddun_threat_ledger.refresh)
        QTimer.singleShot(0, self._refresh_canvas_overlays)
        self._update_title()

    def _on_save_project(self) -> None:
        """Save the current project to disk."""
        if self._project is None:
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
            self.statusBar().showMessage("Project saved.")
        except (ValueError, OSError) as exc:
            QMessageBox.critical(self, "Error", f"Could not save project:\n{exc}")

    def _on_autosave(self) -> None:
        """Automatically save the active project periodically without UX intrusion."""
        if self._project is not None:
            try:
                save_project(self._project)
                self.statusBar().showMessage("Project auto-saved.", 2000)
            except Exception:
                pass

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
            config.save()
            self._autosave_timer.setInterval(config.autosave_interval * 60000)
            self.statusBar().showMessage(f"Settings updated (Auto-save: {config.autosave_interval} min).")

    def _on_prompt_config(self) -> None:
        """Edit the prompt generation parameters."""
        if not self._project:
            QMessageBox.information(self, "Business Context", "Create or open a project first.")
            return

        dialog = PromptSettingsDialog(self._project.prompt_config, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._project.prompt_config = dialog.get_config()
            save_project(self._project)
            self.statusBar().showMessage("Business Context updated.")

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
        elif action == "action_edit_flows":
            self._on_edit_flows()
        elif action == "action_view_threats":
            self._central_tabs.setCurrentIndex(1)
            self._stride_threat_ledger.clear_filter()
            self._linddun_threat_ledger.clear_filter()
            self._threat_panel_dock.show()
            self._threat_panel_dock.raise_()
        elif action == "action_view_risk_matrix" and self._project:
            from threatpilot.ui.risk_matrix_dialog import RiskMatrixDialog
            component_names = [c.name for c in self._project.components]
            component_names.extend([f.name for f in self._project.flows])
            dialog = RiskMatrixDialog(self._project.threat_register.threats, component_names=component_names, is_dark=self._is_dark_theme, parent=self)
            dialog.exec()

    def _on_run_analysis(self) -> None:
        """Trigger AI-driven threat analysis using the configured provider."""
        if not self._project:
            return

        dfd = convert_to_dfd(self._project.components, self._project.flows)
        if not dfd.nodes:
            QMessageBox.warning(self, "Analysis", "No components detected to analyze. Please add or detect components first.")
            return
        try:
            config = AIConfig.load()
            
            if config.provider_type == "gemini":
                reply = QMessageBox.warning(
                    self, 
                    "Data Privacy Acknowledgement",
                    "You are using Google Gemini (Cloud AI).\n\n"
                    "Your system architecture (components, flows, and descriptions) will be sent to "
                    "Google's servers for analysis. Ensure this complies with your organization's "
                    "security and privacy policies.\n\n"
                    "Do you want to proceed?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.No:
                    self.statusBar().showMessage("Analysis cancelled due to privacy preference.")
                    return

            provider = create_ai_provider(config)
        except Exception as exc:
            QMessageBox.critical(self, "AI Error", f"Could not create AI provider:\n{exc}")
            return

        self._progress = QProgressDialog("Analyzing system architecture...", "Cancel", 0, 0, self)
        self._progress.setWindowTitle("AI Threat Analysis")
        self._progress.setWindowModality(Qt.WindowModality.WindowModal)
        self._progress.setMinimumDuration(500)
        
        self.statusBar().showMessage(f"Running threat analysis via {config.provider_type}...")
        if hasattr(self._stride_threat_ledger, "_btn_run"):
            self._stride_threat_ledger._btn_run.setEnabled(False)
        if hasattr(self._linddun_threat_ledger, "_btn_run"):
            self._linddun_threat_ledger._btn_run.setEnabled(False)

        self._worker = AnalysisWorker(
            provider, 
            self._project.prompt_config, 
            dfd, 
            self._project.project_name
        )
        self._worker.finished.connect(self._on_analysis_finished)
        self._worker.failed.connect(self._on_analysis_failed)
        self._worker.finished.connect(self._progress.close)
        self._worker.failed.connect(self._progress.close)
        self._progress.canceled.connect(self._worker.terminate)
        
        self._worker.prompt_ready.connect(lambda p: self.append_ai_log(p, "PROMPT"))
        self._worker.response_ready.connect(lambda r: self.append_ai_log(r, "RESPONSE"))
        self._worker.request_segment_continuation.connect(self._on_request_continuation)
        self._worker.partial_result_ready.connect(self._on_partial_analysis_result)
        
        self.append_ai_log("SECURITY WARNING: Logs may contain architectural details. Masking is active for identified API keys.", "SYSTEM")
        
        self._ai_log_dock.show()
        self._ai_log_dock.raise_()
        self._worker.start()
        self._progress.show()

    def _on_reasoning_requested(self, threat: Threat) -> None:
        """Handle request for deep technical reasoning for a specific threat."""
        config = AIConfig.load()
        provider = create_ai_provider(config)
        
        self.statusBar().showMessage("Analyzing threat reasoning with AI...")
        self._properties_panel.set_reasoning_progress(True)
        
        self._reasoning_worker = ReasoningWorker(
            provider, 
            self._project.prompt_config, 
            threat,
            config.analysis_mode
        )
        self._reasoning_worker.finished.connect(self._on_reasoning_finished)
        self._reasoning_worker.failed.connect(self._on_reasoning_failed)
        self._reasoning_worker.start()

    def _on_reasoning_finished(self, reasoning: str, threat: Threat) -> None:
        """Update threat with reasoning, converting any dict/JSON to Markdown."""
        import json, ast, re

        def _dict_to_markdown(data: dict) -> str:
            SECTION_MAP = {
                "attack_vector":            "### 1. Attack Vector",
                "architectural_root_cause": "### 2. Architectural Root Cause",
                "risk_rationalization":     "### 3. Risk Rationalization",
                "framework_alignment":      "### 4. Framework Alignment",
            }
            md = ""
            for key, heading in SECTION_MAP.items():
                if key in data:
                    val = data[key]
                    if isinstance(val, dict):
                        val = "\n".join(f"- **{k}**: {v}" for k, v in val.items())
                    elif isinstance(val, list):
                        val = "\n".join(f"- {item}" for item in val)
                    md += f"{heading}\n\n{val}\n\n"
            if not md:
                for k, v in data.items():
                    if isinstance(v, (dict, list)):
                        v = str(v)
                    md += f"### {k.replace('_', ' ').title()}\n\n{v}\n\n"
            return md.strip()

        def _regex_extract_dict(text: str) -> dict | None:
            """Fallback: extract key–value pairs from a Python dict string via regex.

            Handles mixed-quote AI output where single-quoted values contain double
            quotes (or vice versa), causing ast.literal_eval to raise SyntaxError.
            """
            result: dict = {}
            key_pattern = re.compile(r"[\"\']([\w]+)[\"\']\s*:\s*", re.DOTALL)
            keys_found = list(key_pattern.finditer(text))
            for i, match in enumerate(keys_found):
                key = match.group(1)
                val_start = match.end()
                val_end = keys_found[i + 1].start() if i + 1 < len(keys_found) else len(text)
                raw_val = text[val_start:val_end].strip().rstrip(",").strip()
                if len(raw_val) >= 2 and raw_val[0] in ('"', "'"):
                    q = raw_val[0]
                    end_idx = raw_val.rfind(q)
                    if end_idx > 0:
                        raw_val = raw_val[1:end_idx]
                result[key] = raw_val
            return result if result else None

        raw = reasoning.strip()
        raw = re.sub(r"^Technical Reasoning\s*[:\-]?\s*\n+", "", raw, flags=re.IGNORECASE).strip()

        processed_markdown = raw
        brace_match = re.search(r"\{[\s\S]+\}", raw)
        if brace_match:
            candidate = brace_match.group(0)
            data = None
            try:
                data = json.loads(candidate)
            except Exception:
                pass
            if data is None:
                try:
                    data = ast.literal_eval(candidate)
                except Exception:
                    pass
            if data is None:
                data = _regex_extract_dict(candidate)
            if isinstance(data, dict):
                processed_markdown = _dict_to_markdown(data)

        threat.reasoning = processed_markdown
        self._properties_panel.set_reasoning_progress(False)
        self._properties_panel.set_item(threat)
        self.statusBar().showMessage("Reasoning analysis complete.")
        save_project(self._project)

    def _on_reasoning_failed(self, error_msg: str) -> None:
        """Clean up UI and show error message on reasoning failure."""
        self._properties_panel.set_reasoning_progress(False)
        self._show_concise_error("Reasoning Error", "XAI Reasoning failed:", error_msg)

    def _on_partial_analysis_result(self, partial_register) -> None:
        """Merge intermediate results from a single segment while analysis continues."""
        if not self._project: return
        for t in partial_register.threats:
            self._project.threat_register.add_threat(t)
            
        self._threat_panel.refresh()
        self._stride_threat_ledger.refresh()
        self._linddun_threat_ledger.refresh()
        self._risk_assessment_panel.refresh()
        
        total_threats = len(self._project.threat_register.threats)
        self.statusBar().showMessage(f"Analysis update: Project now has {total_threats} identified risks.")
        self.statusBar().showMessage(f"Incremental update: {len(partial_register.threats)} threats added from segment.")

    def _on_request_continuation(self, current, total):
        """Prompt user to continue to the next segment for large architecture."""
        if current == 0:
            title = "Large Architecture Detected"
            msg = (
                f"The system architecture is large ({self._project_explorer._tree.topLevelItemCount() if hasattr(self._project_explorer, '_tree') else 'multiple'} components) "
                f"and will be analyzed in {total} separate segments to ensure high-quality results within AI token limits.\n\n"
                f"Do you want to start the segmented analysis?"
            )
        else:
            title = "Segmented Analysis"
            msg = f"Segment {current} of {total} is complete.\n\nDo you want to proceed with analyzing Segment {current + 1}?"

        reply = QMessageBox.question(
            self,
            title,
            msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes
        )
        should_continue = (reply == QMessageBox.StandardButton.Yes)
        self._worker.continue_analysis(should_continue)

    def _on_analysis_finished(self, new_register) -> None:
        """Merge new threats into the project and refresh UI."""
        if hasattr(self._stride_threat_ledger, "_btn_run"):
            self._stride_threat_ledger._btn_run.setEnabled(True)
        if hasattr(self._linddun_threat_ledger, "_btn_run"):
            self._linddun_threat_ledger._btn_run.setEnabled(True)

        if not self._project:
            return

        added = 0
        for t in new_register.threats:
            if self._project.threat_register.add_threat(t):
                added += 1

        total = len(self._project.threat_register.threats)
        self.statusBar().showMessage(f"Analysis complete: {added} new threats added ({total} total in register).")

        self._threat_panel.refresh()
        self._stride_threat_ledger.refresh()
        self._linddun_threat_ledger.refresh()
        self._risk_assessment_panel.refresh()

        save_project(self._project)
        QMessageBox.information(
            self,
            "Analysis Complete",
            f"{added} new threats identified and added to the register.\n"
            f"Total risks in project: {total}"
        )

    def _on_analysis_failed(self, error_msg: str) -> None:
        """Handle analysis failure with concise error reporting."""
        if hasattr(self._stride_threat_ledger, "_btn_run"):
            self._stride_threat_ledger._btn_run.setEnabled(True)
        if hasattr(self._linddun_threat_ledger, "_btn_run"):
            self._linddun_threat_ledger._btn_run.setEnabled(True)
            
        if "cancelled by user" in error_msg.lower():
            self.statusBar().showMessage("Analysis cancelled.")
            return
            
        self.statusBar().showMessage("Analysis failed.")
        self._show_concise_error("Analysis Error", "The AI analysis failed:", error_msg)

    def _show_concise_error(self, title: str, prefix: str, error_msg: str) -> None:
        """Categorize and display a user-friendly version of technical AI/API errors."""
        config = AIConfig.load()
        msg = str(error_msg).lower()
        
        explanation = ""
        if "timeout" in msg or "deadline" in msg or "timed out" in msg:
            explanation = (
                "🕒 **Request Timeout**\n\nThe AI provider took too long to respond. This usually happens "
                "with very large architecture diagrams or slow network connections.\n\n"
                "**Try:** Increase the 'Request Timeout' (e.g. to 120s) in AI Settings."
            )
        elif "connection" in msg or "connect_error" in msg or "reached" in msg:
            explanation = (
                "🔌 **Connection Failed**\n\nThreatPilot could not connect to the AI server.\n\n"
                "**Try:** Check your internet connection. If using Ollama, ensure 'ollama serve' is running."
            )
        elif "model" in msg and ("not found" in msg or "404" in msg):
            explanation = (
                f"🤖 **Model Not Found**\n\nThe model '{config.model_name}' was not recognized by {config.provider_type}.\n\n"
                "**Try:** Check the Model Name in AI Settings. Ensure it's exactly as required (e.g. 'gemini-1.5-flash')."
            )
        elif "api_key" in msg or "401" in msg or "unauthorized" in msg or "invalid" in msg:
            explanation = (
                "🔑 **Authentication Failed**\n\nThe AI provider rejected your API key or credentials.\n\n"
                "**Try:** Verify your API Key in AI Settings. Ensure there are no leading/trailing spaces."
            )
        elif "quota" in msg or "429" in msg or "rate" in msg:
            explanation = (
                "⏳ **Rate Limit Exceeded**\n\nYou have sent too many requests in a short period.\n\n"
                "**Try:** Wait 60 seconds before trying again, or upgrade your AI provider tier."
            )
        else:
            short_technical = (error_msg[:200] + "...") if len(error_msg) > 200 else error_msg
            explanation = (
                "❓ **Unexpected AI Error**\n\nAn unhandled error occurred during analysis.\n\n"
                f"**Technical Details:** {short_technical}"
            )

        if config.api_key and len(config.api_key) > 5:
            explanation = explanation.replace(config.api_key, "[HIDDEN]")
            error_msg = error_msg.replace(config.api_key, "[HIDDEN]")
        try:
            with Path("threatpilot_error.log").open("a", encoding="utf-8") as f:
                f.write(f"\n--- Analysis Error [{datetime.now().isoformat()}] ---\n")
                f.write(f"Context: {prefix}\n")
                f.write(f"Raw Error: {error_msg}\n")
        except Exception:
            pass
            
        QMessageBox.critical(self, title, f"{prefix}\n\n{explanation}")

    def _on_fit_diagram(self) -> None:
        """Fit the diagram image to the canvas viewport."""
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
    def threat_panel_dock(self) -> QDockWidget:
        """Return the Threat Panel dock widget."""
        return self._threat_panel_dock

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
        
        from threatpilot.config.ai_config import AIConfig
        config = AIConfig.load()
        prov_type = config.provider_type.lower()
        model_name = config.model_name.lower()
        
        is_vision_model = (
            "llava" in model_name or 
            "vl" in model_name or 
            "vision" in model_name or 
            prov_type == "gemini"
        )
        
        has_valid_config = (
            (prov_type == "ollama" and config.endpoint_url and is_vision_model)
            or (prov_type == "gemini" and config.api_key)
        )
        if has_valid_config:
            self.statusBar().showMessage(f"Using AI Vision ({prov_type.capitalize()}) to detect components...")
            provider = create_ai_provider(config)
            self._worker_ai_vision = AIVisionWorker(
                provider, str(image_path), self._project.project_name, self._project.prompt_config
            )
            self._worker_ai_vision.finished.connect(self._on_ai_detection_finished)
            self._worker_ai_vision.failed.connect(lambda msg: self._show_concise_error("AI Detection Failed", "Computer Vision detection failed:", msg))
            self._worker_ai_vision.prompt_ready.connect(lambda p: self.append_ai_log(p, "PROMPT"))
            self._worker_ai_vision.response_ready.connect(lambda r: self.append_ai_log(r, "RESPONSE"))

            self._central_tabs.setCurrentIndex(0) 
            self._ai_log_dock.show() 
            self._ai_log_dock.raise_()
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

        comp_list = data.get("c", data.get("components", []))
        flow_list = data.get("f", data.get("flows", []))
        
        img_w, img_h = 1920, 1080 
        if self._current_diagram:
             image_path = Path(self._project.project_path) / self._current_diagram.file_path
             pix = QPixmap(str(image_path))
             if not pix.isNull():
                 img_w, img_h = pix.width(), pix.height()

        for dc in comp_list:
            bbox = dc.get("b", dc.get("bounding_box", [0, 0, 100, 100]))
            if not isinstance(bbox, list) or len(bbox) < 4:
                bbox = [0, 0, 100, 100]

            final_x = (float(bbox[0]) / 1000.0) * img_w
            final_y = (float(bbox[1]) / 1000.0) * img_h
            final_w = (float(bbox[2]) / 1000.0) * img_w
            final_h = (float(bbox[3]) / 1000.0) * img_h

            comp_type = dc.get("t", dc.get("type", "Service"))
            low_type = str(comp_type).lower()
            name = dc.get("n", dc.get("name", "Unknown AI Item"))

            if "boundary" in low_type or "trust" in low_type:
                 b = TrustBoundary(
                     name=name,
                     x=final_x, y=final_y, width=final_w, height=final_h
                 )
                 self._project.boundaries.append(b)
            else:
                element_cls = dc.get("ec", dc.get("element_classification"))
                if not element_cls:
                     element_cls = "Process" if "service" in low_type else "DataStore" if "store" in low_type else "Entity"
                
                asset_cls = dc.get("ac", dc.get("asset_classification"))
                if not asset_cls:
                     asset_cls = "Informational" if "store" in low_type or "data" in low_type else "Physical"

                c = Component(
                    name=name,
                    type=comp_type,
                    element_classification=element_cls,
                    asset_classification=asset_cls,
                    x=final_x, y=final_y, width=final_w, height=final_h
                )
                self._project.components.append(c)

        for df in flow_list:
            bbox = df.get("b", df.get("bounding_box", [0, 0, 10, 10]))
            if not isinstance(bbox, list) or len(bbox) < 4:
                bbox = [0, 0, 10, 10]

            final_x = (float(bbox[0]) / 1000.0) * img_w
            final_y = (float(bbox[1]) / 1000.0) * img_h
            
            src_name = df.get("s", df.get("source", "")).strip()
            dst_name = df.get("d", df.get("target", "")).strip()
            
            def _find_comp_id(search_name: str) -> str:
                if not search_name:
                    return ""
                normalized = search_name.strip().lower()
                for comp in self._project.components:
                    if comp.name.strip().lower() == normalized:
                        return comp.component_id
                for comp in self._project.components:
                    comp_norm = comp.name.strip().lower()
                    if normalized in comp_norm or comp_norm in normalized:
                        return comp.component_id
                return ""
            
            src_id = _find_comp_id(src_name)
            dst_id = _find_comp_id(dst_name)

            f = Flow(
                name=df.get("n", df.get("name", "Data Flow")),
                protocol=df.get("p", df.get("protocol", "HTTPS")),
                source_id=src_id,
                target_id=dst_id,
                start_x=final_x,
                start_y=final_y,
                end_x=final_x + (float(bbox[2])/1000.0)*img_w,
                end_y=final_y + (float(bbox[3])/1000.0)*img_h
            )
            self._project.flows.append(f)

        self._refresh_canvas_overlays()
        save_project(self._project)
        self.statusBar().showMessage(f"AI Detection complete: {len(self._project.components)} components found.")
        QMessageBox.information(self, "AI Vision", f"AI Vision successfully detected {len(self._project.components)} components and {len(self._project.flows)} flows.")

    def _refresh_canvas_overlays(self) -> None:
        """Clear and redraw all detected objects as visual overlays on the image."""
        if not self._project:
            return

        self._canvas.clear_overlays()

        for b in self._project.boundaries:
            rect = QRectF(b.x, b.y, b.width, b.height)
            self._canvas.add_trust_boundary(rect, label=b.name, data=b)
        for c in self._project.components:
            rect = QRectF(c.x, c.y, c.width, c.height)
            self._canvas.add_component_box(rect, label=c.name, data=c)

        for f in self._project.flows:
            if f.start_x or f.start_y or f.end_x or f.end_y:
                start = QPointF(f.start_x, f.start_y)
                end = QPointF(f.end_x, f.end_y)
                self._canvas.add_flow_arrow(start, end, label=f.name, data=f)

    def _on_edit_components(self) -> None:
        """Open the dialog to manage architectural entities and nodes."""
        if not self._project:
            return
            
        dialog = EntitiesDialog(self._project, self._undo_stack, self)
        dialog.project_modified.connect(self._refresh_canvas_overlays)
        dialog.project_modified.connect(self._on_project_modified)
        dialog.exec()
        
        self._refresh_canvas_overlays()
        save_project(self._project)

    def _on_edit_flows(self) -> None:
        """Open the dialog to manage data flow connections."""
        if not self._project:
            return
            
        dialog = DataFlowDialog(self._project, self._undo_stack, self)
        dialog.project_modified.connect(self._on_project_modified)
        dialog.exec()
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
        dialog = AboutDialog(self, is_dark=self._is_dark_theme)
        dialog.exec()

    def _on_quick_start(self) -> None:
        """Launch the Quick Start Wizard for new users."""
        wizard = QuickStartWizard(self, is_dark=self._is_dark_theme)
        wizard.exec()

    def _on_open_logs(self) -> None:
        """Open the application's log directory in the OS file explorer."""
        if LOG_DIR.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(LOG_DIR)))
        else:
            QMessageBox.warning(self, "Logs", "Log directory not found yet.")

    def _on_undo_redo_happened(self, index: int) -> None:
        """Refresh the UI to reflect state changes after an undo or redo action.

        We snapshot _is_panel_editing SYNCHRONOUSLY here, before the finally-block
        in _on_field_changed resets it. The captured value is then forwarded to the
        deferred callback via closure, so set_item() is skipped when the user typed
        the change (preserving keyboard focus) but runs normally for Ctrl+Z/Y.
        """
        panel_was_editing = (
            hasattr(self, "_properties_panel")
            and self._properties_panel._is_panel_editing
        )
        QTimer.singleShot(0, lambda: self._perform_undo_redo_refresh(skip_panel=panel_was_editing))

    def _perform_undo_redo_refresh(self, skip_panel: bool = False) -> None:
        """Execute the UI refresh deferred from indexChanged.

        Args:
            skip_panel: If True, skip rebuilding the Properties Panel widgets.
                        Passed as True when the change came from within the panel
                        itself (user typed), so keyboard focus is preserved.
        """
        self._on_project_modified()

        if not skip_panel and hasattr(self, "_properties_panel"):
            item = self._properties_panel._current_item
            if item:
                self._properties_panel.set_item(item)
        if hasattr(self, "_threat_panel"):
            self._threat_panel.refresh()
        if hasattr(self, "_stride_threat_ledger"):
            self._stride_threat_ledger.refresh()
        if hasattr(self, "_linddun_threat_ledger"):
            self._linddun_threat_ledger.refresh()
        if hasattr(self, "_risk_assessment_panel"):
            self._risk_assessment_panel.refresh()

    def append_ai_log(self, text: str, category: str = "INFO") -> None:
        """Add a timestamped entry to the AI Activity Log dock."""
        time_str = datetime.now().strftime("%H:%M:%S")
        is_dark = getattr(self, "_is_dark_theme", True)
        
        if is_dark:
            color = "#58a6ff" if "PROMPT" in category else "#7ee787" if "RESPONSE" in category else "#8b949e"
            time_color = "#484f58"
        else:
            color = "#0969da" if "PROMPT" in category else "#1a7f37" if "RESPONSE" in category else "#57606a"
            time_color = "#8b949e"
        
        from threatpilot.utils.logger import sanitize_text
        sanitized_text = sanitize_text(text)
        log_entry = f"<span style='color: {time_color};'>[{time_str}]</span> <b style='color: {color};'>{category}</b>: {sanitized_text}<br>"
        self._ai_log_view.append(log_entry)
        self._ai_log_view.verticalScrollBar().setValue(self._ai_log_view.verticalScrollBar().maximum())
