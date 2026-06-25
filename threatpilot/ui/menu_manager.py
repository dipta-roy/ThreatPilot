"""UI Menu and Toolbar Management for ThreatPilot."""

from __future__ import annotations
from typing import TYPE_CHECKING
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import QMenu, QToolBar, QMenuBar
from PySide6.QtCore import Qt, QSize

if TYPE_CHECKING:
    from threatpilot.ui.main_window import MainWindow

class MenuManager:
    """Handles the construction of the application's menu system and toolbars."""

    def __init__(self, main_window: MainWindow) -> None:
        self._mw = main_window

    def setup_menus(self):
        """Builds the main menu bar."""
        mb = self._mw.menuBar()
        self._setup_file_menu(mb)
        self._setup_edit_menu(mb)
        self._setup_intel_menu(mb)
        self._setup_arch_menu(mb)
        self._setup_view_menu(mb)
        self._setup_report_menu(mb)
        self._setup_help_menu(mb)

    def _setup_file_menu(self, mb: QMenuBar):
        menu = mb.addMenu("&File")
        self._mw._action_new_project = QAction("&New Project...", self._mw)
        self._mw._action_new_project.setShortcut(QKeySequence.StandardKey.New)
        menu.addAction(self._mw._action_new_project)
        
        self._mw._action_open_project = QAction("&Open Project...", self._mw)
        self._mw._action_open_project.setShortcut(QKeySequence.StandardKey.Open)
        menu.addAction(self._mw._action_open_project)
        
        menu.addSeparator()
        self._mw._action_save_project = QAction("&Save Project", self._mw)
        self._mw._action_save_project.setShortcut(QKeySequence.StandardKey.Save)
        menu.addAction(self._mw._action_save_project)
        
        self._mw._action_close_project = QAction("&Close Project", self._mw)
        self._mw._action_close_project.setShortcut(QKeySequence("Ctrl+W"))
        menu.addAction(self._mw._action_close_project)
        
        menu.addSeparator()
        exit_act = QAction("E&xit", self._mw)
        exit_act.triggered.connect(self._mw.close)
        menu.addAction(exit_act)

    def _setup_edit_menu(self, mb: QMenuBar):
        menu = mb.addMenu("&Edit")
        menu.addAction(self._mw._undo_action)
        menu.addAction(self._mw._redo_action)
        menu.addSeparator()
        
        self._mw._action_import_diagram = QAction("&Import Architecture Diagram...", self._mw)
        self._mw._action_import_diagram.setShortcut(QKeySequence("Ctrl+I"))
        menu.addAction(self._mw._action_import_diagram)

    def _setup_intel_menu(self, mb: QMenuBar):
        menu = mb.addMenu("&Intelligence")
        self._mw._action_run_analysis = QAction("&Run Security Analysis", self._mw)
        self._mw._action_run_analysis.setShortcut(QKeySequence("Ctrl+R"))
        menu.addAction(self._mw._action_run_analysis)
        
        menu.addSeparator()
        self._mw._action_ai_settings = QAction("&AI Settings...", self._mw)
        menu.addAction(self._mw._action_ai_settings)
        
        self._mw._action_prompt_config = QAction("&Business Context & Policy...", self._mw)
        menu.addAction(self._mw._action_prompt_config)

    def _setup_view_menu(self, mb: QMenuBar):
        menu = mb.addMenu("&View")
        menu.addAction(self._mw._project_explorer_dock.toggleViewAction())
        menu.addAction(self._mw._properties_panel_dock.toggleViewAction())
        menu.addAction(self._mw._ai_log_dock.toggleViewAction())
        menu.addSeparator()
        
        self._mw._action_fit_diagram = QAction("&Center & Fit Diagram", self._mw)
        self._mw._action_fit_diagram.setShortcut(QKeySequence("Ctrl+0"))
        menu.addAction(self._mw._action_fit_diagram)
        
        self._mw._action_toggle_theme = QAction("&Toggle Dark/Light Mode", self._mw)
        self._mw._action_toggle_theme.setShortcut(QKeySequence("Ctrl+T"))
        menu.addAction(self._mw._action_toggle_theme)

    def _setup_report_menu(self, mb: QMenuBar):
        menu = mb.addMenu("&Reporting")
        self._mw._action_export_excel = QAction("Generate &Risk Matrix (Excel)...", self._mw)
        menu.addAction(self._mw._action_export_excel)
        
        menu.addSeparator()
        
        self._mw._action_export_markdown = QAction("Generate &Security Report (MD)...", self._mw)
        menu.addAction(self._mw._action_export_markdown)

        self._mw._action_export_html = QAction("Generate &Security Report (HTML)...", self._mw)
        menu.addAction(self._mw._action_export_html)
       
        menu.addSeparator()
        
        self._mw._action_export_ai_mitigations = QAction("Generate &AI-Reviewed Mitigations (Excel)...", self._mw)
        menu.addAction(self._mw._action_export_ai_mitigations)
        
        self._mw._action_export_mitigation = QAction("Generate &Mitigation Checklist (MD)...", self._mw)
        menu.addAction(self._mw._action_export_mitigation)

        self._mw._action_export_mitigation_html = QAction("Generate &Mitigation Checklist (HTML)...", self._mw)
        menu.addAction(self._mw._action_export_mitigation_html)

    def _setup_help_menu(self, mb: QMenuBar):
        menu = mb.addMenu("&Help")
        self._mw._action_quickstart = QAction("&Quick Start Wizard...", self._mw)
        menu.addAction(self._mw._action_quickstart)
        
        self._mw._action_open_logs = QAction("Open &Log Folder", self._mw)
        menu.addAction(self._mw._action_open_logs)
        
        menu.addSeparator()
        self._mw._action_about = QAction("&About ThreatPilot...", self._mw)
        menu.addAction(self._mw._action_about)

    def _setup_arch_menu(self, mb: QMenuBar):
        menu = mb.addMenu("&Architecture")
        self._mw._action_edit_elements = QAction("Manage &System Elements...", self._mw)
        menu.addAction(self._mw._action_edit_elements)
        
        self._mw._action_edit_assets = QAction("Manage &Business Assets...", self._mw)
        menu.addAction(self._mw._action_edit_assets)
        
        self._mw._action_edit_boundaries = QAction("Manage &Trust Boundaries...", self._mw)
        menu.addAction(self._mw._action_edit_boundaries)

    def setup_toolbar(self):
        """Builds the main toolbar."""
        tb = QToolBar("Performance Controls", self._mw)
        tb.setMovable(False)
        tb.setIconSize(QSize(24, 24))
        tb.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self._mw.addToolBar(tb)
        
        tb.addAction(self._mw._action_import_diagram)
        
        self._mw._action_detect_objects = QAction("Detect Elements", self._mw)
        tb.addAction(self._mw._action_detect_objects)
