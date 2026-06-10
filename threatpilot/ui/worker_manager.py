"""AI Worker Management for ThreatPilot."""

from __future__ import annotations
from typing import TYPE_CHECKING, Any, Optional
from PySide6.QtCore import QObject, Signal, Qt
from PySide6.QtWidgets import QProgressDialog, QMessageBox

if TYPE_CHECKING:
    from threatpilot.ui.main_window import MainWindow
    from threatpilot.core.project_manager import Project

from threatpilot.utils.logger import get_logger
logger = get_logger(__name__)

class WorkerManager(QObject):
    """Orchestrates background AI analysis and vision tasks."""

    def __init__(self, main_window: MainWindow) -> None:
        super().__init__(main_window)
        self._mw = main_window
        self._worker: Optional[Any] = None
        self._progress: Optional[QProgressDialog] = None

    def start_analysis(self, worker_class: type, title: str, label: str, *args, **kwargs):
        """Initializes and runs a background analysis worker."""
        is_vision_running = hasattr(self._mw, "_worker_ai_vision") and self._mw._worker_ai_vision is not None and self._mw._worker_ai_vision.isRunning()
        is_analysis_running = self._worker and self._worker.isRunning()
        if is_vision_running or is_analysis_running:
            QMessageBox.warning(self._mw, "AI Busy", "A background AI task is already running. Please wait until the existing task is complete.")
            return

        # Use non-blocking footer progress bar
        self._mw.show_progress(label, self.stop_active_worker)

        self._worker = worker_class(*args, **kwargs)
        
        # Connect standard QThread lifecycle signals for cleanup
        self._worker.finished.connect(self._on_thread_finished)
        self._worker.failed.connect(self._on_worker_failed)
        
        # Connect custom completion signals
        if hasattr(self._worker, "analysis_completed"):
            self._worker.analysis_completed.connect(self._on_analysis_completed)
        if hasattr(self._worker, "reasoning_completed"):
            self._worker.reasoning_completed.connect(self._on_reasoning_completed)
        
        # Connect optional helper signals
        if hasattr(self._worker, "partial_result_ready"):
            self._worker.partial_result_ready.connect(lambda reg: self._mw._on_partial_analysis_result(reg, self._mw.project))
        if hasattr(self._worker, "request_segment_continuation"):
            self._worker.request_segment_continuation.connect(self._mw._on_request_continuation)
        if hasattr(self._worker, "iteration_progress"):
            self._worker.iteration_progress.connect(self._mw._on_iteration_progress)
        if hasattr(self._worker, "prompt_ready"):
            self._worker.prompt_ready.connect(lambda p: self._mw.append_ai_log(p, "PROMPT"))
        if hasattr(self._worker, "response_ready"):
            self._worker.response_ready.connect(lambda r: self._mw.append_ai_log(r, "RESPONSE"))

        self._worker.start()

    def _on_thread_finished(self) -> None:
        """Called automatically when the QThread finishes executing (success, failed, or terminated)."""
        self._mw.hide_progress()
        self._worker = None

    def _on_analysis_completed(self, register) -> None:
        """Routes completed analysis register results back to MainWindow."""
        self._mw._on_analysis_finished(register, origin_project=self._mw.project)

    def _on_reasoning_completed(self, reasoning, item) -> None:
        """Routes completed technical reasoning back to MainWindow."""
        self._mw._on_reasoning_finished(reasoning, item)

    def _on_worker_failed(self, error_msg: str):
        # Let QThread.finished handle clearing reference and progress bar.
        class_name = self._worker.__class__.__name__ if self._worker else "Unknown"
        if class_name == "ReasoningWorker":
            self._mw._on_reasoning_failed(error_msg)
        else:
            self._mw._on_analysis_failed(error_msg)

    def stop_active_worker(self):
        """Gracefully terminates the running background task."""
        if self._worker and self._worker.isRunning():
            self._worker.terminate()
            # Do NOT wait() here to avoid freezing the GUI thread.
            # The QThread.finished signal will automatically trigger _on_thread_finished for cleanup.
