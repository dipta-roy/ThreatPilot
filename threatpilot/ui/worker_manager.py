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
        if self._worker and self._worker.isRunning():
            QMessageBox.warning(self._mw, "AI Busy", "A background task is already running. Please wait.")
            return

        self._progress = QProgressDialog(label, "Cancel", 0, 0, self._mw)
        self._progress.setWindowTitle(title)
        self._progress.setWindowModality(Qt.WindowModality.WindowModal)
        self._progress.show()

        self._worker = worker_class(*args, **kwargs)
        
        # Connect standard lifecycle signals
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.failed.connect(self._on_worker_failed)
        self._progress.canceled.connect(self.stop_active_worker)
        
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

    def _on_worker_finished(self, *args):
        # Disconnect canceled to prevent stop_active_worker from being called during close()
        if self._progress:
            self._progress.canceled.disconnect(self.stop_active_worker)
            self._progress.close()
            self._progress = None
        
        # Capture worker reference before clearing
        worker = self._worker
        if not worker:
            logger.warning("WorkerManager: Worker finished but self._worker is None.")
            return

        # Check class name to handle different result signatures reliably
        class_name = getattr(worker, "WORKER_TYPE", worker.__class__.__name__)
        logger.info(f"WorkerManager: Worker finished. class={class_name}, args_len={len(args)}")
        
        if class_name == "ReasoningWorker":
             logger.info("WorkerManager: Routing to _on_reasoning_finished")
             self._mw._on_reasoning_finished(*args)
        else:
             logger.info("WorkerManager: Routing to _on_analysis_finished")
             self._mw._on_analysis_finished(*args, origin_project=self._mw.project)

    def _on_worker_failed(self, error_msg: str):
        if self._progress:
            self._progress.close()
            self._progress = None
            
        class_name = self._worker.__class__.__name__
        if class_name == "ReasoningWorker":
            self._mw._on_reasoning_failed(error_msg)
        else:
            self._mw._on_analysis_failed(error_msg)

    def stop_active_worker(self):
        """Gracefully terminates the running background task."""
        if self._worker and self._worker.isRunning():
            self._worker.terminate()
            self._worker.wait()
            self._worker = None
