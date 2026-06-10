"""Background worker modules for ThreatPilot.

Contains QThread implementations for running AI analysis, vision detection, 
and reasoning without blocking the main UI thread.
"""

from __future__ import annotations
import asyncio
import threading
from PySide6.QtCore import Qt, QThread, Signal, QBuffer, QIODevice
from PySide6.QtGui import QImage

from threatpilot.ai.prompt_builder import PromptBuilder
from threatpilot.ai.analyzer import ThreatAnalyzer
from threatpilot.ai.response_parser import extract_json
from threatpilot.core.threat_model import Vulnerability


from threatpilot.utils.logger import get_logger
logger = get_logger(__name__)

class AnalysisWorker(QThread):
    """Background worker for running AI analysis without blocking the UI.
    
    Supports multi-iteration analysis where each iteration runs all segments
    sequentially. When iterations > 1, segments auto-continue without user
    prompts between them.
    
    Signals:
        finished: Emitted when analysis completes successfully.
        failed: Emitted when an error occurs.
        iteration_progress: Emitted with (current_iteration, total_iterations,
            current_segment, total_segments) for UI progress updates.
    """
    analysis_completed = Signal(object)
    failed = Signal(str)
    partial_result_ready = Signal(object)
    prompt_ready = Signal(str)
    response_ready = Signal(str)
    request_segment_continuation = Signal(int, int)
    iteration_progress = Signal(int, int, int, int)

    def __init__(self, provider, prompt_config, dfd, system_name, iterations=1, parent=None):
        super().__init__(parent)
        self.provider = provider
        self.prompt_config = prompt_config
        self.dfd = dfd
        self.system_name = system_name
        self.iterations = max(1, min(iterations, 5))
        
        self._continue_event = threading.Event()
        self._should_continue_result = True

    def continue_analysis(self, should_continue: bool):
        """Called by the UI thread to resume analysis."""
        self._should_continue_result = should_continue
        self._continue_event.set()

    def run(self):
        """Execute the async analysis within a new event loop.
        
        When iterations > 1, all segments auto-continue without prompting
        the user. The iteration_progress signal keeps the UI informed.
        """
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            all_register = None
            auto_mode = self.iterations > 1

            for iteration in range(1, self.iterations + 1):
                analyzer = ThreatAnalyzer(self.provider, self.prompt_config)

                iter_label = f"[Iteration {iteration}/{self.iterations}] " if auto_mode else ""
                
                def on_prompt(sys_p, usr_p):
                    self.prompt_ready.emit(f"{iter_label}SYSTEM: {sys_p}\n\nUSER: {usr_p}")
                
                def on_response(raw_resp):
                    self.response_ready.emit(f"{iter_label}{raw_resp}")

                if auto_mode:
                    # Auto-continue: no user prompts between segments
                    async def progress_cb_auto(current, total, _iter=iteration):
                        self.iteration_progress.emit(_iter, self.iterations, current, total)
                        return True  # always continue

                    register, raw_resp, usage = loop.run_until_complete(
                        analyzer.analyze(
                            self.dfd,
                            self.system_name,
                            progress_callback=progress_cb_auto,
                            result_callback=lambda partial: self.partial_result_ready.emit(partial),
                            prompt_callback=on_prompt,
                            response_callback=on_response
                        )
                    )
                else:
                    # Single iteration: use the original interactive prompt flow
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
                            result_callback=lambda partial: self.partial_result_ready.emit(partial),
                            prompt_callback=on_prompt,
                            response_callback=on_response
                        )
                    )

                if "Analysis cancelled by user" in raw_resp:
                    self.failed.emit("Analysis cancelled by user.")
                    return

                if usage:
                    meta_log = f"{iter_label}METADATA: Tokens [In: {usage.prompt_tokens} | Out: {usage.completion_tokens} | Total: {usage.total_tokens}]"
                    self.response_ready.emit(meta_log)

                # Merge iteration results into the cumulative register
                if all_register is None:
                    all_register = register
                else:
                    for t in register.threats:
                        all_register.add_threat(t)
                    if hasattr(register, "new_vulnerabilities"):
                        if not hasattr(all_register, "new_vulnerabilities"):
                            all_register.new_vulnerabilities = []
                        all_register.new_vulnerabilities.extend(register.new_vulnerabilities)

            self.analysis_completed.emit(all_register)
        except Exception as exc:
            logger.exception(f"AnalysisWorker failed: {exc}")
            self.failed.emit(str(exc))
        finally:
            loop.close()


class AIVisionWorker(QThread):
    """Background worker for multimodal AI architecture detection.

    Signals:
        finished: Emitted when AI vision detection completes.
        failed: Emitted when an error occurs.
    """
    detection_completed = Signal(dict)
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
            
            from threatpilot.detection.image_loader import resize_image_for_ai
            from threatpilot.detection.detection_schemas import get_vision_response_schema
            
            img = QImage(self.image_path)
            if img.isNull():
                raise FileNotFoundError(f"Selected image file at {self.image_path} could not be loaded.")
            
            max_dim = getattr(self.provider.config, "max_vision_resolution", 2048)
            img = resize_image_for_ai(img, max_dim=max_dim)
            
            buffer = QBuffer()
            buffer.open(QIODevice.WriteOnly)
            img.save(buffer, "PNG")
            image_bytes = bytes(buffer.data())

            builder = PromptBuilder(self.prompt_config)
            prompt = builder.build_vision_detection_prompt(self.system_name)
            self.prompt_ready.emit(prompt)

            schema_dict = get_vision_response_schema()

            async def run_vision():
                return await self.provider.vision_complete(prompt, image_bytes, response_schema=schema_dict)

            response_text, usage = loop.run_until_complete(run_vision())
            
            self.response_ready.emit(response_text)
            log_meta = f"METADATA: Tokens [In: {usage.prompt_tokens} | Out: {usage.completion_tokens} | Total: {usage.total_tokens}]"
            self.response_ready.emit(log_meta)
            
            data = extract_json(response_text)
            if data:
                self.detection_completed.emit(data)
            else:
                logger.error("AIVisionWorker failed to parse JSON response.")
                self.failed.emit("Failed to parse AI response. Check the Logs tab for details on the raw output structure.")
        except Exception as exc:
            logger.exception(f"AIVisionWorker failed: {exc}")
            self.failed.emit(str(exc))
        finally:
            loop.close()


class ReasoningWorker(QThread):
    """Background worker for deep technical reasoning (XAI)."""
    WORKER_TYPE = "ReasoningWorker"
    reasoning_completed = Signal(str, object)
    failed = Signal(str)

    def __init__(self, provider, prompt_config, item, analysis_mode, parent=None):
        super().__init__(parent)
        self.provider = provider
        self.prompt_config = prompt_config
        self.item = item
        self.analysis_mode = analysis_mode

    def run(self):
        """Execute the reasoning AI call in a private event loop."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            logger.info(f"ReasoningWorker: mode={self.analysis_mode}, item={type(self.item).__name__}")
            if hasattr(self.item, "category"):
                logger.info(f"ReasoningWorker: item category={self.item.category}")
            
            analyzer = ThreatAnalyzer(self.provider, self.prompt_config)
            analyzer.builder.analysis_mode = self.analysis_mode
            
            if isinstance(self.item, Vulnerability):
                reasoning = loop.run_until_complete(analyzer.analyze_vulnerability_reasoning(self.item))
            else:
                reasoning = loop.run_until_complete(analyzer.analyze_reasoning(self.item))
                
            logger.info(f"ReasoningWorker: Emitting finished signal. reasoning_len={len(reasoning)}")
            self.reasoning_completed.emit(reasoning, self.item)
        except Exception as exc:
            logger.exception(f"ReasoningWorker failed: {exc}")
            self.failed.emit(str(exc))
        finally:
            loop.close()
