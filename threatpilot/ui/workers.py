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
            
            is_ollama = getattr(self.provider.config, "provider_type", "") == "ollama"
            max_dim = getattr(self.provider.config, "max_vision_resolution", 2048)
            img = resize_image_for_ai(img, max_dim=max_dim, force_multiple_of_28=is_ollama)
            
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


class MitigationRequirementsWorker(QThread):
    """Background worker to call AI and consolidate mitigations into an Excel requirements sheet."""
    completed = Signal(list)
    failed = Signal(str)
    prompt_ready = Signal(str)
    response_ready = Signal(str)
    progress = Signal(str)

    def __init__(self, provider, project, output_path=None, parent=None):
        super().__init__(parent)
        self.provider = provider
        self.project = project
        self.output_path = output_path

    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # 1. Gather raw mitigations from project
            threats = self.project.threat_register.threats
            raw_items = []
            for t in threats:
                if t.is_accepted_risk:
                    continue
                mit = (t.mitigation or "").strip()
                if not mit:
                    continue
                elem, asset = t.resolve_affected_elements(self.project)
                component = elem or t.affected_components or "Unknown Component"
                raw_items.append({
                    "component": component,
                    "threat_title": t.title,
                    "mitigation": mit
                })

            if not raw_items:
                self.failed.emit("No active mitigations found to process.")
                return

            # 2. Formulate prompt and batch process
            import json
            batch_size = 50
            all_requirements = []
            total_prompt_tokens = 0
            total_completion_tokens = 0

            system_instructions = (
                "You are an expert cybersecurity threat modeler and security architect.\n"
                "Review the provided JSON list of mitigations identified for various components in a system architecture.\n"
                "Some of these mitigations are duplicates or near-duplicates across components but worded differently.\n\n"
                "Your task is to:\n"
                "1. Consolidate and group only actual duplicates or near-identical semantic mitigations (e.g., 'Encrypt the data at rest' and 'Data at rest must be encrypted') into a single requirement.\n"
                "2. AVOID OVER-CONSOLIDATION: Do not group distinct security controls or mechanisms into a single requirement just because they share a category or target component. For example:\n"
                "   - Multi-Factor Authentication (MFA) and Web Application Firewall (WAF) are distinct controls and should NOT be combined.\n"
                "   - Data Retention Policies are distinct from Log Masking/Redaction and should NOT be combined.\n"
                "   - Secure Token Storage (Keystore/Keychain) is distinct from Cryptographic Token Validation (RS256/claims check) and should NOT be combined.\n"
                "   - Mutual TLS (mTLS) is distinct from CORS/Origin validation and should NOT be combined.\n"
                "3. If a raw mitigation text contains multiple distinct security controls (e.g., 'Enforce strict mTLS and implement database-level integrity checks'), split them and represent them in their respective consolidated requirements so that no security control is lost or hidden.\n"
                "4. For each distinct requirement, generate:\n"
                "   - REQ-ID: A unique ID starting with 'SR-' (e.g., SR-1, SR-2, ...)\n"
                "   - Title: A concise, professional title (e.g., 'Data Encryption')\n"
                "   - Mitigation: The consolidated mitigation statement\n"
                "   - Short Description: A professional description explaining what the requirement is, which components/elements it applies to, and the recommended implementation.\n"
                "   - Test case / Validation: Specific criteria or a test case to verify compliance.\n"
                "   - Affected Components: A comma-separated list of components/elements where this mitigation needs to be implemented (derived from the 'component' values of the raw mitigations that were consolidated into this requirement).\n\n"
                "Your response MUST be a valid JSON array of objects, where each object has these exact keys:\n"
                "- 'req_id': string\n"
                "- 'title': string\n"
                "- 'mitigation': string\n"
                "- 'short_description': string\n"
                "- 'test_case': string\n"
                "- 'affected_components': string (comma-separated, e.g., \"Web Server, Database\")\n\n"
                "Do not include any formatting other than the JSON block. Do not wrap it in markdown block unless it's standard json block."
            )

            async def call_ai(p):
                return await self.provider.chat_complete(p, system_instructions=system_instructions, response_mime_type="application/json")

            from threatpilot.ai.response_parser import extract_json

            current_items = raw_items
            pass_num = 1

            while True:
                num_batches = (len(current_items) + batch_size - 1) // batch_size
                all_requirements = []
                
                self.progress.emit(f"Analyzing duplicate requirements - Iteration {pass_num} (Processing {num_batches} batches...)")
                
                for i in range(0, len(current_items), batch_size):
                    batch_items = current_items[i:i + batch_size]
                    raw_list_str = json.dumps(batch_items, indent=2)
                    
                    if pass_num == 1:
                        prompt = f"Here is the list of raw mitigations to consolidate and review (Pass {pass_num}, Batch {i//batch_size + 1} of {num_batches}):\n\n{raw_list_str}"
                    else:
                        prompt = f"Here is a list of pre-consolidated mitigations. Please perform further review and consolidate any remaining duplicates using the exact same rules (Pass {pass_num}, Batch {i//batch_size + 1} of {num_batches}):\n\n{raw_list_str}"

                    if i == 0 and pass_num == 1:
                        self.prompt_ready.emit(f"SYSTEM: {system_instructions}\n\nUSER: {prompt}\n\n... (additional batches/passes may follow)")

                    response_text, usage = loop.run_until_complete(call_ai(prompt))
                    
                    if i == 0 and pass_num == 1:
                        self.response_ready.emit(f"{response_text}\n\n... (additional batch responses truncated for display)")

                    if usage:
                        total_prompt_tokens += usage.prompt_tokens
                        total_completion_tokens += usage.completion_tokens

                    batch_requirements = extract_json(response_text)
                    if not batch_requirements or not isinstance(batch_requirements, list):
                        self.failed.emit(f"Failed to parse AI response for Pass {pass_num}, Batch {i//batch_size + 1} as a JSON array.")
                        return
                    all_requirements.extend(batch_requirements)

                if num_batches == 1:
                    # Everything fit into a single batch and was consolidated. We are done!
                    break
                elif len(all_requirements) >= len(current_items):
                    # Safety guard: AI wasn't able to consolidate any further across these batches.
                    # Break to prevent an infinite loop.
                    break
                else:
                    # Prepare for the next pass to combine the results of multiple batches
                    current_items = all_requirements
                    pass_num += 1

            # Log usage metadata
            total_tokens = total_prompt_tokens + total_completion_tokens
            meta_log = f"METADATA: Tokens [In: {total_prompt_tokens} | Out: {total_completion_tokens} | Total: {total_tokens}] (Completed in {pass_num} passes)"
            self.response_ready.emit(meta_log)

            # Re-index req_ids for the final output
            for idx, req in enumerate(all_requirements):
                req['req_id'] = f"SR-{idx + 1}"

            requirements = all_requirements

            # 4. Generate the Excel file if output_path is provided
            if self.output_path:
                from threatpilot.export.mitigation_review_exporter import generate_mitigation_requirements_excel
                generate_mitigation_requirements_excel(self.project, requirements, self.output_path)
            
            self.completed.emit(requirements)
        except Exception as exc:
            logger.exception(f"MitigationRequirementsWorker failed: {exc}")
            self.failed.emit(str(exc))
        finally:
            loop.close()


class MitigationReasoningWorker(QThread):
    """Background worker to generate deep XAI reasoning and detailed verification plan for a mitigation requirement."""
    completed = Signal(str, object)  # reasoning_text, requirement
    failed = Signal(str)

    def __init__(self, provider, requirement, parent=None):
        super().__init__(parent)
        self.provider = provider
        self.requirement = requirement

    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            system_instructions = (
                "You are an expert security architect and penetration tester.\n"
                "Your task is to generate Explainable AI (XAI) reasoning and a detailed verification plan for a specific security mitigation requirement.\n"
                "Provide a professional response containing:\n"
                "1. Deep Technical Reasoning: Explain why this requirement is critical, the security threats it prevents, and the architecture/implementation rationale.\n"
                "2. Detailed Verification Plan:\n"
                "   - How to perform the test (step-by-step procedures, tools to use like curl, nmap, OWASP ZAP, etc.).\n"
                "   - How to verify the results (expected outputs, what to look for in logs, responses, or configurations to confirm compliance).\n\n"
                "Format your entire response in clear, professional Markdown. Use headings, lists, and code blocks for instructions where appropriate."
            )

            req = self.requirement
            prompt = (
                f"Requirement Details:\n"
                f"- REQ-ID: {req.req_id}\n"
                f"- Title: {req.title}\n"
                f"- Affected Components: {req.affected_components}\n"
                f"- Mitigation: {req.mitigation}\n"
                f"- Description: {req.short_description}\n"
                f"- High-Level Test Case: {req.test_case}\n\n"
                f"Please generate the deep technical reasoning and the detailed verification plan."
            )

            async def call_ai():
                return await self.provider.chat_complete(prompt, system_instructions=system_instructions)

            response_text, usage = loop.run_until_complete(call_ai())
            self.completed.emit(response_text, self.requirement)
        except Exception as exc:
            logger.exception(f"MitigationReasoningWorker failed: {exc}")
            self.failed.emit(str(exc))
        finally:
            loop.close()


