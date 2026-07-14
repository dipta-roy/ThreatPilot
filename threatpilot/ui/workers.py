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

            # 2. Deterministic Text Similarity Deduplication
            #    Local LLMs are unreliable for categorization tasks, so we use
            #    keyword-based Jaccard similarity to group mitigations.
            import json
            import re
            from collections import defaultdict
            from threatpilot.ai.response_parser import extract_json
            from threatpilot.core.constants import MITIGATION_SIMILARITY_THRESHOLD, AI_MITIGATION_BATCH_SIZE
            
            total_prompt_tokens = 0
            total_completion_tokens = 0

            # --- Step A: Extract distinguishing keywords ---
            # These boilerplate words appear in nearly every cybersecurity mitigation 
            # and create false-positive matches between unrelated controls.
            STOP_WORDS = {
                "implement", "enforce", "ensure", "deploy", "use", "apply", "update",
                "strict", "all", "the", "and", "or", "for", "with", "to", "in", "on",
                "of", "a", "an", "that", "is", "are", "from", "by", "be", "not",
                "before", "between", "within", "across", "such", "as", "should",
                "must", "can", "may", "also", "using", "based", "provide",
                "appropriate", "robust", "sensitive", "data", "security", "service",
                "services", "system", "application", "including", "mechanisms",
                "capabilities", "policies", "rules", "checks", "proper",
                "only", "do", "does", "no", "if", "its", "their", "it",
                "eg", "level", "specific", "directly", "explicitly",
                "component", "server", "web", "cloud", "app", "logic",
                "ensure", "prevent", "protect", "against",
            }
            
            # Normalize synonyms to a single canonical term so that
            # different words for the same security concept all match.
            SYNONYMS = {
                # Log cleaning controls
                "scrub": "logclean", "scrubbing": "logclean", "redact": "logclean",
                "redaction": "logclean", "masking": "logclean", "mask": "logclean",
                "masks": "logclean", "masked": "logclean", "sanitization": "logclean",
                "sanitize": "logclean", "sanitizing": "logclean", "scrubbed": "logclean",
                # Hardware key storage
                "keystore": "hwkey", "keychain": "hwkey", "enclave": "hwkey", "enclaves": "hwkey",
                "hardwarebacked": "hwkey",
                # Mutual TLS
                "mtls": "mtls", "mutual": "mtls", "tls": "mtls",
                "pinning": "mtls", "certificate": "mtls", "certificates": "mtls",
                # Web Application Firewall
                "waf": "waf", "firewall": "waf", "ratelimiting": "waf", "ddos": "waf",
                # Privacy & Consent
                "consent": "privcon", "privacy": "privcon", "disclosure": "privcon",
                "transparency": "privcon",
                # Multi-Factor Auth
                "mfa": "mfa", "multifactor": "mfa",
            }
            
            _keywords_cache = {}
            def extract_keywords(text: str) -> set:
                """Extract meaningful security keywords with synonym normalization."""
                if text not in _keywords_cache:
                    # Replace punctuation with spaces (not remove) so PII/PHI -> pii phi
                    cleaned = re.sub(r'[^a-z0-9 ]', ' ', text.lower())
                    words = cleaned.split()
                    result = set()
                    for w in words:
                        if w in STOP_WORDS or len(w) <= 2:
                            continue
                        # Apply synonym mapping
                        result.add(SYNONYMS.get(w, w))
                    _keywords_cache[text] = result
                return _keywords_cache[text]

            def keyword_similarity(a: str, b: str) -> float:
                """Jaccard similarity on keywords (intersection / union)."""
                ka, kb = extract_keywords(a), extract_keywords(b)
                if not ka or not kb:
                    return 0.0
                intersection = ka & kb
                if not intersection:
                    return 0.0
                union = ka | kb
                return len(intersection) / len(union) if union else 0.0

            # --- Step B: Multi-representative grouping ---
            #     A new item joins a group if it is similar to ANY existing member.
            #     This handles cases where items within the same control use very 
            #     different vocabulary (e.g., "log scrubbing" vs "PII masking").
            groups = []  # List of [list of indices]
            
            n = len(raw_items)
            last_pct = 0
            
            self.progress.emit(f"Analyzing similarity across {n} mitigations...")
            
            for i in range(n):
                best_group = None
                best_sim = 0.0
                
                for g_idx, members in enumerate(groups):
                    # Check against all members (not just centroid)
                    for m_idx in members:
                        sim = keyword_similarity(raw_items[i]["mitigation"], raw_items[m_idx]["mitigation"])
                        if sim >= MITIGATION_SIMILARITY_THRESHOLD and sim > best_sim:
                            best_sim = sim
                            best_group = g_idx
                            break  # Found a match in this group, no need to check other members
                
                if best_group is not None:
                    groups[best_group].append(i)
                else:
                    groups.append([i])
                
                # Emit progress every 10%
                pct = int((i + 1) / n * 100)
                if pct >= last_pct + 10:
                    last_pct = pct
                    self.progress.emit(f"Analyzing similarity... {pct}% ({i+1}/{n})")

            self.progress.emit(f"Found {len(groups)} distinct security controls from {n} raw mitigations...")

            # --- Step C: Consolidate each group ---
            all_requirements = []
            for group_indices in groups:
                group_items = [raw_items[i] for i in group_indices]
                
                # Merge affected components
                components = set()
                for item in group_items:
                    for comp in item["component"].split(","):
                        components.add(comp.strip())
                
                # Pick the longest mitigation text as the representative
                best_item = max(group_items, key=lambda x: len(x["mitigation"]))
                best_mitigation = best_item["mitigation"]
                best_title = best_item["threat_title"]
                
                all_requirements.append({
                    "mitigation": best_mitigation,
                    "short_description": f"Security control to mitigate: {best_title}.",
                    "test_case": f"Verify implementation addresses: {best_title}.",
                    "affected_components": ", ".join(sorted(components)),
                    "_threat_title": best_title
                })

            # --- Step D: Use AI to generate clean titles (batched for scalability) ---
            self.progress.emit("Generating requirement titles...")
            
            title_system = (
                "You are a security architect. For each mitigation below, output a short 2-5 word title.\n"
                "Output a JSON object mapping the index to the title.\n"
                "Example: {\"0\": \"Multi-Factor Authentication\", \"1\": \"Log Masking\"}\n"
                "Do not include any text outside the JSON object."
            )

            async def call_ai(p):
                return await self.provider.chat_complete(p, system_instructions=title_system, response_mime_type="application/json")

            title_batch_size = AI_MITIGATION_BATCH_SIZE
            num_title_batches = (len(all_requirements) + title_batch_size - 1) // title_batch_size
            
            for batch_idx in range(num_title_batches):
                start = batch_idx * title_batch_size
                end = min(start + title_batch_size, len(all_requirements))
                batch_reqs = all_requirements[start:end]
                
                self.progress.emit(f"Generating titles (Batch {batch_idx+1}/{num_title_batches})...")
                
                title_map = {str(i): req["mitigation"][:120] for i, req in enumerate(batch_reqs)}
                title_prompt = f"Generate a short title for each mitigation:\n\n{json.dumps(title_map, indent=2)}"
                
                if batch_idx == 0:
                    self.prompt_ready.emit(f"SYSTEM: {title_system}\n\nUSER: {title_prompt}")

                response_text, usage = loop.run_until_complete(call_ai(title_prompt))
                
                if batch_idx == 0:
                    self.response_ready.emit(response_text)
                
                if usage:
                    total_prompt_tokens += usage.prompt_tokens
                    total_completion_tokens += usage.completion_tokens

                titles = extract_json(response_text)
                if titles and isinstance(titles, dict):
                    for idx_str, title in titles.items():
                        try:
                            idx = int(idx_str)
                            if 0 <= idx < len(batch_reqs):
                                all_requirements[start + idx]["title"] = title.strip()
                        except (ValueError, AttributeError):
                            continue

            # Ensure every requirement has a title (fallback to threat title)
            for req in all_requirements:
                if "title" not in req or not req["title"]:
                    req["title"] = req.get("_threat_title", "Security Control")
                # Clean up internal field
                req.pop("_threat_title", None)

            # Log usage metadata
            total_tokens = total_prompt_tokens + total_completion_tokens
            meta_log = f"METADATA: Tokens [In: {total_prompt_tokens} | Out: {total_completion_tokens} | Total: {total_tokens}] (Grouped {len(raw_items)} mitigations into {len(all_requirements)} requirements)"
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
                return await self.provider.chat_complete(
                    prompt, 
                    system_instructions=system_instructions,
                    response_mime_type="text/plain"
                )

            response_text, usage = loop.run_until_complete(call_ai())
            self.completed.emit(response_text, self.requirement)
        except Exception as exc:
            logger.exception(f"MitigationReasoningWorker failed: {exc}")
            self.failed.emit(str(exc))
        finally:
            loop.close()

class JiraSyncWorker(QThread):
    """Background worker to sync mitigations to Jira."""
    progress = Signal(int, int) # current, total
    completed = Signal(int, int) # success_count, fail_count
    failed = Signal(str)
    item_synced = Signal(object) # MitigationRequirement

    def __init__(self, mitigations, parent=None):
        super().__init__(parent)
        self.mitigations = mitigations

    def run(self):
        try:
            from threatpilot.config.jira_config import JiraConfig
            from threatpilot.core.jira_service import JiraService
            
            config = JiraConfig.load()
            service = JiraService(config)
            
            success, message = service.verify_connection()
            if not success:
                self.failed.emit(f"Jira Connection failed: {message}")
                return
                
            total = len(self.mitigations)
            success_count = 0
            fail_count = 0
            
            for i, mitigation in enumerate(self.mitigations):
                self.progress.emit(i + 1, total)
                
                if mitigation.jira_issue_key:
                    # Already synced
                    continue
                    
                ok, result = service.create_issue(mitigation)
                if ok:
                    mitigation.jira_issue_key = result
                    mitigation.jira_issue_url = f"{config.jira_url.rstrip('/')}/browse/{result}"
                    self.item_synced.emit(mitigation)
                    success_count += 1
                else:
                    fail_count += 1
                    logger.error(f"Failed to sync mitigation {mitigation.req_id}: {result}")
                    
            self.completed.emit(success_count, fail_count)
            
        except Exception as exc:
            logger.exception(f"JiraSyncWorker failed: {exc}")
            self.failed.emit(str(exc))

class NarrativeWorker(QThread):
    """Background worker to generate an architecture narrative."""
    completed = Signal(str)
    failed = Signal(str)

    def __init__(self, provider, prompt_config, dfd, system_name, parent=None):
        super().__init__(parent)
        self.provider = provider
        self.prompt_config = prompt_config
        self.dfd = dfd
        self.system_name = system_name

    def run(self):
        try:
            analyzer = ThreatAnalyzer(self.provider, self.prompt_config)
            narrative_text = analyzer.generate_narrative(self.dfd, self.system_name)
            self.completed.emit(narrative_text)
        except Exception as exc:
            logger.exception(f"NarrativeWorker failed: {exc}")
            self.failed.emit(str(exc))
