"""Lightweight HTTP REST Server for the ThreatPilot Architecture Designer."""

from __future__ import annotations
import json
import os
import mimetypes
import threading
import asyncio
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any
from pydantic import SecretStr

from threatpilot.core.project_manager import save_project
from threatpilot.core.domain_models import Component, Flow, TrustBoundary, Asset
from threatpilot.utils.paths import get_designer_dist_path
from threatpilot.config.ai_config import AIConfig
from threatpilot.ai.factory import create_ai_provider
from threatpilot.ai.analyzer import ThreatAnalyzer
from threatpilot.core.dfd_converter import convert_to_dfd
from threatpilot.core.threat_model import Threat, Vulnerability

if TYPE_CHECKING:
    from threatpilot.ui.main_window import MainWindow

class DesignerHandler(BaseHTTPRequestHandler):
    """Request handler for serving the React designer frontend and REST API endpoints."""

    def log_message(self, format: str, *args: Any) -> None:
        # Override to suppress standard HTTP logging to console to keep CLI clean
        pass

    def _set_headers(self, status: int = 200, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.end_headers()

    def is_authorized(self) -> bool:
        client_ip = self.client_address[0]
        if client_ip in ("127.0.0.1", "localhost", "::1"):
            return True
        if not getattr(self.server, "sharing_active", False):
            return False
        
        cookie_header = self.headers.get("Cookie", "")
        if "threatpilot_session=" in cookie_header:
            import re
            match = re.search(r"threatpilot_session=([a-zA-Z0-9]+)", cookie_header)
            if match:
                token = match.group(1)
                if token in getattr(self.server, "authenticated_sessions", set()):
                    return True
        return False

    def check_auth(self) -> bool:
        if self.is_authorized():
            return True
        if self.path == "/auth" or self.path == "/api/auth/verify":
            return True
        
        if self.path.startswith("/api/"):
            self._set_headers(401)
            self.wfile.write(json.dumps({"error": "Unauthorized"}).encode("utf-8"))
        else:
            self.send_response(302)
            self.send_header("Location", "/auth")
            self.end_headers()
        return False

    def handle_verify_pin(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        try:
            data = json.loads(post_data.decode("utf-8"))
            pin = data.get("pin", "").strip()
            
            server_pin = getattr(self.server, "pin_code", "")
            if server_pin and pin == server_pin:
                import uuid
                session_token = uuid.uuid4().hex
                if not hasattr(self.server, "authenticated_sessions"):
                    self.server.authenticated_sessions = set()
                self.server.authenticated_sessions.add(session_token)
                
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                
                # Build secure session cookie
                cookie_parts = [f"threatpilot_session={session_token}", "Path=/", "SameSite=Strict", "HttpOnly", "Max-Age=86400"]
                if getattr(self.server, "use_https", False):
                    cookie_parts.append("Secure")
                self.send_header("Set-Cookie", "; ".join(cookie_parts))
                
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                self.end_headers()
                
                self.wfile.write(json.dumps({"status": "success", "token": session_token}).encode("utf-8"))
            else:
                self._set_headers(401)
                self.wfile.write(json.dumps({"error": "Invalid PIN"}).encode("utf-8"))
        except Exception as e:
            self._set_headers(500)
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

    def do_OPTIONS(self) -> None:
        self._set_headers(200)

    def do_GET(self) -> None:
        if not self.check_auth():
            return
            
        req_path = self.path.split("?")[0]
        
        if req_path == "/auth":
            self._set_headers(200, content_type="text/html")
            self.wfile.write(AUTH_HTML.encode("utf-8"))
            return

        if req_path == "/api/project":
            self.handle_get_project()
        elif req_path == "/api/project/metadata":
            self.handle_get_metadata()
        elif req_path == "/api/project/prompt_config":
            self.handle_get_prompt_config()
        elif req_path == "/api/ai/config":
            self.handle_get_ai_config()
        elif req_path == "/api/ai/status":
            self.handle_get_ai_status()
        elif req_path == "/api/ai/mitigations/status":
            self.handle_get_mitigations_status()
        elif req_path == "/api/export/excel":
            self.handle_export_excel()
        elif req_path == "/api/export/html":
            self.handle_export_html()
        elif req_path == "/api/export/checklist":
            self.handle_export_checklist()
        elif req_path == "/api/export/checklist_excel":
            self.handle_export_checklist_excel()
        elif req_path == "/api/ai/ollama/models":
            self.handle_get_ollama_models()
        else:
            self.handle_serve_static()

    def do_POST(self) -> None:
        if not self.check_auth():
            return
            
        req_path = self.path.split("?")[0]
        
        if req_path == "/api/auth/verify":
            self.handle_verify_pin()
            return

        if req_path == "/api/project" or req_path == "/api/project/autosave":
            self.handle_save_project()
        elif req_path == "/api/project/prompt_config":
            self.handle_save_prompt_config()
        elif req_path == "/api/ai/config":
            self.handle_save_ai_config()
        elif req_path == "/api/ai/analyze":
            self.handle_run_ai_analysis()
        elif req_path == "/api/ai/mitigations":
            self.handle_run_mitigations_review()
        elif req_path == "/api/project/image":
            self.handle_save_project_image()
        elif req_path == "/api/ai/reason":
            self.handle_generate_reasoning()
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Not Found"}).encode("utf-8"))

    def handle_get_project(self) -> None:
        mw = self.server.main_window
        if not mw or not mw._project:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "No project loaded"}).encode("utf-8"))
            return

        project = mw._project
        # Extract architecture elements matching architecture.json structure
        arch_data = {
            "diagrams": [d.model_dump() for d in project.diagrams],
            "components": [c.model_dump() for c in project.components],
            "flows": [f.model_dump() for f in project.flows],
            "boundaries": [b.model_dump() for b in project.boundaries],
            "assets": [a.model_dump() for a in project.assets],
            "custom_component_types": project.custom_component_types,
            "threats": [t.model_dump() for t in project.threat_register.threats],
            "vulnerabilities": [v.model_dump() for v in project.vulnerability_register.vulnerabilities],
            "mitigation_requirements": [req.model_dump() for req in getattr(project, "mitigation_requirements", [])]
        }
        self._set_headers(200)
        self.wfile.write(json.dumps(arch_data, indent=2).encode("utf-8"))

    def handle_get_metadata(self) -> None:
        mw = self.server.main_window
        if not mw or not mw._project:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "No project loaded"}).encode("utf-8"))
            return

        project = mw._project
        metadata = {
            "project_name": project.project_name,
            "project_path": project.project_path,
            "created_at": project.created_at,
            "updated_at": project.updated_at
        }
        self._set_headers(200)
        self.wfile.write(json.dumps(metadata, indent=2).encode("utf-8"))

    def handle_get_prompt_config(self) -> None:
        mw = self.server.main_window
        if not mw or not mw._project:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "No project loaded"}).encode("utf-8"))
            return

        pc = mw._project.prompt_config
        data = {
            "risk_preference": pc.risk_preference,
            "security_posture": pc.security_posture,
            "compliance_priority": pc.compliance_priority,
            "industry_context": pc.industry_context,
            "business_context_policy": pc.business_context_policy,
            "custom_prompt": pc.custom_prompt
        }
        self._set_headers(200)
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def handle_save_prompt_config(self) -> None:
        mw = self.server.main_window
        if not mw or not mw._project:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "No project loaded"}).encode("utf-8"))
            return

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data.decode("utf-8"))
            pc = mw._project.prompt_config
            
            pc.risk_preference = data.get("risk_preference", pc.risk_preference)
            pc.security_posture = data.get("security_posture", pc.security_posture)
            pc.compliance_priority = data.get("compliance_priority", pc.compliance_priority)
            pc.industry_context = data.get("industry_context", pc.industry_context)
            pc.business_context_policy = data.get("business_context_policy", pc.business_context_policy)
            pc.custom_prompt = data.get("custom_prompt", pc.custom_prompt)
            
            # Persist back to project directory
            save_project(mw._project)
            
            self._set_headers(200)
            self.wfile.write(json.dumps({"status": "success", "message": "Business context saved successfully"}).encode("utf-8"))
        except Exception as e:
            self._set_headers(500)
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

    def handle_save_project(self) -> None:
        mw = self.server.main_window
        if not mw or not mw._project:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "No project loaded"}).encode("utf-8"))
            return

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data.decode("utf-8"))
            project = mw._project

            # Hydrate components, flows, boundaries, assets, and custom types
            project.components = [Component.model_validate(c) for c in data.get("components", [])]
            project.flows = [Flow.model_validate(f) for f in data.get("flows", [])]
            project.boundaries = [TrustBoundary.model_validate(b) for b in data.get("boundaries", [])]
            project.assets = [Asset.model_validate(a) for a in data.get("assets", [])]
            project.custom_component_types = data.get("custom_component_types", [])

            if "threats" in data:
                project.threat_register.threats = [Threat.model_validate(t) for t in data["threats"]]
            if "vulnerabilities" in data:
                project.vulnerability_register.vulnerabilities = [Vulnerability.model_validate(v) for v in data["vulnerabilities"]]
            if "mitigation_requirements" in data:
                from threatpilot.core.domain_models import MitigationRequirement
                project.mitigation_requirements = [MitigationRequirement.model_validate(req) for req in data["mitigation_requirements"]]

            # Persist back to project directory
            save_project(project)

            # Inform GUI thread using safe connection callback
            if hasattr(self.server, "on_save_callback") and self.server.on_save_callback:
                self.server.on_save_callback()

            self._set_headers(200)
            self.wfile.write(json.dumps({"status": "success", "message": "Project saved successfully"}).encode("utf-8"))
        except Exception as e:
            self._set_headers(500)
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

    def handle_save_project_image(self) -> None:
        mw = self.server.main_window
        if not mw or not mw._project:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "No project loaded"}).encode("utf-8"))
            return

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        try:
            data = json.loads(post_data.decode("utf-8"))
            image_data = data.get("image")
            if not image_data:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": "Missing image parameter"}).encode("utf-8"))
                return

            if "," in image_data:
                image_data = image_data.split(",", 1)[1]

            import base64
            img_bytes = base64.b64decode(image_data)

            # Save as architecture.jpg in project path (project directory is mw._project.project_path)
            project_dir = Path(mw._project.project_path).parent
            output_path = project_dir / "architecture.jpg"
            with open(output_path, "wb") as f:
                f.write(img_bytes)

            self._set_headers(200)
            self.wfile.write(json.dumps({"status": "success", "message": f"Image saved successfully to {output_path.name}"}).encode("utf-8"))
        except Exception as e:
            self._set_headers(500)
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

    def handle_get_ai_config(self) -> None:
        try:
            config = AIConfig.load()
            data = {
                "provider_type": config.provider_type,
                "endpoint_url": config.endpoint_url,
                "model_name": config.model_name,
                "gemini_api_key": config.gemini_api_key.get_secret_value() if config.gemini_api_key else "",
                "max_tokens": config.max_tokens
            }
            self._set_headers(200)
            self.wfile.write(json.dumps(data).encode("utf-8"))
        except Exception as e:
            self._set_headers(500)
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

    def handle_save_ai_config(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        try:
            data = json.loads(post_data.decode("utf-8"))
            config = AIConfig.load()
            config.provider_type = data.get("provider_type", config.provider_type)
            config.endpoint_url = data.get("endpoint_url", config.endpoint_url)
            config.model_name = data.get("model_name", config.model_name)
            if "max_tokens" in data:
                config.max_tokens = int(data["max_tokens"])
            if "gemini_api_key" in data:
                config.gemini_api_key = SecretStr(data["gemini_api_key"])
            config.save()
            self._set_headers(200)
            self.wfile.write(json.dumps({"status": "success", "message": "AI configuration saved successfully"}).encode("utf-8"))
        except Exception as e:
            self._set_headers(500)
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

    def handle_get_ai_status(self) -> None:
        self._set_headers(200)
        self.wfile.write(json.dumps(self.server.web_analysis_state).encode("utf-8"))

    def handle_get_mitigations_status(self) -> None:
        self._set_headers(200)
        self.wfile.write(json.dumps(self.server.web_mitigations_state).encode("utf-8"))

    def handle_get_ollama_models(self) -> None:
        """Proxy-fetch installed models from the local Ollama instance's /api/tags endpoint."""
        try:
            config = AIConfig.load()
            endpoint = (config.endpoint_url or "http://localhost:11434").rstrip("/")
            import urllib.request
            req = urllib.request.Request(f"{endpoint}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                models = [m.get("name", "") for m in data.get("models", []) if m.get("name")]
            self._set_headers(200)
            self.wfile.write(json.dumps({"models": models}).encode("utf-8"))
        except Exception as e:
            self._set_headers(200)
            self.wfile.write(json.dumps({"models": [], "error": str(e)}).encode("utf-8"))

    def handle_run_ai_analysis(self) -> None:
        mw = self.server.main_window
        if not mw or not mw._project:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "No project loaded"}).encode("utf-8"))
            return

        if self.server.web_analysis_state.get("status") == "running":
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": "AI analysis is already running"}).encode("utf-8"))
            return

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        try:
            data = json.loads(post_data.decode("utf-8"))
            mode = data.get("mode", "STRIDE")
            iterations = int(data.get("iterations", 1))
            iterations = max(1, min(iterations, 5))

            config = AIConfig.load()
            config.analysis_mode = mode
            provider = create_ai_provider(config)

            dfd = convert_to_dfd(
                mw._project.components,
                mw._project.flows,
                mw._project.boundaries,
                mw._project.assets
            )

            # Reset state
            self.server.web_analysis_state.update({
                "status": "running",
                "current_iteration": 1,
                "total_iterations": iterations,
                "current_segment": 0,
                "total_segments": 0,
                "new_threats": 0,
                "error": None
            })

            # Run in background thread
            thread = threading.Thread(
                target=run_web_analysis,
                args=(
                    self.server,
                    mw._project,
                    provider,
                    mw._project.prompt_config,
                    dfd,
                    mw._project.project_name,
                    iterations
                )
            )
            thread.daemon = True
            thread.start()

            self._set_headers(200)
            self.wfile.write(json.dumps({"status": "started", "message": "AI analysis started in background"}).encode("utf-8"))
        except Exception as e:
            self._set_headers(500)
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

    def handle_run_mitigations_review(self) -> None:
        mw = self.server.main_window
        if not mw or not mw._project:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "No project loaded"}).encode("utf-8"))
            return

        if self.server.web_mitigations_state.get("status") == "running":
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": "Mitigations review is already running"}).encode("utf-8"))
            return

        try:
            config = AIConfig.load()
            provider = create_ai_provider(config)

            self.server.web_mitigations_state.update({
                "status": "running",
                "progress": "Starting Mitigation review in background...",
                "error": None
            })

            thread = threading.Thread(
                target=run_web_mitigations_review,
                args=(
                    self.server,
                    mw._project,
                    provider
                )
            )
            thread.daemon = True
            thread.start()

            self._set_headers(200)
            self.wfile.write(json.dumps({"status": "started", "message": "Mitigation AI review started in background"}).encode("utf-8"))
        except Exception as e:
            self._set_headers(500)
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

    def handle_generate_reasoning(self) -> None:
        mw = self.server.main_window
        if not mw or not mw._project:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "No project loaded"}).encode("utf-8"))
            return

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        try:
            data = json.loads(post_data.decode("utf-8"))
            threat_id = data.get("threat_id")
            vuln_id = data.get("vulnerability_id")
            req_id = data.get("req_id")

            project = mw._project
            item = None
            is_vuln = False
            is_mit = False

            if threat_id:
                item = next((t for t in project.threat_register.threats if t.threat_id == threat_id), None)
            elif vuln_id:
                item = next((v for v in project.vulnerability_register.vulnerabilities if v.vulnerability_id == vuln_id), None)
                is_vuln = True
            elif req_id:
                item = next((r for r in project.mitigation_requirements if r.req_id == req_id), None)
                is_mit = True

            if not item:
                self._set_headers(404)
                self.wfile.write(json.dumps({"error": "Item not found"}).encode("utf-8"))
                return

            config = AIConfig.load()
            from threatpilot.core.threat_model import STRIDECategory
            mode = config.analysis_mode
            if not is_vuln and not is_mit and isinstance(item, Threat):
                if item.category.value in STRIDECategory.get_linddun_values():
                    mode = "LINDDUN"
                else:
                    mode = "STRIDE"

            provider = create_ai_provider(config)
            analyzer = ThreatAnalyzer(provider, project.prompt_config)
            analyzer.builder.analysis_mode = mode

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                if is_vuln:
                    reasoning = loop.run_until_complete(analyzer.analyze_vulnerability_reasoning(item))
                elif is_mit:
                    reasoning = loop.run_until_complete(analyzer.analyze_mitigation_reasoning(item))
                else:
                    reasoning = loop.run_until_complete(analyzer.analyze_reasoning(item))
            finally:
                loop.close()

            item.reasoning = reasoning
            save_project(project)

            # Trigger reload in main window GUI
            if hasattr(self.server, "on_save_callback") and self.server.on_save_callback:
                self.server.on_save_callback()

            self._set_headers(200)
            self.wfile.write(json.dumps({"status": "success", "reasoning": reasoning}).encode("utf-8"))
        except Exception as e:
            self._set_headers(500)
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

    def handle_export_excel(self) -> None:
        mw = self.server.main_window
        if not mw or not mw._project:
            self._set_headers(404)
            return

        from threatpilot.export.excel_exporter import export_to_excel
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tmp:
            tmp_path = tmp.name
        
        try:
            export_to_excel(mw._project, tmp_path)
            with open(tmp_path, "rb") as f:
                content = f.read()

            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            self.send_header("Content-Disposition", f"attachment; filename=\"{mw._project.project_name}_Risk_Matrix.xlsx\"")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self._set_headers(500)
            self.wfile.write(str(e).encode("utf-8"))
        finally:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass

    def handle_export_html(self) -> None:
        mw = self.server.main_window
        if not mw or not mw._project:
            self._set_headers(404)
            return

        from threatpilot.export.html_exporter import export_to_html
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
            tmp_path = tmp.name
        
        try:
            export_to_html(mw._project, tmp_path)
            with open(tmp_path, "rb") as f:
                content = f.read()

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Disposition", f"attachment; filename=\"{mw._project.project_name}_Security_Report.html\"")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self._set_headers(500)
            self.wfile.write(str(e).encode("utf-8"))
        finally:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass

    def handle_export_checklist(self) -> None:
        mw = self.server.main_window
        if not mw or not mw._project:
            self._set_headers(404)
            return

        from threatpilot.export.mitigation_exporter import export_mitigation_checklist_html
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
            tmp_path = tmp.name
        
        try:
            export_mitigation_checklist_html(mw._project, tmp_path)
            with open(tmp_path, "rb") as f:
                content = f.read()

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Disposition", f"attachment; filename=\"{mw._project.project_name}_Mitigation_Checklist.html\"")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self._set_headers(500)
            self.wfile.write(str(e).encode("utf-8"))
        finally:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass

    def handle_export_checklist_excel(self) -> None:
        mw = self.server.main_window
        if not mw or not mw._project:
            self._set_headers(404)
            return

        from threatpilot.export.mitigation_review_exporter import generate_mitigation_requirements_excel
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tmp:
            tmp_path = tmp.name
        
        try:
            req_dicts = [req.model_dump() for req in getattr(mw._project, "mitigation_requirements", [])]
            # If empty, let's create a basic list from existing threats
            if not req_dicts:
                req_dicts = []
                for idx, t in enumerate(mw._project.threat_register.threats):
                    if t.is_accepted_risk:
                        continue
                    mit = (t.mitigation or "").strip()
                    if not mit:
                        continue
                    req_dicts.append({
                        "req_id": f"SR-{idx + 1}",
                        "title": t.title,
                        "mitigation": mit,
                        "short_description": f"Security control to mitigate: {t.title}.",
                        "test_case": f"Verify implementation addresses: {t.title}.",
                        "affected_components": t.affected_components
                    })
                    
            generate_mitigation_requirements_excel(mw._project, req_dicts, tmp_path)
            with open(tmp_path, "rb") as f:
                content = f.read()

            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            self.send_header("Content-Disposition", f"attachment; filename=\"{mw._project.project_name}_Mitigation_Checklist.xlsx\"")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self._set_headers(500)
            self.wfile.write(str(e).encode("utf-8"))
        finally:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass

    def handle_serve_static(self) -> None:
        # Resolve path using dynamic environment helper
        dist_dir = get_designer_dist_path()

        clean_path = self.path.split("?")[0].lstrip("/")
        if not clean_path or clean_path == "":
            clean_path = "index.html"

        target_file = dist_dir / clean_path

        # Fallback to SPA routing for HTML requests (so client side router works)
        if not target_file.exists() or target_file.is_dir():
            target_file = dist_dir / "index.html"

        if not target_file.exists():
            # If still not found, return simple UI fallback
            self._set_headers(200, "text/html")
            fallback_html = """<!DOCTYPE html>
            <html>
            <head><title>ThreatPilot Designer</title></head>
            <body style="font-family: sans-serif; padding: 2rem; background: #0f172a; color: #f8fafc; text-align: center;">
                <h2>ThreatPilot Architecture Designer</h2>
                <p>Frontend assets are not built yet. Run <code>npm run build</code> in the designer directory.</p>
            </body>
            </html>"""
            self.wfile.write(fallback_html.encode("utf-8"))
            return

        content_type, _ = mimetypes.guess_type(str(target_file))
        if not content_type:
            content_type = "application/octet-stream"

        try:
            with open(target_file, "rb") as f:
                content = f.read()
            self._set_headers(200, content_type)
            self.wfile.write(content)
        except Exception as e:
            self._set_headers(500)
            self.wfile.write(str(e).encode("utf-8"))


def run_web_analysis(server: DesignerServer, project: Any, provider: Any, prompt_config: Any, dfd: Any, system_name: str, iterations: int) -> None:
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        all_register = None
        new_threats_count = 0
        
        for iteration in range(1, iterations + 1):
            analyzer = ThreatAnalyzer(provider, prompt_config)
            
            async def progress_cb_auto(current: int, total: int, _iter: int = iteration) -> bool:
                server.web_analysis_state.update({
                    "current_iteration": _iter,
                    "current_segment": current,
                    "total_segments": total
                })
                return True
                
            register, raw_resp, usage = loop.run_until_complete(
                analyzer.analyze(
                    dfd,
                    system_name,
                    progress_callback=progress_cb_auto,
                    result_callback=None,
                    prompt_callback=None,
                    response_callback=None
                )
            )
            
            if "Analysis cancelled by user" in raw_resp:
                server.web_analysis_state.update({
                    "status": "failed",
                    "error": "Analysis cancelled"
                })
                return
                
            if all_register is None:
                all_register = register
            else:
                for t in register.threats:
                    all_register.add_threat(t)
                if hasattr(register, "new_vulnerabilities"):
                    if not hasattr(all_register, "new_vulnerabilities"):
                        all_register.new_vulnerabilities = []
                    all_register.new_vulnerabilities.extend(register.new_vulnerabilities)

        # Merge results into the main project
        if all_register:
            for t in all_register.threats:
                if project.threat_register.add_threat(t):
                    new_threats_count += 1
            if hasattr(all_register, "new_vulnerabilities"):
                for v in all_register.new_vulnerabilities:
                    project.vulnerability_register.add_vulnerability(v)
            
            # Save the project
            save_project(project)
            
            # Trigger reload in main window GUI
            if hasattr(server, "on_save_callback") and server.on_save_callback:
                server.on_save_callback()
                
        server.web_analysis_state.update({
            "status": "completed",
            "new_threats": new_threats_count
        })
    except Exception as exc:
        server.web_analysis_state.update({
            "status": "failed",
            "error": str(exc)
        })
    finally:
        loop.close()


def run_web_mitigations_review(server: DesignerServer, project: Any, provider: Any) -> None:
    try:
        server.web_mitigations_state.update({
            "status": "running",
            "progress": "Gathering raw mitigations...",
            "error": None
        })
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            threats = project.threat_register.threats
            raw_items = []
            for t in threats:
                if t.is_accepted_risk:
                    continue
                mit = (t.mitigation or "").strip()
                if not mit:
                    continue
                elem, asset = t.resolve_affected_elements(project)
                component = elem or t.affected_components or "Unknown Component"
                raw_items.append({
                    "component": component,
                    "threat_title": t.title,
                    "mitigation": mit
                })

            if not raw_items:
                server.web_mitigations_state.update({
                    "status": "failed",
                    "error": "No active mitigations found to process."
                })
                return

            import re
            from threatpilot.ai.response_parser import extract_json
            from threatpilot.core.constants import MITIGATION_SIMILARITY_THRESHOLD, AI_MITIGATION_BATCH_SIZE

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
            SYNONYMS = {
                "scrub": "logclean", "scrubbing": "logclean", "redact": "logclean",
                "redaction": "logclean", "masking": "logclean", "mask": "logclean",
                "masks": "logclean", "masked": "logclean", "sanitization": "logclean",
                "sanitize": "logclean", "sanitizing": "logclean", "scrubbed": "logclean",
                "keystore": "hwkey", "keychain": "hwkey", "enclave": "hwkey", "enclaves": "hwkey",
                "hardwarebacked": "hwkey", "mtls": "mtls", "mutual": "mtls", "tls": "mtls",
                "pinning": "mtls", "certificate": "mtls", "certificates": "mtls",
                "waf": "waf", "firewall": "waf", "ratelimiting": "waf", "ddos": "waf",
                "consent": "privcon", "privacy": "privcon", "disclosure": "privcon",
                "transparency": "privcon", "mfa": "mfa", "multifactor": "mfa",
            }

            _keywords_cache = {}
            def extract_keywords(text: str) -> set:
                if text not in _keywords_cache:
                    cleaned = re.sub(r'[^a-z0-9 ]', ' ', text.lower())
                    words = cleaned.split()
                    result = set()
                    for w in words:
                        if w in STOP_WORDS or len(w) <= 2:
                            continue
                        result.add(SYNONYMS.get(w, w))
                    _keywords_cache[text] = result
                return _keywords_cache[text]

            def keyword_similarity(a: str, b: str) -> float:
                ka, kb = extract_keywords(a), extract_keywords(b)
                if not ka or not kb:
                    return 0.0
                intersection = ka & kb
                if not intersection:
                    return 0.0
                union = ka | kb
                return len(intersection) / len(union) if union else 0.0

            groups = []
            n = len(raw_items)
            
            for i in range(n):
                server.web_mitigations_state.update({
                    "progress": f"Analyzing similarity... {int((i + 1) / n * 100)}% ({i+1}/{n})"
                })
                best_group = None
                best_sim = 0.0
                for g_idx, members in enumerate(groups):
                    for m_idx in members:
                        sim = keyword_similarity(raw_items[i]["mitigation"], raw_items[m_idx]["mitigation"])
                        if sim >= MITIGATION_SIMILARITY_THRESHOLD and sim > best_sim:
                            best_sim = sim
                            best_group = g_idx
                            break
                if best_group is not None:
                    groups[best_group].append(i)
                else:
                    groups.append([i])

            all_requirements = []
            for group_indices in groups:
                group_items = [raw_items[i] for i in group_indices]
                components = set()
                for item in group_items:
                    for comp in item["component"].split(","):
                        components.add(comp.strip())
                best_item = max(group_items, key=lambda x: len(x["mitigation"]))
                all_requirements.append({
                    "mitigation": best_item["mitigation"],
                    "short_description": f"Security control to mitigate: {best_item['threat_title']}.",
                    "test_case": f"Verify implementation addresses: {best_item['threat_title']}.",
                    "affected_components": ", ".join(sorted(components)),
                    "_threat_title": best_item["threat_title"]
                })

            title_system = (
                "You are a security architect. For each mitigation below, output a short 2-5 word title.\n"
                "Output a JSON object mapping the index to the title.\n"
                "Example: {\"0\": \"Multi-Factor Authentication\", \"1\": \"Log Masking\"}\n"
                "Do not include any text outside the JSON object."
            )
            async def call_ai(p):
                return await provider.chat_complete(p, system_instructions=title_system, response_mime_type="application/json")

            title_batch_size = AI_MITIGATION_BATCH_SIZE
            num_title_batches = (len(all_requirements) + title_batch_size - 1) // title_batch_size
            
            for batch_idx in range(num_title_batches):
                start = batch_idx * title_batch_size
                end = min(start + title_batch_size, len(all_requirements))
                batch_reqs = all_requirements[start:end]
                
                server.web_mitigations_state.update({
                    "progress": f"Generating requirement titles (Batch {batch_idx+1}/{num_title_batches})..."
                })
                
                title_map = {str(i): req["mitigation"][:120] for i, req in enumerate(batch_reqs)}
                title_prompt = f"Generate a short title for each mitigation:\n\n{json.dumps(title_map, indent=2)}"
                
                response_text, _ = loop.run_until_complete(call_ai(title_prompt))
                titles = extract_json(response_text)
                if titles and isinstance(titles, dict):
                    for idx_str, title in titles.items():
                        try:
                            idx = int(idx_str)
                            if 0 <= idx < len(batch_reqs):
                                all_requirements[start + idx]["title"] = title.strip()
                        except Exception:
                            continue

            for req in all_requirements:
                if "title" not in req or not req["title"]:
                    req["title"] = req.get("_threat_title", "Security Control")
                req.pop("_threat_title", None)

            for idx, req in enumerate(all_requirements):
                req['req_id'] = f"SR-{idx + 1}"

            from threatpilot.core.domain_models import MitigationRequirement
            req_objects = []
            for req in all_requirements:
                existing_req = next((r for r in project.mitigation_requirements if r.req_id == req.get("req_id", "")), None)
                existing_reasoning = existing_req.reasoning if existing_req else ""
                req_objects.append(MitigationRequirement(
                    req_id=req.get("req_id", ""),
                    title=req.get("title", ""),
                    affected_components=req.get("affected_components", ""),
                    mitigation=req.get("mitigation", ""),
                    short_description=req.get("short_description", ""),
                    test_case=req.get("test_case", ""),
                    reasoning=existing_reasoning
                ))
            
            project.mitigation_requirements = req_objects
            save_project(project)

            if hasattr(server, "on_save_callback") and server.on_save_callback:
                server.on_save_callback()

            server.web_mitigations_state.update({
                "status": "completed",
                "progress": "Mitigation AI Review complete!"
            })
        finally:
            loop.close()
    except Exception as e:
        server.web_mitigations_state.update({
            "status": "failed",
            "error": str(e)
        })


class DesignerServer(HTTPServer):
    """Custom HTTPServer class to hold references to main window and callbacks."""
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], RequestHandlerClass: type[BaseHTTPRequestHandler], main_window: MainWindow, on_save_callback: Any = None) -> None:
        self.main_window = main_window
        self.on_save_callback = on_save_callback
        self.sharing_active: bool = False
        self.use_https: bool = False
        self.pin_code: str = ""
        self.authenticated_sessions: set[str] = set()
        self.web_analysis_state = {
            "status": "idle",
            "current_iteration": 0,
            "total_iterations": 0,
            "current_segment": 0,
            "total_segments": 0,
            "new_threats": 0,
            "error": None
        }
        self.web_mitigations_state = {
            "status": "idle",
            "progress": "",
            "error": None
        }
        super().__init__(server_address, RequestHandlerClass)


class DesignerServerThread(threading.Thread):
    """Daemon thread for running the HTTP designer server."""
    def __init__(self, main_window: MainWindow, host: str = "127.0.0.1", port: int = 8080, on_save_callback: Any = None, use_https: bool = False, shared: bool = False, pin: str = "") -> None:
        super().__init__()
        self.daemon = True
        self.main_window = main_window
        self.host = host
        self.port = port
        self.on_save_callback = on_save_callback
        self.use_https = use_https
        self.shared = shared
        self.pin = pin
        self.server: DesignerServer | None = None

    def run(self) -> None:
        try:
            self.server = DesignerServer((self.host, self.port), DesignerHandler, self.main_window, self.on_save_callback)
            self.server.sharing_active = self.shared
            self.server.use_https = self.use_https
            self.server.pin_code = self.pin
            self.server.authenticated_sessions = set()
            if self.use_https:
                import ssl
                from threatpilot.utils.paths import SSL_CERT_FILE, SSL_KEY_FILE
                if SSL_CERT_FILE.exists() and SSL_KEY_FILE.exists():
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(certfile=str(SSL_CERT_FILE), keyfile=str(SSL_KEY_FILE))
                    self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
                else:
                    print("HTTPS requested but certificates not found. Falling back to HTTP.")
            self.server.serve_forever()
        except Exception as e:
            print(f"Error in DesignerServerThread: {e}")

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()


AUTH_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ThreatPilot Web Workspace Authentication</title>
  <style>
    body {
      background: #0b0f19;
      color: #f3f4f6;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100vh;
      margin: 0;
    }
    .card {
      background: #111827;
      border: 1px solid #1f2937;
      padding: 2.5rem;
      border-radius: 1rem;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
      width: 100%;
      max-width: 380px;
      text-align: center;
      box-sizing: border-box;
    }
    h2 {
      margin-top: 0;
      color: #3b82f6;
      font-size: 1.5rem;
    }
    p {
      color: #9ca3af;
      font-size: 0.875rem;
      line-height: 1.5;
      margin-bottom: 2rem;
    }
    input {
      width: 100%;
      background: #1f2937;
      border: 1px solid #374151;
      padding: 0.75rem;
      color: #fff;
      font-size: 1.25rem;
      letter-spacing: 0.25em;
      text-align: center;
      border-radius: 0.5rem;
      margin-bottom: 1.5rem;
      box-sizing: border-box;
    }
    input:focus {
      outline: none;
      border-color: #3b82f6;
    }
    button {
      width: 100%;
      background: #2563eb;
      color: #fff;
      border: none;
      padding: 0.75rem;
      font-size: 0.875rem;
      font-weight: bold;
      border-radius: 0.5rem;
      cursor: pointer;
      transition: background 0.2s;
    }
    button:hover {
      background: #1d4ed8;
    }
    .error {
      color: #ef4444;
      font-size: 0.875rem;
      margin-top: 1rem;
      display: none;
    }
  </style>
</head>
<body>
  <div class="card">
    <h2>ThreatPilot Workspace</h2>
    <p>Please enter the 8-digit PIN generated by the ThreatPilot desktop application to access this visual architecture model.</p>
    <input type="text" id="pin" maxlength="8" placeholder="00000000" autocomplete="off" />
    <button onclick="verifyPin()">Authenticate Session</button>
    <div class="error" id="error">Invalid PIN. Please try again.</div>
  </div>

  <script>
    async function verifyPin() {
      const pin = document.getElementById('pin').value;
      const errorDiv = document.getElementById('error');
      errorDiv.style.display = 'none';

      try {
        const res = await fetch('/api/auth/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pin })
        });
        if (res.ok) {
          // The backend sets the HttpOnly cookie securely via the Set-Cookie header.
          window.location.href = '/';
        } else {
          errorDiv.style.display = 'block';
        }
      } catch (e) {
        console.error(e);
        errorDiv.innerText = 'Connection error. Please try again.';
        errorDiv.style.display = 'block';
      }
    }
    document.getElementById('pin').addEventListener('keypress', function(e) {
      if (e.key === 'Enter') {
        verifyPin();
      }
    });
  </script>
</body>
</html>
"""

