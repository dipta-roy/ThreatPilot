"""Lightweight HTTP REST Server for the ThreatPilot Architecture Designer."""

from __future__ import annotations
import json
import os
import mimetypes
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any

from threatpilot.core.project_manager import save_project
from threatpilot.core.domain_models import Component, Flow, TrustBoundary, Asset
from threatpilot.utils.paths import get_designer_dist_path

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
        self.end_headers()

    def do_OPTIONS(self) -> None:
        self._set_headers(200)

    def do_GET(self) -> None:
        if self.path == "/api/project":
            self.handle_get_project()
        elif self.path == "/api/project/metadata":
            self.handle_get_metadata()
        else:
            self.handle_serve_static()

    def do_POST(self) -> None:
        if self.path == "/api/project" or self.path == "/api/project/autosave":
            self.handle_save_project()
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
            "custom_component_types": project.custom_component_types
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


class DesignerServer(HTTPServer):
    """Custom HTTPServer class to hold references to main window and callbacks."""
    def __init__(self, server_address: tuple[str, int], RequestHandlerClass: type[BaseHTTPRequestHandler], main_window: MainWindow, on_save_callback: Any = None) -> None:
        self.main_window = main_window
        self.on_save_callback = on_save_callback
        super().__init__(server_address, RequestHandlerClass)


class DesignerServerThread(threading.Thread):
    """Daemon thread for running the HTTP designer server."""
    def __init__(self, main_window: MainWindow, host: str = "127.0.0.1", port: int = 8080, on_save_callback: Any = None) -> None:
        super().__init__()
        self.daemon = True
        self.main_window = main_window
        self.host = host
        self.port = port
        self.on_save_callback = on_save_callback
        self.server: DesignerServer | None = None

    def run(self) -> None:
        try:
            self.server = DesignerServer((self.host, self.port), DesignerHandler, self.main_window, self.on_save_callback)
            self.server.serve_forever()
        except Exception as e:
            print(f"Error in DesignerServerThread: {e}")

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
