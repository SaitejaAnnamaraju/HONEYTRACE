"""
HONEYTRACE - HTTP Deception Decoy Service
Flask-based high-fidelity web honeypot emulating enterprise portals,
admin panels, LFI vulnerabilities, SQLi endpoints, and sensitive file traps.
100% localhost-only, strictly non-executing, safe deception.
"""

import logging
import threading
import time
from typing import Optional
from flask import Flask, Response, jsonify, render_template_string, request
from werkzeug.serving import make_server

from core.database import DatabaseManager
from core.event_collector import EventCollector

logger = logging.getLogger("honeytrace.http_decoy")

# HTML Template for Fake Enterprise Portal
LOGIN_PAGE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Enterprise Secure Gateway - Corporate Intranet</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 2rem; width: 380px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
        h2 { margin-top: 0; color: #38bdf8; font-size: 1.5rem; text-align: center; }
        p.sub { font-size: 0.85rem; color: #94a3b8; text-align: center; margin-bottom: 1.5rem; }
        .form-group { margin-bottom: 1.25rem; }
        label { display: block; font-size: 0.85rem; margin-bottom: 0.4rem; color: #cbd5e1; }
        input[type="text"], input[type="password"] { width: 100%; box-sizing: border-box; padding: 0.65rem; background: #0f172a; border: 1px solid #475569; border-radius: 4px; color: #fff; font-size: 0.95rem; }
        input[type="text"]:focus, input[type="password"]:focus { outline: none; border-color: #38bdf8; }
        button { width: 100%; padding: 0.75rem; background: #0284c7; color: white; border: none; border-radius: 4px; font-weight: 600; cursor: pointer; transition: background 0.2s; }
        button:hover { background: #0369a1; }
        .alert { background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #fca5a5; padding: 0.65rem; border-radius: 4px; font-size: 0.85rem; margin-bottom: 1rem; display: {{ 'block' if error else 'none' }}; }
        .footer { font-size: 0.75rem; color: #64748b; text-align: center; margin-top: 1.5rem; }
    </style>
</head>
<body>
    <div class="card">
        <h2>HONEYCORP</h2>
        <p class="sub">Authorized Personnel Only - Restricted Access</p>
        <div class="alert">{{ error or '' }}</div>
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username or Corporate ID</label>
                <input type="text" id="username" name="username" required autocomplete="off" placeholder="admin@honeycorp.local">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required placeholder="••••••••••••">
            </div>
            <button type="submit">Sign In</button>
        </form>
        <div class="footer">HoneyCorp SSO Gateway v4.8.1-sec &bull; All activity monitored</div>
    </div>
</body>
</html>
"""


class HTTPDecoyServer:
    """Manages the Flask HTTP honeypot daemon on localhost."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.app = Flask("HoneyTraceHTTPDecoy")
        self.collector = EventCollector()
        self.db = DatabaseManager()
        self._server = None
        self._thread: Optional[threading.Thread] = None
        self._is_running = False
        self._setup_routes()

    def _log_interaction(self, event_type: str, username: str = "", password: str = "", payload: str = "") -> None:
        """Packages and ships raw interaction to collector."""
        src_ip = request.remote_addr or "127.0.0.1"
        endpoint = request.path
        method = request.method
        headers_dict = dict(request.headers)
        user_agent = request.headers.get("User-Agent", "Unknown")

        # Compile body payload safely without execution
        if not payload:
            if request.data:
                payload = request.data.decode("utf-8", errors="replace")[:1000]
            elif request.form:
                payload = str(dict(request.form))[:1000]
            elif request.query_string:
                payload = request.query_string.decode("utf-8", errors="replace")[:1000]

        event_data = {
            "source_ip": src_ip,
            "source_port": request.environ.get("REMOTE_PORT", 0),
            "honeypot_type": "HTTP",
            "protocol": "HTTP",
            "event_type": event_type,
            "endpoint": endpoint,
            "http_method": method,
            "username": username,
            "password": password,
            "payload": payload,
            "headers": headers_dict,
            "user_agent": user_agent,
            "session_id": request.cookies.get("session", "")
        }
        self.collector.collect(event_data)

    def _setup_routes(self) -> None:
        """Defines all deceptive endpoints."""

        @self.app.route("/", methods=["GET"])
        def index():
            self._log_interaction("PORTAL_VISIT", payload="GET / Homepage")
            return render_template_string(LOGIN_PAGE_HTML, error=None)

        @self.app.route("/login", methods=["GET", "POST"])
        @self.app.route("/admin", methods=["GET", "POST"])
        @self.app.route("/admin/login", methods=["GET", "POST"])
        def admin_login():
            if request.method == "POST":
                username = request.form.get("username", "") or request.form.get("user", "")
                password = request.form.get("password", "") or request.form.get("pass", "")
                self._log_interaction(
                    "LOGIN_ATTEMPT",
                    username=username,
                    password=password,
                    payload=f"Auth probe username={username}"
                )
                # Realistic authentication rejection
                return render_template_string(
                    LOGIN_PAGE_HTML,
                    error="Authentication failed: Invalid credentials or account locked."
                ), 401
            self._log_interaction("ADMIN_PROBE", payload=f"Navigated to {request.path}")
            return render_template_string(LOGIN_PAGE_HTML, error=None)

        # Sensitive Config Decoys
        @self.app.route("/.env", methods=["GET"])
        def env_trap():
            self._log_interaction("CONFIG_PROBE", payload="Attempted .env download")
            decoy_env = (
                "APP_ENV=production\n"
                "APP_KEY=base64:decoyhoneytracekey9876543210=\n"
                "DB_HOST=127.0.0.1\n"
                "DB_USER=root\n"
                "DB_PASSWORD=HoneyTraceDecoySecret2026!\n"
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            )
            return Response(decoy_env, mimetype="text/plain", status=200)

        @self.app.route("/wp-config.php", methods=["GET"])
        @self.app.route("/config.json", methods=["GET"])
        @self.app.route("/web.config", methods=["GET"])
        def config_traps():
            self._log_interaction("CONFIG_PROBE", payload=f"Probed {request.path}")
            return "<!-- Decoy Config -->\n<?php define('DB_PASSWORD', 'TrapPass2026'); ?>", 200

        # LFI / Directory Traversal Decoy
        @self.app.route("/view", methods=["GET"])
        @self.app.route("/api/view", methods=["GET"])
        def lfi_trap():
            file_param = request.args.get("file", "") or request.args.get("path", "")
            self._log_interaction("DIRECTORY_TRAVERSAL", payload=f"file={file_param}")

            # Return fake mock /etc/passwd if probed
            if "passwd" in file_param:
                fake_passwd = (
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    "honeycorp_admin:x:1000:1000:HoneyCorp Admin,,,:/home/honeycorp:/bin/bash\n"
                    "deploy:x:1001:1001::/home/deploy:/bin/sh\n"
                )
                return Response(fake_passwd, mimetype="text/plain", status=200)

            if "win.ini" in file_param.lower():
                return Response("[fonts]\n[extensions]\n; for 16-bit app support", mimetype="text/plain", status=200)

            return jsonify({"status": "error", "message": "File not found or permission denied"}), 404

        # SQL Injection Trap API
        @self.app.route("/api/v1/users", methods=["GET", "POST"])
        @self.app.route("/api/v1/search", methods=["GET"])
        def sqli_trap():
            q = request.args.get("q", "") or request.args.get("id", "")
            self._log_interaction("SQL_INJECTION", payload=f"Search/User query: {q}")
            if any(term in q.upper() for term in ["SELECT", "UNION", "'", "--", "OR"]):
                # Return realistic simulated SQL error to hook attacker
                return jsonify({
                    "status": "error",
                    "error_code": "SQL_SYNTAX_ERR",
                    "details": f"SQL syntax error near '{q[:20]}' at line 1 in SELECT * FROM tbl_users WHERE user_id = ..."
                }), 500
            return jsonify({"status": "success", "results": []}), 200

        # phpMyAdmin Trap
        @self.app.route("/phpmyadmin", methods=["GET", "POST"])
        @self.app.route("/pma", methods=["GET", "POST"])
        def pma_trap():
            self._log_interaction("PHPMYADMIN_PROBE", payload=f"Accessed {request.path}")
            return "<html><body><h1>phpMyAdmin 5.2.1</h1><p>Access forbidden for external network interface.</p></body></html>", 403

        # Catch-all Route for scanning / fuzzing
        @self.app.route("/<path:catch_all>", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
        def catch_all(catch_all):
            self._log_interaction(
                "SCANNER_PROBE",
                payload=f"{request.method} /{catch_all} Query:{request.query_string.decode('utf-8', errors='ignore')}"
            )
            return jsonify({
                "status": "error",
                "message": f"Resource /{catch_all} not found on this server",
                "code": 404
            }), 404

    def start(self) -> None:
        """Launches the HTTP decoy server on localhost in a dedicated thread."""
        if self._is_running:
            return

        try:
            self._server = make_server(self.host, self.port, self.app, threaded=True)
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True, name="HTTPDecoyThread")
            self._thread.start()
            self._is_running = True
            self.db.update_service_status("HTTP_DECOY", is_running=True, port=self.port, metadata={"host": self.host})
            logger.info(f"HTTP Decoy started successfully on http://{self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Failed to bind HTTP decoy to {self.host}:{self.port}: {e}")
            self._is_running = False
            self.db.update_service_status("HTTP_DECOY", is_running=False, port=self.port, metadata={"error": str(e)})

    def stop(self) -> None:
        """Gracefully halts the server."""
        if self._server:
            self._server.shutdown()
        self._is_running = False
        self.db.update_service_status("HTTP_DECOY", is_running=False, port=self.port)
        logger.info("HTTP Decoy stopped.")

    @property
    def is_running(self) -> bool:
        return self._is_running


# Module-level singleton helper
_http_instance: Optional[HTTPDecoyServer] = None
_http_lock = threading.Lock()


def get_http_decoy(host: str = "127.0.0.1", port: int = 8080) -> HTTPDecoyServer:
    global _http_instance
    with _http_lock:
        if _http_instance is None:
            _http_instance = HTTPDecoyServer(host=host, port=port)
        return _http_instance

