"""
HONEYTRACE - Standalone Application Launcher
Entrypoint for PyInstaller or direct script execution.
Launches the HTTP & SSH low-interaction honeypots and opens the Streamlit SOC Dashboard.
"""

import os
import sys
import threading
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from honeypots.http_decoy import get_http_decoy
from honeypots.ssh_decoy import get_ssh_decoy
from simulation.demo_scenarios import DemoScenarios
from core.database import DatabaseManager


def start_services():
    """Starts background decoy honeypots and verifies seed data."""
    print("=" * 65)
    print("      HONEYTRACE DECEPTION PLATFORM - INITIALIZING SERVICES      ")
    print("=" * 65)

    # Pre-seed sample dataset if missing
    db = DatabaseManager()
    kpis = db.get_kpis()
    if kpis["total_events"] == 0:
        print("[*] Empty database detected. Populating sample telemetry...")
        DemoScenarios().run_all()

    # Start HTTP decoy
    try:
        http_decoy = get_http_decoy(host="127.0.0.1", port=8080)
        http_decoy.start()
        print("[+] HTTP Decoy Honeypot active on: http://127.0.0.1:8080")
    except Exception as e:
        print(f"[!] Warning: HTTP decoy startup: {e}")

    # Start SSH decoy
    try:
        ssh_decoy = get_ssh_decoy(host="127.0.0.1", port=2222)
        ssh_decoy.start()
        print("[+] SSH Decoy Honeypot active on:  tcp://127.0.0.1:2222")
    except Exception as e:
        print(f"[!] Warning: SSH decoy startup: {e}")

    print("=" * 65)


def run_streamlit():
    """Launches the Streamlit SOC dashboard."""
    import streamlit.web.bootstrap as bootstrap
    from streamlit import config as _config

    _config.set_option("server.headless", False)
    _config.set_option("browser.serverAddress", "localhost")
    _config.set_option("server.port", 8501)

    app_path = str(ROOT_DIR / "app.py")
    bootstrap.run(app_path, False, [], flag_options={})


if __name__ == "__main__":
    start_services()
    print("[*] Launching Streamlit SOC Dashboard on http://localhost:8501...")
    run_streamlit()

