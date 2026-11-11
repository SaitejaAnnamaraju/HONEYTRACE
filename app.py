"""
HONEYTRACE - Main Streamlit Application Entrypoint
AI-Assisted Deception-Based Intrusion Detection & Attack Intelligence Platform.
Engineered as an Enterprise-Grade Cybersecurity SOC Command Center.
"""

import os
import sys
import time
from pathlib import Path

# Ensure HoneyTrace root is in python path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st
from PIL import Image

from core.database import DatabaseManager
from honeypots.http_decoy import get_http_decoy
from honeypots.ssh_decoy import get_ssh_decoy
from simulation.demo_scenarios import DemoScenarios

# Design System Theme Engine
from dashboard.theme import apply_custom_css, render_top_header

# 7 Dashboard Page Views
from dashboard.overview import render_overview
from dashboard.live_monitor import render_live_monitor
from dashboard.honeypot_mgmt import render_honeypot_mgmt
from dashboard.threat_analysis import render_threat_analysis
from dashboard.incident_investigation import render_incident_investigation
from dashboard.attack_timeline import render_attack_timeline
from dashboard.reports import render_reports

# Page Configuration
st.set_page_config(
    page_title="HONEYTRACE | Enterprise Cybersecurity SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply World-Class Master SOC Theme CSS
apply_custom_css()


def init_state():
    """Initializes session state and starts decoy services safely on first load."""
    if "db" not in st.session_state:
        st.session_state.db = DatabaseManager()

    if "http_decoy" not in st.session_state:
        st.session_state.http_decoy = get_http_decoy(host="127.0.0.1", port=8080)
        try:
            st.session_state.http_decoy.start()
        except Exception:
            pass

    if "ssh_decoy" not in st.session_state:
        st.session_state.ssh_decoy = get_ssh_decoy(host="127.0.0.1", port=2222)
        try:
            st.session_state.ssh_decoy.start()
        except Exception:
            pass

    # Pre-seed initial sample telemetry if database is empty so dashboard is active immediately
    kpis = st.session_state.db.get_kpis()
    if kpis.get("total_events", 0) == 0:
        demo = DemoScenarios()
        demo.run_all()


def main():
    init_state()
    db: DatabaseManager = st.session_state.db

    # --- ENTERPRISE TOP HEADER BAR ---
    render_top_header(db)

    # --- SIDEBAR NAVIGATION ---
    with st.sidebar:
        # Sidebar Branding
        st.markdown("""
        <div style="display:flex; align-items:center; gap:12px; margin-bottom:18px; padding-bottom:14px; border-bottom:1px solid rgba(255,255,255,0.08);">
            <div style="width:40px; height:40px; border-radius:10px; background:linear-gradient(135deg, rgba(0,212,255,0.2) 0%, rgba(139,92,246,0.2) 100%); border:1px solid rgba(0,212,255,0.4); display:flex; align-items:center; justify-content:center; font-size:1.3rem;">🛡️</div>
            <div>
                <div style="font-weight:800; font-size:1.15rem; letter-spacing:0.04em; color:#F8FAFC;">HONEYTRACE</div>
                <div style="font-size:0.7rem; color:#00D4FF; font-weight:600; letter-spacing:0.1em;">ENTERPRISE SOC</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div style="font-size:0.7rem; font-weight:700; color:#64748B; letter-spacing:0.12em; text-transform:uppercase; margin-bottom:6px;">
            // OPERATIONS CONSOLE
        </div>
        """, unsafe_allow_html=True)

        page = st.radio(
            "Select Dashboard View:",
            [
                "1. SOC Overview",
                "2. Live Attack Monitor",
                "3. Honeypot Management",
                "4. Threat Intelligence",
                "5. Incident Investigation",
                "6. Attack Timeline",
                "7. Reports & Forensics",
                "8. System Architecture"
            ],
            index=0,
            label_visibility="collapsed"
        )

        st.markdown("<br>", unsafe_allow_html=True)

        # Tactical Simulation Control
        st.markdown("""
        <div style="font-size:0.7rem; font-weight:700; color:#64748B; letter-spacing:0.12em; text-transform:uppercase; margin-bottom:8px;">
            // ADVERSARY EMULATION
        </div>
        """, unsafe_allow_html=True)

        demo = DemoScenarios()

        # One-Click Master Demo
        if st.button("🔥 ONE-CLICK DEMO (ALL 5 VECTORS)", type="primary", use_container_width=True):
            with st.spinner("Injecting 5-vector demonstration suite..."):
                demo.run_all()
            st.toast("Executed all 5 demonstration attack scenarios!", icon="🎯")
            st.rerun()

        st.caption("Quick Vector Injections:")
        c_v1, c_v2 = st.columns(2)
        with c_v1:
            if st.button("🔑 SSH Spray", use_container_width=True):
                demo.scenario_ssh_brute_force()
                st.toast("Injected SSH dictionary spray!", icon="🔑")
                st.rerun()
            if st.button("📁 Dir Fuzz", use_container_width=True):
                demo.scenario_http_directory_enumeration()
                st.toast("Injected HTTP Directory Fuzzing!", icon="📁")
                st.rerun()
        with c_v2:
            if st.button("👤 User Enum", use_container_width=True):
                demo.scenario_username_enumeration()
                st.toast("Injected Username Enumeration!", icon="👤")
                st.rerun()
            if st.button("💻 Shell Probe", use_container_width=True):
                demo.scenario_suspicious_command_probing()
                st.toast("Injected Command Probing (Zero Execution)!", icon="💻")
                st.rerun()

        st.markdown("<br>", unsafe_allow_html=True)

        # Database Management Section
        st.markdown("""
        <div style="font-size:0.7rem; font-weight:700; color:#64748B; letter-spacing:0.12em; text-transform:uppercase; margin-bottom:8px;">
            // DATABASE CONTROLS
        </div>
        """, unsafe_allow_html=True)

        c_p, c_s = st.columns(2)
        with c_p:
            if st.button("🗑️ Purge DB", use_container_width=True):
                db.clear_database()
                st.toast("SQLite database purged.", icon="🧹")
                st.rerun()
        with c_s:
            if st.button("🌱 Seed Data", use_container_width=True):
                demo.run_all()
                st.toast("Generated fresh multi-scenario telemetry!", icon="🌱")
                st.rerun()

        st.markdown("<br>", unsafe_allow_html=True)

        # Auto-Refresh Toggle
        auto_refresh = st.checkbox("Auto-Refresh Stream (3s)", value=False)
        if st.button("🔄 Manual Refresh Now", use_container_width=True):
            st.rerun()

        # Engine Health Pill Card at Bottom of Sidebar
        st.markdown("""
        <div style="margin-top:24px; padding:12px; background:rgba(0,0,0,0.3); border:1px solid rgba(255,255,255,0.06); border-radius:8px; font-size:0.72rem; color:#64748B;">
            <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                <span>ENGINE:</span>
                <span style="color:#10B981; font-weight:600;">ACTIVE (WAL MODE)</span>
            </div>
            <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                <span>SANDBOX:</span>
                <span style="color:#00D4FF; font-weight:600;">100% LOCALHOST</span>
            </div>
            <div style="display:flex; justify-content:space-between;">
                <span>SAFETY:</span>
                <span style="color:#F59E0B; font-weight:600;">ZERO-EXECUTION TRAP</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # --- 8 DASHBOARD PAGES ROUTING ---
    if page == "1. SOC Overview":
        render_overview(db)
    elif page == "2. Live Attack Monitor":
        render_live_monitor(db)
    elif page == "3. Honeypot Management":
        render_honeypot_mgmt(db)
    elif page == "4. Threat Intelligence":
        render_threat_analysis(db)
    elif page == "5. Incident Investigation":
        render_incident_investigation(db)
    elif page == "6. Attack Timeline":
        render_attack_timeline(db)
    elif page == "7. Reports & Forensics":
        render_reports(db)
    elif page == "8. System Architecture":
        render_architecture_view()

    # Periodic Auto-Refresh
    if auto_refresh:
        time.sleep(3.0)
        st.rerun()


def render_architecture_view():
    """Renders comprehensive academic system architecture, viva defense slides, and methodology."""
    from dashboard.theme import render_section_header
    
    render_section_header(
        eyebrow="SYSTEM ARCHITECTURE // ACADEMIC SPECIFICATION",
        title="HONEYTRACE Platform Architecture & Defense Dossier",
        caption="High-level modular data flow, deception taxonomy, and containment security policies."
    )

    c1, c2 = st.columns([1.5, 1])
    with c1:
        st.markdown("""
        <div style="background:#111B2D; border:1px solid rgba(255,255,255,0.08); border-radius:10px; padding:20px; margin-bottom:18px;">
            <div style="font-size:0.8rem; text-transform:uppercase; color:#00D4FF; font-weight:700; margin-bottom:8px;">// CORE METHODOLOGY</div>
            <div style="font-size:1.1rem; font-weight:700; color:#F8FAFC; margin-bottom:10px;">The Active Deception Defense Advantage</div>
            <div style="font-size:0.88rem; color:#94A3B8; line-height:1.6;">
                Traditional perimeter Intrusion Detection Systems (IDS) and firewalls inspect massive volumes of mixed production traffic, resulting in devastating rates of <strong>false positives</strong> and alert fatigue.
                <br><br>
                <strong>HONEYTRACE flips the asymmetric advantage to the defender:</strong>
                <ul style="margin-top:8px;">
                    <li><strong>Zero False Positives:</strong> Honeypots possess no legitimate production function. Any interaction is unauthorized by definition.</li>
                    <li><strong>Pre-Breach Telemetry:</strong> Traps adversary TTPs during initial reconnaissance and credential access before production compromise.</li>
                    <li><strong>Explainable AI Heuristics:</strong> Computes Shannon entropy (<em>H = -∑ p(x) log₂ p(x)</em>) and token density without external cloud APIs.</li>
                </ul>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with c2:
        st.markdown("""
        <div style="background:#111B2D; border:1px solid rgba(16,185,129,0.3); border-radius:10px; padding:20px; background:rgba(16,185,129,0.04); margin-bottom:18px;">
            <div style="font-size:0.8rem; text-transform:uppercase; color:#34D399; font-weight:700; margin-bottom:8px;">// SAFETY &amp; CONTAINMENT POLICY</div>
            <div style="font-size:1.1rem; font-weight:700; color:#F8FAFC; margin-bottom:10px;">Host Protection Guarantees</div>
            <div style="font-size:0.85rem; color:#94A3B8; line-height:1.6;">
                <div>🔒 <strong>Strict Zero-Execution:</strong> Submitted shell commands are parsed as passive text strings for regex matching; never passed to <code>os.system()</code> or <code>subprocess</code>.</div>
                <div style="margin-top:6px;">🌐 <strong>Localhost Bound:</strong> Decoy sockets bind exclusively to <code>127.0.0.1</code>; zero outbound network scanning.</div>
                <div style="margin-top:6px;">📦 <strong>Air-Gapped Capable:</strong> 100% operational without internet after local installation.</div>
                <div style="margin-top:6px;">📁 <strong>Relative Anchoring:</strong> Uses Python <code>pathlib.Path</code> relative anchors for seamless Windows PC portability.</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div style="background:#0F1A2E; border:1px solid rgba(255,255,255,0.08); border-radius:10px; padding:20px; margin-bottom:20px;">
        <div style="font-size:0.8rem; text-transform:uppercase; color:#8B5CF6; font-weight:700; margin-bottom:12px;">// MODULAR DATA FLOW PIPELINE</div>
        <pre style="background:#070B14; padding:16px; border-radius:8px; border:1px solid rgba(255,255,255,0.06); color:#38BDF8; font-size:0.82rem; overflow-x:auto;">
[ Simulated Adversary / Prober ]
               │
      ┌────────┴────────┐
      ▼                 ▼
[ HTTP Decoy :8080 ] [ SSH Decoy :2222 ]
      │                 │
      └────────┬────────┘
               ▼
   [ Event Collector Queue ]
               │
      ┌────────┼────────┐
      ▼        ▼        ▼
[ Detection ] [ Risk ] [ Incident ]
 (Signatures) (0-100)  (Clustering)
      │        │        │
      └────────┼────────┘
               ▼
     [ SQLite WAL Engine ]
               │
               ▼
  [ Streamlit SOC Dashboard ]
        </pre>
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
