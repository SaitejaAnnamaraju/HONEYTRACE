"""
HONEYTRACE - Honeypot Decoy Management & Simulation Control (Enterprise SOC)
Direct lifecycle management of low-interaction deception services,
port configuration verification, process health, and controlled simulation testing.
"""

import time
import socket
import requests
import streamlit as st
import pandas as pd
from core.database import DatabaseManager
from honeypots.http_decoy import get_http_decoy
from honeypots.ssh_decoy import get_ssh_decoy
from simulation.demo_scenarios import DemoScenarios
from simulation.attack_simulator import AttackSimulator
from dashboard.theme import render_section_header


def test_port_connectivity(host: str, port: int) -> bool:
    """Tests if a TCP port is actively accepting localhost connections."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        res = s.connect_ex((host, port))
        s.close()
        return res == 0
    except Exception:
        return False


def render_honeypot_mgmt(db: DatabaseManager):
    """Renders the Honeypot Management and Service Orchestration view."""
    render_section_header(
        eyebrow="DECEPTION FABRIC // SENSOR ORCHESTRATION",
        title="Honeypot Decoy Management & Service Control",
        caption="Manage isolated low-interaction deception listeners, verify port bindings, and trigger controlled attacks."
    )

    http_server = get_http_decoy()
    ssh_server = get_ssh_decoy()
    kpis = db.get_kpis()

    # --- TOP SERVICE CONTROL CARDS ---
    c_http, c_ssh = st.columns(2)

    with c_http:
        is_http_up = http_server.is_running
        port_open = test_port_connectivity("127.0.0.1", 8080) if is_http_up else False
        status_color = "#10B981" if (is_http_up and port_open) else "#EF4444"
        status_badge = "ACTIVE LISTENING" if (is_http_up and port_open) else "INACTIVE / STOPPED"

        st.markdown(f"""
        <div style="background:#111B2D; border:1px solid rgba(255,255,255,0.08); border-radius:10px; padding:20px; box-shadow:0 4px 20px rgba(0,0,0,0.3); margin-bottom:16px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
                <div style="display:flex; align-items:center; gap:10px;">
                    <div style="width:36px; height:36px; border-radius:8px; background:rgba(0,212,255,0.1); border:1px solid rgba(0,212,255,0.3); display:flex; align-items:center; justify-content:center; font-size:1.1rem;">🌐</div>
                    <div>
                        <div style="font-weight:700; font-size:1.1rem; color:#F8FAFC;">HTTP Web Decoy</div>
                        <div style="font-size:0.75rem; color:#64748B;">TCP/8080 &bull; Flask Low-Interaction</div>
                    </div>
                </div>
                <div class="soc-pill" style="border-color:{status_color}; color:{status_color};">
                    <span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:{status_color};"></span>
                    <span>{status_badge}</span>
                </div>
            </div>
            <div style="font-size:0.83rem; color:#94A3B8; margin-bottom:12px; line-height:1.6;">
                <div><strong>Interface:</strong> <code>127.0.0.1:8080</code> (Strict Localhost Loopback)</div>
                <div><strong>Trapped Incursions:</strong> <code style="color:#00D4FF;">{kpis.get('http_events', 0):,}</code> events</div>
                <div><strong>Active Decoy Surfaces:</strong> <code>/login</code>, <code>/admin</code>, <code>/.env</code>, <code>/wp-config.php</code>, <code>/view?file=</code>, <code>/api/v1/users</code></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        btn_col1, btn_col2, btn_col3 = st.columns(3)
        with btn_col1:
            if not is_http_up:
                if st.button("▶️ Start HTTP", use_container_width=True, key="mgmt_start_http"):
                    http_server.start()
                    st.toast("HTTP Decoy started on 127.0.0.1:8080", icon="🟢")
                    st.rerun()
            else:
                if st.button("⏹️ Stop HTTP", use_container_width=True, key="mgmt_stop_http"):
                    http_server.stop()
                    st.toast("HTTP Decoy stopped", icon="🔴")
                    st.rerun()

        with btn_col2:
            if st.button("🔍 Probe :8080", use_container_width=True, key="mgmt_probe_http"):
                try:
                    resp = requests.get("http://127.0.0.1:8080/", timeout=1.5)
                    st.toast(f"Loopback Probe Success: HTTP {resp.status_code}", icon="✅")
                except Exception as e:
                    st.toast(f"Probe failed: {e}", icon="⚠️")

        with btn_col3:
            st.markdown("<div style='text-align:center; padding-top:6px; font-size:0.75rem; color:#34D399; font-weight:600;'>🔒 Trap Only</div>", unsafe_allow_html=True)

    with c_ssh:
        is_ssh_up = ssh_server.is_running
        ssh_port_open = test_port_connectivity("127.0.0.1", 2222) if is_ssh_up else False
        ssh_status_color = "#10B981" if (is_ssh_up and ssh_port_open) else "#EF4444"
        ssh_status_badge = "ACTIVE LISTENING" if (is_ssh_up and ssh_port_open) else "INACTIVE / STOPPED"

        st.markdown(f"""
        <div style="background:#111B2D; border:1px solid rgba(255,255,255,0.08); border-radius:10px; padding:20px; box-shadow:0 4px 20px rgba(0,0,0,0.3); margin-bottom:16px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
                <div style="display:flex; align-items:center; gap:10px;">
                    <div style="width:36px; height:36px; border-radius:8px; background:rgba(139,92,246,0.1); border:1px solid rgba(139,92,246,0.3); display:flex; align-items:center; justify-content:center; font-size:1.1rem;">🔒</div>
                    <div>
                        <div style="font-weight:700; font-size:1.1rem; color:#F8FAFC;">SSH Shell Decoy</div>
                        <div style="font-size:0.75rem; color:#64748B;">TCP/2222 &bull; Low-Interaction Socket</div>
                    </div>
                </div>
                <div class="soc-pill" style="border-color:{ssh_status_color}; color:{ssh_status_color};">
                    <span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:{ssh_status_color};"></span>
                    <span>{ssh_status_badge}</span>
                </div>
            </div>
            <div style="font-size:0.83rem; color:#94A3B8; margin-bottom:12px; line-height:1.6;">
                <div><strong>Interface:</strong> <code>127.0.0.1:2222</code> (Strict Localhost Loopback)</div>
                <div><strong>Trapped Incursions:</strong> <code style="color:#8B5CF6;">{kpis.get('ssh_events', 0):,}</code> events</div>
                <div><strong>Emulated Banner:</strong> <code>SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1</code></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        s_col1, s_col2, s_col3 = st.columns(3)
        with s_col1:
            if not is_ssh_up:
                if st.button("▶️ Start SSH", use_container_width=True, key="mgmt_start_ssh"):
                    ssh_server.start()
                    st.toast("SSH Decoy started on 127.0.0.1:2222", icon="🟢")
                    st.rerun()
            else:
                if st.button("⏹️ Stop SSH", use_container_width=True, key="mgmt_stop_ssh"):
                    ssh_server.stop()
                    st.toast("SSH Decoy stopped", icon="🔴")
                    st.rerun()

        with s_col2:
            if st.button("🔍 Probe :2222", use_container_width=True, key="mgmt_probe_ssh"):
                sim = AttackSimulator()
                ok = sim.trigger_live_ssh_probe("probe_user", "probe_pass")
                if ok:
                    st.toast("SSH Decoy Handshake verified over TCP socket!", icon="✅")
                else:
                    st.toast("SSH Decoy socket probe failed. Is port 2222 running?", icon="⚠️")

        with s_col3:
            st.markdown("<div style='text-align:center; padding-top:6px; font-size:0.75rem; color:#34D399; font-weight:600;'>🔒 Shell Trapped</div>", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # --- CONTROLLED ATTACK SIMULATION SUITE ---
    st.markdown("""
    <div class="soc-section-eyebrow">
        <span>// ADVERSARY EMULATION</span>
    </div>
    <div style="font-size:1.15rem; font-weight:700; color:#F8FAFC; margin-bottom:6px;">
        Controlled Attack Simulation Engine
    </div>
    <div style="font-size:0.83rem; color:#64748B; margin-bottom:16px;">
        Generate reproducible, safe adversary campaigns across localhost decoys for laboratory and viva evaluations.
    </div>
    """, unsafe_allow_html=True)

    demo = DemoScenarios()

    # Master One-Click Button
    if st.button("🔥 ONE-CLICK MASTER DEMO (EXECUTE ALL 5 ATTACK VECTORS)", type="primary", use_container_width=True, key="mgmt_master_btn"):
        with st.spinner("Injecting multi-stage demonstration attack scenarios into active honeypots..."):
            demo.run_all()
        st.toast("All 5 demonstration scenarios successfully executed!", icon="🚀")
        st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown("#### Individual Attack Vector Emulators")
    t1, t2, t3, t4, t5 = st.columns(5)

    with t1:
        if st.button("🔑 SSH Brute-Force", use_container_width=True, key="m_bf"):
            demo.scenario_ssh_brute_force()
            st.toast("Injected SSH brute-force attack!", icon="🔑")
            st.rerun()

    with t2:
        if st.button("👤 Username Enum", use_container_width=True, key="m_enum"):
            demo.scenario_username_enumeration()
            st.toast("Injected Username Enumeration!", icon="👤")
            st.rerun()

    with t3:
        if st.button("📁 Directory Fuzz", use_container_width=True, key="m_dir"):
            demo.scenario_http_directory_enumeration()
            st.toast("Injected Directory Enumeration!", icon="📁")
            st.rerun()

    with t4:
        if st.button("💻 Command Injection", use_container_width=True, key="m_cmd"):
            demo.scenario_suspicious_command_probing()
            st.toast("Injected Command Probing (Zero Execution)!", icon="💻")
            st.rerun()

    with t5:
        if st.button("🚨 Rapid Auth Fail", use_container_width=True, key="m_rapid"):
            demo.scenario_repeated_auth_failures()
            st.toast("Injected High-Velocity Auth Failure Burst!", icon="🚨")
            st.rerun()
