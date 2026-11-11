"""
HONEYTRACE - Incident Investigation Panel (Enterprise SOC)
Interactive forensic investigation of correlated attack sessions,
containment status workflows, multi-vector pivot analysis, and deep event drill-downs.
"""

import json
import streamlit as st
import pandas as pd
from core.database import DatabaseManager
from dashboard.theme import render_section_header, render_severity_badge


def render_incident_investigation(db: DatabaseManager):
    """Renders the comprehensive Incident Investigation SOC panel."""
    render_section_header(
        eyebrow="CASE MANAGEMENT // INCIDENT RESPONSE",
        title="Incident Investigation & Triage Workflow",
        caption="Correlate atomic deception events into cohesive incident sessions and manage containment lifecycles."
    )

    incidents = db.get_incidents(limit=50)

    if not incidents:
        st.info("No security incidents correlated yet. Trigger demonstration scenarios from Honeypot Management or Overview.")
        return

    # --- TOP INCIDENT SELECTION & SUMMARY ---
    inc_ids = [inc["incident_id"] for inc in incidents]
    selected_inc_id = st.selectbox(
        "Select Correlated Security Incident to Investigate:",
        options=inc_ids,
        format_func=lambda x: f"{x} — Attacker IP: {next((i['attacker_ip'] for i in incidents if i['incident_id'] == x), '')} — Sev: {next((i['severity'] for i in incidents if i['incident_id'] == x), '')}"
    )

    incident = next((i for i in incidents if i["incident_id"] == selected_inc_id), None)
    if not incident:
        return

    # --- INCIDENT OVERVIEW HEADER METRICS ---
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.markdown(f"""
        <div style="background:#111B2D; border:1px solid rgba(255,255,255,0.08); border-radius:8px; padding:12px 16px;">
            <div style="font-size:0.75rem; text-transform:uppercase; color:#64748B; font-weight:600;">Incident ID</div>
            <div style="font-size:1.1rem; font-weight:700; color:#00D4FF; font-family:monospace; margin-top:4px;">{incident['incident_id']}</div>
        </div>
        """, unsafe_allow_html=True)
    with m2:
        st.markdown(f"""
        <div style="background:#111B2D; border:1px solid rgba(255,255,255,0.08); border-radius:8px; padding:12px 16px;">
            <div style="font-size:0.75rem; text-transform:uppercase; color:#64748B; font-weight:600;">Attacker IP</div>
            <div style="font-size:1.1rem; font-weight:700; color:#F8FAFC; font-family:monospace; margin-top:4px;">{incident['attacker_ip']}</div>
        </div>
        """, unsafe_allow_html=True)
    with m3:
        st.markdown(f"""
        <div style="background:#111B2D; border:1px solid rgba(255,255,255,0.08); border-radius:8px; padding:12px 16px;">
            <div style="font-size:0.75rem; text-transform:uppercase; color:#64748B; font-weight:600; margin-bottom:6px;">Severity</div>
            {render_severity_badge(incident['severity'])}
        </div>
        """, unsafe_allow_html=True)
    with m4:
        st.markdown(f"""
        <div style="background:#111B2D; border:1px solid rgba(255,255,255,0.08); border-radius:8px; padding:12px 16px;">
            <div style="font-size:0.75rem; text-transform:uppercase; color:#64748B; font-weight:600;">Peak Risk Score</div>
            <div style="font-size:1.1rem; font-weight:700; color:#EF4444; margin-top:4px;">{incident['peak_risk_score']}/100</div>
        </div>
        """, unsafe_allow_html=True)
    with m5:
        st.markdown(f"""
        <div style="background:#111B2D; border:1px solid rgba(255,255,255,0.08); border-radius:8px; padding:12px 16px;">
            <div style="font-size:0.75rem; text-transform:uppercase; color:#64748B; font-weight:600;">Trapped Events</div>
            <div style="font-size:1.1rem; font-weight:700; color:#38BDF8; margin-top:4px;">{incident['event_count']} hits</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # --- STATUS WORKFLOW CONTROLLER ---
    st.markdown("#### 🔄 Incident Status & Containment Lifecycle")
    current_status = incident.get("status", "OPEN")
    
    status_colors = {
        "OPEN": "#EF4444",
        "INVESTIGATING": "#F59E0B",
        "CONTAINED": "#38BDF8",
        "RESOLVED": "#10B981"
    }

    c_stat, c_btn = st.columns([2, 1])
    with c_stat:
        new_status = st.selectbox(
            "Active SOC Workflow State:",
            ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED"],
            index=["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED"].index(current_status) if current_status in ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED"] else 0,
            key="inc_status_select"
        )
    with c_btn:
        st.write("")
        st.write("")
        if st.button("💾 Apply Status Transition", use_container_width=True, key="btn_update_status"):
            db.update_incident_status(incident["incident_id"], new_status)
            st.toast(f"Incident {incident['incident_id']} transitioned to {new_status}!", icon="✅")
            st.rerun()

    # --- INCIDENT DOSSIER NARRATIVE ---
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(f"""
    <div style="background:#0F1A2E; border:1px solid rgba(0,212,255,0.2); border-radius:8px; padding:18px; margin-bottom:18px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
            <span style="font-size:0.75rem; text-transform:uppercase; letter-spacing:0.1em; color:#00D4FF; font-weight:700;">// THREAT NARRATIVE DOSSIER</span>
            <span class="soc-pill" style="border-color:{status_colors.get(current_status, '#64748B')}; color:{status_colors.get(current_status, '#64748B')}; font-size:0.7rem;">
                STATUS: {current_status}
            </span>
        </div>
        <div style="font-size:0.9rem; color:#E2E8F0; line-height:1.6;">
            {incident.get('summary', 'No automated narrative generated.')}
        </div>
    </div>
    """, unsafe_allow_html=True)

    c_tactic, c_vector = st.columns(2)
    with c_tactic:
        st.markdown("**Traversed MITRE ATT&CK Tactics:**")
        tactics = incident.get("mitre_tactics", [])
        if tactics:
            for t in tactics:
                st.markdown(f"- 🎯 `{t}`")
        else:
            st.write("Initial Reconnaissance")

    with c_vector:
        st.markdown("**Engaged Decoy Attack Vectors:**")
        vectors = incident.get("attack_vectors", [])
        if vectors:
            for v in vectors:
                st.markdown(f"- 🪤 `{v}`")
        else:
            st.write("Generic Decoy Probe")

    st.markdown("<br>", unsafe_allow_html=True)

    # --- CORRELATED EVENT DRILL-DOWN ---
    st.subheader(f"📑 Correlated Forensic Events for Actor {incident['attacker_ip']}")
    related_events = db.get_events(limit=100, search_query=incident["attacker_ip"])

    if related_events:
        df_rel = pd.DataFrame(related_events)

        def badge_sev(s):
            return {"CRITICAL": "🔴 CRITICAL", "HIGH": "🟠 HIGH", "MEDIUM": "🟡 MEDIUM", "LOW": "🔵 LOW", "INFO": "🟢 INFO"}.get(s, s)

        df_rel["Severity"] = df_rel["severity"].apply(badge_sev)
        cols_to_show = ["id", "timestamp", "honeypot_type", "event_type", "endpoint", "risk_score", "Severity", "rule_name"]

        st.dataframe(
            df_rel[cols_to_show].rename(columns={
                "id": "ID",
                "timestamp": "Timestamp",
                "honeypot_type": "Decoy",
                "event_type": "Event Type",
                "endpoint": "Endpoint/Port",
                "risk_score": "Risk",
                "rule_name": "Detection Rule"
            }),
            use_container_width=True,
            hide_index=True
        )

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("#### 🔬 Detailed Event Disassembly")
        ev_id = st.selectbox(
            "Select specific event to dissect:",
            options=[e["id"] for e in related_events],
            format_func=lambda x: f"Event #{x} — {next((e['event_type'] + ' ' + e.get('endpoint', '') for e in related_events if e['id'] == x), '')}"
        )

        ev_sel = next((e for e in related_events if e["id"] == ev_id), None)
        if ev_sel:
            p_col1, p_col2 = st.columns([1.5, 1])
            with p_col1:
                st.markdown("**Raw Intercepted Payload:**")
                st.code(ev_sel.get("payload") or "(Empty payload)", language="text")
            with p_col2:
                st.markdown("**Detection Explanation:**")
                st.info(ev_sel.get("detection_reason") or "Rule matched")
                st.markdown(f"**Calculated Score:** `{ev_sel.get('risk_score', 0)}/100` &bull; **Decoy:** `{ev_sel.get('honeypot_type')}`")
