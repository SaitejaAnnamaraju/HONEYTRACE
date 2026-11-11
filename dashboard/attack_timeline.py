"""
HONEYTRACE - Attack Timeline Reconstruction View (Enterprise SOC)
Interactive forensic timeline mapping sequential adversary progression,
kill-chain escalation, time-delta analysis, and honeypot containment outcomes.
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from core.database import DatabaseManager
from core.incident_engine import IncidentEngine
from dashboard.theme import render_section_header, render_severity_badge, apply_plotly_theme


def render_attack_timeline(db: DatabaseManager):
    """Renders the chronological attack timeline reconstruction view."""
    render_section_header(
        eyebrow="FORENSIC RECONSTRUCTION // ADVERSARY TRAJECTORY",
        title="Chronological Attack Progression Timeline",
        caption="Reconstruct step-by-step adversary progression, time deltas, and kill-chain escalation milestones."
    )

    incidents = db.get_incidents(limit=50)

    if not incidents:
        st.info("No attack campaigns recorded yet. Trigger a demonstration scenario to populate timeline forensics.")
        return

    inc_ids = [inc["incident_id"] for inc in incidents]
    selected_inc_id = st.selectbox(
        "Select Incident Campaign to Reconstruct Timeline:",
        options=inc_ids,
        format_func=lambda x: f"{x} — Attacker: {next((i['attacker_ip'] for i in incidents if i['incident_id'] == x), '')} — Sev: {next((i['severity'] for i in incidents if i['incident_id'] == x), '')}"
    )

    incident = next((i for i in incidents if i["incident_id"] == selected_inc_id), None)
    if not incident:
        return

    inc_engine = IncidentEngine(db)
    timeline_steps = inc_engine.reconstruct_attack_timeline(selected_inc_id)

    if not timeline_steps:
        st.write("No chronological steps recorded for this incident.")
        return

    df_steps = pd.DataFrame(timeline_steps)

    # --- TOP PROGRESSION METRICS ---
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f"""
        <div style="background:#111B2D; border:1px solid rgba(255,255,255,0.08); border-radius:8px; padding:12px 16px;">
            <div style="font-size:0.75rem; text-transform:uppercase; color:#64748B; font-weight:600;">Kill-Chain Steps</div>
            <div style="font-size:1.4rem; font-weight:800; color:#00D4FF; margin-top:2px;">{len(timeline_steps)} Phases</div>
        </div>
        """, unsafe_allow_html=True)
    with m2:
        first_step_time = timeline_steps[0]["timestamp"][11:19]
        last_step_time = timeline_steps[-1]["timestamp"][11:19]
        st.markdown(f"""
        <div style="background:#111B2D; border:1px solid rgba(255,255,255,0.08); border-radius:8px; padding:12px 16px;">
            <div style="font-size:0.75rem; text-transform:uppercase; color:#64748B; font-weight:600;">Active Window</div>
            <div style="font-size:1.1rem; font-weight:700; color:#F8FAFC; margin-top:4px; font-family:monospace;">{first_step_time} → {last_step_time}</div>
        </div>
        """, unsafe_allow_html=True)
    with m3:
        st.markdown(f"""
        <div style="background:#111B2D; border:1px solid rgba(255,255,255,0.08); border-radius:8px; padding:12px 16px;">
            <div style="font-size:0.75rem; text-transform:uppercase; color:#64748B; font-weight:600;">Peak Threat Score</div>
            <div style="font-size:1.4rem; font-weight:800; color:#EF4444; margin-top:2px;">{incident['peak_risk_score']}/100</div>
        </div>
        """, unsafe_allow_html=True)
    with m4:
        st.markdown(f"""
        <div style="background:#111B2D; border:1px solid rgba(16,185,129,0.3); border-radius:8px; padding:12px 16px; background:rgba(16,185,129,0.06);">
            <div style="font-size:0.75rem; text-transform:uppercase; color:#34D399; font-weight:600;">Containment Status</div>
            <div style="font-size:1.1rem; font-weight:800; color:#34D399; margin-top:4px;">100% Contained (Decoy)</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # --- PLOTLY PROGRESSION CHART ---
    st.markdown("""
    <div class="soc-section-eyebrow">
        <span>// THREAT TRAJECTORY</span>
    </div>
    <div style="font-size:1.1rem; font-weight:700; color:#F8FAFC; margin-bottom:10px;">
        Adversary Kill-Chain Risk Escalation Curve
    </div>
    """, unsafe_allow_html=True)

    fig_risk_curve = go.Figure()
    fig_risk_curve.add_trace(go.Scatter(
        x=df_steps['step'],
        y=df_steps['risk_score'],
        mode='lines+markers+text',
        text=[f"S{s}: {r['tactic'][:12]}" for s, r in zip(df_steps['step'], timeline_steps)],
        textposition="top center",
        line=dict(color='#EF4444', width=2.5, shape='spline'),
        marker=dict(size=9, color='#F59E0B', line=dict(width=2, color='#080D19')),
        name="Assessed Threat Score"
    ))
    apply_plotly_theme(fig_risk_curve)
    fig_risk_curve.update_layout(
        height=300,
        xaxis=dict(title="Sequential Kill-Chain Phase Number", tickmode='linear', tick0=1, dtick=1),
        yaxis=dict(title="Calculated Risk (0-100)", range=[0, 115])
    )
    st.plotly_chart(fig_risk_curve, use_container_width=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # --- CHRONOLOGICAL TIMELINE CARDS ---
    st.markdown("""
    <div class="soc-section-eyebrow">
        <span>// SEQUENTIAL TELEMETRY</span>
    </div>
    <div style="font-size:1.1rem; font-weight:700; color:#F8FAFC; margin-bottom:14px;">
        Step-by-Step Adversary Action Telemetry
    </div>
    """, unsafe_allow_html=True)

    for step in timeline_steps:
        sev = step.get("severity", "INFO")
        sev_color = "#EF4444" if sev == "CRITICAL" else ("#F97316" if sev == "HIGH" else "#38BDF8")

        with st.expander(f"Phase {step['step']:02d} [{step['elapsed']}] — {step['action']} — Risk: {step['risk_score']}/100"):
            st.markdown(f"""
            <div style="background:#0F1A2E; border:1px solid rgba(255,255,255,0.06); border-radius:6px; padding:12px; margin-bottom:10px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="soc-pill" style="font-size:0.75rem; color:#00D4FF; border-color:rgba(0,212,255,0.3);">
                            {step['decoy']} DECOY
                        </span>
                        <span style="font-size:0.8rem; color:#94A3B8; margin-left:8px;">
                            <strong>MITRE Tactic:</strong> <code>{step['tactic']}</code> (<code>{step['technique']}</code>)
                        </span>
                    </div>
                    {render_severity_badge(sev)}
                </div>
            </div>
            """, unsafe_allow_html=True)

            c1, c2 = st.columns([1.5, 1])
            with c1:
                st.markdown("**Intercepted Attack Vector &amp; Payload:**")
                st.code(step.get("payload_sample") or "(Connection probe / empty body)", language="text")
            with c2:
                st.markdown("**Detection Rule:**")
                st.write(f"🏷️ `{step['rule_name']}`")
                st.markdown("**Containment Outcome:**")
                st.markdown(f"""
                <div style="background:rgba(16,185,129,0.08); border:1px solid rgba(16,185,129,0.3); border-radius:6px; padding:8px 12px; font-size:0.8rem; color:#34D399;">
                    🛡️ {step['outcome']}
                </div>
                """, unsafe_allow_html=True)
