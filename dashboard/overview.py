"""
HONEYTRACE - Dashboard Overview View (Enterprise SOC Command Center)
Executive security operations center summary with real-time KPI metrics,
interactive Plotly visualizations, timeline tracking, and live simulation controls.
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from core.database import DatabaseManager
from simulation.demo_scenarios import DemoScenarios
from dashboard.theme import (
    render_section_header,
    render_kpi_card,
    render_severity_badge,
    apply_plotly_theme
)


def render_overview(db: DatabaseManager):
    """Renders the enterprise SOC Executive Overview dashboard."""
    kpis = db.get_kpis()
    services = db.get_service_statuses()

    # --- TOP CONTROL & STATUS BAR ---
    render_section_header(
        eyebrow="SYSTEM TELEMETRY // REAL-TIME COMMAND",
        title="Security Operations Center (SOC) Overview",
        caption="High-fidelity telemetry captured by isolated deception decoys deployed on localhost."
    )

    # Decoy Service Status Ribbon
    http_stat = services.get("HTTP_DECOY", {}).get("is_running", False)
    ssh_stat = services.get("SSH_DECOY", {}).get("is_running", False)
    
    col_stat, col_sim = st.columns([3, 2])
    with col_stat:
        st.markdown(f"""
        <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:18px;">
            <div class="soc-pill {'soc-pill-live' if http_stat else ''}">
                <span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:{'#10B981' if http_stat else '#EF4444'};"></span>
                <span>HTTP Decoy (:8080) — <strong>{'ONLINE' if http_stat else 'OFFLINE'}</strong></span>
            </div>
            <div class="soc-pill {'soc-pill-live' if ssh_stat else ''}">
                <span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:{'#10B981' if ssh_stat else '#EF4444'};"></span>
                <span>SSH Decoy (:2222) — <strong>{'ONLINE' if ssh_stat else 'OFFLINE'}</strong></span>
            </div>
            <div class="soc-pill soc-pill-cyan">
                <span>🛡️ Localhost Containment Active</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col_sim:
        sim_c1, sim_c2 = st.columns(2)
        with sim_c1:
            if st.button("⚡ Fire Web Attack", use_container_width=True, key="ov_btn_kc"):
                demo = DemoScenarios()
                demo.scenario_http_directory_enumeration()
                st.toast("Simulated Web Reconnaissance injected!", icon="🎯")
                st.rerun()
        with sim_c2:
            if st.button("🔥 Master Demo (All 5)", type="primary", use_container_width=True, key="ov_btn_all"):
                demo = DemoScenarios()
                demo.run_all()
                st.toast("Executed all 5 demonstration attack scenarios!", icon="🔥")
                st.rerun()

    # --- KPI METRIC CARDS GRID ---
    total_ev = kpis.get("total_events", 0)
    crit_ev = kpis.get("critical_events", 0)
    high_ev = kpis.get("high_events", 0)
    actors = kpis.get("unique_attackers", 0)
    open_inc = kpis.get("open_incidents", 0)
    avg_risk = kpis.get("avg_risk_score", 0.0)

    kpi_html = f"""
    <div class="kpi-container">
        {render_kpi_card(
            title="Total Trapped Incursions",
            value=f"{total_ev:,}",
            icon="🪤",
            trend_text=f"+{total_ev} Events" if total_ev > 0 else "0",
            trend_type="cyan",
            description="Zero false-positive decoy hits",
            card_type="default"
        )}
        {render_kpi_card(
            title="Critical Threats",
            value=f"{crit_ev:,}",
            icon="🚨",
            trend_text=f"{high_ev} High Risk",
            trend_type="critical" if crit_ev > 0 else "emerald",
            description="Immediate triage priority",
            card_type="critical"
        )}
        {render_kpi_card(
            title="Unique Adversary IPs",
            value=f"{actors:,}",
            icon="🕵️",
            trend_text="Isolated Trackers",
            trend_type="violet",
            description="Longitudinal actor profiles",
            card_type="violet"
        )}
        {render_kpi_card(
            title="Active Incidents",
            value=f"{open_inc:,}",
            icon="⚡",
            trend_text="Kill-Chains",
            trend_type="amber" if open_inc > 0 else "emerald",
            description="Temporal session clusters",
            card_type="amber"
        )}
        {render_kpi_card(
            title="Composite Risk Index",
            value=f"{avg_risk:.1f}/100",
            icon="📈",
            trend_text="Severity Score",
            trend_type="cyan",
            description="Velocity & diversity weighted",
            card_type="default"
        )}
    </div>
    """
    st.markdown(kpi_html, unsafe_allow_html=True)

    # --- VISUALIZATION ROW 1: TIMELINE & SEVERITY DONUT ---
    row1_col1, row1_col2 = st.columns([2, 1])

    with row1_col1:
        st.markdown("""
        <div class="soc-section-eyebrow">
            <span>// ADVERSARY VELOCITY</span>
        </div>
        <div style="font-size:1.05rem; font-weight:700; color:#F8FAFC; margin-bottom:10px;">
            Real-Time Incursion Telemetry Timeline
        </div>
        """, unsafe_allow_html=True)

        timeline_data = db.get_timeline(limit=30)
        if timeline_data:
            df_tl = pd.DataFrame(timeline_data)
            fig_tl = go.Figure()

            # Area trace for total attacks
            fig_tl.add_trace(go.Scatter(
                x=df_tl['time_bucket'],
                y=df_tl['count'],
                name='Total Incursions',
                mode='lines+markers',
                line=dict(color='#00D4FF', width=2.5, shape='spline'),
                marker=dict(size=5, color='#00D4FF'),
                fill='tozeroy',
                fillcolor='rgba(0, 212, 255, 0.12)'
            ))

            # Bar trace for critical spikes
            fig_tl.add_trace(go.Bar(
                x=df_tl['time_bucket'],
                y=df_tl['critical_count'],
                name='Critical Severity',
                marker=dict(
                    color='#EF4444',
                    line=dict(color='rgba(239, 68, 68, 0.6)', width=1)
                ),
                opacity=0.85
            ))

            apply_plotly_theme(fig_tl)
            fig_tl.update_layout(
                height=320,
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
            )
            st.plotly_chart(fig_tl, use_container_width=True)
        else:
            st.info("No timeline telemetry logged yet. Trigger an attack scenario above to stream data.")

    with row1_col2:
        st.markdown("""
        <div class="soc-section-eyebrow">
            <span>// THREAT CLASSIFICATION</span>
        </div>
        <div style="font-size:1.05rem; font-weight:700; color:#F8FAFC; margin-bottom:10px;">
            Severity Distribution
        </div>
        """, unsafe_allow_html=True)

        sev_data = db.get_severity_distribution()
        if any(sev_data.values()):
            df_sev = pd.DataFrame([
                {"Severity": k, "Count": v} for k, v in sev_data.items() if v > 0
            ])
            color_map = {
                "CRITICAL": "#EF4444",
                "HIGH": "#F97316",
                "MEDIUM": "#F59E0B",
                "LOW": "#38BDF8",
                "INFO": "#10B981"
            }
            fig_donut = px.pie(
                df_sev,
                names="Severity",
                values="Count",
                hole=0.68,
                color="Severity",
                color_discrete_map=color_map
            )
            apply_plotly_theme(fig_donut)
            fig_donut.update_traces(
                textposition='inside',
                textinfo='percent',
                marker=dict(line=dict(color='#080D19', width=2))
            )
            fig_donut.update_layout(
                height=320,
                showlegend=True,
                legend=dict(orientation="v", yanchor="middle", y=0.5, xanchor="left", x=1.02),
                annotations=[dict(
                    text=f"<b>{total_ev}</b><br><span style='font-size:10px;color:#64748B;'>EVENTS</span>",
                    x=0.5, y=0.5,
                    font_size=16,
                    font_color="#F8FAFC",
                    showarrow=False
                )]
            )
            st.plotly_chart(fig_donut, use_container_width=True)
        else:
            st.info("Awaiting telemetry for distribution analysis.")

    # --- VISUALIZATION ROW 2: TOP ADVERSARIES & DECOY SPLIT ---
    row2_col1, row2_col2 = st.columns([1.5, 1])

    with row2_col1:
        st.markdown("""
        <div class="soc-section-eyebrow">
            <span>// ACTOR RECONNAISSANCE</span>
        </div>
        <div style="font-size:1.05rem; font-weight:700; color:#F8FAFC; margin-bottom:10px;">
            Top Incurring Adversary Entities
        </div>
        """, unsafe_allow_html=True)

        top_actors = db.get_top_attackers(limit=6)
        if top_actors:
            df_actors = pd.DataFrame(top_actors)
            st.dataframe(
                df_actors.rename(columns={
                    "source_ip": "Attacker IP",
                    "event_count": "Total Hits",
                    "max_risk": "Peak Risk",
                    "last_seen": "Last Active",
                    "decoys_hit": "Decoys Engaged"
                }),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.write("No active adversaries logged yet.")

    with row2_col2:
        st.markdown("""
        <div class="soc-section-eyebrow">
            <span>// SENSOR WORKLOAD</span>
        </div>
        <div style="font-size:1.05rem; font-weight:700; color:#F8FAFC; margin-bottom:10px;">
            Decoy Incursion Split
        </div>
        """, unsafe_allow_html=True)

        decoy_df = pd.DataFrame([
            {"Decoy": "HTTP Decoy (:8080)", "Events": kpis.get("http_events", 0)},
            {"Decoy": "SSH Decoy (:2222)", "Events": kpis.get("ssh_events", 0)}
        ])
        fig_bar = px.bar(
            decoy_df,
            x="Decoy",
            y="Events",
            color="Decoy",
            color_discrete_sequence=["#00D4FF", "#8B5CF6"]
        )
        apply_plotly_theme(fig_bar)
        fig_bar.update_layout(
            height=280,
            showlegend=False
        )
        st.plotly_chart(fig_bar, use_container_width=True)
