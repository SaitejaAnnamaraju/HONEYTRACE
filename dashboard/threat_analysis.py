"""
HONEYTRACE - Threat Intelligence & MITRE Analysis View (Enterprise SOC)
Adversary behavioral analytics, MITRE ATT&CK matrix mapping,
credential harvesting intelligence, and threat actor profiling dossiers.
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from core.database import DatabaseManager
from dashboard.theme import render_section_header, apply_plotly_theme


def render_threat_analysis(db: DatabaseManager):
    """Renders advanced threat intelligence and MITRE analytics view."""
    render_section_header(
        eyebrow="ADVERSARY PROFILING // MITRE ATT&CK TAXONOMY",
        title="Threat Intelligence & Adversary Behavioral Analytics",
        caption="Map adversary behaviors across MITRE ATT&CK techniques, inspect actor dossiers, and analyze credential harvests."
    )

    # --- MITRE ATT&CK TACTICS SECTION ---
    mitre_data = db.get_mitre_breakdown()
    if mitre_data:
        df_mitre = pd.DataFrame(mitre_data)

        col_m1, col_m2 = st.columns([1.4, 1])

        with col_m1:
            st.markdown("""
            <div style="font-size:0.95rem; font-weight:700; color:#F8FAFC; margin-bottom:8px;">
                🎯 MITRE ATT&CK Sunburst Hierarchy
            </div>
            """, unsafe_allow_html=True)
            fig_sunburst = px.sunburst(
                df_mitre,
                path=["mitre_tactic", "mitre_technique_id", "rule_name"],
                values="count",
                color="max_risk",
                color_continuous_scale=["#00D4FF", "#F59E0B", "#EF4444"],
            )
            apply_plotly_theme(fig_sunburst)
            fig_sunburst.update_layout(
                height=340,
                margin=dict(l=5, r=5, t=10, b=5)
            )
            st.plotly_chart(fig_sunburst, use_container_width=True)

        with col_m2:
            st.markdown("""
            <div style="font-size:0.95rem; font-weight:700; color:#F8FAFC; margin-bottom:8px;">
                📊 Most Triggered Detection Rules
            </div>
            """, unsafe_allow_html=True)
            rule_counts = df_mitre.groupby("rule_name")["count"].sum().reset_index().sort_values(by="count", ascending=True)
            fig_rules = px.bar(
                rule_counts,
                x="count",
                y="rule_name",
                orientation="h",
                color="count",
                color_continuous_scale=["#0284C7", "#00D4FF"]
            )
            apply_plotly_theme(fig_rules)
            fig_rules.update_layout(
                height=340,
                margin=dict(l=10, r=10, t=10, b=10),
                showlegend=False
            )
            st.plotly_chart(fig_rules, use_container_width=True)
    else:
        st.info("No MITRE telemetry recorded yet. Trigger simulation scenarios to populate analytics.")

    st.markdown("<br>", unsafe_allow_html=True)

    # --- THREAT ACTOR PROFILING DOSSIERS ---
    st.markdown("""
    <div class="soc-section-eyebrow">
        <span>// ADVERSARY TRACKING</span>
    </div>
    <div style="font-size:1.15rem; font-weight:700; color:#F8FAFC; margin-bottom:12px;">
        Threat Actor Profiling &amp; Reputation Dossiers
    </div>
    """, unsafe_allow_html=True)

    actors = db.get_threat_actors(limit=20)
    if actors:
        for actor in actors:
            rep = actor.get("reputation_score", 0)
            rep_color = "#EF4444" if rep >= 80 else ("#F97316" if rep >= 50 else "#38BDF8")
            classification = actor.get("classification", "UNKNOWN")

            class_badge_color = "#EF4444" if "APT" in classification else ("#F59E0B" if "Credential" in classification else "#00D4FF")

            with st.expander(f"🕵️ Actor IP: {actor['ip']}  —  [{classification}]  —  Reputation: {rep}/100"):
                st.markdown(f"""
                <div style="background:#0F1A2E; border:1px solid rgba(255,255,255,0.06); border-radius:8px; padding:16px; margin-bottom:12px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                        <span style="font-size:0.8rem; font-weight:700; color:{class_badge_color}; text-transform:uppercase; letter-spacing:0.06em;">
                            Archetype: {classification}
                        </span>
                        <span class="soc-pill" style="border-color:{rep_color}; color:{rep_color};">
                            Threat Index: {rep}/100
                        </span>
                    </div>
                    <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:12px; font-size:0.82rem; color:#94A3B8;">
                        <div><strong>First Detected:</strong> <code>{actor.get('first_seen', 'N/A')}</code></div>
                        <div><strong>Last Active:</strong> <code>{actor.get('last_seen', 'N/A')}</code></div>
                        <div><strong>Total Incursions:</strong> <code style="color:#00D4FF;">{actor.get('total_attempts', 0)} hits</code></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown(f"**Targeted Deception Decoys:** `{', '.join(actor.get('targeted_honeypots', [])) or 'None'}`")

                creds = actor.get("known_credentials_tried", [])
                if creds:
                    st.markdown("**Intercepted Credential Probes:**")
                    st.code(", ".join(creds), language="text")
    else:
        st.write("No threat actor profiles compiled yet.")

    st.markdown("<br>", unsafe_allow_html=True)

    # --- CREDENTIAL HARVESTING INTELLIGENCE ---
    st.markdown("""
    <div class="soc-section-eyebrow">
        <span>// IDENTITY TELEMETRY</span>
    </div>
    <div style="font-size:1.15rem; font-weight:700; color:#F8FAFC; margin-bottom:12px;">
        Harvested Credential Intelligence &amp; Spray Analytics
    </div>
    """, unsafe_allow_html=True)

    creds_data = db.get_top_credentials(limit=10)
    if creds_data:
        c_left, c_right = st.columns([1.4, 1])
        with c_left:
            df_creds = pd.DataFrame(creds_data)
            st.dataframe(
                df_creds.rename(columns={
                    "username": "Harvested Username",
                    "password": "Harvested Password",
                    "attempts": "Total Spray Frequency",
                    "last_attempt": "Last Probed"
                }),
                use_container_width=True,
                hide_index=True
            )
        with c_right:
            fig_c = px.bar(
                df_creds.head(6),
                x="attempts",
                y="username",
                orientation="h",
                title="Top Targeted Account Usernames",
                color="attempts",
                color_continuous_scale=["#8B5CF6", "#C084FC"]
            )
            apply_plotly_theme(fig_c)
            fig_c.update_layout(
                height=260,
                margin=dict(l=10, r=10, t=30, b=10),
                showlegend=False
            )
            st.plotly_chart(fig_c, use_container_width=True)
    else:
        st.info("No credential harvesting attempts recorded yet.")
