"""
HONEYTRACE - Live Attack Monitor & Deep Packet Inspector (Enterprise SOC)
Streaming forensic telemetry view with multi-attribute filtering,
raw payload disassembly, and AI heuristic evaluation inspection.
"""

from datetime import date, datetime, timedelta
import json
import pandas as pd
import streamlit as st
from core.database import DatabaseManager
from dashboard.theme import (
    render_section_header,
    render_severity_badge
)


def render_live_monitor(db: DatabaseManager):
    """Renders the real-time event log and deep payload inspection view."""
    render_section_header(
        eyebrow="TELEMETRY STREAM // FORENSIC LOG",
        title="Live Attack Monitor & Deep Packet Inspector",
        caption="Inspect real-time adversary probes and dissect raw payload telemetry captured on isolated decoys."
    )

    # --- FILTER TOOLBAR PANEL ---
    with st.container():
        distinct_types = ["ALL"] + db.get_distinct_event_types()

        col_f1, col_f2, col_f3 = st.columns([1.5, 1.5, 2])
        with col_f1:
            severity_filter = st.selectbox(
                "Severity Classification",
                ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                index=0
            )
        with col_f2:
            event_type_filter = st.selectbox(
                "Attack Event Category",
                distinct_types,
                index=0
            )
        with col_f3:
            honeypot_filter = st.selectbox(
                "Target Decoy Listener",
                ["ALL", "HTTP", "SSH"],
                index=0
            )

        col_d1, col_d2, col_s = st.columns([1.5, 1.5, 2])
        with col_d1:
            start_d = st.date_input("Start Date", value=date.today() - timedelta(days=7))
        with col_d2:
            end_d = st.date_input("End Date", value=date.today() + timedelta(days=1))
        with col_s:
            search_query = st.text_input("Deep Search (IP, Endpoint, Payload, User)", placeholder="e.g. 192.168, union, admin, etc/passwd")

        limit = st.select_slider("Events Stream Limit", options=[25, 50, 100, 200, 500], value=50)

    # Query events from database
    start_str = f"{start_d}T00:00:00"
    end_str = f"{end_d}T23:59:59"

    events = db.get_events(
        limit=limit,
        honeypot_type=honeypot_filter if honeypot_filter != "ALL" else None,
        severity=severity_filter if severity_filter != "ALL" else None,
        event_type=event_type_filter if event_type_filter != "ALL" else None,
        start_date=start_str,
        end_date=end_str,
        search_query=search_query if search_query else None
    )

    if not events:
        st.info("No matching telemetry events found for the active filter parameters. Adjust filters or launch an attack scenario from Overview.")
        return

    # Convert to DataFrame for display
    df = pd.DataFrame(events)

    def format_severity(sev):
        badges = {
            "CRITICAL": "🔴 CRITICAL",
            "HIGH": "🟠 HIGH",
            "MEDIUM": "🟡 MEDIUM",
            "LOW": "🔵 LOW",
            "INFO": "🟢 INFO"
        }
        return badges.get(sev, sev)

    df["Severity_Badge"] = df["severity"].apply(format_severity)

    display_cols = [
        "id", "event_uuid" if "event_uuid" in df.columns else "id", "timestamp", "source_ip", "honeypot_type", "event_type",
        "endpoint", "risk_score", "Severity_Badge", "mitre_technique_id", "rule_name"
    ]
    display_cols = list(dict.fromkeys(display_cols))

    rename_map = {
        "id": "ID",
        "event_uuid": "Event UUID",
        "timestamp": "Timestamp",
        "source_ip": "Attacker IP",
        "honeypot_type": "Decoy",
        "event_type": "Event Type",
        "endpoint": "Endpoint/Port",
        "risk_score": "Risk",
        "Severity_Badge": "Severity",
        "mitre_technique_id": "MITRE ID",
        "rule_name": "Triggered Rule"
    }

    st.markdown(f"**Showing {len(events)} captured incursion events:**")
    st.dataframe(
        df[display_cols].rename(columns=rename_map),
        use_container_width=True,
        hide_index=True
    )

    st.markdown("<br>", unsafe_allow_html=True)

    # --- DEEP FORENSIC PAYLOAD INSPECTOR ---
    st.markdown("""
    <div class="soc-section-eyebrow">
        <span>// FORENSIC DISASSEMBLY</span>
    </div>
    <div style="font-size:1.15rem; font-weight:700; color:#F8FAFC; margin-bottom:12px;">
        Deep Packet &amp; Payload Inspector
    </div>
    """, unsafe_allow_html=True)

    event_ids = [e["id"] for e in events]
    selected_id = st.selectbox(
        "Select Event ID to inspect deep forensics & AI diagnostic evaluation:",
        options=event_ids,
        format_func=lambda x: f"Event #{x} — {next((e.get('event_uuid', '') + ' | ' + e['source_ip'] + ' ' + e['event_type'] for e in events if e['id'] == x), '')}"
    )

    selected_event = next((e for e in events if e["id"] == selected_id), None)
    if selected_event:
        d1, d2 = st.columns([1.5, 1])

        with d1:
            st.markdown(f"""
            <div style="background:#111B2D; border:1px solid rgba(255,255,255,0.08); border-radius:8px; padding:16px; margin-bottom:16px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <span style="font-size:0.75rem; text-transform:uppercase; letter-spacing:0.08em; color:#00D4FF; font-weight:700;">// RAW PAYLOAD DISASSEMBLY</span>
                    <span style="font-size:0.75rem; color:#64748B; font-family:monospace;">UUID: {selected_event.get('event_uuid', 'N/A')}</span>
                </div>
                <div style="font-size:0.85rem; color:#94A3B8; margin-bottom:6px;">
                    <strong>Endpoint:</strong> <code style="color:#00D4FF;">{selected_event.get('endpoint') or '/'}</code> &bull; 
                    <strong>Timestamp:</strong> <code>{selected_event.get('timestamp')}</code>
                </div>
            </div>
            """, unsafe_allow_html=True)

            st.code(selected_event.get("payload") or "(Empty body / connection handshake)", language="text")

            # Captured Authentication Credentials
            user = selected_event.get("username") or "None"
            pwd = selected_event.get("password") or "None"
            if user != "None" or pwd != "None":
                st.markdown("""
                <div style="font-size:0.8rem; font-weight:700; text-transform:uppercase; color:#F59E0B; margin-top:14px; margin-bottom:6px;">
                    🔑 Trapped Authentication Credentials
                </div>
                """, unsafe_allow_html=True)
                c_u, c_p = st.columns(2)
                c_u.info(f"**Username Sprayed:** `{user}`")
                c_p.warning(f"**Password Sprayed:** `{pwd}`")

            # Request Headers
            st.markdown("""
            <div style="font-size:0.8rem; font-weight:700; text-transform:uppercase; color:#94A3B8; margin-top:14px; margin-bottom:6px;">
                🌐 Client Fingerprint &amp; Protocol Headers
            </div>
            """, unsafe_allow_html=True)
            try:
                headers = json.loads(selected_event.get("headers") or "{}")
                if headers:
                    st.json(headers)
                else:
                    st.caption("No custom client headers recorded for this connection.")
            except Exception:
                st.code(selected_event.get("headers") or "{}")

        with d2:
            st.markdown("""
            <div style="font-size:0.85rem; font-weight:700; text-transform:uppercase; color:#8B5CF6; margin-bottom:8px;">
                🧬 AI Threat Diagnostics &amp; Rule Heuristics
            </div>
            """, unsafe_allow_html=True)

            # Metadata Card
            risk_val = selected_event.get("risk_score", 0.0)
            sev = selected_event.get("severity", "INFO")
            rule = selected_event.get("rule_name", "UNKNOWN")
            reason = selected_event.get("detection_reason", "Heuristic matched")
            evidence = selected_event.get("evidence", {})

            st.markdown(f"""
            <div style="background:#0F1A2E; border:1px solid rgba(255,255,255,0.08); border-radius:8px; padding:16px; margin-bottom:14px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                    <span style="font-size:0.75rem; color:#94A3B8; text-transform:uppercase; font-weight:600;">Calculated Risk</span>
                    {render_severity_badge(sev)}
                </div>
                <div style="font-size:1.8rem; font-weight:800; color:#F8FAFC; margin-bottom:8px;">
                    {risk_val}<span style="font-size:1rem; color:#64748B;">/100</span>
                </div>
                <div style="font-size:0.8rem; color:#94A3B8; margin-bottom:4px;">
                    <strong>Triggered Rule:</strong> <code style="color:#00D4FF;">{rule}</code>
                </div>
                <div style="font-size:0.8rem; color:#94A3B8; margin-bottom:4px;">
                    <strong>MITRE Technique:</strong> <code>{selected_event.get('mitre_technique_id', 'T1595')}</code> ({selected_event.get('mitre_tactic', 'Reconnaissance')})
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Detection Reason Box
            st.markdown("**Explainable Detection Reasoning:**")
            st.info(f"💡 {reason}")

            # Evidence Payload
            st.markdown("**Correlated Forensic Evidence:**")
            if isinstance(evidence, dict) and evidence:
                st.json(evidence)
            else:
                st.code(str(evidence) if evidence else "No auxiliary evidence tokens attached.")

            # Safety confirmation badge
            st.markdown("""
            <div style="background:rgba(16, 185, 129, 0.08); border:1px solid rgba(16, 185, 129, 0.3); border-radius:6px; padding:10px 14px; margin-top:14px;">
                <span style="color:#34D399; font-weight:700; font-size:0.8rem;">🛡️ DECOY CONTAINED:</span>
                <span style="color:#94A3B8; font-size:0.78rem;"> Payload strictly logged as passive text. Zero host system execution.</span>
            </div>
            """, unsafe_allow_html=True)
