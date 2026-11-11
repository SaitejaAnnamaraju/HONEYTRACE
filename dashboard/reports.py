"""
HONEYTRACE - Incident Reports & Forensic Export
Generates downloadable incident reports in PDF, JSON, Markdown, and CSV,
complete with event evidence, timestamps, risk scores, severity,
detection explanations, and defensive countermeasure recommendations.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from fpdf import FPDF
import pandas as pd
import streamlit as st

from core.database import DatabaseManager
from core.incident_engine import IncidentEngine

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"


def get_defensive_recommendations(incident: dict, events: list) -> List[str]:
    """Generates specific defensive countermeasure actions based on observed attack vectors."""
    recs = [
        "1. Perimeter Defense: Enforce immediate firewall drop rule / fail2ban jail for source IP " + incident.get("attacker_ip", "127.0.0.1") + ".",
        "2. Identity & Access: Lock targeted accounts, enforce Multi-Factor Authentication (MFA), and audit active sessions.",
        "3. Application Hardening: Enforce parameterized queries (OWASP A03) and strict path canonicalization for file APIs.",
        "4. Non-Compromise Containment: Host assets safe. Maintain decoy honeypot monitoring to gather lateral movement telemetry."
    ]
    vectors = incident.get("attack_vectors", [])
    if any("SQL" in v for v in vectors):
        recs.append("5. Database Security: Review database user permissions and revoke administrative rights from application connection strings.")
    if any("COMMAND" in v for v in vectors):
        recs.append("6. Shell Execution Audit: Verify that application daemons run under non-root / unprivileged service accounts.")
    return recs


def generate_json_incident_report(incident: dict, events: list) -> str:
    """Generates structured forensic JSON report complete with evidence, timestamps, and reasoning."""
    now_str = datetime.now().isoformat()
    recs = get_defensive_recommendations(incident, events)

    report_obj = {
        "platform": "HONEYTRACE Active Deception Platform",
        "report_type": "FORENSIC_INCIDENT_REPORT",
        "generated_at": now_str,
        "incident_id": incident.get("incident_id"),
        "attacker_ip": incident.get("attacker_ip"),
        "severity": incident.get("severity"),
        "peak_risk_score": incident.get("peak_risk_score"),
        "event_count": incident.get("event_count"),
        "first_seen": incident.get("first_seen"),
        "last_seen": incident.get("last_seen"),
        "status": incident.get("status"),
        "summary": incident.get("summary", ""),
        "attack_vectors": incident.get("attack_vectors", []),
        "mitre_tactics": incident.get("mitre_tactics", []),
        "compromise_assessment": "ATTEMPT_CAPTURED_NO_COMPROMISE (Decoy Trapped - Non-Executed)",
        "recommended_defensive_actions": recs,
        "correlated_events": [
            {
                "id": e.get("id"),
                "event_uuid": e.get("event_uuid"),
                "timestamp": e.get("timestamp"),
                "source_ip": e.get("source_ip"),
                "source_port": e.get("source_port"),
                "honeypot_type": e.get("honeypot_type"),
                "protocol": e.get("protocol"),
                "event_type": e.get("event_type"),
                "endpoint": e.get("endpoint"),
                "risk_score": e.get("risk_score"),
                "severity": e.get("severity"),
                "rule_name": e.get("rule_name"),
                "detection_explanation": e.get("detection_reason", ""),
                "evidence": json.loads(e.get("evidence")) if isinstance(e.get("evidence"), str) and e.get("evidence").strip().startswith(("{", "[")) else (e.get("evidence") or {}),
                "payload_sample": str(e.get("payload", ""))[:250]
            }
            for e in events
        ]
    }
    return json.dumps(report_obj, indent=2)


def generate_markdown_incident_dossier(incident: dict, events: list) -> str:
    """Generates structured forensic markdown report for an incident."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    recs = get_defensive_recommendations(incident, events)

    report = f"""# HONEYTRACE INCIDENT DOSSIER
**Incident Identifier:** `{incident['incident_id']}`  
**Classification:** {incident['severity']}  
**Generated At:** {now_str}  
**Platform:** HoneyTrace Deception-Based Intrusion Detection System  
**Compromise Assessment:** ATTEMPT CAPTURED (Decoy Trapped - Zero Host Compromise)  

---

## 1. Executive Summary
- **Attacker Source IP:** `{incident['attacker_ip']}`
- **Initial Detection:** `{incident['first_seen']}`
- **Last Active:** `{incident['last_seen']}`
- **Peak Risk Rating:** **{incident['peak_risk_score']} / 100**
- **Total Interaction Events:** {incident['event_count']}
- **Investigation Status:** `{incident['status']}`

### Threat Narrative
> {incident.get('summary', 'No narrative summary compiled.')}

---

## 2. Attack Vectors & MITRE ATT&CK Alignment
### Observed Techniques:
"""
    for v in incident.get("attack_vectors", []):
        report += f"- `{v}`\n"

    report += "\n### MITRE Tactics Traversed:\n"
    for t in incident.get("mitre_tactics", []):
        report += f"- **{t}**\n"

    report += """
---

## 3. Recommended Defensive Actions
"""
    for r in recs:
        report += f"- {r}\n"

    report += """
---

## 4. Timeline of Forensic Telemetry
| Timestamp | Decoy | Event Type | Endpoint | Risk Score | Rule Name | Detection Explanation |
|---|---|---|---|---|---|---|
"""
    for e in events[:15]:
        reason_clean = str(e.get('detection_reason', 'Rule heuristic matched'))[:60].replace('|', '/')
        report += f"| {e['timestamp']} | {e['honeypot_type']} | {e['event_type']} | {e['endpoint']} | {e['risk_score']} | {e['rule_name']} | {reason_clean} |\n"

    report += """
---
*Report automatically compiled by HONEYTRACE Forensic Engine. Telemetry gathered from isolated deception decoys.*
"""
    return report


def generate_pdf_incident_report(incident: dict, events: list) -> bytes:
    """Generates an executive PDF incident report using fpdf2."""
    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_left_margin(10)
    pdf.set_right_margin(10)
    pdf.add_page()

    def clean_text(s: Any) -> str:
        if s is None:
            return ""
        # Ensure latin-1 compatibility for default standard PDF fonts
        return str(s).encode("latin-1", "replace").decode("latin-1")

    # Header Banner
    pdf.set_fill_color(15, 23, 42)
    pdf.rect(0, 0, 210, 32, "F")

    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(56, 189, 248)
    pdf.set_xy(10, 8)
    pdf.cell(190, 8, "HONEYTRACE CYBERSECURITY INCIDENT REPORT", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(148, 163, 184)
    pdf.set_xy(10, 18)
    pdf.cell(190, 6, "AI-Assisted Deception Platform - Formal Evaluation Dossier", new_x="LMARGIN", new_y="NEXT")

    pdf.set_text_color(15, 23, 42)

    # Incident Overview Box
    pdf.set_fill_color(241, 245, 249)
    pdf.set_draw_color(203, 213, 225)
    pdf.rect(10, 36, 190, 42, "DF")

    pdf.set_xy(14, 40)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(40, 6, "Incident ID:")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(55, 6, clean_text(incident.get("incident_id", "N/A")))

    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(40, 6, "Severity:")
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(45, 6, clean_text(incident.get("severity", "N/A")), new_x="LMARGIN", new_y="NEXT")

    pdf.set_xy(14, 48)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(40, 6, "Attacker IP:")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(55, 6, clean_text(incident.get("attacker_ip", "N/A")))

    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(40, 6, "Peak Risk Score:")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(45, 6, f"{incident.get('peak_risk_score', 0)}/100", new_x="LMARGIN", new_y="NEXT")

    pdf.set_xy(14, 56)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(40, 6, "First Seen:")
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(55, 6, clean_text(incident.get("first_seen", "N/A")))

    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(40, 6, "Last Seen:")
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(45, 6, clean_text(incident.get("last_seen", "N/A")), new_x="LMARGIN", new_y="NEXT")

    pdf.set_xy(14, 64)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(40, 6, "Compromise Status:")
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(16, 185, 129)
    pdf.cell(140, 6, "ATTEMPT CAPTURED (Zero Host Compromise - Decoy Trapped)", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(15, 23, 42)

    # Narrative Summary Section
    pdf.set_xy(10, 83)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(190, 7, "1. Executive Narrative Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_x(10)
    pdf.multi_cell(190, 5, clean_text(incident.get("summary", "No narrative recorded.")), new_x="LMARGIN", new_y="NEXT")

    pdf.ln(3)

    # Recommended Defensive Actions
    pdf.set_x(10)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(190, 7, "2. Recommended Defensive Countermeasures", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    recs = get_defensive_recommendations(incident, events)
    for r in recs:
        pdf.set_x(10)
        pdf.multi_cell(190, 5, clean_text(r), new_x="LMARGIN", new_y="NEXT")

    pdf.ln(3)

    # Forensic Telemetry Table
    pdf.set_x(10)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(190, 7, "3. Chronological Forensic Telemetry (Decoy Captures)", new_x="LMARGIN", new_y="NEXT")

    # Table Header
    pdf.set_x(10)
    pdf.set_fill_color(30, 41, 59)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(32, 6, "Timestamp", border=1, align="C", fill=True)
    pdf.cell(16, 6, "Decoy", border=1, align="C", fill=True)
    pdf.cell(34, 6, "Event Type", border=1, align="C", fill=True)
    pdf.cell(38, 6, "Endpoint / Port", border=1, align="C", fill=True)
    pdf.cell(14, 6, "Risk", border=1, align="C", fill=True)
    pdf.cell(56, 6, "Detection Rule & Reasoning", border=1, align="C", fill=True, new_x="LMARGIN", new_y="NEXT")

    # Table Rows
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(30, 41, 59)
    for e in events[:16]:
        ts_short = clean_text(e.get("timestamp", ""))[-8:]
        decoy_short = clean_text(e.get("honeypot_type", ""))[:6]
        ev_type_short = clean_text(e.get("event_type", ""))[:18]
        ep_short = clean_text(e.get("endpoint", "") or f":{e.get('source_port', '')}")[:22]
        risk_str = str(e.get("risk_score", 0))
        rule_desc = clean_text(e.get("rule_name", "") + " - " + str(e.get("detection_reason", "")))[:38]

        pdf.set_x(10)
        pdf.cell(32, 5, ts_short, border=1)
        pdf.cell(16, 5, decoy_short, border=1, align="C")
        pdf.cell(34, 5, ev_type_short, border=1)
        pdf.cell(38, 5, ep_short, border=1)
        pdf.cell(14, 5, risk_str, border=1, align="C")
        pdf.cell(56, 5, rule_desc, border=1, new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)
    pdf.set_x(10)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(190, 5, "Report compiled by HONEYTRACE Forensic Engine. 100% Localhost isolated deception.", align="C", new_x="LMARGIN", new_y="NEXT")

    # Output raw PDF bytes
    return bytes(pdf.output())


def render_reports(db: DatabaseManager):
    """Renders the reports and forensic exports tab."""
    from dashboard.theme import render_section_header

    render_section_header(
        eyebrow="FORENSIC COMPLIANCE // AUDIT DOSSIERS",
        title="Forensic Evidence Packages & Incident Reports",
        caption="Generate audit-grade forensic packages and executive dossiers in PDF, JSON, Markdown, and CSV."
    )

    incidents = db.get_incidents(limit=25)

    if not incidents:
        st.info("No security incidents correlated yet. Trigger an attack scenario from Overview to compile dossiers.")
        return

    # Incident Selection
    inc_ids = [inc["incident_id"] for inc in incidents]
    selected_inc_id = st.selectbox(
        "Select Correlated Incident to compile report:",
        options=inc_ids,
        format_func=lambda x: f"{x} — Attacker: {next((i['attacker_ip'] for i in incidents if i['incident_id'] == x), '')} — Sev: {next((i['severity'] for i in incidents if i['incident_id'] == x), '')}"
    )

    incident = next((i for i in incidents if i["incident_id"] == selected_inc_id), None)
    if incident:
        ip = incident["attacker_ip"]
        related_events = db.get_events(limit=50, search_query=ip)

        markdown_dossier = generate_markdown_incident_dossier(incident, related_events)
        json_report = generate_json_incident_report(incident, related_events)

        try:
            pdf_bytes = generate_pdf_incident_report(incident, related_events)
        except Exception as e:
            pdf_bytes = None
            st.error(f"PDF generation error: {e}")

        # Download Buttons Cards Grid
        st.markdown("""
        <div style="font-size:0.9rem; font-weight:700; color:#F8FAFC; margin-bottom:12px;">
            📥 Download Formal Evidence Packages:
        </div>
        """, unsafe_allow_html=True)

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            if pdf_bytes:
                st.download_button(
                    label="📄 Download PDF Report",
                    data=pdf_bytes,
                    file_name=f"{incident['incident_id']}_Report.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            else:
                st.button("PDF Unavailable", disabled=True, use_container_width=True)

        with c2:
            st.download_button(
                label="📦 Download JSON Package",
                data=json_report,
                file_name=f"{incident['incident_id']}_Forensics.json",
                mime="application/json",
                use_container_width=True
            )

        with c3:
            st.download_button(
                label="📥 Download Markdown Dossier",
                data=markdown_dossier,
                file_name=f"{incident['incident_id']}_Dossier.md",
                mime="text/markdown",
                use_container_width=True
            )

        with c4:
            df_all = pd.DataFrame(related_events)
            csv_data = df_all.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="📊 Export Evidence CSV",
                data=csv_data,
                file_name=f"{incident['incident_id']}_Forensics.csv",
                mime="text/csv",
                use_container_width=True
            )

        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("💾 Persist All Formats (PDF, JSON, MD) to Local `reports/` Directory", use_container_width=True):
            REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            inc_id = incident["incident_id"]

            # Save MD
            with open(REPORTS_DIR / f"{inc_id}_Dossier.md", "w", encoding="utf-8") as f:
                f.write(markdown_dossier)
            # Save JSON
            with open(REPORTS_DIR / f"{inc_id}_Forensics.json", "w", encoding="utf-8") as f:
                f.write(json_report)
            # Save PDF
            if pdf_bytes:
                with open(REPORTS_DIR / f"{inc_id}_Report.pdf", "wb") as f:
                    f.write(pdf_bytes)

            st.success(f"Reports successfully saved to local directory `reports/{inc_id}_*`")

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("""
        <div class="soc-section-eyebrow">
            <span>// AUDIT TRAIL</span>
        </div>
        <div style="font-size:1.05rem; font-weight:700; color:#F8FAFC; margin-bottom:10px;">
            Reconstructed Kill-Chain Progression Telemetry
        </div>
        """, unsafe_allow_html=True)

        timeline = IncidentEngine(db).reconstruct_attack_timeline(incident["incident_id"])
        if timeline:
            df_tl = pd.DataFrame(timeline)
            st.dataframe(
                df_tl[["step", "elapsed", "decoy", "tactic", "rule_name", "action", "risk_score", "severity", "outcome"]].rename(columns={
                    "step": "Step",
                    "elapsed": "T-Elapsed",
                    "decoy": "Decoy",
                    "tactic": "MITRE Tactic",
                    "rule_name": "Detection Rule",
                    "action": "Attacker Action",
                    "risk_score": "Risk",
                    "severity": "Severity",
                    "outcome": "Outcome / Containment"
                }),
                use_container_width=True,
                hide_index=True
            )

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("""
        <div class="soc-section-eyebrow">
            <span>// FORMAL INCIDENT ALERTS</span>
        </div>
        <div style="font-size:1.05rem; font-weight:700; color:#F8FAFC; margin-bottom:10px;">
            Correlated Alerts &amp; Forensic Evidence (SQLite alerts Table)
        </div>
        """, unsafe_allow_html=True)

        alerts = db.get_alerts(limit=25)
        if alerts:
            df_alerts = pd.DataFrame(alerts)
            st.dataframe(
                df_alerts[["alert_id", "timestamp", "source_ip", "honeypot_type", "rule_name", "severity", "risk_score", "detection_reason"]].rename(columns={
                    "alert_id": "Alert ID",
                    "timestamp": "Timestamp",
                    "source_ip": "Source IP",
                    "honeypot_type": "Decoy",
                    "rule_name": "Triggered Rule",
                    "severity": "Severity",
                    "risk_score": "Score",
                    "detection_reason": "Detection Reasoning"
                }),
                use_container_width=True,
                hide_index=True
            )

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("### 📋 Preview of Compiled Incident Dossier")
        st.markdown(markdown_dossier)
        st.markdown("### Preview of Compiled Incident Dossier")
        st.markdown(markdown_dossier)
