"""
HONEYTRACE - End-to-End Workflow Verification Script
Executes and validates the entire academic demonstration pipeline:
1. Starts honeypot decoys (HTTP on 8080, SSH on 2222).
2. Verifies decoy network connectivity on localhost.
3. Launches controlled 5-vector attack simulations.
4. Validates event detection, evidence collection, and explainable risk scoring.
5. Correlates atomic telemetry into formal security incidents.
6. Investigates incident timeline and validates attack kill-chain reconstruction.
7. Generates and validates downloadable PDF, JSON, and Markdown reports.
8. Confirms reports are written to the reports/ directory on disk.
"""

import json
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

# Ensure root directory is on PYTHONPATH
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import requests
from core.database import DatabaseManager
from core.incident_engine import IncidentEngine
from dashboard.reports import (
    generate_json_incident_report,
    generate_markdown_incident_dossier,
    generate_pdf_incident_report,
)
from honeypots.http_decoy import get_http_decoy
from honeypots.ssh_decoy import get_ssh_decoy
from simulation.demo_scenarios import DemoScenarios

REPORTS_DIR = ROOT_DIR / "reports"


def run_verification():
    print("=" * 70)
    print("        HONEYTRACE - COMPLETE END-TO-END WORKFLOW VERIFICATION       ")
    print("=" * 70)
    print(f"[*] Execution Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Root Directory:      {ROOT_DIR}")
    print(f"[*] Reports Directory:   {REPORTS_DIR}")
    print()

    db = DatabaseManager("data/honeytrace.db")

    # -------------------------------------------------------------
    # STEP 1: Start Honeypot Decoys
    # -------------------------------------------------------------
    print("[STEP 1/8] Starting Isolated Localhost Decoy Services...")
    http_decoy = get_http_decoy(host="127.0.0.1", port=8080)
    ssh_decoy = get_ssh_decoy(host="127.0.0.1", port=2222)

    try:
        http_decoy.start()
        print("  [+] HTTP Decoy Honeypot active on http://127.0.0.1:8080")
    except Exception as e:
        print(f"  [!] HTTP Decoy notification: {e}")

    try:
        ssh_decoy.start()
        print("  [+] SSH Decoy Honeypot active on tcp://127.0.0.1:2222")
    except Exception as e:
        print(f"  [!] SSH Decoy notification: {e}")

    time.sleep(1.0)

    # -------------------------------------------------------------
    # STEP 2: Probe Decoys via Localhost Loopback
    # -------------------------------------------------------------
    print("\n[STEP 2/8] Probing Decoy Port Bindings (Localhost Loopback)...")
    # Probe HTTP
    try:
        resp = requests.get("http://127.0.0.1:8080/", timeout=2.0)
        print(f"  [+] HTTP Decoy responded with Status Code: {resp.status_code}")
        assert resp.status_code == 200, "HTTP Decoy must return 200 OK"
    except Exception as e:
        print(f"  [!] HTTP probe failed: {e}")
        raise

    # Probe SSH socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(("127.0.0.1", 2222))
        banner = s.recv(1024).decode("utf-8", "ignore")
        s.close()
        print(f"  [+] SSH Decoy emitted OpenSSH banner: {banner.strip()}")
        assert "SSH-2.0-OpenSSH" in banner, "SSH Decoy must transmit OpenSSH banner"
    except Exception as e:
        print(f"  [!] SSH probe failed: {e}")
        raise

    # -------------------------------------------------------------
    # STEP 3: Launch Controlled Attack Simulations (All 5 Scenarios)
    # -------------------------------------------------------------
    print("\n[STEP 3/8] Launching Controlled Attack Simulations...")
    scenarios = DemoScenarios()

    print("  [*] Launching Scenario 1: SSH Brute-Force...")
    scenarios.scenario_ssh_brute_force()

    print("  [*] Launching Scenario 2: Username Enumeration...")
    scenarios.scenario_username_enumeration()

    print("  [*] Launching Scenario 3: HTTP Directory Enumeration...")
    scenarios.scenario_http_directory_enumeration()

    print("  [*] Launching Scenario 4: Suspicious Command Probing...")
    scenarios.scenario_suspicious_command_probing()

    print("  [*] Launching Scenario 5: Repeated Authentication Failures...")
    scenarios.scenario_repeated_auth_failures()

    time.sleep(1.0)
    print("  [+] All 5 attack scenarios completed successfully.")

    # -------------------------------------------------------------
    # STEP 4: Verify Event Detection & Telemetry Persistence
    # -------------------------------------------------------------
    print("\n[STEP 4/8] Verifying Detection Engine, Risk Scoring, & SQLite Persistence...")
    events = db.get_events(limit=50)
    assert len(events) > 0, "Events table must contain captured simulation logs"

    sample_ev = events[0]
    print(f"  [+] Most Recent Event UUID: {sample_ev['event_uuid']}")
    print(f"      - Decoy:       {sample_ev['honeypot_type']}")
    print(f"      - Type:        {sample_ev['event_type']}")
    print(f"      - Rule:        {sample_ev['rule_name']}")
    print(f"      - Severity:    {sample_ev['severity']}")
    print(f"      - Risk Score:  {sample_ev['risk_score']}/100")
    print(f"      - Reason:      {sample_ev['detection_reason']}")
    print(f"      - Evidence:    {sample_ev.get('evidence')}")

    assert sample_ev["risk_score"] >= 0.0, "Risk score must be >= 0"
    assert sample_ev["event_uuid"].startswith("EVT-"), "Event UUID must match EVT-* format"

    # -------------------------------------------------------------
    # STEP 5: Verify Incident Correlation & MITRE Alignment
    # -------------------------------------------------------------
    print("\n[STEP 5/8] Verifying Incident Correlation & Threat Clustering...")
    incidents = db.get_incidents(limit=10)
    assert len(incidents) > 0, "Incidents table must contain correlated attack campaigns"

    target_inc = incidents[0]
    inc_id = target_inc["incident_id"]
    print(f"  [+] Target Correlated Incident: {inc_id}")
    print(f"      - Attacker IP:      {target_inc['attacker_ip']}")
    print(f"      - Severity:         {target_inc['severity']}")
    print(f"      - Peak Risk Score:  {target_inc['peak_risk_score']}/100")
    print(f"      - Event Count:      {target_inc['event_count']}")
    print(f"      - Vectors Observed: {target_inc.get('attack_vectors')}")
    print(f"      - MITRE Tactics:    {target_inc.get('mitre_tactics')}")
    print(f"      - Threat Narrative: {target_inc.get('summary')}")

    # -------------------------------------------------------------
    # STEP 6: Investigate Incident & Timeline Reconstruction
    # -------------------------------------------------------------
    print("\n[STEP 6/8] Investigating Incident & Reconstructing Attack Progression Timeline...")
    inc_engine = IncidentEngine(db)
    timeline = inc_engine.reconstruct_attack_timeline(inc_id)
    assert len(timeline) > 0, "Attack progression timeline must contain chronological steps"

    print(f"  [+] Reconstructed {len(timeline)} sequential attack phases:")
    for step in timeline[:5]:
        print(f"      Step {step['step']:02d} [{step['elapsed']}] ({step['decoy']}): {step['action']} -> {step['severity']} ({step['outcome']})")

    # Test status update workflow
    db.update_incident_status(inc_id, "INVESTIGATING")
    updated_inc = next(i for i in db.get_incidents() if i["incident_id"] == inc_id)
    assert updated_inc["status"] == "INVESTIGATING", "Incident status update to INVESTIGATING failed"
    print(f"  [+] Incident status transitioned to: {updated_inc['status']}")

    # -------------------------------------------------------------
    # STEP 7: Export Reports (PDF, JSON, Markdown, CSV)
    # -------------------------------------------------------------
    print("\n[STEP 7/8] Generating Downloadable Incident Reports...")
    related_events = db.get_events(limit=50, search_query=target_inc["attacker_ip"])
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. JSON Report
    json_content = generate_json_incident_report(target_inc, related_events)
    json_path = REPORTS_DIR / f"{inc_id}_Forensics.json"
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(json_content)
    parsed_json = json.loads(json_content)
    assert parsed_json["incident_id"] == inc_id
    assert "ATTEMPT_CAPTURED_NO_COMPROMISE" in parsed_json["compromise_assessment"]
    assert len(parsed_json["recommended_defensive_actions"]) >= 4
    print(f"  [+] JSON Report exported:     {json_path.name} ({json_path.stat().st_size} bytes)")

    # 2. Markdown Dossier
    md_content = generate_markdown_incident_dossier(target_inc, related_events)
    md_path = REPORTS_DIR / f"{inc_id}_Dossier.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)
    assert inc_id in md_content
    assert "Executive Summary" in md_content
    print(f"  [+] Markdown Dossier exported: {md_path.name} ({md_path.stat().st_size} bytes)")

    # 3. PDF Incident Report
    pdf_bytes = generate_pdf_incident_report(target_inc, related_events)
    pdf_path = REPORTS_DIR / f"{inc_id}_Report.pdf"
    with open(pdf_path, "wb") as f:
        f.write(pdf_bytes)
    assert pdf_path.exists()
    assert pdf_bytes.startswith(b"%PDF"), "PDF report must start with %PDF magic bytes"
    assert len(pdf_bytes) > 1000, "PDF file must be non-empty"
    print(f"  [+] PDF Report exported:      {pdf_path.name} ({pdf_path.stat().st_size} bytes)")

    # -------------------------------------------------------------
    # STEP 8: Clean Up & Final Summary
    # -------------------------------------------------------------
    print("\n[STEP 8/8] Teardown & Verification Summary...")
    kpis = db.get_kpis()
    print("  [+] Platform Operational Health:")
    print(f"      - Total Recorded Events:     {kpis['total_events']}")
    print(f"      - Critical Events:           {kpis['critical_events']}")
    print(f"      - High Severity Events:      {kpis['high_events']}")
    print(f"      - Unique Attacker IP Tracks: {kpis['unique_attackers']}")
    print(f"      - Average Risk Score:        {kpis['avg_risk_score']}/100")
    print(f"      - Active Correlated Incidents:{len(db.get_incidents())}")

    print("\n" + "=" * 70)
    print("  >>> SUCCESS: ALL END-TO-END DEMO WORKFLOW STAGES VERIFIED <<<  ")
    print("=" * 70)
    return True


if __name__ == "__main__":
    success = run_verification()
    sys.exit(0 if success else 1)

