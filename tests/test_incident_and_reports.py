"""
HONEYTRACE - Incident & Forensic Reports Test Suite
Validates incident correlation, timeline reconstruction, defensive recommendations,
and PDF/JSON/Markdown report generation with attached evidence and timestamps.
"""

import json
from pathlib import Path
import pytest
from core.database import DatabaseManager
from core.incident_engine import IncidentEngine
from dashboard.reports import (
    generate_json_incident_report,
    generate_markdown_incident_dossier,
    generate_pdf_incident_report,
    get_defensive_recommendations,
)


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_reports.db"
    db = DatabaseManager(str(db_file))
    yield db


def test_incident_correlation_and_timeline(temp_db):
    # Insert multiple correlated events
    ev1_id = temp_db.insert_event({
        "timestamp": "2026-11-09T01:00:00",
        "source_ip": "192.168.1.150",
        "source_port": 51234,
        "honeypot_type": "HTTP_DECOY",
        "protocol": "HTTP",
        "event_type": "DIRECTORY_TRAVERSAL",
        "endpoint": "/view?file=../../../../etc/passwd",
        "payload": "GET /view?file=../../../../etc/passwd HTTP/1.1",
        "risk_score": 85.0,
        "severity": "HIGH",
        "rule_name": "RULE_DIRECTORY_TRAVERSAL",
        "detection_reason": "Relative path escape pattern detected",
        "evidence": {"matched_pattern": "../../../../etc/passwd"},
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1083",
    })
    assert ev1_id is not None

    ev2_id = temp_db.insert_event({
        "timestamp": "2026-11-09T01:00:20",
        "source_ip": "192.168.1.150",
        "source_port": 51236,
        "honeypot_type": "HTTP_DECOY",
        "protocol": "HTTP",
        "event_type": "SQL_INJECTION",
        "endpoint": "/api/v1/users?id=1' UNION SELECT username,password FROM users--",
        "payload": "UNION SELECT username,password FROM users--",
        "risk_score": 95.0,
        "severity": "CRITICAL",
        "rule_name": "RULE_SQL_INJECTION",
        "detection_reason": "SQL injection token UNION SELECT detected",
        "evidence": {"matched_token": "UNION SELECT"},
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190",
    })
    assert ev2_id is not None

    engine = IncidentEngine(temp_db)
    ev1_dict = {"source_ip": "192.168.1.150", "honeypot_type": "HTTP_DECOY", "endpoint": "/view"}
    det1 = {"rule_name": "RULE_DIRECTORY_TRAVERSAL", "mitre_tactic": "Discovery"}
    risk1 = {"risk_score": 85.0, "severity": "HIGH"}
    incident_id = engine.correlate_event(ev1_dict, det1, risk1)
    assert incident_id is not None
    assert incident_id.startswith("INC-")

    ev2_dict = {"source_ip": "192.168.1.150", "honeypot_type": "HTTP_DECOY", "endpoint": "/api/v1/users"}
    det2 = {"rule_name": "RULE_SQL_INJECTION", "mitre_tactic": "Initial Access"}
    risk2 = {"risk_score": 95.0, "severity": "CRITICAL"}
    incident_id2 = engine.correlate_event(ev2_dict, det2, risk2)
    assert incident_id2 == incident_id

    # Verify incident was recorded in DB
    incidents = temp_db.get_incidents()
    assert len(incidents) >= 1
    inc = next(i for i in incidents if i["incident_id"] == incident_id)
    assert inc["attacker_ip"] == "192.168.1.150"
    assert inc["severity"] == "CRITICAL"
    assert inc["peak_risk_score"] >= 95.0
    assert inc["event_count"] >= 2

    # Verify timeline reconstruction
    timeline = engine.reconstruct_attack_timeline(incident_id)
    assert len(timeline) >= 2
    assert timeline[0]["step"] == 1
    assert timeline[0]["action"] is not None
    assert "outcome" in timeline[0]
    assert "No host system compromise" in timeline[0]["outcome"]

    # Verify status update
    updated = temp_db.update_incident_status(incident_id, "INVESTIGATING")
    assert updated is True
    inc_after = next(i for i in temp_db.get_incidents() if i["incident_id"] == incident_id)
    assert inc_after["status"] == "INVESTIGATING"


def test_defensive_recommendations():
    mock_incident = {
        "incident_id": "INC-TEST-001",
        "attacker_ip": "10.0.0.99",
        "attack_vectors": ["SQL_INJECTION", "COMMAND_INJECTION"],
        "severity": "CRITICAL"
    }
    recs = get_defensive_recommendations(mock_incident, [])
    assert len(recs) >= 4
    # Check that IP is in recommendation
    assert any("10.0.0.99" in r for r in recs)
    # Check that SQL and command injection actions are present
    assert any("Database Security" in r for r in recs)
    assert any("Shell Execution Audit" in r for r in recs)


def test_json_incident_report_generation(temp_db):
    incident = {
        "incident_id": "INC-TEST-2026",
        "attacker_ip": "192.168.5.88",
        "severity": "CRITICAL",
        "peak_risk_score": 96.5,
        "event_count": 3,
        "first_seen": "2026-11-09T01:10:00",
        "last_seen": "2026-11-09T01:12:00",
        "status": "OPEN",
        "summary": "Multi-stage automated attack targeting corporate decoys.",
        "attack_vectors": ["DIRECTORY_TRAVERSAL", "SQL_INJECTION"],
        "mitre_tactics": ["Discovery", "Initial Access"],
    }
    events = [
        {
            "id": 1,
            "event_uuid": "EVT-001",
            "timestamp": "2026-11-09T01:10:00",
            "source_ip": "192.168.5.88",
            "source_port": 49201,
            "honeypot_type": "HTTP_DECOY",
            "protocol": "HTTP",
            "event_type": "DIRECTORY_TRAVERSAL",
            "endpoint": "/view?file=../../../../etc/passwd",
            "risk_score": 85.0,
            "severity": "HIGH",
            "rule_name": "RULE_DIRECTORY_TRAVERSAL",
            "detection_reason": "Traversal sequence detected in path parameter",
            "evidence": {"matched_sequence": "../../../.."},
            "payload": "GET /view?file=../../../../etc/passwd HTTP/1.1"
        }
    ]

    json_str = generate_json_incident_report(incident, events)
    data = json.loads(json_str)

    assert data["incident_id"] == "INC-TEST-2026"
    assert data["attacker_ip"] == "192.168.5.88"
    assert data["severity"] == "CRITICAL"
    assert data["peak_risk_score"] == 96.5
    assert "ATTEMPT_CAPTURED_NO_COMPROMISE" in data["compromise_assessment"]
    assert len(data["recommended_defensive_actions"]) >= 4
    assert len(data["correlated_events"]) == 1
    assert data["correlated_events"][0]["event_uuid"] == "EVT-001"
    assert data["correlated_events"][0]["detection_explanation"] == "Traversal sequence detected in path parameter"
    assert data["correlated_events"][0]["evidence"] == {"matched_sequence": "../../../.."}


def test_markdown_incident_dossier_generation():
    incident = {
        "incident_id": "INC-TEST-MD",
        "attacker_ip": "192.168.5.88",
        "severity": "HIGH",
        "peak_risk_score": 80.0,
        "event_count": 2,
        "first_seen": "2026-11-09T01:10:00",
        "last_seen": "2026-11-09T01:12:00",
        "status": "OPEN",
        "summary": "Demonstration reconnaissance activity.",
        "attack_vectors": ["DIRECTORY_TRAVERSAL"],
        "mitre_tactics": ["Discovery"],
    }
    events = [
        {
            "timestamp": "2026-11-09T01:10:00",
            "honeypot_type": "HTTP_DECOY",
            "event_type": "DIRECTORY_TRAVERSAL",
            "endpoint": "/view",
            "risk_score": 80.0,
            "rule_name": "RULE_DIR_TRAV",
            "detection_reason": "Traversal signature"
        }
    ]

    md = generate_markdown_incident_dossier(incident, events)
    assert "# HONEYTRACE INCIDENT DOSSIER" in md
    assert "INC-TEST-MD" in md
    assert "192.168.5.88" in md
    assert "ATTEMPT CAPTURED" in md
    assert "Recommended Defensive Actions" in md


def test_pdf_incident_report_generation():
    incident = {
        "incident_id": "INC-TEST-PDF",
        "attacker_ip": "172.16.0.45",
        "severity": "CRITICAL",
        "peak_risk_score": 98.0,
        "event_count": 5,
        "first_seen": "2026-11-09T01:05:00",
        "last_seen": "2026-11-09T01:07:00",
        "status": "OPEN",
        "summary": "Multi-vector penetration test targeting SSH and HTTP decoys.",
        "attack_vectors": ["SSH_BRUTE_FORCE", "COMMAND_INJECTION"],
        "mitre_tactics": ["Credential Access", "Execution"],
    }
    events = [
        {
            "timestamp": "2026-11-09T01:05:00",
            "honeypot_type": "SSH_DECOY",
            "event_type": "SSH_LOGIN_ATTEMPT",
            "endpoint": "/ssh",
            "source_port": 2222,
            "risk_score": 85.0,
            "rule_name": "RULE_SSH_BRUTE_FORCE",
            "detection_reason": "High frequency failed SSH logins",
            "evidence": {"attempts": 6}
        },
        {
            "timestamp": "2026-11-09T01:06:00",
            "honeypot_type": "HTTP_DECOY",
            "event_type": "COMMAND_INJECTION",
            "endpoint": "/api/v1/ping",
            "source_port": 8080,
            "risk_score": 98.0,
            "rule_name": "RULE_COMMAND_INJECTION",
            "detection_reason": "OS shell pipeline invocation trapped",
            "evidence": {"matched_token": "; cat /etc/shadow"}
        }
    ]

    pdf_bytes = generate_pdf_incident_report(incident, events)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")
