"""
Unit Tests for HONEYTRACE Database Module
Verifies SQLite schema creation, CRUD operations, KPI aggregation, and threat profiling.
"""

import os
import tempfile
import pytest
from pathlib import Path
from core.database import DatabaseManager


@pytest.fixture
def temp_db():
    """Provides a fresh isolated database for each test run."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_path = Path(f.name)

    db = DatabaseManager(db_path=temp_path)
    yield db

    # Cleanup
    try:
        if temp_path.exists():
            os.remove(temp_path)
    except Exception:
        pass


def test_db_initialization(temp_db):
    """Verifies all tables are properly created on init."""
    kpis = temp_db.get_kpis()
    assert kpis["total_events"] == 0
    assert kpis["critical_events"] == 0
    assert kpis["unique_attackers"] == 0


def test_insert_and_get_events(temp_db):
    """Tests inserting and querying events."""
    event_data = {
        "timestamp": "2026-11-09T00:00:00",
        "source_ip": "192.168.1.100",
        "source_port": 45123,
        "honeypot_type": "HTTP",
        "protocol": "HTTP",
        "event_type": "SQL_INJECTION",
        "endpoint": "/api/v1/users",
        "payload": "' OR 1=1 --",
        "risk_score": 85.0,
        "severity": "CRITICAL",
        "mitre_technique_id": "T1190",
        "mitre_tactic": "Initial Access",
        "rule_name": "SQL_INJECTION"
    }

    event_id = temp_db.insert_event(event_data)
    assert event_id > 0

    events = temp_db.get_events(limit=10)
    assert len(events) == 1
    assert events[0]["source_ip"] == "192.168.1.100"
    assert events[0]["severity"] == "CRITICAL"
    assert events[0]["risk_score"] == 85.0


def test_kpis_calculation(temp_db):
    """Verifies aggregated metrics math."""
    temp_db.insert_event({
        "source_ip": "10.0.0.1",
        "honeypot_type": "HTTP",
        "severity": "CRITICAL",
        "risk_score": 90.0
    })
    temp_db.insert_event({
        "source_ip": "10.0.0.2",
        "honeypot_type": "SSH",
        "severity": "LOW",
        "risk_score": 20.0
    })

    kpis = temp_db.get_kpis()
    assert kpis["total_events"] == 2
    assert kpis["critical_events"] == 1
    assert kpis["unique_attackers"] == 2
    assert kpis["ssh_events"] == 1
    assert kpis["http_events"] == 1
    assert kpis["avg_risk_score"] == 55.0


def test_threat_actor_upsert(temp_db):
    """Verifies attacker profiling records."""
    temp_db.upsert_threat_actor(
        ip="192.168.1.50",
        classification="Targeted Exploiter",
        risk_score=80.0,
        decoy="HTTP",
        cred="admin:password"
    )

    actors = temp_db.get_threat_actors()
    assert len(actors) == 1
    assert actors[0]["ip"] == "192.168.1.50"
    assert actors[0]["classification"] == "Targeted Exploiter"
    assert "HTTP" in actors[0]["targeted_honeypots"]
    assert "admin:password" in actors[0]["known_credentials_tried"]


def test_clear_database(temp_db):
    """Verifies purging operations."""
    temp_db.insert_event({"source_ip": "10.0.0.1", "honeypot_type": "HTTP"})
    assert temp_db.get_kpis()["total_events"] == 1

    temp_db.clear_database()
    assert temp_db.get_kpis()["total_events"] == 0


def test_event_uuid_assigned(temp_db):
    """Verifies each event receives a unique identifier."""
    temp_db.insert_event({
        "event_uuid": "EVT-20261109-TEST01",
        "source_ip": "127.0.0.1",
        "honeypot_type": "HTTP"
    })
    events = temp_db.get_events(limit=5)
    assert len(events) == 1
    assert events[0]["event_uuid"] == "EVT-20261109-TEST01"


def test_alerts_storage_and_evidence(temp_db):
    """Verifies that alerts are stored in SQLite with evidence and detection reasoning."""
    alert_id = temp_db.insert_alert({
        "event_uuid": "EVT-20261109-ALERTTST",
        "source_ip": "192.168.1.88",
        "honeypot_type": "HTTP",
        "rule_name": "SUSPICIOUS_COMMAND_PATTERN",
        "severity": "CRITICAL",
        "risk_score": 95.0,
        "mitre_technique_id": "T1059",
        "detection_reason": "OS command injection detected.",
        "evidence": {"matched_pattern": "; whoami", "contained": True}
    })
    assert alert_id > 0

    alerts = temp_db.get_alerts(limit=5)
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "SUSPICIOUS_COMMAND_PATTERN"
    assert alerts[0]["severity"] == "CRITICAL"
    assert alerts[0]["evidence"]["matched_pattern"] == "; whoami"
    assert "ATTEMPT_CAPTURED_NO_COMPROMISE" in alerts[0]["compromise_assessment"]


def test_attack_timeline_reconstruction(temp_db):
    """Verifies chronological attack timeline reconstruction for an incident."""
    from core.incident_engine import IncidentEngine
    inc_engine = IncidentEngine(db=temp_db)

    ip = "192.168.100.5"
    # Event 1: Recon
    temp_db.insert_event({
        "timestamp": "2026-11-09T01:00:00",
        "source_ip": ip,
        "honeypot_type": "HTTP",
        "event_type": "SCANNER_PROBE",
        "endpoint": "/.env",
        "risk_score": 50.0,
        "severity": "MEDIUM",
        "mitre_tactic": "Reconnaissance"
    })
    # Event 2: Command injection
    temp_db.insert_event({
        "timestamp": "2026-11-09T01:00:15",
        "source_ip": ip,
        "honeypot_type": "HTTP",
        "event_type": "COMMAND_INJECTION",
        "endpoint": "/search?q=;whoami",
        "risk_score": 95.0,
        "severity": "CRITICAL",
        "mitre_tactic": "Execution"
    })

    # Group incident
    inc_id = "INC-202611090100-1005"
    temp_db.upsert_incident({
        "incident_id": inc_id,
        "attacker_ip": ip,
        "first_seen": "2026-11-09T01:00:00",
        "last_seen": "2026-11-09T01:00:15",
        "severity": "CRITICAL",
        "peak_risk_score": 95.0,
        "event_count": 2,
        "attack_vectors": ["HTTP:SCANNER_PROBE", "HTTP:COMMAND_INJECTION"],
        "mitre_tactics": ["Reconnaissance", "Execution"],
        "summary": "Multi-stage attack.",
        "status": "OPEN"
    })

    timeline = inc_engine.reconstruct_attack_timeline(inc_id)
    assert len(timeline) == 2
    assert timeline[0]["step"] == 1
    assert timeline[1]["step"] == 2
    assert timeline[0]["elapsed"] == "+00:00"
    assert timeline[1]["elapsed"] == "+00:15"
    assert "No host system compromise" in timeline[0]["outcome"]

