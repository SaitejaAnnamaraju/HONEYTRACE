"""
Unit Tests for HONEYTRACE Risk Engine Module
Verifies dynamic risk scoring, velocity multipliers, decoy diversity bonus, and reputation.
"""

import pytest
from core.risk_engine import RiskEngine


@pytest.fixture
def risk_engine():
    return RiskEngine(velocity_window_seconds=10)


def test_baseline_risk_assessment(risk_engine):
    """Verifies baseline risk calculation for an isolated event."""
    detection = {
        "base_score": 50.0,
        "rule_name": "TEST_RULE",
        "ai_analysis": {"obfuscated": False, "entropy": 2.5}
    }
    risk = risk_engine.assess_risk("10.0.0.1", detection, "HTTP")
    assert risk["risk_score"] >= 50.0
    assert risk["severity"] in ["MEDIUM", "HIGH"]


def test_velocity_burst_multiplier(risk_engine):
    """Verifies repeated attacks from the same IP escalate risk score."""
    detection = {
        "base_score": 60.0,
        "rule_name": "CRED_SPRAY",
        "ai_analysis": {"obfuscated": False, "entropy": 2.0}
    }

    # First event
    r1 = risk_engine.assess_risk("192.168.1.99", detection, "SSH")
    # Simulate burst of 8 rapid attempts
    for _ in range(7):
        risk_engine.assess_risk("192.168.1.99", detection, "SSH")
    r8 = risk_engine.assess_risk("192.168.1.99", detection, "SSH")

    assert r8["risk_score"] > r1["risk_score"]
    assert r8["breakdown"]["velocity_multiplier"] > 1.0


def test_cross_decoy_diversity_bonus(risk_engine):
    """Verifies adversary attacking multiple honeypot types receives diversity penalty."""
    detection = {
        "base_score": 60.0,
        "rule_name": "SCAN",
        "ai_analysis": {"obfuscated": False, "entropy": 3.0}
    }

    # Hit HTTP only
    r_single = risk_engine.assess_risk("10.1.1.5", detection, "HTTP")

    # Hit SSH as well with different IP to test diversity logic
    risk_engine.assess_risk("10.1.1.6", detection, "HTTP")
    r_multi = risk_engine.assess_risk("10.1.1.6", detection, "SSH")

    assert r_multi["breakdown"]["diversity_bonus"] > 0
    assert r_multi["risk_score"] > r_single["risk_score"]


def test_actor_reputation_classification(risk_engine):
    """Verifies threat actor archetype classification logic."""
    rep1, cls1 = risk_engine.calculate_actor_reputation(total_attempts=2, peak_risk=20.0, unique_decoys=1)
    assert cls1 == "Opportunistic Reconnaissance"

    rep2, cls2 = risk_engine.calculate_actor_reputation(total_attempts=25, peak_risk=95.0, unique_decoys=2)
    assert cls2 == "Advanced Persistent Threat (APT) Emulation"
    assert rep2 >= 90.0


def test_explainable_risk_breakdown(risk_engine):
    """Verifies that every score has a human-readable formula explanation and 0-100 bounds."""
    detection = {
        "base_score": 80.0,
        "rule_name": "SQL_INJECTION",
        "ai_analysis": {"obfuscated": True, "entropy": 5.1}
    }
    risk = risk_engine.assess_risk("192.168.10.5", detection, "HTTP")
    assert "explanation" in risk
    assert "Formula:" in risk["explanation"]
    assert 0.0 <= risk["risk_score"] <= 100.0
    assert "compromise_disclaimer" in risk["breakdown"]


def test_normal_vs_suspicious_risk(risk_engine):
    """Verifies that normal benign requests stay in INFO/LOW band while exploits reach HIGH/CRITICAL."""
    benign_det = {
        "base_score": 10.0,
        "rule_name": "BENIGN_NORMAL_ACTIVITY",
        "ai_analysis": {"obfuscated": False, "entropy": 1.5}
    }
    r_benign = risk_engine.assess_risk("10.0.0.1", benign_det, "HTTP")
    assert r_benign["risk_score"] < 25.0
    assert r_benign["severity"] == "INFO"

    exploit_det = {
        "base_score": 95.0,
        "rule_name": "SUSPICIOUS_COMMAND_PATTERN",
        "ai_analysis": {"obfuscated": True, "entropy": 4.9}
    }
    r_exploit = risk_engine.assess_risk("10.0.0.2", exploit_det, "HTTP")
    assert r_exploit["risk_score"] >= 85.0
    assert r_exploit["severity"] == "CRITICAL"

