"""
Unit Tests for HONEYTRACE Detection Engine
Verifies signature regex matching, AI heuristic analysis, and MITRE ATT&CK taxonomy.
"""

import pytest
from core.detection_engine import DetectionEngine


@pytest.fixture
def detector():
    return DetectionEngine()


def test_sqli_detection(detector):
    """Verifies SQL injection detection and MITRE tag assignment."""
    payload = "1' UNION SELECT username, password FROM users --"
    res = detector.analyze(event_type="SQL_INJECTION", payload=payload, endpoint="/api/v1/users")
    assert res["detected"] is True
    assert res["rule_name"] == "SQL_INJECTION"
    assert res["severity"] == "HIGH"
    assert res["mitre_technique_id"] == "T1190"
    assert res["mitre_tactic"] == "Initial Access"


def test_directory_traversal_detection(detector):
    """Verifies directory traversal / LFI detection."""
    payload = "../../../../etc/passwd"
    res = detector.analyze(event_type="PROBE", payload=payload, endpoint=f"/view?file={payload}")
    assert res["detected"] is True
    assert res["rule_name"] == "DIRECTORY_TRAVERSAL"
    assert res["mitre_technique_id"] == "T1083"
    assert res["mitre_tactic"] == "Discovery"


def test_command_injection_detection(detector):
    """Verifies OS command injection detection."""
    payload = "; cat /etc/shadow"
    res = detector.analyze(event_type="PROBE", payload=payload, endpoint="/search")
    assert res["detected"] is True
    assert res["rule_name"] in ["SUSPICIOUS_COMMAND_PATTERN", "COMMAND_INJECTION"]
    assert res["severity"] == "CRITICAL"
    assert res["mitre_technique_id"] == "T1059"
    assert res["mitre_tactic"] == "Execution"


def test_log4j_injection_detection(detector):
    """Verifies Log4Shell / JNDI probe detection."""
    payload = "${jndi:ldap://127.0.0.1:1389/Exploit}"
    res = detector.analyze(event_type="PROBE", payload=payload, user_agent=payload)
    assert res["detected"] is True
    assert res["rule_name"] == "LOG4J_JNDI_INJECTION"
    assert res["severity"] == "CRITICAL"


def test_scanner_user_agent_detection(detector):
    """Verifies automated scanning tools detection."""
    ua = "Mozilla/5.00 (Nikto/2.1.6) (CVE-2001-0842)"
    res = detector.analyze(event_type="PROBE", user_agent=ua)
    assert res["detected"] is True
    assert res["mitre_tactic"] == "Reconnaissance"


def test_ssh_heuristics(detector):
    """Verifies SSH brute force and command trapping."""
    res_auth = detector.analyze(event_type="AUTH_FAILED", username="root", password="123", protocol="SSH")
    assert res_auth["detected"] is True
    assert res_auth["rule_name"] == "SSH_BRUTE_FORCE"
    assert res_auth["mitre_tactic"] == "Credential Access"

    res_cmd = detector.analyze(event_type="COMMAND_ATTEMPT", payload="whoami", protocol="SSH")
    assert res_cmd["detected"] is True
    assert res_cmd["rule_name"] in ["SUSPICIOUS_COMMAND_PATTERN", "SSH_COMMAND_TRAP"]
    assert res_cmd["severity"] == "CRITICAL"


def test_entropy_and_obfuscation(detector):
    """Verifies AI Shannon entropy and obfuscation indicators."""
    low_entropy = detector._calculate_shannon_entropy("aaaaaaa")
    high_entropy = detector._calculate_shannon_entropy("aX9#mK2$vL8!zQ4@")
    assert high_entropy > low_entropy

    is_obf, ind = detector._detect_obfuscation("%2e%2e%2f%2e%2e%2f%2e%2e%2f")
    assert is_obf is True
    assert len(ind) > 0


def test_normal_benign_web_activity(detector):
    """Verifies that legitimate normal web traffic is classified as BENIGN with INFO severity."""
    res = detector.analyze(
        event_type="PORTAL_VISIT",
        endpoint="/",
        payload="GET / HTTP/1.1",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        protocol="HTTP",
        source_ip="192.168.1.5"
    )
    assert res["detected"] is False
    assert res["rule_name"] == "BENIGN_NORMAL_ACTIVITY"
    assert res["severity"] == "INFO"
    assert res["base_score"] <= 15.0
    assert "compromise" in res["evidence"]["compromise_status"].lower()
    assert res["evidence"]["is_malicious"] is False
    assert "normal baseline" in res["detection_reason"].lower()


def test_repeated_failed_ssh_logins_rule(detector):
    """Verifies that 3 or more failed SSH attempts from the same IP trigger REPEATED_SSH_LOGIN_FAILURES."""
    ip = "192.168.50.25"
    # First 2 attempts
    detector.analyze(event_type="AUTH_FAILED", username="root", password="1", protocol="SSH", source_ip=ip)
    detector.analyze(event_type="AUTH_FAILED", username="root", password="2", protocol="SSH", source_ip=ip)
    # Third attempt triggers rule
    res = detector.analyze(event_type="AUTH_FAILED", username="root", password="3", protocol="SSH", source_ip=ip)
    assert res["detected"] is True
    assert res["rule_name"] == "REPEATED_SSH_LOGIN_FAILURES"
    assert res["severity"] in ["HIGH", "CRITICAL"]
    assert res["evidence"]["failed_count_in_window"] >= 3
    assert "brute-force" in res["detection_reason"].lower()


def test_multiple_username_attempts_rule(detector):
    """Verifies that probing 3 or more distinct usernames triggers MULTIPLE_USERNAME_ATTEMPTS."""
    ip = "192.168.60.30"
    detector.analyze(event_type="LOGIN_ATTEMPT", username="alice", endpoint="/login", protocol="HTTP", source_ip=ip)
    detector.analyze(event_type="LOGIN_ATTEMPT", username="bob", endpoint="/login", protocol="HTTP", source_ip=ip)
    res = detector.analyze(event_type="LOGIN_ATTEMPT", username="charlie", endpoint="/login", protocol="HTTP", source_ip=ip)
    assert res["detected"] is True
    assert res["rule_name"] == "MULTIPLE_USERNAME_ATTEMPTS"
    assert res["severity"] == "HIGH"
    assert res["evidence"]["total_unique_count"] >= 3


def test_http_directory_enumeration_rule(detector):
    """Verifies that fuzzing sensitive endpoints triggers HTTP_DIRECTORY_ENUMERATION."""
    ip = "10.0.5.12"
    res = detector.analyze(event_type="SCANNER_PROBE", endpoint="/.env", protocol="HTTP", source_ip=ip)
    assert res["detected"] is True
    assert res["rule_name"] == "HTTP_DIRECTORY_ENUMERATION"
    assert res["mitre_technique_id"] == "T1083"


def test_suspicious_command_pattern_rule(detector):
    """Verifies OS command injection syntax triggers SUSPICIOUS_COMMAND_PATTERN with CRITICAL severity."""
    res = detector.analyze(
        event_type="COMMAND_INJECTION",
        payload="; cat /etc/passwd",
        endpoint="/api/v1/search?q=; cat /etc/passwd",
        protocol="HTTP",
        source_ip="172.16.1.9"
    )
    assert res["detected"] is True
    assert res["rule_name"] == "SUSPICIOUS_COMMAND_PATTERN"
    assert res["severity"] == "CRITICAL"
    assert res["base_score"] >= 90.0
    assert "ATTEMPT_CAPTURED_NO_COMPROMISE" in res["evidence"]["compromise_status"]


def test_rapid_repeated_requests_rule(detector):
    """Verifies that high-frequency request bursts trigger RAPID_REQUEST_RATE_ANOMALY."""
    ip = "10.20.30.40"
    # Send 8 rapid requests
    for _ in range(7):
        detector.analyze(event_type="PROBE", endpoint="/test", protocol="HTTP", source_ip=ip)
    res = detector.analyze(event_type="PROBE", endpoint="/test", protocol="HTTP", source_ip=ip)
    assert res["detected"] is True
    assert res["rule_name"] == "RAPID_REQUEST_RATE_ANOMALY"
    assert res["evidence"]["request_burst_count"] >= 8
    assert res["evidence"]["requests_per_second"] > 0


def test_five_simulation_scenarios():
    """Verifies all 5 required demonstration attack simulation scenarios execute cleanly."""
    from simulation.attack_simulator import AttackSimulator
    sim = AttackSimulator()

    # 1. SSH brute force
    r1 = sim.simulate_ssh_brute_force(count=3)
    assert len(r1) == 3
    assert r1[0]["honeypot_type"] == "SSH"

    # 2. Username enumeration
    r2 = sim.simulate_username_enumeration(count=4)
    assert len(r2) == 4

    # 3. HTTP directory enumeration
    r3 = sim.simulate_http_directory_enumeration(count=4)
    assert len(r3) == 4
    assert r3[0]["honeypot_type"] == "HTTP"

    # 4. Suspicious command probing
    r4 = sim.simulate_suspicious_command_probing(count=3)
    assert len(r4) == 3

    # 5. Repeated auth failures
    r5 = sim.simulate_repeated_auth_failures(count=5)
    assert len(r5) == 5
    assert r5[0]["event_type"] == "LOGIN_ATTEMPT"

