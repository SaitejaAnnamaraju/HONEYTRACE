"""
HONEYTRACE - Detection & Threat Intelligence Engine
Rule-based signature matching, stateful behavioral tracking,
MITRE ATT&CK taxonomy mapping, and AI-assisted heuristic intent analysis.
Strictly non-executing and local-only.
"""

import math
import re
import threading
import time
import urllib.parse
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple


class DetectionEngine:
    """Multi-tiered intrusion detection engine with stateful tracking and explainable diagnostics."""

    def __init__(self, state_window_seconds: int = 60):
        self.state_window = state_window_seconds
        self._compile_signatures()

        # Stateful sliding-window behavioral trackers: ip -> list of (timestamp, metadata)
        self._ssh_failed_window: Dict[str, List[Tuple[float, str, str]]] = defaultdict(list)
        self._username_window: Dict[str, Dict[str, float]] = defaultdict(dict)  # ip -> {username: last_ts}
        self._directory_window: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        self._request_rate_window: Dict[str, List[float]] = defaultdict(list)
        self._state_lock = threading.Lock()

    def _compile_signatures(self) -> None:
        """Pre-compiles regex patterns for high-throughput packet/payload inspection."""
        self.signatures = [
            # 1. Suspicious Command Patterns (T1059 - Command and Scripting Interpreter) - Priority 1
            {
                "rule_name": "SUSPICIOUS_COMMAND_PATTERN",
                "severity": "CRITICAL",
                "base_score": 95.0,
                "mitre_id": "T1059",
                "mitre_tactic": "Execution",
                "intent": "EXECUTION",
                "description": "Arbitrary OS command injection syntax detected in input parameters.",
                "patterns": [
                    r"(?i)(;\s*(cat|ls|dir|whoami|id|uname|pwd)\b)",
                    r"(?i)(\|\s*(cat|ls|dir|whoami|id|uname|bash|sh|powershell|cmd)\b)",
                    r"(?i)(`.*(whoami|id|cat|curl|wget).*`)",
                    r"(?i)(\$\((whoami|id|cat|curl|wget).*\))",
                    r"(?i)(\bwget\b|\bcurl\s+-|nc\s+-e|\bbash\s+-i\b)",
                    r"(?i)(powershell\s+(-enc|-encodedcommand|-nop|-w\s+hidden))"
                ]
            },
            # 2. Log4j / JNDI Exploit (T1190)
            {
                "rule_name": "LOG4J_JNDI_INJECTION",
                "severity": "CRITICAL",
                "base_score": 95.0,
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "intent": "EXPLOITATION",
                "description": "JNDI lookup exploit string targeting log4j vulnerabilities.",
                "patterns": [
                    r"(?i)(\$\{jndi:(ldap|rmi|dns|nis|iiop|corba):)"
                ]
            },
            # 3. Web Shell & Backdoor Probes (T1505.003)
            {
                "rule_name": "WEBSHELL_PROBE",
                "severity": "CRITICAL",
                "base_score": 90.0,
                "mitre_id": "T1505.003",
                "mitre_tactic": "Persistence",
                "intent": "PERSISTENCE",
                "description": "Probing known webshell scripts and backdoor files.",
                "patterns": [
                    r"(?i)(c99\.php|r57\.php|wso\.php|alfa\.php|b374k\.php|cmd\.php|shell\.php)",
                    r"(?i)(\bpassthru\(|\bsystem\(|\bshell_exec\(|\beval\(base64_decode)"
                ]
            },
            # 4. SQL Injection (T1190 - Exploit Public-Facing Application)
            {
                "rule_name": "SQL_INJECTION",
                "severity": "HIGH",
                "base_score": 80.0,
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "intent": "EXPLOITATION",
                "description": "SQL syntax injection attempting database extraction or authentication bypass.",
                "patterns": [
                    r"(?i)(\bunion\b.*\bselect\b)",
                    r"(?i)('\s*(or|and)\s*'?\d+'?\s*=\s*'?\d+)",
                    r"(?i)('\s*or\s+'1'\s*=\s*'1)",
                    r"(?i)(--\s*$|#|/\*.*\*/)",
                    r"(?i)(\bbenchmark\s*\(|\bsleep\s*\(|\bwaitfor\s+delay\b)",
                    r"(?i)(\bdrop\s+table\b|\binsert\s+into\b|\bdelete\s+from\b)",
                    r"(?i)(\binformation_schema\b|\bsys\.tables\b)"
                ]
            },
            # 5. Directory Traversal / LFI (T1083 - File and Directory Discovery)
            {
                "rule_name": "DIRECTORY_TRAVERSAL",
                "severity": "HIGH",
                "base_score": 75.0,
                "mitre_id": "T1083",
                "mitre_tactic": "Discovery",
                "intent": "EXPLOITATION",
                "description": "Path traversal sequences attempting unauthorized filesystem traversal.",
                "patterns": [
                    r"(\.\./|\.\.\\){2,}",
                    r"(?i)(\.\.%2f|\.\.%5c)",
                    r"(?i)(/etc/passwd|/etc/shadow|/etc/hosts)",
                    r"(?i)(win\.ini|boot\.ini|system32\\config)"
                ]
            },
            # 6. Sensitive Config Exposure Probing (T1552 - Unsecured Credentials)
            {
                "rule_name": "CONFIG_CREDENTIAL_PROBE",
                "severity": "MEDIUM",
                "base_score": 60.0,
                "mitre_id": "T1552",
                "mitre_tactic": "Credential Access",
                "intent": "RECONNAISSANCE",
                "description": "Targeted probes against sensitive configuration files and environment secrets.",
                "patterns": [
                    r"(?i)(\.env|\.git/config|wp-config\.php|\.aws/credentials|id_rsa|id_dsa)",
                    r"(?i)(web\.config|database\.yml|application\.properties|settings\.json)"
                ]
            },
            # 7. Automated Vulnerability Scanners (T1595.002 - Vulnerability Scanning)
            {
                "rule_name": "VULN_SCANNER_PROBE",
                "severity": "MEDIUM",
                "base_score": 50.0,
                "mitre_id": "T1595.002",
                "mitre_tactic": "Reconnaissance",
                "intent": "RECONNAISSANCE",
                "description": "User-Agent or request format matching automated security testing tools.",
                "patterns": [
                    r"(?i)(nikto|sqlmap|nmap|masscan|acunetix|dirbuster|gobuster|wpscan|nuclei|zgrab)"
                ]
            }
        ]

    def _clean_stale_state(self, now: float) -> None:
        """Purges behavioral window entries older than state_window."""
        cutoff = now - self.state_window
        for ip in list(self._ssh_failed_window.keys()):
            self._ssh_failed_window[ip] = [e for e in self._ssh_failed_window[ip] if e[0] >= cutoff]
            if not self._ssh_failed_window[ip]:
                del self._ssh_failed_window[ip]

        for ip in list(self._username_window.keys()):
            self._username_window[ip] = {u: t for u, t in self._username_window[ip].items() if t >= cutoff}
            if not self._username_window[ip]:
                del self._username_window[ip]

        for ip in list(self._directory_window.keys()):
            self._directory_window[ip] = [e for e in self._directory_window[ip] if e[0] >= cutoff]
            if not self._directory_window[ip]:
                del self._directory_window[ip]

        for ip in list(self._request_rate_window.keys()):
            self._request_rate_window[ip] = [t for t in self._request_rate_window[ip] if t >= cutoff]
            if not self._request_rate_window[ip]:
                del self._request_rate_window[ip]

    def _calculate_shannon_entropy(self, text: str) -> float:
        """Calculates Shannon entropy to detect packed, obfuscated or encrypted payloads."""
        if not text:
            return 0.0
        entropy = 0.0
        text_len = len(text)
        counts = Counter(text)
        for count in counts.values():
            p_x = count / text_len
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return round(entropy, 2)

    def _detect_obfuscation(self, payload: str) -> Tuple[bool, List[str]]:
        """Detects adversary obfuscation techniques (base64, hex encoding, char codes)."""
        indicators = []
        if "%" in payload and len(re.findall(r"%[0-9a-fA-F]{2}", payload)) > 3:
            indicators.append("Heavy URL Hex Encoding")
        if re.search(r"[A-Za-z0-9+/]{20,}={0,2}", payload):
            indicators.append("Potential Base64 Encoded Block")
        if re.search(r"(?i)char\(\d+\)", payload):
            indicators.append("Character Code Assembly Obfuscation")
        if "%00" in payload or "\x00" in payload:
            indicators.append("Null Byte Evasion")
        return (len(indicators) > 0, indicators)

    def _heuristic_intent_analysis(self, payload: str, endpoint: str, user_agent: str) -> Dict[str, Any]:
        """AI-assisted heuristic classifier evaluating token distribution and intent."""
        combined = f"{endpoint} {payload} {user_agent}".strip()
        entropy = self._calculate_shannon_entropy(combined)
        is_obfuscated, obf_indicators = self._detect_obfuscation(combined)

        recon_terms = ["test", "ping", "info", "robots.txt", "sitemap", "scan", "check", "version"]
        cred_terms = ["admin", "root", "login", "password", "auth", "token", "jwt", "shadow"]
        exploit_terms = ["select", "union", "../", "eval", "system", "jndi", "exec", "drop"]

        text_lower = combined.lower()
        score_recon = sum(1 for term in recon_terms if term in text_lower)
        score_cred = sum(1 for term in cred_terms if term in text_lower)
        score_exploit = sum(2 for term in exploit_terms if term in text_lower)

        if score_exploit >= 2 or is_obfuscated:
            intent_class = "EXPLOITATION"
            confidence = min(0.95, 0.65 + (0.1 * score_exploit) + (0.1 if is_obfuscated else 0.0))
        elif score_cred >= 1:
            intent_class = "CREDENTIAL_ACCESS"
            confidence = min(0.90, 0.60 + (0.15 * score_cred))
        elif score_recon >= 1:
            intent_class = "RECONNAISSANCE"
            confidence = min(0.85, 0.50 + (0.15 * score_recon))
        elif entropy > 4.5:
            intent_class = "ANOMALOUS_PAYLOAD"
            confidence = 0.70
        else:
            intent_class = "BENIGN_BASELINE"
            confidence = 0.80

        return {
            "entropy": entropy,
            "obfuscated": is_obfuscated,
            "obfuscation_indicators": obf_indicators,
            "intent_class": intent_class,
            "confidence": round(confidence, 2)
        }

    def analyze(
        self,
        event_type: str,
        payload: str = "",
        endpoint: str = "",
        username: str = "",
        password: str = "",
        user_agent: str = "",
        protocol: str = "HTTP",
        source_ip: str = "127.0.0.1",
        source_port: int = 0
    ) -> Dict[str, Any]:
        """
        Main inspection entrypoint with stateful correlation and explainable diagnostics.
        Evaluates signatures, velocity anomalies, and MITRE ATT&CK taxonomy.
        """
        now = time.time()
        try:
            decoded_payload = urllib.parse.unquote(payload)
        except Exception:
            decoded_payload = payload

        inspect_target = f"{endpoint} {decoded_payload} {username} {password} {user_agent}".strip()
        ai_meta = self._heuristic_intent_analysis(decoded_payload, endpoint, user_agent)

        with self._state_lock:
            self._clean_stale_state(now)
            # Record request timestamp for rate anomaly tracking
            self._request_rate_window[source_ip].append(now)
            rate_window = self._request_rate_window[source_ip]
            req_count = len(rate_window)

            # Record username if provided
            if username:
                self._username_window[source_ip][username] = now
            unique_users = list(self._username_window[source_ip].keys())

            # Record directory / endpoint if HTTP
            if protocol.upper() == "HTTP" and endpoint:
                self._directory_window[source_ip].append((now, endpoint))
            dir_window = self._directory_window[source_ip]
            unique_paths = list(set(e[1] for e in dir_window))

            # Record failed SSH if SSH auth event
            if protocol.upper() == "SSH" and (event_type in ["AUTH_FAILED", "SSH_HANDSHAKE"] or username or password):
                self._ssh_failed_window[source_ip].append((now, username, password))
            ssh_failed_records = self._ssh_failed_window[source_ip]

        # -------------------------------------------------------------
        # RULE 1: Suspicious Command Patterns (T1059) - Priority 1
        # -------------------------------------------------------------
        for rule in self.signatures:
            if rule["rule_name"] == "SUSPICIOUS_COMMAND_PATTERN":
                for pat in rule["patterns"]:
                    match = re.search(pat, inspect_target)
                    if match:
                        matched_str = match.group(0)
                        return {
                            "detected": True,
                            "rule_name": "SUSPICIOUS_COMMAND_PATTERN",
                            "severity": "CRITICAL",
                            "base_score": 95.0,
                            "mitre_technique_id": "T1059",
                            "mitre_tactic": "Execution",
                            "attack_intent": "EXECUTION",
                            "detection_reason": (
                                f"Observed suspicious command pattern '{matched_str}' in payload/endpoint. "
                                f"Indicates adversary attempting command execution or reverse shell injection. "
                                f"(Note: Telemetry captured on decoy honeypot; command strictly non-executed, host safe)."
                            ),
                            "evidence": {
                                "matched_pattern": pat,
                                "matched_fragment": matched_str,
                                "raw_payload": decoded_payload[:250],
                                "endpoint": endpoint,
                                "compromise_status": "ATTEMPT_CAPTURED_NO_COMPROMISE"
                            },
                            "ai_analysis": ai_meta
                        }

        # -------------------------------------------------------------
        # RULE 2: Repeated Failed SSH Logins (T1110.001)
        # -------------------------------------------------------------
        if protocol.upper() == "SSH" and len(ssh_failed_records) >= 3:
            return {
                "detected": True,
                "rule_name": "REPEATED_SSH_LOGIN_FAILURES",
                "severity": "HIGH",
                "base_score": 85.0,
                "mitre_technique_id": "T1110.001",
                "mitre_tactic": "Credential Access",
                "attack_intent": "CREDENTIAL_ACCESS",
                "detection_reason": (
                    f"Observed {len(ssh_failed_records)} failed SSH authentication attempts from {source_ip} "
                    f"within {self.state_window}s. Frequency exceeds normal human typing threshold, "
                    f"strongly indicating automated dictionary brute-force. (Decoy rejected all authentications)."
                ),
                "evidence": {
                    "failed_count_in_window": len(ssh_failed_records),
                    "window_seconds": self.state_window,
                    "target_port": source_port or 2222,
                    "recent_user_attempted": username,
                    "compromise_status": "ATTEMPT_CAPTURED_NO_COMPROMISE"
                },
                "ai_analysis": ai_meta
            }

        # -------------------------------------------------------------
        # RULE 3: Multiple Username Attempts (T1078 / T1110)
        # -------------------------------------------------------------
        if len(unique_users) >= 3 and (username or event_type in ["LOGIN_ATTEMPT", "AUTH_FAILED"]):
            return {
                "detected": True,
                "rule_name": "MULTIPLE_USERNAME_ATTEMPTS",
                "severity": "HIGH",
                "base_score": 75.0,
                "mitre_technique_id": "T1110",
                "mitre_tactic": "Credential Access",
                "attack_intent": "CREDENTIAL_ACCESS",
                "detection_reason": (
                    f"Source IP {source_ip} attempted authentication with {len(unique_users)} distinct "
                    f"usernames ({', '.join(unique_users[:5])}). Multi-identity probing indicates systematic "
                    f"account enumeration or credential stuffing."
                ),
                "evidence": {
                    "distinct_usernames_probed": unique_users,
                    "total_unique_count": len(unique_users),
                    "last_attempted_user": username,
                    "protocol": protocol,
                    "compromise_status": "ATTEMPT_CAPTURED_NO_COMPROMISE"
                },
                "ai_analysis": ai_meta
            }

        # -------------------------------------------------------------
        # RULE 4: HTTP Directory Enumeration (T1083 / T1595.002)
        # -------------------------------------------------------------
        sensitive_paths = ["/.env", "/admin", "/phpmyadmin", "/wp-config.php", "/config.json", "/.git/config", "/actuator"]
        is_sensitive_probe = any(sp in endpoint.lower() for sp in sensitive_paths)
        if protocol.upper() == "HTTP" and (len(unique_paths) >= 4 or is_sensitive_probe):
            return {
                "detected": True,
                "rule_name": "HTTP_DIRECTORY_ENUMERATION",
                "severity": "HIGH" if is_sensitive_probe else "MEDIUM",
                "base_score": 75.0 if is_sensitive_probe else 60.0,
                "mitre_technique_id": "T1083",
                "mitre_tactic": "Discovery",
                "attack_intent": "RECONNAISSANCE",
                "detection_reason": (
                    f"Source IP {source_ip} probed {len(unique_paths)} distinct path(s) including sensitive routes "
                    f"({endpoint}). Sequential path exploration matches automated directory fuzzers (e.g., Nikto, Gobuster)."
                ),
                "evidence": {
                    "unique_paths_probed": unique_paths[:10],
                    "target_endpoint": endpoint,
                    "user_agent": user_agent,
                    "compromise_status": "ATTEMPT_CAPTURED_NO_COMPROMISE"
                },
                "ai_analysis": ai_meta
            }

        # -------------------------------------------------------------
        # RULE 5: Rapid Repeated Requests Anomaly (T1595)
        # -------------------------------------------------------------
        if req_count >= 8:
            duration = max(1.0, now - rate_window[0])
            req_rate = round(req_count / duration, 2)
            return {
                "detected": True,
                "rule_name": "RAPID_REQUEST_RATE_ANOMALY",
                "severity": "MEDIUM",
                "base_score": 65.0,
                "mitre_technique_id": "T1595",
                "mitre_tactic": "Reconnaissance",
                "attack_intent": "RECONNAISSANCE",
                "detection_reason": (
                    f"Request rate from {source_ip} reached {req_rate} req/s ({req_count} requests in {round(duration, 1)}s). "
                    f"Velocity significantly exceeds human browser pacing, characteristic of automated crawlers or DoS fuzzers."
                ),
                "evidence": {
                    "request_burst_count": req_count,
                    "window_duration_seconds": round(duration, 1),
                    "requests_per_second": req_rate,
                    "compromise_status": "ATTEMPT_CAPTURED_NO_COMPROMISE"
                },
                "ai_analysis": ai_meta
            }

        # -------------------------------------------------------------
        # OTHER STATIC SIGNATURES (SQLi, WebShell, Log4j, Traversal)
        # -------------------------------------------------------------
        for rule in self.signatures:
            for pat in rule["patterns"]:
                match = re.search(pat, inspect_target)
                if match:
                    matched_str = match.group(0)
                    return {
                        "detected": True,
                        "rule_name": rule["rule_name"],
                        "severity": rule["severity"],
                        "base_score": rule["base_score"],
                        "mitre_technique_id": rule["mitre_id"],
                        "mitre_tactic": rule["mitre_tactic"],
                        "attack_intent": rule["intent"],
                        "detection_reason": (
                            f"{rule['description']} Matched pattern '{matched_str}'. "
                            f"(Note: Captured on honeypot decoy; strictly isolated from production assets)."
                        ),
                        "evidence": {
                            "matched_pattern": pat,
                            "matched_fragment": matched_str,
                            "target_endpoint": endpoint,
                            "compromise_status": "ATTEMPT_CAPTURED_NO_COMPROMISE"
                        },
                        "ai_analysis": ai_meta
                    }

        # SSH baseline auth failure
        if protocol.upper() == "SSH" and (event_type == "AUTH_FAILED" or username or password):
            return {
                "detected": True,
                "rule_name": "SSH_BRUTE_FORCE",
                "severity": "HIGH",
                "base_score": 75.0,
                "mitre_technique_id": "T1110.001",
                "mitre_tactic": "Credential Access",
                "attack_intent": "CREDENTIAL_ACCESS",
                "detection_reason": f"SSH authentication attempt for user '{username}'. Probed on decoy port 2222.",
                "evidence": {"username": username, "port": source_port or 2222, "compromise_status": "ATTEMPT_CAPTURED_NO_COMPROMISE"},
                "ai_analysis": ai_meta
            }

        # SSH interactive shell command attempt
        if protocol.upper() == "SSH" and event_type == "COMMAND_ATTEMPT":
            return {
                "detected": True,
                "rule_name": "SUSPICIOUS_COMMAND_PATTERN",
                "severity": "CRITICAL",
                "base_score": 95.0,
                "mitre_technique_id": "T1059",
                "mitre_tactic": "Execution",
                "attack_intent": "EXECUTION",
                "detection_reason": (
                    f"Adversary entered interactive command '{payload}' in SSH decoy restricted shell. "
                    f"(Decoy safely trapped input; command strictly non-executed, zero host compromise occurred)."
                ),
                "evidence": {
                    "attempted_command": payload,
                    "channel": "SSH_DECOY_SHELL",
                    "compromise_status": "ATTEMPT_CAPTURED_NO_COMPROMISE"
                },
                "ai_analysis": ai_meta
            }

        # Scanner User-Agent check
        scanner_agents = ["nikto", "sqlmap", "nmap", "curl", "python-requests", "masscan", "zgrab"]
        if any(sa in user_agent.lower() for sa in scanner_agents):
            return {
                "detected": True,
                "rule_name": "AUTOMATED_SCANNER_UA",
                "severity": "LOW",
                "base_score": 35.0,
                "mitre_technique_id": "T1595",
                "mitre_tactic": "Reconnaissance",
                "attack_intent": "RECONNAISSANCE",
                "detection_reason": f"Automated scanner User-Agent header '{user_agent}' identified.",
                "evidence": {"user_agent": user_agent, "compromise_status": "ATTEMPT_CAPTURED_NO_COMPROMISE"},
                "ai_analysis": ai_meta
            }

        # -------------------------------------------------------------
        # NORMAL / BENIGN BASELINE
        # -------------------------------------------------------------
        return {
            "detected": False,
            "rule_name": "BENIGN_NORMAL_ACTIVITY",
            "severity": "INFO",
            "base_score": 10.0,
            "mitre_technique_id": "T1595",
            "mitre_tactic": "Reconnaissance",
            "attack_intent": "BENIGN_BASELINE",
            "detection_reason": (
                "Normal baseline activity observed. Clean HTTP request with standard headers and no malicious "
                "signatures or abnormal velocity. Interaction recorded for baseline telemetry; no compromise suspected."
            ),
            "evidence": {
                "endpoint": endpoint,
                "protocol": protocol,
                "is_malicious": False,
                "compromise_status": "NO_COMPROMISE_BENIGN_ACTIVITY"
            },
            "ai_analysis": ai_meta
        }
