"""
HONEYTRACE - Attack Simulation Engine
Generates realistic adversary telemetry, multi-stage kill chains, and protocol probes
aimed strictly at localhost honeypot decoys. Safe, reproducible, zero external network.
"""

import logging
import random
import socket
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
import requests

from core.event_collector import EventCollector

logger = logging.getLogger("honeytrace.simulator")


class AttackSimulator:
    """Simulates realistic cyber-attack scenarios against localhost decoys."""

    def __init__(
        self,
        http_target: str = "http://127.0.0.1:8080",
        ssh_host: str = "127.0.0.1",
        ssh_port: int = 2222
    ):
        self.http_target = http_target
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.collector = EventCollector()

    def simulate_ssh_brute_force(self, source_ip: str = "192.168.1.105", count: int = 10) -> List[Dict[str, Any]]:
        """1. SSH brute-force simulation with dictionary wordlists."""
        usernames = ["root", "admin", "ubuntu", "postgres", "guest", "deploy", "oracle", "test"]
        passwords = ["admin123", "toor", "123456", "password", "P@ssw0rd2026", "root123", "letmein", "master"]
        results = []
        for i in range(count):
            u = usernames[i % len(usernames)]
            p = passwords[i % len(passwords)]
            evt = {
                "source_ip": source_ip,
                "source_port": 50000 + i,
                "honeypot_type": "SSH",
                "protocol": "SSH",
                "event_type": "AUTH_FAILED",
                "endpoint": f":{self.ssh_port}",
                "username": u,
                "password": p,
                "payload": f"SSH Dictionary Attack attempt {u}:{p}",
                "user_agent": "SSH-2.0-libssh-0.9.6",
                "session_id": f"SIM-SSH-BF-{source_ip}-{i}"
            }
            res = self.collector.collect(evt, block_sync=True)
            results.append(res)
        return results

    def simulate_username_enumeration(self, source_ip: str = "192.168.1.115", count: int = 8) -> List[Dict[str, Any]]:
        """2. Username enumeration across HTTP admin and SSH decoys."""
        target_users = [
            "administrator", "root", "honeycorp_admin", "service_worker",
            "backup_operator", "db_admin", "devops_lead", "auditor"
        ]
        results = []
        for i, user in enumerate(target_users[:count]):
            # Alternate between HTTP and SSH
            is_http = (i % 2 == 0)
            if is_http:
                evt = {
                    "source_ip": source_ip,
                    "source_port": 51000 + i,
                    "honeypot_type": "HTTP",
                    "protocol": "HTTP",
                    "event_type": "LOGIN_ATTEMPT",
                    "endpoint": "/admin/login",
                    "http_method": "POST",
                    "username": user,
                    "password": "ProbeDummyPassword!2026",
                    "payload": f"Username enumeration probe user='{user}'",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) EnumTools/2.0",
                    "session_id": f"SIM-ENUM-{source_ip}-{i}"
                }
            else:
                evt = {
                    "source_ip": source_ip,
                    "source_port": 51000 + i,
                    "honeypot_type": "SSH",
                    "protocol": "SSH",
                    "event_type": "AUTH_FAILED",
                    "endpoint": f":{self.ssh_port}",
                    "username": user,
                    "password": "ProbeDummyPassword!2026",
                    "payload": f"SSH User Account Enumeration: {user}",
                    "user_agent": "SSH-2.0-OpenSSH_7.4",
                    "session_id": f"SIM-ENUM-{source_ip}-{i}"
                }
            res = self.collector.collect(evt, block_sync=True)
            results.append(res)
        return results

    def simulate_http_directory_enumeration(self, source_ip: str = "10.10.2.45", count: int = 10) -> List[Dict[str, Any]]:
        """3. HTTP directory enumeration fuzzing sensitive routes."""
        fuzz_paths = [
            "/.env", "/admin", "/admin/login", "/phpmyadmin", "/wp-config.php",
            "/.git/config", "/backup.sql", "/api/v1/users", "/actuator/health", "/config.json"
        ]
        scanner_agents = [
            "Mozilla/5.0 (compatible; Nikto/2.1.6)",
            "gobuster/3.1.0",
            "dirbuster/1.0-RC1",
            "Wfuzz/3.1.0"
        ]
        results = []
        for i in range(count):
            path = fuzz_paths[i % len(fuzz_paths)]
            evt = {
                "source_ip": source_ip,
                "source_port": 52000 + i,
                "honeypot_type": "HTTP",
                "protocol": "HTTP",
                "event_type": "SCANNER_PROBE",
                "endpoint": path,
                "http_method": "GET",
                "payload": f"Directory fuzzing request to endpoint {path}",
                "user_agent": scanner_agents[i % len(scanner_agents)],
                "session_id": f"SIM-DIR-{source_ip}-{i}"
            }
            res = self.collector.collect(evt, block_sync=True)
            results.append(res)
        return results

    def simulate_suspicious_command_probing(self, source_ip: str = "172.16.8.99", count: int = 6) -> List[Dict[str, Any]]:
        """4. Suspicious OS command injection probing across HTTP and fake SSH shell."""
        commands = [
            "; cat /etc/passwd",
            "| whoami",
            "; uname -a; id",
            "& powershell -nop -enc JABzACAAPQ...",
            "`curl -O http://127.0.0.1/malware.sh`",
            "; id; pwd"
        ]
        results = []
        for i in range(count):
            cmd = commands[i % len(commands)]
            is_ssh = (i % 2 == 1)
            if is_ssh:
                evt = {
                    "source_ip": source_ip,
                    "source_port": 53000 + i,
                    "honeypot_type": "SSH",
                    "protocol": "SSH",
                    "event_type": "COMMAND_ATTEMPT",
                    "endpoint": f":{self.ssh_port}",
                    "username": "root",
                    "payload": cmd,
                    "user_agent": "SSH-2.0-libssh-0.9.6",
                    "session_id": f"SIM-CMD-SSH-{source_ip}-{i}"
                }
            else:
                evt = {
                    "source_ip": source_ip,
                    "source_port": 53000 + i,
                    "honeypot_type": "HTTP",
                    "protocol": "HTTP",
                    "event_type": "COMMAND_INJECTION",
                    "endpoint": f"/api/v1/search?q={cmd}",
                    "http_method": "POST",
                    "payload": cmd,
                    "user_agent": "Python-urllib/3.14",
                    "session_id": f"SIM-CMD-HTTP-{source_ip}-{i}"
                }
            res = self.collector.collect(evt, block_sync=True)
            results.append(res)
        return results

    def simulate_repeated_auth_failures(self, source_ip: str = "192.168.1.180", count: int = 12) -> List[Dict[str, Any]]:
        """5. Rapid repeated authentication failures to demonstrate velocity burst escalation."""
        results = []
        for i in range(count):
            evt = {
                "source_ip": source_ip,
                "source_port": 54000 + i,
                "honeypot_type": "HTTP",
                "protocol": "HTTP",
                "event_type": "LOGIN_ATTEMPT",
                "endpoint": "/login",
                "http_method": "POST",
                "username": "corporate_admin",
                "password": f"WrongPassword_{i}!@#",
                "payload": f"Repeated login failure sequence item {i+1}",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Bot/1.0",
                "session_id": f"SIM-BURST-{source_ip}-{i}"
            }
            res = self.collector.collect(evt, block_sync=True)
            results.append(res)
        return results

    def run_direct_event_simulation(
        self,
        scenario_name: str,
        source_ip: str,
        count: int = 5,
        delay_seconds: float = 0.0
    ) -> List[Dict[str, Any]]:
        """Dispatcher for scenario execution by identifier."""
        if scenario_name == "SSH_BRUTE_FORCE":
            return self.simulate_ssh_brute_force(source_ip=source_ip, count=count)
        elif scenario_name == "USERNAME_ENUMERATION":
            return self.simulate_username_enumeration(source_ip=source_ip, count=count)
        elif scenario_name == "DIRECTORY_ENUMERATION" or scenario_name == "SCANNER_RECON":
            return self.simulate_http_directory_enumeration(source_ip=source_ip, count=count)
        elif scenario_name == "COMMAND_INJECTION" or scenario_name == "COMMAND_PROBING":
            return self.simulate_suspicious_command_probing(source_ip=source_ip, count=count)
        elif scenario_name == "AUTH_FAILURES":
            return self.simulate_repeated_auth_failures(source_ip=source_ip, count=count)
        elif scenario_name == "SQL_INJECTION":
            sqli_payloads = [
                "' OR '1'='1' --",
                "1' UNION SELECT null, username, password FROM users --",
                "1; DROP TABLE users; --",
                "' OR 1=1 AND SLEEP(5) --"
            ]
            results = []
            for i in range(count):
                payload = sqli_payloads[i % len(sqli_payloads)]
                evt = {
                    "source_ip": source_ip,
                    "source_port": 45000 + i,
                    "honeypot_type": "HTTP",
                    "protocol": "HTTP",
                    "event_type": "SQL_INJECTION",
                    "endpoint": f"/api/v1/users?id={payload}",
                    "http_method": "GET",
                    "payload": payload,
                    "user_agent": "sqlmap/1.6.4#stable",
                    "session_id": f"SIM-SQLI-{source_ip}-{i}"
                }
                res = self.collector.collect(evt, block_sync=True)
                results.append(res)
            return results
        elif scenario_name == "DIRECTORY_TRAVERSAL":
            lfi_payloads = ["../../../../etc/passwd", "../../../../win.ini"]
            results = []
            for i in range(count):
                payload = lfi_payloads[i % len(lfi_payloads)]
                evt = {
                    "source_ip": source_ip,
                    "source_port": 46000 + i,
                    "honeypot_type": "HTTP",
                    "protocol": "HTTP",
                    "event_type": "DIRECTORY_TRAVERSAL",
                    "endpoint": f"/view?file={payload}",
                    "http_method": "GET",
                    "payload": payload,
                    "user_agent": "Mozilla/5.0",
                    "session_id": f"SIM-LFI-{source_ip}-{i}"
                }
                res = self.collector.collect(evt, block_sync=True)
                results.append(res)
            return results
        return []

    def trigger_live_http_probe(self, endpoint: str, params: Optional[dict] = None) -> bool:
        """Sends an actual loopback HTTP probe over TCP socket to 127.0.0.1:8080."""
        try:
            url = f"{self.http_target}{endpoint}"
            requests.get(url, params=params, timeout=2.0)
            return True
        except Exception:
            return False

    def trigger_live_ssh_probe(self, username: str = "root", password: str = "123456") -> bool:
        """Connects over socket to 127.0.0.1:2222 and transmits authentication probe."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((self.ssh_host, self.ssh_port))
            s.recv(1024)
            s.sendall(b"SSH-2.0-HoneyTraceClientSim_1.0\r\n")
            s.sendall(f"{username}:{password}\n".encode("utf-8"))
            time.sleep(0.1)
            s.close()
            return True
        except Exception:
            return False
