"""
HONEYTRACE - Academic Demonstration Scenarios
Pre-packaged cyber-attack simulations for viva defense and project demonstrations.
Runs locally against decoys without external internet.
"""

import logging
from typing import Dict, List
from simulation.attack_simulator import AttackSimulator

logger = logging.getLogger("honeytrace.demo_scenarios")


class DemoScenarios:
    """Orchestrates comprehensive multi-stage cyber attack demonstrations."""

    def __init__(self):
        self.simulator = AttackSimulator()

    def scenario_ssh_brute_force(self) -> Dict[str, str]:
        """
        Scenario 1: SSH Brute-Force Simulation
        Fires automated dictionary attacks against the SSH decoy on port 2222.
        Demonstrates credential harvesting, IP tracking, and T1110 alert triggers.
        """
        attacker_ip = "192.168.1.105"
        self.simulator.simulate_ssh_brute_force(source_ip=attacker_ip, count=10)
        return {
            "title": "SSH Brute-Force Simulation",
            "attacker_ip": attacker_ip,
            "tactics": "Credential Access (T1110.001)",
            "description": "10 rapid credential guessing attempts fired against SSH decoy port 2222. Trapped usernames and passwords stored in database."
        }

    def scenario_username_enumeration(self) -> Dict[str, str]:
        """
        Scenario 2: Username Enumeration
        Probes targeted accounts (root, administrator, service_worker, honeycorp_admin).
        Demonstrates enumeration pattern detection across HTTP and SSH.
        """
        attacker_ip = "192.168.1.115"
        self.simulator.simulate_username_enumeration(source_ip=attacker_ip, count=8)
        return {
            "title": "Username Enumeration",
            "attacker_ip": attacker_ip,
            "tactics": "Reconnaissance (T1595) & Credential Access (T1110)",
            "description": "Probed 8 sensitive user accounts across HTTP Admin login and SSH handshake to detect account validity probing."
        }

    def scenario_http_directory_enumeration(self) -> Dict[str, str]:
        """
        Scenario 3: HTTP Directory Enumeration
        Simulates automated tools (Nikto, Gobuster, DirBuster) fuzzing sensitive paths.
        """
        attacker_ip = "10.10.2.45"
        self.simulator.simulate_http_directory_enumeration(source_ip=attacker_ip, count=10)
        return {
            "title": "HTTP Directory Enumeration",
            "attacker_ip": attacker_ip,
            "tactics": "Discovery (T1083) & Reconnaissance (T1595.002)",
            "description": "Fuzzed 10 high-value endpoints (/.env, /admin, /phpmyadmin, /wp-config.php, /actuator) using scanner User-Agents."
        }

    def scenario_suspicious_command_probing(self) -> Dict[str, str]:
        """
        Scenario 4: Suspicious Command Probing
        Attacker submits shell metacharacters and OS commands (; cat /etc/passwd, | whoami).
        Demonstrates zero-execution command trapping and T1059 CRITICAL severity flagging.
        """
        attacker_ip = "172.16.8.99"
        self.simulator.simulate_suspicious_command_probing(source_ip=attacker_ip, count=6)
        return {
            "title": "Suspicious Command Probing",
            "attacker_ip": attacker_ip,
            "tactics": "Execution (T1059)",
            "description": "Injected OS command strings across HTTP search query and SSH fake restricted shell. Trapped and safely contained with zero execution."
        }

    def scenario_repeated_auth_failures(self) -> Dict[str, str]:
        """
        Scenario 5: Repeated Authentication Failures
        Fires 12 rapid failed authentication attempts in a tight time window.
        Demonstrates the dynamic Risk Engine's Velocity Multiplier (1.55x burst penalty).
        """
        attacker_ip = "192.168.1.180"
        self.simulator.simulate_repeated_auth_failures(source_ip=attacker_ip, count=12)
        return {
            "title": "Repeated Authentication Failures",
            "attacker_ip": attacker_ip,
            "tactics": "Credential Access (T1110) - Velocity Burst",
            "description": "12 rapid authentication failures against /login within seconds. Triggered the velocity burst multiplier, escalating risk score to CRITICAL."
        }

    # Backward compatibility aliases
    def scenario_brute_force_spray(self) -> Dict[str, str]:
        return self.scenario_ssh_brute_force()

    def scenario_automated_recon_fuzzing(self) -> Dict[str, str]:
        return self.scenario_http_directory_enumeration()

    def scenario_web_killchain(self) -> Dict[str, str]:
        """Multi-stage kill-chain combining directory fuzzing, SQLi, traversal, and command execution."""
        ip = "192.168.1.220"
        self.simulator.simulate_http_directory_enumeration(source_ip=ip, count=3)
        self.simulator.run_direct_event_simulation("SQL_INJECTION", source_ip=ip, count=4)
        self.simulator.run_direct_event_simulation("DIRECTORY_TRAVERSAL", source_ip=ip, count=3)
        self.simulator.simulate_suspicious_command_probing(source_ip=ip, count=2)
        return {
            "title": "Multi-Stage Web Kill-Chain",
            "attacker_ip": ip,
            "tactics": "Reconnaissance -> Initial Access -> Discovery -> Execution",
            "description": "Coordinated multi-vector attack progressing through the full cyber kill-chain."
        }

    def scenario_apt_multi_decoy(self) -> Dict[str, str]:
        """Simultaneous multi-vector attack against both HTTP and SSH decoys."""
        ip = "172.16.50.15"
        self.simulator.run_direct_event_simulation("SQL_INJECTION", source_ip=ip, count=3)
        self.simulator.simulate_ssh_brute_force(source_ip=ip, count=5)
        self.simulator.simulate_suspicious_command_probing(source_ip=ip, count=2)
        return {
            "title": "APT Multi-Decoy Campaign",
            "attacker_ip": ip,
            "tactics": "Lateral Cross-Decoy Engagement (HTTP + SSH)",
            "description": "Simultaneous attack triggering cross-decoy diversity bonus and classifying threat actor as APT Emulation."
        }

    def run_all(self) -> List[Dict[str, str]]:
        """Executes all 5 core demonstration scenarios in one click."""
        return [
            self.scenario_ssh_brute_force(),
            self.scenario_username_enumeration(),
            self.scenario_http_directory_enumeration(),
            self.scenario_suspicious_command_probing(),
            self.scenario_repeated_auth_failures()
        ]
