"""
HONEYTRACE - SSH Deception Decoy Service
Low-interaction socket-based SSH honeypot emulating OpenSSH 8.9p1 on localhost.
Captures credential brute-forcing, client fingerprinting, and interactive command attempts.
100% localhost-only, strictly non-executing, safe deception.
"""

import logging
import re
import socket
import threading
import time
from typing import Optional

from core.database import DatabaseManager
from core.event_collector import EventCollector

logger = logging.getLogger("honeytrace.ssh_decoy")


class SSHDecoyServer:
    """Socket-based low-interaction SSH honeypot daemon on localhost."""

    def __init__(self, host: str = "127.0.0.1", port: int = 2222):
        self.host = host
        self.port = port
        self.collector = EventCollector()
        self.db = DatabaseManager()
        self._server_socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._is_running = False
        self._lock = threading.Lock()

    def _handle_client(self, client_sock: socket.socket, addr: tuple) -> None:
        """Handles an individual incoming adversary connection."""
        src_ip, src_port = addr[0], addr[1]
        session_id = f"SSH-{int(time.time())}-{src_port}"

        try:
            client_sock.settimeout(12.0)

            # 1. Send realistic OpenSSH server banner
            server_banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
            client_sock.sendall(server_banner)

            # 2. Receive client identification banner
            data = client_sock.recv(1024)
            if not data:
                return

            client_banner = data.decode("utf-8", errors="replace").strip()

            # Record client fingerprint probe
            self.collector.collect({
                "source_ip": src_ip,
                "source_port": src_port,
                "honeypot_type": "SSH",
                "protocol": "SSH",
                "event_type": "SSH_HANDSHAKE",
                "endpoint": f":{self.port}",
                "payload": f"Client Banner: {client_banner}",
                "user_agent": client_banner[:100],
                "session_id": session_id
            })

            # Check if client sent plaintext login prompt sequence (e.g. netcat, telnet or raw scanner)
            if not client_banner.startswith("SSH-"):
                # Handle raw socket / netcat brute-force attempts
                self._handle_plaintext_emulation(client_sock, src_ip, src_port, session_id, data)
                return

            # For binary SSH protocol clients (ssh, paramiko, hydra, nmap):
            # Read subsequent key exchange packet and capture authentication attempts
            try:
                auth_data = client_sock.recv(2048)
                if auth_data:
                    # Extract plaintext strings if hydra / scanner sent credentials
                    extracted_strings = re.findall(rb"[\x20-\x7E]{3,}", auth_data)
                    creds = [s.decode("utf-8", errors="ignore") for s in extracted_strings]

                    user = creds[0] if len(creds) > 0 else "unknown"
                    pwd = creds[1] if len(creds) > 1 else ""

                    self.collector.collect({
                        "source_ip": src_ip,
                        "source_port": src_port,
                        "honeypot_type": "SSH",
                        "protocol": "SSH",
                        "event_type": "AUTH_FAILED",
                        "endpoint": f":{self.port}",
                        "username": user[:50],
                        "password": pwd[:50],
                        "payload": f"SSH Key Exchange / Auth attempt with client {client_banner}",
                        "session_id": session_id
                    })
            except socket.timeout:
                pass

        except Exception as e:
            logger.debug(f"SSH client interaction ended: {e}")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _handle_plaintext_emulation(
        self,
        client_sock: socket.socket,
        src_ip: str,
        src_port: int,
        session_id: str,
        initial_data: bytes
    ) -> None:
        """Simulates decoy terminal login prompt for raw scanner or telnet/nc probes."""
        client_sock.sendall(b"HoneyCorp Production Gateway OS 22.04 LTS\r\nlogin: ")
        user_data = client_sock.recv(512)
        username = user_data.decode("utf-8", errors="replace").strip()

        client_sock.sendall(b"Password: ")
        pass_data = client_sock.recv(512)
        password = pass_data.decode("utf-8", errors="replace").strip()

        self.collector.collect({
            "source_ip": src_ip,
            "source_port": src_port,
            "honeypot_type": "SSH",
            "protocol": "SSH",
            "event_type": "AUTH_FAILED",
            "endpoint": f":{self.port}",
            "username": username,
            "password": password,
            "payload": f"Captured Decoy Login: user='{username}', pass='{password}'",
            "session_id": session_id
        })

        # Fake access granted to decoy restricted shell to capture adversary command attempts
        client_sock.sendall(b"\r\nLast login: Tue Nov 03 14:12:00 from 192.168.1.10\r\nroot@honeycorp-gw:~# ")
        cmd_data = client_sock.recv(1024)
        if cmd_data:
            attempted_command = cmd_data.decode("utf-8", errors="replace").strip()
            # NEVER execute attacker commands! Trap and log!
            self.collector.collect({
                "source_ip": src_ip,
                "source_port": src_port,
                "honeypot_type": "SSH",
                "protocol": "SSH",
                "event_type": "COMMAND_ATTEMPT",
                "endpoint": f":{self.port}",
                "username": username,
                "payload": attempted_command,
                "session_id": session_id
            })
            client_sock.sendall(b"\r\nbash: command permission denied by security policy.\r\nConnection closed by remote host.\r\n")

    def _listen_loop(self) -> None:
        """Main listener loop binding socket on localhost."""
        while self._is_running:
            try:
                client_sock, addr = self._server_socket.accept()
                handler = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, addr),
                    daemon=True
                )
                handler.start()
            except socket.timeout:
                continue
            except Exception:
                if self._is_running:
                    logger.error("SSH listener exception in accept loop", exc_info=True)
                break

    def start(self) -> None:
        """Starts SSH honeypot listener on 127.0.0.1:port."""
        with self._lock:
            if self._is_running:
                return

            try:
                self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._server_socket.bind((self.host, self.port))
                self._server_socket.listen(10)
                self._server_socket.settimeout(1.0)
                self._is_running = True

                self._thread = threading.Thread(target=self._listen_loop, daemon=True, name="SSHDecoyThread")
                self._thread.start()

                self.db.update_service_status("SSH_DECOY", is_running=True, port=self.port, metadata={"host": self.host})
                logger.info(f"SSH Decoy started successfully on {self.host}:{self.port}")
            except Exception as e:
                logger.error(f"Failed to start SSH decoy on {self.host}:{self.port}: {e}")
                self._is_running = False
                self.db.update_service_status("SSH_DECOY", is_running=False, port=self.port, metadata={"error": str(e)})

    def stop(self) -> None:
        """Stops the SSH decoy service cleanly."""
        with self._lock:
            self._is_running = False
            if self._server_socket:
                try:
                    self._server_socket.close()
                except Exception:
                    pass
            self.db.update_service_status("SSH_DECOY", is_running=False, port=self.port)
            logger.info("SSH Decoy stopped.")

    @property
    def is_running(self) -> bool:
        return self._is_running


# Module-level singleton helper
_ssh_instance: Optional[SSHDecoyServer] = None
_ssh_lock = threading.Lock()


def get_ssh_decoy(host: str = "127.0.0.1", port: int = 2222) -> SSHDecoyServer:
    global _ssh_instance
    with _ssh_lock:
        if _ssh_instance is None:
            _ssh_instance = SSHDecoyServer(host=host, port=port)
        return _ssh_instance

