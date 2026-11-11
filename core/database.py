"""
HONEYTRACE - Core Database Management Module
Thread-safe SQLite database manager for deception events, incidents, and threat actors.
Uses relative paths anchored to the project root directory.
"""

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("honeytrace.database")

# Base directory relative to this file: HONEYTRACE/
BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "data" / "honeytrace.db"


class DatabaseManager:
    """Thread-safe SQLite manager for HoneyTrace events and threat intelligence."""

    _instances = {}
    _lock = threading.Lock()

    def __new__(cls, db_path: Optional[Path] = None):
        target_path = str(Path(db_path).resolve()) if db_path else str(DEFAULT_DB_PATH.resolve())
        with cls._lock:
            if target_path not in cls._instances:
                inst = super(DatabaseManager, cls).__new__(cls)
                inst._initialized = False
                cls._instances[target_path] = inst
            return cls._instances[target_path]

    def __init__(self, db_path: Optional[Path] = None):
        if getattr(self, "_initialized", False):
            return

        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db_lock = threading.Lock()
        self._init_db()
        self._initialized = True
        logger.info(f"DatabaseManager initialized with DB at: {self.db_path}")

    def _get_connection(self) -> sqlite3.Connection:
        """Returns a connection configured with row factory and WAL mode for high concurrency."""
        conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            timeout=15.0
        )
        conn.row_factory = sqlite3.Row
        # Enable Write-Ahead Logging for fast concurrent read/writes
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
        except Exception:
            pass
        return conn

    def _init_db(self) -> None:
        """Creates tables, indices, and views if they do not exist."""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Table: events
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_uuid TEXT DEFAULT '',
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER DEFAULT 0,
                    honeypot_type TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    endpoint TEXT DEFAULT '',
                    http_method TEXT DEFAULT '',
                    username TEXT DEFAULT '',
                    password TEXT DEFAULT '',
                    payload TEXT DEFAULT '',
                    headers TEXT DEFAULT '{}',
                    user_agent TEXT DEFAULT '',
                    session_id TEXT DEFAULT '',
                    risk_score REAL DEFAULT 0.0,
                    severity TEXT DEFAULT 'INFO',
                    mitre_technique_id TEXT DEFAULT '',
                    mitre_tactic TEXT DEFAULT '',
                    rule_name TEXT DEFAULT '',
                    status TEXT DEFAULT 'CAPTURED',
                    evidence TEXT DEFAULT '{}',
                    detection_reason TEXT DEFAULT ''
                );
                """)

                # Table: alerts
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT UNIQUE NOT NULL,
                    event_uuid TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    honeypot_type TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    mitre_technique_id TEXT DEFAULT '',
                    mitre_tactic TEXT DEFAULT '',
                    detection_reason TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    compromise_assessment TEXT DEFAULT 'ATTEMPT_CAPTURED_NO_COMPROMISE'
                );
                """)

                # Migration guard for existing tables
                for col_def in [
                    "ALTER TABLE events ADD COLUMN event_uuid TEXT DEFAULT '';",
                    "ALTER TABLE events ADD COLUMN evidence TEXT DEFAULT '{}';",
                    "ALTER TABLE events ADD COLUMN detection_reason TEXT DEFAULT '';"
                ]:
                    try:
                        cursor.execute(col_def)
                    except Exception:
                        pass

                # Table: incidents
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT UNIQUE NOT NULL,
                    attacker_ip TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    peak_risk_score REAL DEFAULT 0.0,
                    event_count INTEGER DEFAULT 1,
                    attack_vectors TEXT DEFAULT '[]',
                    mitre_tactics TEXT DEFAULT '[]',
                    summary TEXT DEFAULT '',
                    status TEXT DEFAULT 'OPEN'
                );
                """)

                # Table: threat_actors
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_actors (
                    ip TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    reputation_score REAL DEFAULT 50.0,
                    classification TEXT DEFAULT 'Suspicious Probe',
                    country TEXT DEFAULT 'Internal Lab / Decoy Network',
                    total_attempts INTEGER DEFAULT 1,
                    targeted_honeypots TEXT DEFAULT '[]',
                    known_credentials_tried TEXT DEFAULT '[]'
                );
                """)

                # Table: system_status
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_status (
                    service_name TEXT PRIMARY KEY,
                    is_running INTEGER DEFAULT 0,
                    port INTEGER DEFAULT 0,
                    last_heartbeat TEXT DEFAULT '',
                    metadata TEXT DEFAULT '{}'
                );
                """)

                # Indices for fast analytics and filtering
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_uuid ON events(event_uuid);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_honeypot ON events(honeypot_type);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents(attacker_ip);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(source_ip);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);")

                conn.commit()

    def insert_event(self, event_data: Dict[str, Any]) -> int:
        """Inserts a new raw/analyzed deception event into the database."""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                ts = event_data.get("timestamp") or datetime.now().isoformat()
                event_uuid = event_data.get("event_uuid") or f"EVT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8].upper()}"
                headers = event_data.get("headers", {})
                if isinstance(headers, (dict, list)):
                    headers = json.dumps(headers)

                evidence = event_data.get("evidence", {})
                if isinstance(evidence, (dict, list)):
                    evidence = json.dumps(evidence)

                cursor.execute("""
                INSERT INTO events (
                    event_uuid, timestamp, source_ip, source_port, honeypot_type, protocol,
                    event_type, endpoint, http_method, username, password,
                    payload, headers, user_agent, session_id, risk_score,
                    severity, mitre_technique_id, mitre_tactic, rule_name, status,
                    evidence, detection_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event_uuid,
                    ts,
                    event_data.get("source_ip", "127.0.0.1"),
                    event_data.get("source_port", 0),
                    event_data.get("honeypot_type", "UNKNOWN"),
                    event_data.get("protocol", "TCP"),
                    event_data.get("event_type", "PROBE"),
                    event_data.get("endpoint", ""),
                    event_data.get("http_method", ""),
                    event_data.get("username", ""),
                    event_data.get("password", ""),
                    str(event_data.get("payload", "")),
                    headers,
                    event_data.get("user_agent", ""),
                    event_data.get("session_id", ""),
                    float(event_data.get("risk_score", 0.0)),
                    event_data.get("severity", "INFO"),
                    event_data.get("mitre_technique_id", ""),
                    event_data.get("mitre_tactic", ""),
                    event_data.get("rule_name", ""),
                    event_data.get("status", "CAPTURED"),
                    evidence,
                    event_data.get("detection_reason", "")
                ))
                conn.commit()
                return cursor.lastrowid

    def insert_alert(self, alert_data: Dict[str, Any]) -> int:
        """Stores a high-confidence security alert with evidence and reason."""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                now = alert_data.get("timestamp") or datetime.now().isoformat()
                alert_id = alert_data.get("alert_id") or f"ALT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8].upper()}"
                evidence = alert_data.get("evidence", {})
                if isinstance(evidence, (dict, list)):
                    evidence = json.dumps(evidence)

                cursor.execute("""
                INSERT OR REPLACE INTO alerts (
                    alert_id, event_uuid, timestamp, source_ip, honeypot_type,
                    rule_name, severity, risk_score, mitre_technique_id, mitre_tactic,
                    detection_reason, evidence, compromise_assessment
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert_id,
                    alert_data.get("event_uuid", ""),
                    now,
                    alert_data.get("source_ip", "127.0.0.1"),
                    alert_data.get("honeypot_type", "UNKNOWN"),
                    alert_data.get("rule_name", "ANOMALY"),
                    alert_data.get("severity", "MEDIUM"),
                    float(alert_data.get("risk_score", 50.0)),
                    alert_data.get("mitre_technique_id", ""),
                    alert_data.get("mitre_tactic", ""),
                    alert_data.get("detection_reason", "Detection heuristic matched"),
                    evidence,
                    alert_data.get("compromise_assessment", "ATTEMPT_CAPTURED_NO_COMPROMISE (Decoy Trapped - Non-Executed)")
                ))
                conn.commit()
                return cursor.lastrowid

    def get_alerts(self, limit: int = 50, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves alerts with parsed evidence dictionaries."""
        query = "SELECT * FROM alerts WHERE 1=1"
        params: List[Any] = []
        if severity and severity.upper() != "ALL":
            query += " AND severity = ?"
            params.append(severity.upper())
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                rows = cursor.fetchall()
                results = []
                for r in rows:
                    d = dict(r)
                    try:
                        d["evidence"] = json.loads(d["evidence"])
                    except Exception:
                        pass
                    results.append(d)
                return results

    def get_events(
        self,
        limit: int = 100,
        offset: int = 0,
        honeypot_type: Optional[str] = None,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        search_query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieves events matching optional filters including severity, event_type, and date ranges."""
        query = "SELECT * FROM events WHERE 1=1"
        params: List[Any] = []

        if honeypot_type and honeypot_type.upper() != "ALL":
            query += " AND honeypot_type = ?"
            params.append(honeypot_type.upper())

        if severity and severity.upper() != "ALL":
            query += " AND severity = ?"
            params.append(severity.upper())

        if event_type and event_type.upper() != "ALL":
            query += " AND event_type = ?"
            params.append(event_type)

        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date)

        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date)

        if search_query:
            query += " AND (source_ip LIKE ? OR payload LIKE ? OR username LIKE ? OR endpoint LIKE ?)"
            term = f"%{search_query}%"
            params.extend([term, term, term, term])

        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                rows = cursor.fetchall()
                results = []
                for row in rows:
                    d = dict(row)
                    ev = d.get("evidence")
                    if isinstance(ev, str) and ev.strip().startswith(("{", "[")):
                        try:
                            d["evidence"] = json.loads(ev)
                        except Exception:
                            pass
                    results.append(d)
                return results

    def get_distinct_event_types(self) -> List[str]:
        """Returns unique event types present in the database."""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT DISTINCT event_type FROM events ORDER BY event_type ASC")
                return [r[0] for r in cursor.fetchall() if r[0]]

    def update_incident_status(self, incident_id: str, new_status: str) -> bool:
        """Updates the status of an incident (e.g. OPEN, INVESTIGATING, CONTAINED, RESOLVED)."""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE incidents SET status = ? WHERE incident_id = ?", (new_status, incident_id))
                conn.commit()
                return cursor.rowcount > 0

    def get_kpis(self) -> Dict[str, Any]:
        """Calculates executive dashboard metrics."""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("SELECT COUNT(*) FROM events")
                total_events = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM events WHERE severity = 'CRITICAL'")
                critical_events = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM events WHERE severity = 'HIGH'")
                high_events = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM events")
                unique_ips = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM incidents WHERE status = 'OPEN'")
                open_incidents = cursor.fetchone()[0]

                cursor.execute("SELECT AVG(risk_score) FROM events")
                avg_risk_row = cursor.fetchone()[0]
                avg_risk = round(avg_risk_row, 1) if avg_risk_row is not None else 0.0

                cursor.execute("SELECT COUNT(*) FROM events WHERE honeypot_type = 'SSH'")
                ssh_count = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM events WHERE honeypot_type = 'HTTP'")
                http_count = cursor.fetchone()[0]

                return {
                    "total_events": total_events,
                    "critical_events": critical_events,
                    "high_events": high_events,
                    "unique_attackers": unique_ips,
                    "open_incidents": open_incidents,
                    "avg_risk_score": avg_risk,
                    "ssh_events": ssh_count,
                    "http_events": http_count
                }

    def get_timeline(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns time-bucketed event counts for chart visualization."""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                # Aggregate by minute/hour based on timestamp format
                cursor.execute("""
                SELECT 
                    substr(timestamp, 1, 16) as time_bucket,
                    COUNT(*) as count,
                    SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                    SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high_count,
                    AVG(risk_score) as avg_risk
                FROM events
                GROUP BY time_bucket
                ORDER BY time_bucket DESC
                LIMIT ?
                """, (limit,))
                rows = cursor.fetchall()
                results = [dict(r) for r in rows]
                results.reverse()  # Chronological order
                return results

    def get_top_attackers(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Retrieves most active attacker IPs."""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT 
                    source_ip,
                    COUNT(*) as event_count,
                    MAX(risk_score) as max_risk,
                    MAX(timestamp) as last_seen,
                    GROUP_CONCAT(DISTINCT honeypot_type) as decoys_hit
                FROM events
                GROUP BY source_ip
                ORDER BY event_count DESC, max_risk DESC
                LIMIT ?
                """, (limit,))
                return [dict(r) for r in cursor.fetchall()]

    def get_top_credentials(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieves most frequently targeted usernames and passwords."""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT 
                    username,
                    password,
                    COUNT(*) as attempts,
                    MAX(timestamp) as last_attempt
                FROM events
                WHERE username != '' OR password != ''
                GROUP BY username, password
                ORDER BY attempts DESC
                LIMIT ?
                """, (limit,))
                return [dict(r) for r in cursor.fetchall()]

    def get_mitre_breakdown(self) -> List[Dict[str, Any]]:
        """Returns event counts grouped by MITRE ATT&CK tactic and technique."""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT 
                    mitre_tactic,
                    mitre_technique_id,
                    rule_name,
                    COUNT(*) as count,
                    MAX(risk_score) as max_risk
                FROM events
                WHERE mitre_tactic != ''
                GROUP BY mitre_tactic, mitre_technique_id, rule_name
                ORDER BY count DESC
                """)
                return [dict(r) for r in cursor.fetchall()]

    def get_severity_distribution(self) -> Dict[str, int]:
        """Returns distribution of events by severity category."""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM events
                GROUP BY severity
                """)
                results = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
                for row in cursor.fetchall():
                    results[row["severity"]] = row["count"]
                return results

    def upsert_threat_actor(self, ip: str, classification: str, risk_score: float, decoy: str, cred: str = "") -> None:
        """Maintains attacker reputation and profile in threat_actors table."""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                now = datetime.now().isoformat()
                cursor.execute("SELECT * FROM threat_actors WHERE ip = ?", (ip,))
                row = cursor.fetchone()

                if row:
                    decoy_list = json.loads(row["targeted_honeypots"] or "[]")
                    if decoy not in decoy_list:
                        decoy_list.append(decoy)

                    cred_list = json.loads(row["known_credentials_tried"] or "[]")
                    if cred and cred not in cred_list and len(cred_list) < 25:
                        cred_list.append(cred)

                    new_attempts = row["total_attempts"] + 1
                    new_score = max(row["reputation_score"], risk_score)

                    cursor.execute("""
                    UPDATE threat_actors
                    SET last_seen = ?,
                        total_attempts = ?,
                        reputation_score = ?,
                        classification = ?,
                        targeted_honeypots = ?,
                        known_credentials_tried = ?
                    WHERE ip = ?
                    """, (
                        now,
                        new_attempts,
                        new_score,
                        classification,
                        json.dumps(decoy_list),
                        json.dumps(cred_list),
                        ip
                    ))
                else:
                    decoys = [decoy] if decoy else []
                    creds = [cred] if cred else []
                    cursor.execute("""
                    INSERT INTO threat_actors (
                        ip, first_seen, last_seen, reputation_score,
                        classification, total_attempts, targeted_honeypots, known_credentials_tried
                    ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                    """, (
                        ip,
                        now,
                        now,
                        risk_score,
                        classification,
                        json.dumps(decoys),
                        json.dumps(creds)
                    ))
                conn.commit()

    def upsert_incident(self, incident_data: Dict[str, Any]) -> str:
        """Creates or updates correlated incident session."""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                inc_id = incident_data.get("incident_id")
                ip = incident_data.get("attacker_ip")

                cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (inc_id,))
                existing = cursor.fetchone()

                vectors = incident_data.get("attack_vectors", [])
                tactics = incident_data.get("mitre_tactics", [])
                if isinstance(vectors, list):
                    vectors = json.dumps(vectors)
                if isinstance(tactics, list):
                    tactics = json.dumps(tactics)

                if existing:
                    cursor.execute("""
                    UPDATE incidents
                    SET last_seen = ?,
                        severity = ?,
                        peak_risk_score = ?,
                        event_count = ?,
                        attack_vectors = ?,
                        mitre_tactics = ?,
                        summary = ?,
                        status = ?
                    WHERE incident_id = ?
                    """, (
                        incident_data.get("last_seen"),
                        incident_data.get("severity"),
                        incident_data.get("peak_risk_score"),
                        incident_data.get("event_count"),
                        vectors,
                        tactics,
                        incident_data.get("summary"),
                        incident_data.get("status", "OPEN"),
                        inc_id
                    ))
                else:
                    cursor.execute("""
                    INSERT INTO incidents (
                        incident_id, attacker_ip, first_seen, last_seen,
                        severity, peak_risk_score, event_count, attack_vectors,
                        mitre_tactics, summary, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        inc_id,
                        ip,
                        incident_data.get("first_seen"),
                        incident_data.get("last_seen"),
                        incident_data.get("severity"),
                        incident_data.get("peak_risk_score", 0.0),
                        incident_data.get("event_count", 1),
                        vectors,
                        tactics,
                        incident_data.get("summary", ""),
                        incident_data.get("status", "OPEN")
                    ))
                conn.commit()
                return inc_id

    def get_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns all correlated incidents ordered by recency."""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,))
                rows = cursor.fetchall()
                results = []
                for r in rows:
                    d = dict(r)
                    try:
                        d["attack_vectors"] = json.loads(d["attack_vectors"])
                    except Exception:
                        d["attack_vectors"] = []
                    try:
                        d["mitre_tactics"] = json.loads(d["mitre_tactics"])
                    except Exception:
                        d["mitre_tactics"] = []
                    results.append(d)
                return results

    def get_threat_actors(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns list of profiled threat actors."""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM threat_actors ORDER BY reputation_score DESC LIMIT ?", (limit,))
                rows = cursor.fetchall()
                results = []
                for r in rows:
                    d = dict(r)
                    try:
                        d["targeted_honeypots"] = json.loads(d["targeted_honeypots"])
                    except Exception:
                        d["targeted_honeypots"] = []
                    try:
                        d["known_credentials_tried"] = json.loads(d["known_credentials_tried"])
                    except Exception:
                        d["known_credentials_tried"] = []
                    results.append(d)
                return results

    def update_service_status(self, service_name: str, is_running: bool, port: int = 0, metadata: Optional[Dict] = None) -> None:
        """Records state of honeypot and simulation daemons."""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                now = datetime.now().isoformat()
                meta_json = json.dumps(metadata or {})
                cursor.execute("""
                INSERT INTO system_status (service_name, is_running, port, last_heartbeat, metadata)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(service_name) DO UPDATE SET
                    is_running = excluded.is_running,
                    port = excluded.port,
                    last_heartbeat = excluded.last_heartbeat,
                    metadata = excluded.metadata
                """, (service_name, 1 if is_running else 0, port, now, meta_json))
                conn.commit()

    def get_service_statuses(self) -> Dict[str, Dict[str, Any]]:
        """Gets runtime status of all system components."""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM system_status")
                statuses = {}
                for row in cursor.fetchall():
                    statuses[row["service_name"]] = {
                        "is_running": bool(row["is_running"]),
                        "port": row["port"],
                        "last_heartbeat": row["last_heartbeat"],
                        "metadata": json.loads(row["metadata"] or "{}")
                    }
                return statuses

    def clear_database(self) -> None:
        """Purges event tables for fresh demonstrations."""
        with self._db_lock:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM events;")
                conn.execute("DELETE FROM incidents;")
                conn.execute("DELETE FROM threat_actors;")
                conn.commit()
                logger.info("Database purged successfully.")
