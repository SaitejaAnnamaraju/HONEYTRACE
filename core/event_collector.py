"""
HONEYTRACE - Central Event Collector Module
Central broker connecting honeypot decoys, detection, risk scoring,
database persistence, and incident correlation in a thread-safe pipeline.
"""

import json
import logging
import queue
import re
import threading
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from core.database import DatabaseManager
from core.detection_engine import DetectionEngine
from core.incident_engine import IncidentEngine
from core.risk_engine import RiskEngine

logger = logging.getLogger("honeytrace.collector")


def sanitize_input(value: Any, max_len: int = 2000) -> str:
    """
    Sanitizes untrusted input from network decoys:
    - Replaces null bytes and non-printable control characters.
    - Limits string length to protect against memory exhaustion.
    - Preserves attack payloads for forensic inspection.
    """
    if value is None:
        return ""
    text = str(value)
    # Remove null bytes
    text = text.replace("\x00", "")
    # Remove non-printable control characters except standard whitespace (\t, \n, \r)
    text = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    # Truncate
    return text[:max_len].strip()


class EventCollector:
    """Central processing hub for all decoy capture events."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(EventCollector, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, db: Optional[DatabaseManager] = None):
        if getattr(self, "_initialized", False):
            return

        self.db = db or DatabaseManager()
        self.detector = DetectionEngine()
        self.risk_engine = RiskEngine()
        self.incident_engine = IncidentEngine(self.db)

        # Non-blocking async ingestion queue
        self._queue: queue.Queue = queue.Queue(maxsize=10000)
        self._running = True
        self._worker_thread = threading.Thread(target=self._process_queue, daemon=True, name="EventCollectorWorker")
        self._worker_thread.start()

        self._initialized = True
        logger.info("EventCollector initialized and ingestion worker active.")

    def collect(self, raw_event: Dict[str, Any], block_sync: bool = False) -> Dict[str, Any]:
        """
        Public intake method for decoys and simulators.
        Can process synchronously (for test verification) or queue asynchronously.
        """
        # Ensure timestamp and unique event UUID exist
        if not raw_event.get("timestamp"):
            raw_event["timestamp"] = datetime.now().isoformat()
        if not raw_event.get("event_uuid"):
            raw_event["event_uuid"] = f"EVT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8].upper()}"

        # Sanitize incoming fields
        raw_event["username"] = sanitize_input(raw_event.get("username", ""), max_len=100)
        raw_event["password"] = sanitize_input(raw_event.get("password", ""), max_len=100)
        raw_event["endpoint"] = sanitize_input(raw_event.get("endpoint", ""), max_len=500)
        raw_event["payload"] = sanitize_input(raw_event.get("payload", ""), max_len=2000)
        raw_event["user_agent"] = sanitize_input(raw_event.get("user_agent", ""), max_len=250)

        if block_sync:
            return self._pipeline(raw_event)
        else:
            self._queue.put(raw_event)
            return {"status": "QUEUED", "event_uuid": raw_event["event_uuid"]}

    def _pipeline(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Core analysis, enrichment, and storage pipeline."""
        try:
            # 1. Detection & AI intent analysis
            src_ip = event_data.get("source_ip", "127.0.0.1")
            src_port = event_data.get("source_port", 0)

            detection = self.detector.analyze(
                event_type=event_data.get("event_type", "PROBE"),
                payload=str(event_data.get("payload", "")),
                endpoint=event_data.get("endpoint", ""),
                username=event_data.get("username", ""),
                password=event_data.get("password", ""),
                user_agent=event_data.get("user_agent", ""),
                protocol=event_data.get("protocol", "TCP"),
                source_ip=src_ip,
                source_port=src_port
            )

            # 2. Dynamic risk assessment
            risk = self.risk_engine.assess_risk(
                source_ip=src_ip,
                detection_result=detection,
                honeypot_type=event_data.get("honeypot_type", "UNKNOWN")
            )

            # 3. Enrich event record with evidence and explainable reasoning
            event_data["risk_score"] = risk["risk_score"]
            event_data["severity"] = risk["severity"]
            event_data["mitre_technique_id"] = detection.get("mitre_technique_id", "")
            event_data["mitre_tactic"] = detection.get("mitre_tactic", "")
            event_data["rule_name"] = detection.get("rule_name", "")
            event_data["detection_reason"] = detection.get("detection_reason", "")
            event_data["evidence"] = detection.get("evidence", {})
            event_data["risk_explanation"] = risk.get("explanation", "")
            event_data["status"] = "ANALYZED"

            # 4. Persist event to SQLite
            event_id = self.db.insert_event(event_data)
            event_data["id"] = event_id

            # 5. Persist formal Alert in SQLite if severity > INFO or detection fired
            if detection.get("detected") or risk["severity"] != "INFO":
                self.db.insert_alert({
                    "event_uuid": event_data["event_uuid"],
                    "timestamp": event_data["timestamp"],
                    "source_ip": src_ip,
                    "honeypot_type": event_data.get("honeypot_type", "UNKNOWN"),
                    "rule_name": detection.get("rule_name", "ANOMALY"),
                    "severity": risk["severity"],
                    "risk_score": risk["risk_score"],
                    "mitre_technique_id": detection.get("mitre_technique_id", ""),
                    "mitre_tactic": detection.get("mitre_tactic", ""),
                    "detection_reason": detection.get("detection_reason", ""),
                    "evidence": detection.get("evidence", {}),
                    "compromise_assessment": "ATTEMPT_CAPTURED_NO_COMPROMISE (Decoy Trapped - Non-Executed)"
                })

            # 6. Update Threat Actor profile
            cred = ""
            if event_data.get("username") or event_data.get("password"):
                cred = f"{event_data.get('username')}:{event_data.get('password')}"

            rep_score, classification = self.risk_engine.calculate_actor_reputation(
                total_attempts=risk["breakdown"]["recent_burst_count"],
                peak_risk=risk["risk_score"],
                unique_decoys=risk["breakdown"]["unique_decoys_hit"]
            )
            self.db.upsert_threat_actor(
                ip=src_ip,
                classification=classification,
                risk_score=rep_score,
                decoy=event_data.get("honeypot_type", "UNKNOWN"),
                cred=cred
            )

            # 7. Incident correlation and grouping
            inc_id = self.incident_engine.correlate_event(event_data, detection, risk)
            event_data["incident_id"] = inc_id

            return event_data

        except Exception as e:
            logger.error(f"Error in EventCollector pipeline: {e}", exc_info=True)
            return {"status": "ERROR", "error": str(e)}

    def _process_queue(self) -> None:
        """Background thread loop draining event queue into pipeline."""
        while self._running:
            try:
                event = self._queue.get(timeout=1.0)
                self._pipeline(event)
                self._queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Queue processing error: {e}")

    def shutdown(self) -> None:
        """Flushes queue and halts worker."""
        self._running = False
        if self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)

