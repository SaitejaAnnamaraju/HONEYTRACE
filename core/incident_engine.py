"""
HONEYTRACE - Incident Correlation & Intelligence Engine
Correlates atomic events across temporal windows and multi-decoy interactions
into unified incident dossiers with attack timeline reconstruction and MITRE kill-chain mapping.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from core.database import DatabaseManager

logger = logging.getLogger("honeytrace.incident")


class IncidentEngine:
    """Automates attack session clustering, incident grouping, and attack timeline reconstruction."""

    def __init__(self, db: Optional[DatabaseManager] = None, session_timeout_minutes: int = 15):
        self.db = db or DatabaseManager()
        self.session_timeout = timedelta(minutes=session_timeout_minutes)

    def correlate_event(
        self,
        event_dict: Dict[str, Any],
        detection_res: Dict[str, Any],
        risk_res: Dict[str, Any]
    ) -> str:
        """
        Links an incoming event to an existing active incident for that source IP,
        or creates a new correlated incident if the session timed out or doesn't exist.
        """
        ip = event_dict.get("source_ip", "127.0.0.1")
        now_dt = datetime.now()
        now_str = now_dt.isoformat()
        risk_score = risk_res.get("risk_score", 0.0)
        severity = risk_res.get("severity", "INFO")
        rule_name = detection_res.get("rule_name", "UNKNOWN")
        tactic = detection_res.get("mitre_tactic", "")
        decoy = event_dict.get("honeypot_type", "UNKNOWN")

        # Check existing incidents for this IP
        incidents = self.db.get_incidents(limit=25)
        matched_inc = None

        for inc in incidents:
            if inc["attacker_ip"] == ip and inc["status"] in ["OPEN", "INVESTIGATING"]:
                try:
                    last_seen_dt = datetime.fromisoformat(inc["last_seen"])
                    if now_dt - last_seen_dt <= self.session_timeout:
                        matched_inc = inc
                        break
                except Exception:
                    pass

        vector_name = f"{decoy}:{rule_name}"

        if matched_inc:
            # Update existing incident grouping
            inc_id = matched_inc["incident_id"]
            vectors = matched_inc.get("attack_vectors", [])
            if vector_name not in vectors:
                vectors.append(vector_name)

            tactics = matched_inc.get("mitre_tactics", [])
            if tactic and tactic not in tactics:
                tactics.append(tactic)

            peak_risk = max(matched_inc.get("peak_risk_score", 0.0), risk_score)
            new_count = matched_inc.get("event_count", 1) + 1

            severity_ranks = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            old_sev = matched_inc.get("severity", "INFO")
            new_sev = severity if severity_ranks.get(severity, 0) > severity_ranks.get(old_sev, 0) else old_sev

            summary = self._generate_summary(ip, vectors, tactics, new_count, peak_risk, new_sev)

            self.db.upsert_incident({
                "incident_id": inc_id,
                "attacker_ip": ip,
                "first_seen": matched_inc["first_seen"],
                "last_seen": now_str,
                "severity": new_sev,
                "peak_risk_score": peak_risk,
                "event_count": new_count,
                "attack_vectors": vectors,
                "mitre_tactics": tactics,
                "summary": summary,
                "status": "OPEN"
            })
            return inc_id
        else:
            # Create new correlated incident group
            clean_ip = ip.replace(".", "").replace(":", "")[-6:]
            inc_id = f"INC-{now_dt.strftime('%Y%m%d%H%M')}-{clean_ip}"
            vectors = [vector_name]
            tactics = [tactic] if tactic else []
            summary = self._generate_summary(ip, vectors, tactics, 1, risk_score, severity)

            self.db.upsert_incident({
                "incident_id": inc_id,
                "attacker_ip": ip,
                "first_seen": now_str,
                "last_seen": now_str,
                "severity": severity,
                "peak_risk_score": risk_score,
                "event_count": 1,
                "attack_vectors": vectors,
                "mitre_tactics": tactics,
                "summary": summary,
                "status": "OPEN"
            })
            return inc_id

    def reconstruct_attack_timeline(self, incident_id: str) -> List[Dict[str, Any]]:
        """
        Reconstructs the chronological progression of an incident.
        Calculates relative timestamps, kill-chain phases, and attaches forensic evidence.
        """
        incidents = self.db.get_incidents(limit=100)
        incident = next((i for i in incidents if i["incident_id"] == incident_id), None)
        if not incident:
            return []

        ip = incident["attacker_ip"]
        events = self.db.get_events(limit=100, search_query=ip)
        if not events:
            return []

        # Sort chronologically
        events.sort(key=lambda e: e.get("timestamp", ""))

        try:
            first_ts = datetime.fromisoformat(events[0]["timestamp"])
        except Exception:
            first_ts = None

        timeline = []
        for idx, ev in enumerate(events):
            # Calculate elapsed time
            elapsed_str = "+00:00"
            if first_ts:
                try:
                    cur_ts = datetime.fromisoformat(ev["timestamp"])
                    diff_seconds = int((cur_ts - first_ts).total_seconds())
                    mins = diff_seconds // 60
                    secs = diff_seconds % 60
                    elapsed_str = f"+{mins:02d}:{secs:02d}"
                except Exception:
                    pass

            # Determine kill-chain narrative
            action_desc = f"{ev['event_type']} on {ev['honeypot_type']} ({ev['endpoint'] or 'port ' + str(ev['source_port'])})"
            if ev.get("username"):
                action_desc += f" [User: '{ev['username']}']"

            timeline.append({
                "step": idx + 1,
                "event_uuid": ev.get("event_uuid", ""),
                "timestamp": ev["timestamp"],
                "elapsed": elapsed_str,
                "decoy": ev["honeypot_type"],
                "tactic": ev.get("mitre_tactic", "Reconnaissance"),
                "technique": ev.get("mitre_technique_id", "N/A"),
                "rule_name": ev.get("rule_name", "UNKNOWN"),
                "action": action_desc,
                "payload_sample": str(ev.get("payload", ""))[:120],
                "risk_score": ev.get("risk_score", 0.0),
                "severity": ev.get("severity", "INFO"),
                "outcome": "CONTAINED_BY_DECOY (No host system compromise)"
            })

        return timeline

    def _generate_summary(
        self,
        ip: str,
        vectors: List[str],
        tactics: List[str],
        count: int,
        peak_risk: float,
        severity: str
    ) -> str:
        """Constructs an automated human-readable threat analysis narrative."""
        unique_decoys = set(v.split(":")[0] for v in vectors if ":" in v)
        decoy_str = " & ".join(unique_decoys) if unique_decoys else "decoys"
        tactics_str = ", ".join(tactics) if tactics else "Initial Reconnaissance"

        summary = (
            f"Adversary from {ip} engaged {decoy_str} with {count} distinct malicious interaction(s). "
            f"Observed MITRE Tactics: [{tactics_str}]. "
            f"Assessed Threat Level: {severity} (Peak Risk Score: {peak_risk}/100). "
            f"Progression observed across {len(vectors)} technique vector(s). "
            f"(Note: All interactions isolated on deception sensors; zero host system compromise)."
        )
        return summary
