"""
HONEYTRACE - Explainable Risk Calculation Engine
Calculates transparent risk scores from 0 to 100 combining base severity,
velocity burst multipliers, multi-decoy lateral engagement, and evasion indicators.
"""

import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Tuple


class RiskEngine:
    """Dynamic multi-factor explainable risk assessment engine for deception events."""

    def __init__(self, velocity_window_seconds: int = 60):
        self.velocity_window = velocity_window_seconds
        # In-memory sliding windows: ip -> list of (timestamp, honeypot_type, rule_name)
        self._history: Dict[str, List[Tuple[float, str, str]]] = defaultdict(list)
        self._lock = threading.Lock()

    def _clean_stale_history(self, now: float) -> None:
        """Removes entries older than the velocity window."""
        cutoff = now - self.velocity_window
        for ip in list(self._history.keys()):
            self._history[ip] = [entry for entry in self._history[ip] if entry[0] >= cutoff]
            if not self._history[ip]:
                del self._history[ip]

    def assess_risk(
        self,
        source_ip: str,
        detection_result: Dict[str, Any],
        honeypot_type: str
    ) -> Dict[str, Any]:
        """
        Calculates an explainable composite risk score (0 - 100) and severity rating.
        Every point added is justified with mathematical components and clear text.
        """
        now = time.time()
        base_score = float(detection_result.get("base_score", 15.0))
        rule_name = detection_result.get("rule_name", "UNKNOWN")
        ai_analysis = detection_result.get("ai_analysis", {})

        with self._lock:
            self._clean_stale_history(now)
            # Record current event
            self._history[source_ip].append((now, honeypot_type, rule_name))
            ip_records = self._history[source_ip]

            # 1. Velocity factor
            event_count = len(ip_records)
            if event_count <= 1:
                velocity_multiplier = 1.0
            elif event_count <= 5:
                velocity_multiplier = 1.15
            elif event_count <= 15:
                velocity_multiplier = 1.35
            else:
                velocity_multiplier = 1.55  # Aggressive automated fuzzing / brute-force

            # 2. Vector diversity (Cross-Decoy Lateral Engagement)
            unique_decoys = set(r[1] for r in ip_records)
            unique_rules = set(r[2] for r in ip_records)
            diversity_bonus = 0.0

            if len(unique_decoys) > 1:
                diversity_bonus += 15.0

            if len(unique_rules) > 2:
                diversity_bonus += 10.0

        # 3. Evasion & Obfuscation Penalties
        evasion_penalty = 0.0
        if ai_analysis.get("obfuscated"):
            evasion_penalty += 15.0
        if ai_analysis.get("entropy", 0.0) > 4.8:
            evasion_penalty += 8.0

        # Explainable Composite Calculation
        computed_score = (base_score * velocity_multiplier) + diversity_bonus + evasion_penalty
        final_score = max(5.0, min(100.0, round(computed_score, 1)))

        # Severity Classification Bands
        if final_score >= 85.0:
            severity = "CRITICAL"
        elif final_score >= 65.0:
            severity = "HIGH"
        elif final_score >= 45.0:
            severity = "MEDIUM"
        elif final_score >= 25.0:
            severity = "LOW"
        else:
            severity = "INFO"

        # Explicit Human-Readable Explanation
        components = [f"Base: {base_score} ({rule_name})"]
        if velocity_multiplier > 1.0:
            components.append(f"Velocity: {velocity_multiplier}x ({event_count} reqs in {self.velocity_window}s)")
        if diversity_bonus > 0:
            components.append(f"Diversity: +{diversity_bonus} ({len(unique_decoys)} decoys, {len(unique_rules)} techniques)")
        if evasion_penalty > 0:
            components.append(f"Evasion/Entropy: +{evasion_penalty}")

        explanation = (
            f"Formula: [{' + '.join(components)}] = {final_score}/100 [{severity}]. "
            f"Assessed adversary intent level on decoy sensors. "
            f"(Note: Deceptive honeypot contained interaction; no system compromise confirmed)."
        )

        return {
            "risk_score": final_score,
            "severity": severity,
            "explanation": explanation,
            "breakdown": {
                "base_score": base_score,
                "velocity_multiplier": velocity_multiplier,
                "recent_burst_count": event_count,
                "diversity_bonus": diversity_bonus,
                "evasion_penalty": evasion_penalty,
                "unique_decoys_hit": len(unique_decoys),
                "unique_techniques_tried": len(unique_rules),
                "compromise_disclaimer": "Interaction isolated on decoy; zero host compromise."
            }
        }

    def calculate_actor_reputation(self, total_attempts: int, peak_risk: float, unique_decoys: int) -> Tuple[float, str]:
        """
        Determines overall threat actor reputation score (0 - 100) and classification archetype.
        """
        reputation = min(100.0, peak_risk * 0.7 + (total_attempts * 1.5) + (unique_decoys * 10))
        reputation = round(reputation, 1)

        if total_attempts > 20 and unique_decoys > 1:
            classification = "Advanced Persistent Threat (APT) Emulation"
        elif peak_risk >= 85.0:
            classification = "Exploit Operator / Weaponizer"
        elif total_attempts >= 8:
            classification = "Automated Credential Stuffer"
        elif unique_decoys == 1 and total_attempts <= 3:
            classification = "Opportunistic Reconnaissance"
        else:
            classification = "Script Kiddie / Port Scanner"

        return reputation, classification
