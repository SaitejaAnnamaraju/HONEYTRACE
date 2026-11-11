"""
HONEYTRACE - Sample Dataset Seeder
Generates a realistic multi-stage intrusion detection and attack intelligence dataset
with diverse attacker profiles, MITRE ATT&CK techniques, risk scores, and correlated incidents.
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta

# Ensure project root is in path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from core.database import DatabaseManager
from simulation.demo_scenarios import DemoScenarios


def seed_sample_dataset(db_path: str = "data/honeytrace.db"):
    """Seeds the database with rich historical demonstration data."""
    print(f"[*] Seeding HONEYTRACE sample dataset into {db_path}...")
    db = DatabaseManager(db_path)

    # Run the demo scenarios to populate realistic telemetry
    scenarios = DemoScenarios()
    scenarios.run_all()

    # Verify counts
    events = db.get_events(limit=500)
    incidents = db.get_incidents()
    alerts = db.get_alerts()
    kpis = db.get_kpis()

    print(f"[+] Dataset successfully created:")
    print(f"    - Total Events: {kpis.get('total_events', len(events))}")
    print(f"    - Total Incidents: {len(incidents)}")
    print(f"    - Total Alerts: {len(alerts)}")
    print(f"    - High/Crit Alerts: {kpis.get('critical_events', 0) + kpis.get('high_events', 0)}")
    print(f"    - Unique Attackers: {kpis.get('unique_attackers', 0)}")
    print(f"    - Avg Risk Score: {kpis.get('avg_risk_score', 0):.1f}/100")


if __name__ == "__main__":
    seed_sample_dataset()
