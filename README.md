# 🛡️ HONEYTRACE
### AI-Assisted Deception-Based Intrusion Detection & Attack Intelligence Platform
**A B.Tech Cybersecurity Capstone Demonstration Suite**

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)
![Architecture: Localhost_Air_Gapped](https://img.shields.io/badge/Environment-Air--Gapped_Localhost-orange.svg)
![MITRE_ATT&CK: Compliant](https://img.shields.io/badge/Taxonomy-MITRE_ATT%26CK-red.svg)
![UI: Streamlit_Plotly](https://img.shields.io/badge/Dashboard-Streamlit_Plotly-blueviolet.svg)
![Tests: 33_Passing](https://img.shields.io/badge/Tests-33%20Passed-brightgreen.svg)
![Reports: PDF_JSON_MD_CSV](https://img.shields.io/badge/Forensic_Reports-PDF%20%7C%20JSON%20%7C%20MD%20%7C%20CSV-purple.svg)

---

## 📌 Executive Summary & Academic Scope

In traditional enterprise security architectures, perimeter Intrusion Detection Systems (IDS) and Next-Generation Firewalls inspect massive volumes of legitimate business traffic, resulting in debilitating rates of **false positives** and alert fatigue. 

**HONEYTRACE** is an **Active Deception Platform** engineered to flip the asymmetry of cyber defense:
1. **Zero False Positives:** Honeypot decoys are strictly isolated entities with no valid operational role in production. Any interaction with a decoy is by definition unauthorized, malicious, or reconnaissance.
2. **Pre-Breach Telemetry:** Captures adversary Tactics, Techniques, and Procedures (TTPs) before critical production infrastructure is targeted.
3. **AI-Assisted Threat Diagnostics:** Evaluates Shannon entropy, token obfuscation, and intent classification in real-time without external cloud dependencies.
4. **MITRE ATT&CK Taxonomy:** Standardized mapping across Reconnaissance (T1595), Initial Access (T1190), Credential Access (T1110), Discovery (T1083), and Execution (T1059).
5. **Strict Localhost Containment:** Built specifically for university vivas, laboratory evaluations, and security conferences—100% localhost-only, strictly non-executing, and requiring zero external API keys or cloud connections.

---

## 🏛️ System Architecture

```
                                [ Threat Actor / Simulated Adversary ]
                                                  │
                         ┌────────────────────────┴────────────────────────┐
                         ▼                                                 ▼
             [ HTTP Decoy (:8080) ]                            [ SSH Decoy (:2222) ]
          - Fake Corporate SSO Portal                       - OpenSSH 8.9p1 Banner
          - Admin Panel & PMA Traps                         - Credential Harvesting
          - .env & Config Leaks                             - Decoy Restricted Shell
          - LFI & SQLi Traps                                - Command Attempt Trapper
                         │                                                 │
                         └────────────────────────┬────────────────────────┘
                                                  ▼
                                      [ Core Event Collector ]
                                    (Thread-Safe Async Queue)
                                                  │
                 ┌────────────────────────────────┼────────────────────────────────┐
                 ▼                                ▼                                ▼
      [ Detection Engine ]              [ Risk Engine ]                 [ Incident Engine ]
    - Multi-Tier Signatures           - Dynamic Risk (0-100)          - Temporal Clustering
    - Shannon Entropy Scoring         - Velocity Multiplier           - Session Correlation
    - Obfuscation Heuristics          - Vector Diversity Multiplier   - Automated Dossiers
    - MITRE ATT&CK Mapping            - Severity Classification       - Kill-Chain Progress
                 │                                │                                │
                 └────────────────────────────────┼────────────────────────────────┘
                                                  ▼
                                      [ SQLite Storage Engine ]
                                        (data/honeytrace.db)
                                                  │
                                                  ▼
                                 [ Streamlit SOC Dashboard (:8501) ]
                        - 1. SOC Overview (KPIs & Incursion Timeline)
                        - 2. Live Attack Monitor (Real-Time Stream & DPI)
                        - 3. Honeypot Management (Decoy Daemon Controls)
                        - 4. Threat Intelligence (MITRE Hierarchy & Actor Dossiers)
                        - 5. Incident Investigation (Triage & Status Workflow)
                        - 6. Attack Timeline (Chronological Kill-Chain Graph)
                        - 7. Reports & Forensics (Downloadable PDF, JSON, MD, CSV)
```

---

## 📂 Project Directory Structure

```text
HONEYTRACE/
│
├── app.py                      # Main Streamlit SOC dashboard application entry point
├── launcher.py                 # Standalone script and PyInstaller entry point
├── requirements.txt            # Pinned dependencies (Streamlit, Plotly, Flask, fpdf2, pytest, etc.)
├── run.bat                     # Windows one-click execution & environment auto-detection script
├── package_zip.py              # Packaging utility building portable distribution ZIP
├── build_exe.bat               # Optional PyInstaller standalone executable builder
├── honeytrace.spec             # PyInstaller compilation specification
├── verify_workflow.py          # End-to-end automated demo pipeline verification
├── README.md                   # Comprehensive academic documentation and viva defense guide
│
├── core/                       # Core analytical and persistence engines
│   ├── database.py             # Thread-safe SQLite manager (WAL mode) and query analytics
│   ├── event_collector.py      # Async ingestion queue routing events between decoys and engines
│   ├── detection_engine.py     # Regex signature matching, Shannon entropy, and MITRE mapping
│   ├── risk_engine.py          # Dynamic risk scoring (0-100), velocity burst, and actor profiling
│   └── incident_engine.py      # Temporal session correlation and automated incident narrative
│
├── honeypots/                  # Deception decoy services (strictly non-executing)
│   ├── http_decoy.py           # Flask-based web honeypot emulating SSO, admin, LFI, and SQLi
│   └── ssh_decoy.py            # Socket-based SSH honeypot emulating OpenSSH 8.9p1 banner & shell
│
├── simulation/                 # Self-contained attack generation engine
│   ├── attack_simulator.py     # Synthetic adversary traffic generator targeting localhost
│   ├── demo_scenarios.py       # Pre-packaged multi-stage demonstration scenarios for examiners
│   └── seed_data.py            # Dataset seeder initializing historical demonstration telemetry
│
├── dashboard/                  # Streamlit SOC user interface components
│   ├── overview.py             # 1. SOC Overview (KPIs, incursion timeline & severity donut)
│   ├── live_monitor.py         # 2. Live Attack Monitor (streaming event feed, filters & packet inspector)
│   ├── honeypot_mgmt.py        # 3. Honeypot Management (service daemons, port bindings & test probes)
│   ├── threat_analysis.py      # 4. Threat Intelligence (MITRE sunburst hierarchy & actor dossiers)
│   ├── incident_investigation.py # 5. Incident Investigation (triage, status workflow & event drill-down)
│   ├── attack_timeline.py      # 6. Attack Timeline (chronological progression, elapsed times & containment)
│   └── reports.py              # 7. Reports & Forensics (downloadable PDF, JSON, MD, CSV exports)
│
├── reports/                    # Auto-generated forensic evidence exports (PDF, JSON, MD, CSV)
├── data/                       # Local SQLite database storage (honeytrace.db)
│   └── .gitkeep
├── tests/                      # Automated unit test suite (33 passing unit tests)
│   ├── test_detection.py       # Validates detection rules, MITRE tags, and entropy calculation
│   ├── test_risk.py            # Validates velocity multiplier, diversity bonus, and risk scores
│   ├── test_database.py        # Validates SQLite schema, CRUD operations, and KPI aggregations
│   └── test_incident_and_reports.py # Validates incident clustering, timeline, and PDF/JSON generation
├── assets/
│   └── logo.png                # Official HoneyTrace cyber shield logo asset
└── dist/
    └── HONEYTRACE_Demonstration_Suite.zip # Clean distribution ZIP for external PCs
```

---

## 🖥️ The 7 Streamlit SOC Dashboard Views

The user interface is structured like an industrial Security Operations Center (SOC) with a dark navy palette (`#0b1120`), responsive Plotly charts, and real-time streaming telemetry:

### 1. SOC Overview (`dashboard/overview.py`)
- **Executive KPI Cards:** Total Recorded Incursions, Critical Incursions, High-Severity Incursions, Unique Attacker IP Tracks, Average Risk Score ($/100$), Active Correlated Incidents.
- **Incursion Timeline:** Plotly time-series tracking telemetry ingestion rates and burst velocity.
- **Severity Distribution:** Donut chart breaking down events by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- **Top Incurring IPs:** Horizontal bar chart profiling the most aggressive source IPs.
- **Decoy Distribution:** Ratio of interaction events trapped by HTTP Decoy vs SSH Decoy.

### 2. Live Attack Monitor (`dashboard/live_monitor.py`)
- **Real-Time Telemetry Feed:** Streaming table with timestamps, decoy type, event type, endpoint, risk score, severity badge, and detection rule.
- **Multi-Factor Filters:** Filter by severity, honeypot decoy, event classification, and IP/payload search.
- **Deep Packet Inspector (DPI):** Select any atomic event to inspect complete forensic evidence, captured credentials, raw headers, payload sample, and detection reasoning.

### 3. Honeypot Management (`dashboard/honeypot_mgmt.py`)
- **Lifecycle Controls:** Start, stop, and restart controls for both HTTP Decoy (`:8080`) and SSH Decoy (`:2222`).
- **Operational Heartbeat:** Live daemon status table displaying thread state, uptime, port bindings, and connection counts.
- **Loopback Connectivity Probe:** One-click localhost probe testing both services and reporting response latency and banners.

### 4. Threat Intelligence (`dashboard/threat_analysis.py`)
- **MITRE ATT&CK Sunburst Hierarchy:** Interactive radial visualization mapping tactics (Reconnaissance, Initial Access, Credential Access, Execution) to specific sub-techniques.
- **Detection Rule Frequency:** Bar chart indicating the most frequently triggered heuristic and signature rules.
- **Threat Actor Profiling Dossiers:** Longitudinal tracking of attacker IP reputations, classification archetypes (*APT Emulation*, *Credential Stuffer*, *Web Reconnaissance Bot*), and target lists.
- **Harvested Credential Intelligence:** Security intelligence table displaying passwords and usernames sprayed against honeypots.

### 5. Incident Investigation (`dashboard/incident_investigation.py`)
- **Incident Selector:** Inspect correlated incident sessions grouped by attacker IP and 15-minute sliding temporal windows.
- **Triage Status Workflow:** Interactive status updater allowing analysts to progress an incident through `OPEN` $\rightarrow$ `INVESTIGATING` $\rightarrow$ `CONTAINED` $\rightarrow$ `RESOLVED`.
- **Automated Threat Narrative:** Synthesizes an executive summary explaining the attacker's trajectory, risk level, and containment status.
- **Correlated Event Drill-Down:** Table of all atomic events tied to the incident.

### 6. Attack Timeline (`dashboard/attack_timeline.py`)
- **Sequential Progression:** Chronological kill-chain table with Step Number, Relative Elapsed Time ($+00:00$, $+00:15$), Decoy Vector, MITRE Tactic, Attacker Action, Risk Score, and Outcome.
- **Risk Escalation Curve:** Plotly line chart illustrating risk escalation as the attacker transitioned from reconnaissance to exploitation.
- **Containment Outcome:** Reaffirms non-compromise containment on isolated deception nodes.

### 7. Reports & Forensics (`dashboard/reports.py`)
- **Forensic Dossier Compilation:** Compiles formal incident evidence packages for academic evaluation.
- **Downloadable Formats:**
  - 📄 **PDF Incident Report:** Formal executive report formatted via `fpdf2` with header branding, incident metadata box, threat narrative, defensive countermeasures, and forensic telemetry table.
  - 📦 **JSON Forensic Package:** Machine-readable JSON export with complete event evidence, timestamps, risk score, severity, detection explanation, and defensive actions.
  - 📥 **Markdown Dossier (`.md`):** Portable documentation report ready for reports and wikis.
  - 📊 **CSV Evidence Export (`.csv`):** Raw tabular event dump for spreadsheet analysis.
- **Disk Persistence:** One-click save button to persist all formats directly to the local `reports/` folder.

---

## 📑 Downloadable PDF & JSON Incident Reports

All exported reports follow strict forensic integrity standards and incorporate:
1. **Event Evidence:** Captured payloads, regex match fragments, token analysis, and Shannon entropy.
2. **Timestamps:** ISO-8601 timestamps and relative elapsed time deltas from initial detection.
3. **Explainable Risk Score:** Mathematical score ($0-100$) derived from base weight, velocity multiplier, and decoy diversity bonus.
4. **Severity Classification:** `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`.
5. **Detection Explanation:** Human-readable reasoning explaining why the rule triggered without ambiguity.
6. **Defensive Countermeasures:** Actionable remediation recommendations tailored to the observed vectors (firewall drop rules, account locking, parameterized queries, least-privilege service accounts).
7. **Compromise Assessment:** Explicit disclaimer: `ATTEMPT_CAPTURED_NO_COMPROMISE (Decoy Trapped - Non-Executed)`.

### Sample JSON Export Structure (`reports/*_Forensics.json`)
```json
{
  "platform": "HONEYTRACE Active Deception Platform",
  "report_type": "FORENSIC_INCIDENT_REPORT",
  "generated_at": "2026-11-09T02:06:46.469866",
  "incident_id": "INC-202611090206-127001",
  "attacker_ip": "172.16.8.99",
  "severity": "CRITICAL",
  "peak_risk_score": 100.0,
  "event_count": 4,
  "compromise_assessment": "ATTEMPT_CAPTURED_NO_COMPROMISE (Decoy Trapped - Non-Executed)",
  "recommended_defensive_actions": [
    "1. Perimeter Defense: Enforce immediate firewall drop rule / fail2ban jail for source IP 172.16.8.99.",
    "2. Identity & Access: Lock targeted accounts, enforce Multi-Factor Authentication (MFA), and audit active sessions.",
    "3. Application Hardening: Enforce parameterized queries (OWASP A03) and strict path canonicalization for file APIs.",
    "4. Non-Compromise Containment: Host assets safe. Maintain decoy honeypot monitoring to gather lateral movement telemetry."
  ],
  "correlated_events": [
    {
      "event_uuid": "EVT-20261109020754-6C1CC8CF",
      "timestamp": "2026-11-09T02:07:54.911573",
      "honeypot_type": "HTTP",
      "event_type": "COMMAND_INJECTION",
      "endpoint": "/api/v1/search?q=`curl -O http://127.0.0.1/malware.sh`",
      "risk_score": 100.0,
      "severity": "CRITICAL",
      "rule_name": "SUSPICIOUS_COMMAND_PATTERN",
      "detection_explanation": "Observed suspicious command pattern in payload/endpoint. Indicates adversary attempting command execution or reverse shell injection.",
      "evidence": {
        "matched_pattern": "(?i)(`.*(whoami|id|cat|curl|wget).*`)",
        "matched_fragment": "`curl -O http://127.0.0.1/malware.sh`",
        "compromise_status": "ATTEMPT_CAPTURED_NO_COMPROMISE"
      }
    }
  ]
}
```

---

## ⚡ Quick Start & Installation

### Prerequisites
- Windows 10 or Windows 11 PC (also compatible with Linux and macOS)
- Python 3.10, 3.11, 3.12, 3.13, or 3.14

### One-Click Launch (Windows)
Double-click `run.bat` or run from command prompt:
```cmd
run.bat
```
*The script automatically detects your installed Python, verifies dependencies, pre-seeds the SQLite database if empty, executes all 33 unit tests, and launches the Streamlit SOC interface on `http://localhost:8501`.*

### Manual Launch (Command Line)
```cmd
cd HONEYTRACE
pip install -r requirements.txt
pytest
streamlit run app.py
```

### Pre-Seeding Sample Dataset
If you ever reset the database or want to re-populate historical sample data:
```cmd
python simulation/seed_data.py
```

---

## 🧪 Comprehensive Automated Test Suite

HONEYTRACE includes **33 unit tests** covering normal benign activity, exploit heuristics, dynamic risk scoring, incident correlation, and report compilation:

```cmd
pytest -v
```

### Test Suite Structure:
- `tests/test_database.py`: Tests thread-safe SQLite CRUD, KPI calculation, event UUID generation, alert storage with evidence, and timeline reconstruction.
- `tests/test_detection.py`: Tests SQL injection, directory traversal, OS command injection, Log4j, scanner User-Agents, SSH dictionary heuristics, Shannon entropy, benign baseline web requests, and the 5 simulation scenarios.
- `tests/test_risk.py`: Tests velocity burst multiplier, cross-decoy diversity bonus, actor archetype classification, explainable score breakdown, and normal vs suspicious risk separation.
- `tests/test_incident_and_reports.py`: Tests temporal session correlation, attack timeline generation, defensive recommendation synthesis, JSON report structure, Markdown dossier formatting, and PDF binary report generation.

---

## 📦 Distribution Packaging (ZIP Instructions)

To distribute HONEYTRACE to an external PC or examiner machine without git caches or bytecode:

1. Run the included packaging script:
   ```cmd
   python package_zip.py
   ```
2. The clean archive will be created at:
   ```text
   dist/HONEYTRACE_Demonstration_Suite.zip
   ```
3. Copy `HONEYTRACE_Demonstration_Suite.zip` to the target Windows PC, extract it, and double-click `run.bat`.

---

## 🔨 Optional PyInstaller Standalone Executable Build

HONEYTRACE can also be compiled into a standalone Windows executable directory:

1. Run the builder script:
   ```cmd
   build_exe.bat
   ```
   *This uses the pre-configured `honeytrace.spec` file and bundles all dashboard components, core engines, decoys, sample databases, and assets.*
2. Once compiled, launch the standalone binary:
   ```cmd
   dist\HONEYTRACE\HONEYTRACE.exe
   ```
*(Note: Python 3.10, 3.11, or 3.12 is recommended when using PyInstaller. For general demonstration, `run.bat` is recommended across all Python versions including Python 3.14).*

---

## 🔄 End-to-End Demo Workflow Verification

To verify the entire demonstration pipeline programmatically before stepping in front of examiners:

```cmd
python verify_workflow.py
```

This headless script automatically tests the complete workflow:
1. Starts HTTP Decoy on port 8080 and SSH Decoy on port 2222.
2. Validates localhost socket connectivity.
3. Fires all 5 attack simulation scenarios.
4. Confirms event detection and explainable risk calculation.
5. Correlates atomic telemetry into formal security incidents.
6. Investigates incident timeline and validates attack kill-chain progression.
7. Generates and validates downloadable PDF, JSON, and Markdown reports.
8. Confirms reports are written to disk in `reports/`.

---

## 🎓 Viva Defense & Examiner Walkthrough Guide

Follow this 5-minute walkthrough to conduct a flawless presentation for external examiners:

### Step 1: System Health & Baseline Verification
- Open the dashboard at `http://localhost:8501`.
- Direct the examiners' attention to the top status bar:
  - Both **HTTP Decoy (:8080)** and **SSH Decoy (:2222)** are active.
  - The system operates strictly within an isolated localhost sandbox (`127.0.0.1`).
  - Executive KPIs reflect live, real-time data queried directly from SQLite (`data/honeytrace.db`).

### Step 2: Demonstrating Scenario 1 — SSH Brute-Force & Credential Spraying
- Click **"1️⃣ SSH Brute-Force"** on the sidebar.
- Navigate to **"1. SOC Overview"**: Show the burst spike in the **Incursion Timeline** and how the **Velocity Multiplier** scaled up the risk score.
- Navigate to **"4. Threat Intelligence"**: Point to the **Harvested Credential Intelligence** table showing trapped passwords and usernames.

### Step 3: Demonstrating Scenario 2 — Suspicious Command Probing & Zero Execution
- Click **"4️⃣ Suspicious Command Probing"** on the sidebar.
- Navigate to **"2. Live Attack Monitor"**:
  - Filter for `CRITICAL` severity.
  - Open the **Deep Packet Inspector (DPI)** on the command injection event.
  - Show examiners the raw payload: `; cat /etc/passwd` or `` `curl -O http://127.0.0.1/malware.sh` ``.
  - Highlight the **Detection Reasoning** and **Compromise Status**: `ATTEMPT_CAPTURED_NO_COMPROMISE (Decoy Trapped - Non-Executed)`.
  - Explain to examiners that the command was trapped as a passive text string and **never** passed to the operating system shell.

### Step 4: Demonstrating Scenario 3 — Multi-Stage Kill-Chain & Actor Profiling
- Click **"🔥 ONE-CLICK DEMO (ALL 5 VECTORS)"**.
- Navigate to **"4. Threat Intelligence"**:
  - Show the **Threat Actor Profile**: the system recognized cross-decoy engagement (HTTP + SSH) and categorized the actor archetype as **"Advanced Persistent Threat (APT) Emulation"**.
  - Show the **MITRE ATT&CK Sunburst Chart** illustrating the progression across Initial Access, Credential Access, and Execution.

### Step 5: Incident Investigation & Status Workflow
- Navigate to **"5. Incident Investigation"**.
- Select the correlated incident (e.g., `INC-2026...`).
- Show the auto-generated executive narrative.
- Update the status from `OPEN` to `INVESTIGATING` to demonstrate operational SOC workflow integration.
- Navigate to **"6. Attack Timeline"**: Show the chronological reconstruction with elapsed time deltas ($+00:00$, $+00:15$) and the risk escalation curve.

### Step 6: Exporting Formal Forensic Reports
- Navigate to **"7. Reports & Forensics"**.
- Click **"📄 Download Report (PDF)"** to open the generated PDF report.
- Click **"📦 Download Package (JSON)"** to view the structured evidence JSON package.
- Click **"💾 Save All Formats (PDF, JSON, MD) to `reports/` Folder"** and open the folder to show examiners the saved files on disk.

---

## ❓ Frequently Asked Viva Questions (Q&A)

**Q1: Why use deception technology when standard firewalls exist?**  
*Answer:* Firewalls and signature-based IDSs inspect mixed production traffic, causing significant false positive rates and alert fatigue. Honeypot decoys have no legitimate production function, meaning every single interaction is unauthorized by definition. Deception provides high-fidelity, actionable threat intelligence with near-zero false positive rates.

**Q2: How does HONEYTRACE ensure the host PC is not compromised by attacker commands?**  
*Answer:* HONEYTRACE implements strict low-interaction deception principles. Decoys simulate protocol banners and canned terminal responses. Submitted commands are analyzed as passive text strings for regex signatures and Shannon entropy; they are never passed to `os.system()` or `subprocess.Popen()`.

**Q3: How does the AI heuristic component work without external internet or cloud APIs?**  
*Answer:* It calculates mathematical Shannon entropy ($H = -\sum p(x) \log_2 p(x)$) to evaluate byte randomness (detecting packed payloads, hex encoding, and fuzzing) and structural token density to classify attacker intent deterministically on localhost with zero network latency.

**Q4: How does the platform achieve explainable risk scoring?**  
*Answer:* Instead of a black-box machine learning probability, HONEYTRACE uses a transparent, deterministic mathematical formula:
$$\text{Final Risk} = \min(100.0, (\text{Base Weight} \times \text{Velocity Multiplier}) + \text{Diversity Bonus} + \text{Evasion Penalty})$$
Every alert includes an explicit explanation of each component contributing to the final score.

**Q5: How does the system handle database concurrency between listeners and the UI?**  
*Answer:* SQLite is initialized in Write-Ahead Logging (`WAL`) mode with `threading.Lock` per database path. This allows concurrent read operations by the Streamlit dashboard while background decoy threads and simulation scripts write events simultaneously without lock contention or `database is locked` errors.

---

## 🔒 Security & Containment Policy
- **Localhost Bound:** Decoys listen strictly on `127.0.0.1`.
- **Read-Only / Trap Handlers:** No shell execution, no arbitrary file uploads.
- **Academic Demonstration Safe:** Zero risk of compromise or outbound network scanning.

---
*Developed for B.Tech Cybersecurity Capstone Demonstration.*
