# AI SOC Triage Platform

![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)
![License MIT](https://img.shields.io/badge/license-MIT-green.svg)

An AI-native Security Operations Center (SOC) triage platform that ingests real Windows attack logs (`.evtx`), runs MITRE ATT&CK-aligned detection rules, and uses **Claude AI** to analyse every alert — replicating the core workflow of enterprise tools like Microsoft Sentinel Copilot, but fully local and open to customisation.

Built for blue team engineers and security analysts who want a portfolio-quality project demonstrating AI-assisted threat detection, log analysis, and SOC automation.

---

## Features

- 📊 **AI-powered alert triage** — Claude analyses every triggered alert and returns a plain-English summary, urgency score, false-positive likelihood, recommended actions, and investigation steps.
- 🔍 **Splunk-style natural language search** — type `failed logins from external IPs` or `event_id=4625 AND source_ip=10.0.0.1`; Claude translates ambiguous queries automatically.
- 🤖 **Conversational AI chat** — floating "Ask AI" button opens a chat panel where Claude answers questions about your actual loaded log data and live alerts.
- ✨ **AI-generated custom dashboard views** — describe a chart in plain English and Claude generates the Plotly + pandas code live; views can be saved and reloaded.

---

## Architecture

```
EVTX Logs ──► ingestor.py ──► detector.py ──► ai_triage.py ──► dashboard.py
                                   ▲                                  │
                       detection_rules.yml              search + chat + views
```

---

## Quick Start (local)

```bash
# 1. Clone this repo
git clone https://github.com/YOUR_USERNAME/ai-soc-triage.git
cd ai-soc-triage

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure API key
cp .env.example .env
# Edit .env and add your Anthropic API key

# 4. Download attack log samples
# Visit: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
# Click "Code" -> "Download ZIP", extract, and copy the folders into:
#   ai-soc-triage/data/raw_logs/
# Expected structure:
#   data/raw_logs/Credential Access/*.evtx
#   data/raw_logs/Defense Evasion/*.evtx
#   data/raw_logs/Lateral Movement/*.evtx  etc.

# 5. Launch the dashboard
streamlit run src/dashboard.py
# Open http://localhost:8501
# Click "Run New Scan" in the sidebar
```

---

## Docker Start

```bash
# 1. Configure API key
cp .env.example .env
# Edit .env and add your Anthropic API key

# 2. Start
docker-compose up
# Open http://localhost:8501
```

---

## Detection Rules

| Rule ID  | Rule Name                             | MITRE ID  | Severity |
|----------|---------------------------------------|-----------|----------|
| RULE-001 | Brute Force Login Attempts            | T1110     | Critical |
| RULE-002 | Mimikatz Credential Dumping Behavior  | T1003     | Critical |
| RULE-003 | Suspicious PowerShell Encoded Command | T1059.001 | High     |
| RULE-004 | New Local Admin Account Created       | T1136     | High     |
| RULE-005 | Scheduled Task Outside Business Hours | T1053     | Medium   |
| RULE-006 | Lateral Movement via PsExec           | T1021     | High     |
| RULE-007 | Known Malware Process Name            | T1059     | Critical |
| RULE-008 | Outbound High-Risk Port Connection    | T1071     | High     |
| RULE-009 | Registry Run Key Modification         | T1547     | Medium   |
| RULE-010 | Shadow Copy Deletion Indicator        | T1490     | Critical |

---

## Log Source

Real Windows attack samples from **[@sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)** — a public collection of Windows Event Logs captured during actual red team exercises covering the full MITRE ATT&CK matrix.

**Download:**
```
https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
```
Extract and place the category folders inside `data/raw_logs/`.

---

## Tech Stack

| Component  | Technology              |
|------------|-------------------------|
| Language   | Python 3.11             |
| Dashboard  | Streamlit               |
| Charts     | Plotly                  |
| AI Model   | Anthropic Claude (Haiku)|
| Data       | pandas                  |
| Log Parser | python-evtx + lxml      |

---

## Add Custom Detection Rules

1. Open `rules/detection_rules.yml`.
2. Add a new YAML rule with `id`, `name`, `description`, `mitre_id`, `mitre_name`, `severity`, `type`, and `conditions`.
3. Supported operators: `equals`, `contains`, `regex`, `in`, `exists`, `gt`, `gte`, `lt`, `lte`, `outside_business_hours`.
4. Click "Run New Scan" in the dashboard to apply.

---

## License

MIT
