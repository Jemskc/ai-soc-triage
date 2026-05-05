# SOC Sentinel — AI-Powered Security Operations Dashboard

A full-stack Security Operations Center (SOC) dashboard with a locally-running AI assistant powered by open-source LLMs. Built for real-time threat monitoring, log analysis, email phishing detection, and AI-assisted incident response — all running on your own infrastructure with no external API calls.

---

## What This Project Does

SOC Sentinel gives a security analyst a single pane of glass to monitor threats, investigate incidents, and get AI assistance — without sending sensitive security data to any third-party cloud service. The AI runs entirely on your own GPU using open-source models.

---

## Current Features

### Dashboard & Navigation
- **Overview** — KPI cards (total events, critical alerts, unique IPs, affected users), threat trend chart, severity donut, top sources table, recent alerts table
- **Alerts** — Full alert table with severity filtering, search, and detail view
- **Logs Explorer** — Advanced log search with two modes:
  - **AI Search** — natural language queries (`failed logins last hour`, `what did admin do today`) and structured field queries (`src ip = 10.0.0.1`, `severity = high time = 24h`)
  - **Query Mode** — `field:value` syntax (`source:windows severity:CRITICAL`)
  - Time range filter, source filter, severity filter, export to CSV
- **Email Analysis** — 7-tab email detail panel (Overview, Headers, Body, URLs, Attachments, IOCs, AI Assessment) with phishing risk scoring
- **Investigations** — Timeline view with MITRE ATT&CK coverage mapping
- **Threat Hunting** — Hypothesis-driven hunting workspace
- **Assets** — Asset inventory derived from log data
- **Reports** — Exportable security reports
- **Settings** — Dashboard configuration

### AI Assistant (Right Panel)
- Standalone chatbot — free-form conversation, not tied to any tab
- Knows the current dashboard state (active tab, loaded logs, alert counts, top IPs, top rules, top users, top hosts)
- Only references dashboard data when you ask about it — behaves like a normal chatbot otherwise
- Streaming responses — tokens appear word by word in real time
- Conversation history maintained across turns within a session
- Suggested starter questions on welcome screen

### MITRE ATT&CK Integration
- Auto-maps log events to ATT&CK techniques
- Clickable technique IDs, tactic pills, mitigation chips — all link to the official ATT&CK website
- Attack chain visualization in the Investigations view

### Log Import
- Supports JSON, CSV, and plain text log formats
- Progress bar for large files
- Sample data included for demo

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, Vite 5, Tailwind CSS v3 |
| Charts | Recharts |
| Icons | Lucide React |
| Backend | FastAPI, Python 3.11+ |
| AI Model | Qwen/Qwen2.5-14B-Instruct (local, HuggingFace) |
| Inference | `transformers`, `torch`, bfloat16, GPU |
| Streaming | Server-Sent Events (SSE) via FastAPI `StreamingResponse` |

---

## Project Structure

```
ai-soc-triage/          ← FastAPI backend
  src/
    api_server.py       ← REST + streaming endpoints
    llm_backend.py      ← HuggingFace model loader & inference
    ai_triage.py        ← Alert triage logic
  .env                  ← Model config (LOCAL_MODEL_NAME, etc.)
  requirements.txt

soc-sentinel/           ← React frontend
  src/
    components/
      AIPanel.jsx       ← AI chatbot panel
      Sidebar.jsx       ← Navigation sidebar
      MitreCards.jsx    ← MITRE ATT&CK visualization
    pages/
      LogsExplorer.jsx  ← Log search & analysis
      EmailAnalysis.jsx ← Email threat analysis
    utils/
      aiLogSearch.js    ← Structured + NLP log search parser
      emailParser.js    ← Email header/body parser
      mitreMapper.js    ← Log → MITRE technique mapping
    data/
      navConfig.js      ← Single source of truth for all tabs
```

---

## Setup & Running

### Requirements
- Node.js 18+
- Python 3.11+
- CUDA-capable GPU (recommended: 24GB+ VRAM for 14B model)
- Conda environment with `transformers`, `torch`, `fastapi`, `uvicorn`

### Backend
```bash
conda activate /your/conda/env
cd ai-soc-triage
cp .env.example .env          # set LOCAL_MODEL_NAME and HF_HOME
uvicorn src.api_server:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend
```bash
cd soc-sentinel
npm install
npm run dev
```

Dashboard opens at `http://localhost:5173`
API health check at `http://localhost:8000/health`

### Environment Variables (`.env`)
```
LOCAL_MODEL_NAME=Qwen/Qwen2.5-14B-Instruct
LOCAL_MAX_NEW_TOKENS=1024
HF_HOME=/path/to/hf/model/cache
```

---

## AI Architecture

The AI backend is a local inference server — no data ever leaves your machine.

```
User message
    ↓
Dashboard context built fresh each message
(active tab, log counts, top rules, top IPs, top users, top hosts)
    ↓
FastAPI /chat-stream endpoint
    ↓
Qwen2.5-14B-Instruct
  - Thinking mode disabled (enable_thinking=False)
  - Deterministic decoding (do_sample=False)
  - Per-action token budgets
  - torch.inference_mode() for speed
    ↓
TextIteratorStreamer → SSE tokens → frontend
    ↓
Blinking cursor, tokens appear word by word
```

### Supported Query Syntax (Log Search)

| Syntax | Example |
|---|---|
| Natural language | `failed logins last hour` |
| Structured field | `src ip = 10.0.0.1` |
| Field with colon | `severity:HIGH` |
| Combined | `src ip = 10.0.0.1 severity = critical time = 24h` |
| Multiple conditions | `user = admin host = DC01` |

---

## Roadmap

### Phase 2 — Smarter AI (In Progress)
- [ ] RAG with MITRE ATT&CK knowledge base — AI answers from actual technique descriptions, not training data
- [ ] Persistent conversation memory across browser sessions
- [ ] Richer per-tab context — actual alert/log samples sent to AI, not just counts
- [ ] Improved system prompt with SOC-specific reasoning patterns

### Phase 3 — Feels Like a Real Assistant
- [ ] Proactive AI summaries — auto-trigger short analysis when critical alerts arrive
- [ ] Multi-turn investigation mode — AI remembers the full investigation thread
- [ ] Confidence signals — AI rates its own answer confidence (High / Medium / Low)
- [ ] AI-suggested pivots — "Based on this IP, you should also check..."

### Phase 4 — Platform Features
- [ ] User authentication and analyst accounts
- [ ] Saved investigations with notes
- [ ] Alert assignment and workflow (open → investigating → closed)
- [ ] Integration with real log sources (Elasticsearch, Splunk, Syslog)
- [ ] Webhook alerts for critical detections
- [ ] Multi-model support — switch between local models from the UI

---

## Contributing

This project is under active development. The architecture is intentionally kept simple — one backend, one frontend, one model. Complexity will be added only when there's a clear user need.

---

## License

MIT
