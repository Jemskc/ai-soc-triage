# SOC Sentinel — Multi-Agent AI Triage for Security Operations

A Security Operations Center platform where a team of local LLM agents does the
Tier-1 triage pass. Raw Windows event logs go in; correlated cases come out —
each with a risk score you can decompose, the cross-domain evidence behind it, a
MITRE ATT&CK attribution that is **retrieved rather than recalled**, and a
response plan held behind analyst approval.

Everything runs on your own GPU. No API keys, no egress, no third party sees the
telemetry.

---

## The problem it addresses

Rule-based detection produces more alerts than anyone can read, and most are
noise. The scarce resource is analyst attention, so the useful question is not
"what fired?" but "what deserves a human, and why?".

Three constraints shaped the design:

**You cannot run an LLM per log line.** 4,633 events at ~15s each is roughly 19
GPU-hours. The pipeline correlates events into *incidents* first — grouping by
host, account, technique and time window — collapsing thousands of events into a
few dozen units of work. That is also how an analyst thinks: nobody triages
forty PsExec alerts individually, they triage "PsExec on PC02".

**An attribution you cannot check is worse than none.** The MITRE mapping this
replaced was 23 lines of keyword matching over 11 techniques, with `T1190` as the
fallback — so every unrecognised event was confidently labelled "Exploit
Public-Facing Application". Now a technique may only be cited if it came back
from retrieval, and the UI links to the source.

**A single confident agent should not be able to escalate on its own.** So
judgement and scoring are separated: agents reason, and a deterministic Risk
Engine fuses their findings. Corroboration across independent telemetry is
weighted heavily, which is what makes one wrong agent survivable.

---

## Architecture

Two layers. Layer 1 is volume reduction and runs in about a second; Layer 2 is
the expensive reasoning and only ever sees what Layer 1 hands it.

### Layer 1 — the funnel

```
  10M events
    -> stream processing      bounded memory, one pass, running baselines
    -> rules + statistics     rule hits + rarity/content signals
    -> UEBA                   per-entity baseline deviation
    -> correlation            alerts -> incidents
    -> rank against a budget  top-N, where N is the AI budget
    -> Layer 2
```

**No stage filters.** Every stage contributes signal and the narrowing happens
once, at the end, by ranking. That is the design decision that matters.
Measured on the labelled corpus, the 10 detection rules reach only **14.5% of
the 249 attack samples**; if rules gated the pipeline the other 85% could never
reach the AI however good it is. Adding behavioural signal takes coverage to
**34.1%**, and the 4,633-event corpus runs the whole funnel in **1.3 seconds**:

| Stage | In | Out | |
|---|---|---|---|
| stream | 4,633 | 4,633 | baselines for 42 accounts, 19 hosts |
| rules | 4,633 | 123 | high precision, low recall |
| analytics | 4,633 | 2,320 | events carrying any behavioural signal |
| promotion | 2,320 | 142 | **reached the AI with no rule hit at all** |
| correlation | 265 | 79 | incidents |
| ranking | 79 | 40 | budget applied; 39 deferred, not discarded |

**Budget, not threshold.** A fixed suspicion threshold breaks when volume moves:
a noisy day either floods the model or silently drops the tail. Taking the top N
keeps cost bounded whatever arrives, and everything below the line is recorded
as deferred so an analyst can see what was left and raise the budget.

**Unsupervised, and labelled as such.** There is no benign corpus here to train
on, so "ML/UEBA" means rarity scoring and per-entity baseline deviation, not a
fitted model. Three things this cost real effort to get right:

- *Rarity that flags most of your data is not rarity.* 62% of parent-child pairs
  in this corpus occur exactly once, so "seen once" described the common case.
  Rarity is now damped by how ordinary singletons are in that population —
  reported per-population as `discriminative_power` (lineage 0.38, event id 0.78).
- *SYSTEM is not a user.* `NT AUTHORITY\SYSTEM appears on 10 hosts` scored as
  maximally anomalous while being the most normal fact in a Windows estate.
  Machine accounts and service principals are excluded from baselines.
- *The displayed score and the ranking key must differ.* Noisy-OR saturates at
  three or more signals and every incident ties at 1.0. Ranking uses the
  unbounded log-space accumulation; the bounded probability is for display only.

Self-baselining — computing rarity against the same data being scored — is a
genuine weakness, so the funnel emits a caveat saying so whenever no separate
baseline is supplied. A baseline learned from known-normal traffic is a
supported input.

### Layer 2 — the agents

```
                      ┌─────────────────────┐
                      │  Agent Orchestrator │
                      └──────────┬──────────┘
                                 │
        ┌────────────────┬───────┴────────┬────────────────┐
        ▼                ▼                ▼                ▼
   Intel Agent     Triage Agent      Hunt Agent      Response Agent
   what is it,     real? urgent?     what did the    contain / eradicate
   what's next     evidence          rules miss      / recover (gated)
        └────────────────┴───────┬────────┴────────────────┘
                                 ▼
                    ┌────────────────────────┐
                    │ Investigation/Evidence │
                    │        Engine          │
                    └───────────┬────────────┘
                                │
      endpoint · identity · network · ad │ email · dns · cloud · firewall · saas
         (connected)                     │        (declared, no connector)
                                ▼
                    ┌────────────────────────┐
                    │  Risk / Verdict Engine │  ← deterministic, not a model
                    └───────────┬────────────┘
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                 ▼
          Dashboard      Analyst approval    Response plan
```

### Why the Risk Engine is not a model call

Agents supply judgement; `src/risk_engine.py` turns judgement into a number with
fixed weights. Same case, same score, every time. Every point is attributable to
a named factor, so "why is this a 78?" has an answer that does not require
re-running anything.

| Factor | Weight | What it measures |
|---|---|---|
| `rule_severity` | 20 | What the deterministic rules thought |
| `triage_urgency` | 30 | Triage agent's call, discounted by its own confidence |
| `intel_attribution` | 15 | How well the technique is evidenced |
| `cross_domain` | 20 | Corroboration across independent telemetry |
| `blast_radius` | 15 | Hosts, accounts and alert volume involved |

No single factor can escalate a case alone. Low agent confidence damps the
urgency contribution but never erases it — under-reacting to a possible
intrusion is the worse error.

### Evidence Engine and honest blind spots

Each data domain is a pluggable adapter. Adapters with a real source return
evidence; adapters without one report **NOT CONNECTED** rather than returning
empty results that read like "nothing found".

That distinction is the point: *"we found nothing in Cloud"* and *"we cannot see
Cloud"* are different statements, and conflating them is how a tool quietly
loses trust. Unconnected domains also cap how much corroboration any verdict can
earn, and the Risk Engine says so in its caveats.

### Tab-aware prompting

`src/tab_contracts.py` is the single registry of what the AI owes each surface:
the analyst question, the exact JSON schema, what to retrieve, a token budget.
The prompt builder, the pipeline and the response validator all read from it, so
adding a tab means adding a contract rather than hand-writing another prompt.
The model is also told the whole product surface exists — that is what makes it
one engine rather than nine disconnected calls.

### Grounding rules

Enforced in `src/prompts.py` and checked in code, not merely requested:

- Cite an ATT&CK ID **only** if it appears in the retrieved context
- Point at specific log fields for every judgement
- Output `UNKNOWN` rather than guess when evidence is thin
- Emit a calibrated `confidence` and the `sources` actually used

`check_grounding()` re-reads each response and flags any technique cited that was
not retrieved. The UI renders that warning rather than hiding it.

### Retrieval

749 chunks: all 697 live ATT&CK Enterprise techniques (detection guidance joined
from `x-mitre-detection-strategy` and `x-mitre-analytic` objects), Windows and
Sysmon event semantics with benign baselines, LOLBAS abuse notes, the platform's
own rules, and response playbooks.

Hybrid **BM25 + dense embeddings** fused with Reciprocal Rank Fusion. Lexical
matters more than usual here — security text is full of exact tokens (`T1003`,
`lsass.exe`, `4625`) that embeddings blur. Two details that turned out to matter:

- **Term coverage, not just score.** A chunk matching one rare term can outscore
  a chunk matching three relevant ones. Requiring overlap on ≥2 query terms is
  what stops an unrelated technique being presented as grounding.
- **Retrieving nothing is a valid outcome.** Below a relevance floor the KB
  returns empty, and the grounding rule turns that into `UNKNOWN`.

### Response is proposed, never executed

The Response Agent produces contain/eradicate/recover steps naming the actual
hosts and accounts. Any step that changes production state — isolate, disable,
reset, block — is flagged destructive and held behind an explicit analyst
decision recorded via `POST /approve`. An agent that can isolate a domain
controller on its own judgement is a liability, not a feature.

### Improving without fine-tuning

Analyst Agree/Disagree writes to `output/analyst_feedback.json`, indexed back
into the knowledge base as correction examples retrieved on similar future
incidents. Accuracy improves with use, and every correction stays inspectable —
which a fine-tuned weight would not be.

---

## Measurement

`data/raw_logs/evtx_data.csv` carries 4,633 attack events from 249 EVTX files,
each labelled with its MITRE tactic. `scripts/benchmark.py` scores against it and
runs twice — retrieval on and off — so the RAG contribution is a measured number.

Reported: escalation recall, tactic accuracy with a per-tactic breakdown,
ungrounded-citation count, parse/schema failure counts, throughput.

> **Limitation, stated on the dashboard as well as here:** every event in this
> corpus is malicious. There is no benign traffic, so a **false-positive rate
> cannot be computed from it**. What is reported is a suppression rate, which
> needs a human spot-check to interpret. A real FP number requires a benign
> baseline — the next thing worth building.

```bash
python scripts/benchmark.py            # full corpus, with ablation
python scripts/benchmark.py --limit 10 # quick pass
```

### Tests

The deterministic layers are the ones that must be provable without a GPU, and
they are where a silent failure would be most dangerous — a scoring bug or a
grounding gate that quietly passes would corrupt every downstream number.

```bash
cd ai-soc-triage && python -m pytest tests/ -q     # 92 tests, ~2s, no GPU
```

What they pin:

| Area | Property under test |
|---|---|
| `test_risk_engine.py` | Reproducibility; no single factor can escalate a case alone; low confidence damps but never erases urgency; factor points sum to the score; graceful degradation when an agent fails |
| `test_correlator.py` | Grouping tightness; stable incident ids so cached triage survives a re-run; **ground-truth labels never reach the model**; evidence stays bounded regardless of input size |
| `test_grounding.py` | A technique cited without retrieval support is flagged; empty retrieval forbids any citation; `extract_json` raises rather than defaulting |
| `test_retrieval.py` | Five real incident shapes land on the right ATT&CK technique; irrelevant queries return **nothing**; every tactic has a playbook |
| `test_evidence_engine.py` | "Checked, found nothing" never looks like "cannot see this domain" |
| `test_funnel.py` | Nothing is silently dropped; the ranking key never saturates; singleton rarity is damped when singletons are normal; SYSTEM and machine accounts are excluded; an external baseline is never polluted by the data being scored |

---

## Setup

Python 3.10+, Node 18+, CUDA GPU (24GB+ for the 14B model).

```bash
# Knowledge base (once)
cd ai-soc-triage
curl -sL -o data/kb/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
python scripts/build_kb.py             # --no-embeddings for BM25 only

# Backend
cp .env.example .env                   # LOCAL_MODEL_NAME, HF_HOME
uvicorn src.api_server:app --host 0.0.0.0 --port 8000

# Frontend
cd ../soc-sentinel && npm install && npm run dev
```

Dashboard `http://localhost:5173`, API `http://localhost:8000`.

All four agents share **one** loaded model — nine agents must not mean nine
copies of a 14B model in VRAM.

### A note on dtype

`llm_backend.py` picks fp16 or bf16 from the GPU's compute capability rather than
from `torch.cuda.is_bf16_supported()`, which returns `True` on Volta because
recent PyTorch counts *emulated* bf16. Measured on a V100-PCIE-32GB:

| dtype | throughput |
|---|---|
| fp16 | 84.7 TFLOP/s |
| bf16 (emulated) | 9.5 TFLOP/s |

An 8.9x difference, so the check is worth getting right.

---

## API

| Endpoint | Purpose |
|---|---|
| `POST /analyze-logs` | Start a background analysis run → `job_id` |
| `GET /analyze-status/{id}` | Stage, percent, live counts |
| `GET /analysis` | The bundle every tab reads |
| `GET /cases`, `/cases/{id}` | Work queue and full case files |
| `GET /agents` | The agents and the risk weights |
| `GET /telemetry-coverage` | Connected domains and blind spots |
| `POST /approve` | Analyst decision on a proposed action |
| `GET /incidents`, `/incidents/{id}` | Incidents with verdicts |
| `GET /metrics` | Funnel and effort estimate (assumption stated inline) |
| `GET /benchmark` | Scorecard and limitations |
| `GET /kb/search?q=` | Retrieval, exposed directly |
| `GET /tab-contracts` | What the AI produces per tab |
| `POST /feedback` | Analyst agreement → correction examples |

Existing `/health`, `/chat`, `/chat-stream`, `/log-search`, `/email-analyze`,
`/analyze` are unchanged.

---

## Layout

```
ai-soc-triage/src/
  orchestrator.py      coordinates the agents; owns the Case object
  agents/
    base.py            Agent + Finding contracts
    triage.py          real? urgent? what now
    intel.py           what is it, what follows, how strong the attribution
    hunt.py            leads across the whole case set
    response.py        contain/eradicate/recover, approval-gated
  evidence_engine.py   pluggable per-domain adapters, honest about blind spots
  risk_engine.py       deterministic fusion -> score, band, action
  tab_contracts.py     what each surface needs from the AI
  prompts.py           layered assembly, grounding rules, validation
  knowledge_base.py    hybrid BM25 + dense retrieval
  stream.py            chunked ingestion, running baselines
  analytics.py         statistical rarity + UEBA, calibrated
  funnel.py            Layer 1: score, rank, apply the AI budget
  correlator.py        events -> incidents
  pipeline.py          stage orchestration, job state, caching
  api_server.py        FastAPI

soc-sentinel/src/
  context/AnalysisContext.jsx        the bundle every tab reads
  components/agents/                 SOC core, risk breakdown, agent findings,
                                     response approval, telemetry coverage
  components/alerts/AITriageVerdict.jsx   verdict, evidence, clickable sources
  components/pages/BenchmarkReport.jsx    scorecard and limitations
```

---

## Not built

Stated because a demo that hides its edges is worth less than one that names
them: no authentication or multi-tenancy; single-node only; file import rather
than live SIEM ingestion; five of nine telemetry domains have no connector; and
phishing email is not yet linked to the endpoint activity that follows it.

## License

MIT
