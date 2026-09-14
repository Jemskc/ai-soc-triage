# SOC Sentinel — Multi-Agent AI Triage for Security Operations

A Security Operations Center platform where a team of local LLM agents does the
Tier-1 triage pass. Raw Windows event logs go in; correlated cases come out —
each with a risk score you can decompose, the cross-domain evidence behind it, a
MITRE ATT&CK attribution that is **retrieved rather than recalled**, and a
response plan held behind analyst approval.

Everything runs on your own GPU. No API keys, no egress, no third party sees the
telemetry.

Measured against 20,200 labelled authentication events: **100% recall on Layer
1, and a base-rate-corrected precision of 0.00084%** — both reported in the
dashboard, side by side, because the second number is the one that decides
whether the first one means anything. See [Measurement](#measurement) and
[Not finished](#not-finished).

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

Two corpora, measured differently, because they answer different questions.

### The labelled corpus — can it find attacks, and at what cost?

`ai-soc-eval/golden_sample.jsonl` is 20,200 authentication events drawn from the
Los Alamos National Laboratory dataset, of which **200 are labelled red-team
activity**. The dashboard's **Accuracy** tab scores both layers against those
labels live, as the run proceeds.

| | |
|---|---|
| Events | 20,200 |
| Labelled malicious | 200 (0.99%) |
| Incidents produced | 223 (**90.6× reduction**) |
| Layer 1 recall | **100%** — 200 caught, 0 missed |
| Layer 1 false alarms | 1,611 |
| Precision *on this sample* | 11.0% |
| Precision *at the real base rate* | **0.00084%** |

That last row is the one that matters, and the tab shows both figures side by
side deliberately. Attacks are over-represented in a curated corpus by roughly
**14,829×** relative to a production network. Sample precision is inflated by
about that factor, so the same rules projected onto a real estate would raise
around **23.9 million** false alarms. Quoting the 11% alone — the number a
vendor slide would carry — is the single most misleading thing this dashboard
could do, so it is never displayed without its correction.

**Recall is the honest win here; precision is the honest problem.** A funnel
that surfaces every attack and buries them in noise is not deployable. Better
discriminating features, not better prompts, are what close that gap.

### The full corpus — what a published technique actually scores

New-edge detection (first-time-seen `user → host` authentication pairs) is the
standard approach for this dataset. `ai-soc-eval/newedge_full.py` runs it over
**all 1,051,430,459 events**, not a sample:

| Feature | Recall | FP rate | Alerts/day |
|---|---|---|---|
| new `user → host` | 28.2% | 0.074% | 13,460 |
| new `source → host` | 36.2% | 0.040% | 7,233 |
| both | 18.2% | 0.028% | 5,070 |

On a 1M-event sample the same feature measured **55.6% recall at 20.9% FP** —
both numbers wrong, in opposite directions. Sampling destroys temporal novelty:
when 99.9% of history is discarded, almost every edge looks new. **Single
features do not reach 90%**; a scored combination is required, and that is
stated rather than papered over.

### The malicious-only corpus — and what it cannot tell you

`data/raw_logs/evtx_data.csv` carries 4,633 attack events from 249 EVTX files,
each labelled with its MITRE tactic. `scripts/benchmark.py` scores against it
and runs twice — retrieval on and off — so the RAG contribution is a measured
number rather than a claim.

> **Limitation, stated on the dashboard as well as here:** every event in that
> corpus is malicious. There is no benign traffic, so a **false-positive rate
> cannot be computed from it**. What is reported is a suppression rate, which
> needs a human spot-check to interpret.

### Comparing models honestly

`scripts/model_ab.py` exists because speed is easy to measure and easy to be
wrong about. Incident ids are derived from `host|user|technique|first_seen`, so
the same corpus yields the same ids under any model — snapshot the verdicts,
change the model, re-run, and compare case by case. It reports agreement and,
separately, the two directions of disagreement: a candidate that downgrades an
`ESCALATE` has closed something real, one that adds an `ESCALATE` has wasted a
morning. Summing them into one accuracy number hides the failure that matters.

Measured on this hardware (one Tesla V100S 32GB, Qwen2.5-14B fp16), replaying
the eleven prompts of a real investigation:

| Configuration | Throughput | Output valid |
|---|---|---|
| 14B fp16, batch 1 | 12.7 tok/s | 11/11 |
| 14B fp16, batch 3 | **17.4 tok/s** (+37%, byte-identical) | 11/11 |
| 14B NF4 4-bit | 10.9 tok/s — *slower* | 11/11 |
| Qwen3-4B fp16 | 25.2 tok/s | **3/11** |

Two results worth keeping. **4-bit quantisation made it slower**: weights drop
from 27.5GB to 9.3GB, but Volta has to dequantise every block back to fp16
before the matmul and that costs more than the bandwidth it saves. And
**Qwen3-4B is disqualified on correctness, not speed** — it is a reasoning model
that spends its budget in `<think>` blocks and fails to emit a parseable action
two times in three. Faster and useless.

vLLM would be the right answer — continuous batching plus prefix caching is
exactly this workload — but its V1 engine requires compute capability 8.0 and
V100 is 7.0.

### Tests

The deterministic layers are the ones that must be provable without a GPU, and
they are where a silent failure would be most dangerous — a scoring bug or a
grounding gate that quietly passes would corrupt every downstream number.

```bash
cd ai-soc-triage && python -m pytest tests/ -q     # 265 tests, ~5s, no GPU
```

What they pin:

| Area | Property under test |
|---|---|
| `test_risk_engine.py` | Reproducibility; no single factor can escalate a case alone; low confidence damps but never erases urgency; factor points sum to the score; graceful degradation when an agent fails |
| `test_correlator.py` | Grouping tightness; stable incident ids so cached triage survives a re-run; **ground-truth labels never reach the model**; evidence stays bounded regardless of input size |
| `test_grounding.py` | A technique cited without retrieval support is flagged; empty retrieval forbids any citation; `extract_json` raises rather than defaulting |
| `test_retrieval.py` | Five real incident shapes land on the right ATT&CK technique; irrelevant queries return **nothing**; every tactic has a playbook |
| `test_evidence_engine.py` | "Checked, found nothing" never looks like "cannot see this domain" |
| `test_incident_retention.py` | A later batch never erases an earlier one; a decided incident survives eviction; a restart re-queues the undecided backlog instead of abandoning it — **and the restore path cannot deadlock** |
| `test_ground_truth_labels.py` | A labelled corpus arrives labelled through both import paths; absent and zero stay distinct, so an unlabelled corpus can never be scored as if it were benign |
| `test_event_time_filter.py` | Every timestamp shape the corpus contains is readable; an unparseable time is excluded from a window rather than guessed; `source` and the time bounds stay inside the filter gate |
| `test_questions.py` | The agent is not offered the ask-a-human tool at all; the environment can restore it |
| `test_funnel.py` | Nothing is silently dropped; the ranking key never saturates; singleton rarity is damped when singletons are normal; SYSTEM and machine accounts are excluded; an external baseline is never polluted by the data being scored |

---

## The dashboard

Nine tabs, each answering one question rather than exposing one subsystem.

| Tab | The question it answers |
|---|---|
| **Live Logs** | What came in? Server-side paging and filtering — the browser never holds the corpus. Every row has a content-derived id (`LOG-AEED61BA21`) that survives a rebuild, so it can be pasted into a ticket. Plain-English search covering hosts, accounts, event ids and **absolute time windows** ("from 01:00 to 02:00"), and it states what it understood before showing results. Timestamps are UTC, because the wall clock of whoever opened the browser is not the timeline a SOC reasons in. |
| **Alerts** | What did Layer 1 make of it? Rule hits, grouped into incidents. |
| **AI Investigation** | What did the agent decide, and why? Every finished case listed with its conclusion in plain words — *Malicious — escalated* / *Not malicious — closed*. Click for the reasoning, the recommended actions, the evidence fields, and confidence. The full tool-by-tool trace is one click further down: the verdict is the answer, the trace is the audit. |
| **Sent by Analyst** | What did the AI make of a log *I* chose? A durable queue with live status; the evaluation stays attached to the log instead of scrolling away in a chat. |
| **Accuracy** | Was any of it right? Both layers scored against corpus labels, with sample precision and base-rate-corrected precision side by side. |
| **Evidence Graph** | What connects to what? |
| **Response** | What should be done, and who may do it? Approval gating is deterministic and never confidence-gated. |
| **Phishing** | Email analysis. |
| **Settings** | Import, clear, configuration. |

### The agent decides

`ask_analyst` — a tool that let the agent park a case and put a question to a
human — is **no longer offered to the model**. It looked like diligence and
behaved like an outage: the incident left the queue, nothing was concluded, and
the backlog grew while the GPU idled. Where evidence genuinely does not settle a
case, the honest output is a low-confidence verdict naming what is missing.
That is still a decision, and an analyst can disagree with it.

The tool is *withheld*, not discouraged. An agent that can see a tool will try
it, and being refused mid-investigation costs a whole model round trip to learn
what the catalogue could have said. `SOC_ALLOW_ASK_HUMAN=1` restores it.

---

## Running it

```bash
cd ai-soc-triage
./soc.sh start      # bring it up and keep it up
./soc.sh status     # what is running, and how many times it has restarted
./soc.sh stop       # the only thing that takes it down
./soc.sh log        # follow the server log
```

The server used to be launched with a bare `nohup … &`. Nothing owned it, so
any death was permanent and silent — an unhandled exception in a worker thread,
the OOM killer taking it while the model was resident, a stray `kill`. The first
sign was a dashboard full of zeros.

`soc.sh start` runs a supervisor that owns the process and restarts it within
three seconds of any exit. `stop` writes a stop-marker *before* killing
anything, so the supervisor cannot respawn what it is about to kill. One
deliberate exception: more than five deaths in five minutes and it gives up,
writing the tail of the server log — a process that dies instantly on every
start is a broken configuration, and restarting it forever would hide the error
while pinning the GPU.

---

## Setup

Python 3.10+, Node 18+, CUDA GPU (24GB+ for the 14B model).

```bash
# Knowledge base (once)
cd ai-soc-triage
curl -sL -o data/kb/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
python scripts/build_kb.py             # --no-embeddings for BM25 only

# Frontend (built once; the API serves it)
cd ../soc-sentinel && npm install && npm run build

# Backend, supervised
cd ../ai-soc-triage
cp .env.example .env                   # LOCAL_MODEL_NAME, HF_HOME
./soc.sh start
```

Everything on `http://localhost:8000` — the API serves the built dashboard, so
there is one port and one process to think about. For frontend development,
`npm run dev` still gives hot reload on `:5173` against the same API.

Load a labelled corpus to see the Accuracy tab work:

```bash
./scripts/ingest_golden.py --golden ../ai-soc-eval/golden_sample.jsonl
```

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
| `GET /events` | The log view — paged and filtered server-side, including `time_from` / `time_to` |
| `GET /sources` | Which files have been imported, and how many events each carried |
| `GET /scorecard/live` | Both layers scored against whatever ground truth the corpus carries |
| `POST /manual-review` | Queue one log for AI evaluation; `GET` lists them with results |
| `POST /enrich/event` | Explain one log line, grounded in retrieved knowledge |
| `POST /reset` | Clear every ingested event, incident, verdict, question and review |

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
  autopilot.py         continuous ingestion and investigation, on separate threads
  manual_review.py     durable queue for logs an analyst sent to the AI by hand
  live_scorecard.py    grades both layers against corpus labels
  api_server.py        FastAPI
scripts/
  soc.sh               supervised start / stop / status
  audit_endtoend.py    walks the whole chain and reports every break at once
  model_ab.py          does a faster model reach the same verdicts?
  ingest_golden.py     load a labelled corpus

soc-sentinel/src/
  context/AnalysisContext.jsx        the bundle every tab reads
  components/agents/                 SOC core, risk breakdown, agent findings,
                                     response approval, telemetry coverage
  components/alerts/AITriageVerdict.jsx   verdict, evidence, clickable sources
  components/pages/BenchmarkReport.jsx    scorecard and limitations
  components/pages/Scorecard.jsx          both layers vs ground truth
  components/pages/ManualReview.jsx       logs an analyst sent to the AI
  components/pages/AIInvestigation.jsx    verdicts first, trace one click down
  components/ResizablePane.jsx            drag-to-resize, remembered per pane
  utils/aiLogSearch.js                    plain-English query → filters
  utils/logParser.js                      browser-side import mapping
```

---

## Not finished

Stated because a demo that hides its edges is worth less than one that names
them. Roughly in the order I would fix them.

**The AI layer is not yet scored.** Layer 1 is defensible — 100% recall against
labelled ground truth. Layer 2 is not, yet: in the runs so far the agent has
correctly closed benign incidents but has not been handed a confirmed attack, so
its precision and recall are *undefined* rather than good or bad. An agent that
has only ever said "no" has demonstrated it can say no. The Accuracy tab
displays `—` for both rather than a flattering zero, and no accuracy claim
should be made for Layer 2 until that changes.

**Precision is not deployable.** 100% recall alongside 23.9 million projected
false alarms is a smoke alarm wired to a fog machine. The recall proves the
pipeline surfaces attacks; the precision says the funnel needs far more
discriminating features before this runs against a live estate.

**No single feature reaches the target.** Measured over the full 1.05B-event
corpus, new-edge detection scores 28.2% recall. Getting past 90% needs a scored
combination of features, and probably scoring per user-day rather than per
event — which is how the published results are computed, and a large part of
why they look better.

**It is slow.** ~85 seconds per investigation, one at a time. Batching three
cases is a measured +37% with byte-identical output and is not yet wired into
the agent loop. A 7B model is untested. Speculative decoding is blocked by VRAM
(27.5GB of a 31.7GB card leaves no room for a draft model) and by Qwen2.5
padding its vocabulary on 7B and up but not on 0.5B, so the two count as
different tokenizers.

**It is a single-node prototype.** Authentication is off by default; there is no
RBAC, no multi-tenancy, no SIEM ingestion, and no exported audit trail. The
supervisor recovers a crashed process but is not a system service and does not
survive the host.

**Graceful shutdown does not.** The API ignores `SIGTERM` and needs the 30-second
`SIGKILL` fallback, most likely a worker thread holding the GPU lock. The stop
works; it just takes half a minute.

**One labelled corpus.** Everything measured here is authentication telemetry.
Process execution, network, and email run through the same pipeline with no
ground truth, so no accuracy is claimed for them. Five of nine telemetry domains
have no connector, and phishing email is not yet linked to the endpoint activity
that follows it.

**The feedback loop is unmeasured.** Analyst agreement is captured and indexed
back as correction examples, but nothing yet demonstrates that accuracy improves
as it accumulates. Until it does, it is a mechanism, not a result.

---

## Things that were broken, and what they cost

Kept because the failure modes are more instructive than the features, and every
one of these looked like something else first.

**Forty threads and a dead dashboard.** `/stream` was a plain `def` returning a
blocking generator. Starlette runs those in the AnyIO worker pool — exactly 40
threads — and that generator never returns, because it waits on a queue. Every
open dashboard tab permanently consumed one worker; after forty of them, every
other synchronous endpoint queued behind connections that would never finish.
`/health` took seven seconds, the page never loaded, and the logs showed nothing
but `200 OK`. It is an async generator now, and 60 simultaneous subscribers cost
8 threads and single-digit milliseconds.

**Verified the link, not the chain.** Bugs were found one at a time, each by a
person hitting the next broken link — the import did not reach the server, the
fields did not match the rules, nothing published when nothing was detected,
ingestion blocked on inference, the tab read the wrong source. Every fix was
verified in isolation and every one left the next link broken.
`scripts/audit_endtoend.py` exists because verifying a link proves nothing about
the chain.

**Two import paths that disagreed.** The command-line script preserved ground
truth; the browser Import button silently dropped it. The same file scored fine
from a terminal and arrived unlabelled from the UI — worse than either being
broken, because whichever one was checked reported success.

**Measured from the wrong side of the wire.** Nothing was compressed. 12.8MB of
JSON per page load, invisible on the machine running the server and fatal over a
tunnel. Every performance measurement taken locally said "fast".

**A restart abandoned the backlog.** Only verdicts were restored, never the
queue, so after any restart the agent sat idle with 222 undecided incidents on
disk. Restarts happen for ordinary reasons, so the backlog evaporated each time.

**Sampling inverted a result.** New-edge recall measured 55.6% on a 1M sample
and 28.2% on the full 1.05B corpus, with the false-positive rate wrong by a
factor of 280 in the other direction. Temporal novelty cannot be sampled.

## License

MIT
