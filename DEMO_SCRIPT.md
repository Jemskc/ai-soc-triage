# SOC Sentinel — Demo Script

Target length: **4-5 minutes**. Audience: a CISO evaluating the engineer, not
buying the product. That changes the emphasis — depth and honest measurement
beat polish, and a stated limitation reads as judgement rather than a gap.

---

## Before you record

```bash
# 1. Backend (loads Qwen2.5-14B in fp16 across 2 GPUs, ~1 min)
cd ai-soc-triage
HF_HOME=/work/aiw642/hf_cache CUDA_VISIBLE_DEVICES=0,1 \
  /work/aiw642/conda_envs/falcon3-7b/bin/python -m uvicorn src.api_server:app \
  --host 0.0.0.0 --port 8000

# 2. Frontend
cd soc-sentinel && npm run dev
```

Checklist:
- [ ] `output/analysis.json` and `output/cases.json` exist and are current
- [ ] `GET /agents` returns the four agents and the risk weights
- [ ] `output/benchmark.json` exists — the Reports tab needs it
- [ ] `output/triage_cache.json` present, so a live re-run returns instantly
- [ ] Model already loaded (hit `/health` once) — never record a cold start
- [ ] Browser at 1440x900, zoom 100%, dark theme
- [ ] **Hand-check 20 verdicts first.** If the model is visibly wrong on a
      meaningful share, change the claim, not the numbers.

---

## Shot list

### 1 — The problem (0:00–0:20)

Open on the Alerts tab, unsorted.

> "A mid-size SOC sees thousands of alerts a week. Tier-1 analysts trudge
> through them one at a time, and the real intrusion is somewhere in there.
> This is a triage engine that does that pass first — running entirely on our
> own GPU, with nothing leaving the building."

### 2 — Ingest and watch it think (0:20–0:55)

Trigger an analysis run. Stay on the progress panel — do not cut away.

> "Real Windows event logs going in — the EVTX-ATTACK-SAMPLES corpus, 4,633
> events across eight MITRE tactics."

Let the stages land on camera: normalize → detect → **correlate** → triage.

> "The correlation step is what makes this work. Running a language model on
> every log line would take about nineteen GPU-hours. Grouping events by host,
> account, technique and time window collapses those thousands of events into
> a couple of dozen incidents — which is also how an analyst actually thinks.
> Nobody triages forty PsExec alerts individually; they triage 'PsExec on PC02'."

**Point at the funnel counters as they update.** That reduction is the
engineering claim.

### 3 — The verdict (0:55–2:15) — *the core of the demo*

Open the top case. Walk the panel top to bottom.

Start with the **Risk Verdict** block:

> "The score at the top isn't the model's opinion — it's deterministic
> arithmetic over what the agents found. Five weighted factors, and you can see
> each one's contribution. Same case, same score, every time. When an analyst
> asks 'why is this a 78?', there's an actual answer rather than a re-run."

> "Note the biggest single contributor isn't the model's urgency call — it's
> cross-domain corroboration. One agent shouting is weak evidence. Three
> independent telemetry domains agreeing is strong evidence. That's what stops
> one confident-but-wrong agent from escalating a case on its own."

Then the agent stack:

> "Escalate, urgency 8 of 10, and here's the part that matters — the evidence.
> It's naming the actual log fields: the process is lsass.exe, the rule that
> fired, the account involved. Not 'this looks suspicious' — this field, this
> value, this is why."

Expand **Grounded in N knowledge sources**.

> "And the ATT&CK attribution is retrieved, not remembered. The model is only
> permitted to cite a technique that came back from the knowledge base — 749
> chunks covering all 697 ATT&CK techniques, Windows and Sysmon event
> semantics, and LOLBAS abuse. If retrieval comes back empty, it has to say
> UNKNOWN. I can click straight through to the technique it used."

If you can find one live, show an incident where it returned `UNKNOWN`:

> "Here it declined to attribute. That's the behaviour I want — an honest
> unknown beats a confident guess an analyst would act on."

Then hit **Agree / Disagree**.

> "The analyst always overrules the model. And disagreements get indexed back
> into the knowledge base as correction examples, retrieved on similar
> incidents later. The system improves as it's used, with no retraining."

### 3b — The agents (2:15–2:50)

Expand the **Agent Findings** section.

> "Four specialists, not one prompt. The Intel Agent runs first and establishes
> what the technique is and what an adversary typically does next. Triage runs
> second, so its judgement rests on a grounded technique instead of a rule name.
> The Risk Engine fuses them. Response runs last, because what you do depends on
> the score."

> "Each one shows its own timing, its own confidence, and what knowledge it
> used. If one fails, you can see which."

Then the **Response Actions** block:

> "The Response Agent proposes; it never executes. Anything that changes
> production state — isolate, disable, reset — is flagged and held behind an
> explicit approval. An agent that can isolate a domain controller on its own
> judgement is a liability, not a feature."

Then **Telemetry Coverage**:

> "And here's what I can and can't see. Four domains connected, five with no
> connector. That matters: 'we found nothing in Cloud' and 'we can't see Cloud'
> are completely different statements, and the tool says which one it means.
> Every unconnected domain caps how much corroboration a verdict can get."

### 4 — One brain, every tab (2:50–3:20)

Click Overview → Investigations → Assets → Playbooks. Move quickly.

> "Same analysis, different questions. Overview gives me the situation report
> and what to touch first. Investigations reconstructs the kill chain in order.
> Assets ranks machines by risk with the reason attached — not by which one was
> noisiest. Playbooks fills in contain, eradicate, recover for that specific
> incident."

> "Each tab declares what it needs from the model in one registry, server-side.
> Adding a tab means adding a contract, not writing another prompt."

### 5 — The scorecard (3:20–4:10) — *what nobody else's demo has*

Reports tab.

> "I scored it against ground truth. Every one of those events carries a
> labelled MITRE tactic, so escalation recall and tactic accuracy are
> measurable, not asserted."

Read the real numbers off the screen. Then the ablation:

> "And I ran it twice — retrieval on, retrieval off, same prompts, same model.
> That delta is the RAG contribution, measured rather than claimed."

**Scroll to Limitations and read one aloud.**

> "One thing I want to be straight about: this corpus is entirely malicious.
> There's no benign traffic in it, so I cannot compute a false-positive rate
> from it, and I'm not going to pretend otherwise. What's reported is a
> suppression rate with a hand-checked sample. Getting a real FP number needs
> a benign baseline, and that's the next thing I'd build."

### 6 — Architecture (4:10–4:40)

> "One 14B model shared by four agents — nine agents must not mean nine copies
> of a model in VRAM. Qwen2.5-14B in fp16 on a V100, and fp16 specifically,
> because Volta has no native bfloat16 and the emulated path measured nine times
> slower. BM25 plus dense retrieval fused with reciprocal rank fusion. Judgement
> from the model, scoring from deterministic code. No API keys, no egress."

> "What I'd build next: a benign baseline for a real false-positive rate,
> linking phishing email to the endpoint activity that follows it as one
> incident, and live SIEM ingestion instead of file import."

---

## Delivery notes

- **Don't apologise for numbers.** "It scored 61% and here's the failure mode"
  is a stronger signal than a demo with no number at all.
- **Let the correlation and grounding beats breathe.** They're the two ideas
  that separate this from a chatbot on a dashboard.
- Say **"I measured"**, **"I don't know yet"**, **"that's an assumption"** —
  those are the phrases a CISO is listening for.
- If something breaks live, say what you'd check. That's the actual job.

## Do not claim

- ❌ A false-positive rate — not computable from this corpus
- ❌ "Replaces Tier-1" — it does the first pass; the analyst decides
- ❌ Hours-saved figures without naming the 8-minutes-per-alert assumption
- ❌ Production readiness — no auth, no multi-tenancy, single-node
