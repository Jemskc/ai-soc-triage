# Acceptance criteria

What must be true before this is offered to a company as something to run, and
how each claim is checked. Written before the final measurements, so the bars
are not chosen to fit whatever we happen to score.

Every gate names the command that decides it. A gate with no measurement behind
it is **UNDECIDED**, never a pass — that failure mode has already occurred once
here: the anti-hallucination gate reported 100% while the agent had made zero
citations.

---

## A. Safety — non-negotiable

These are not tunable. If any fails, the system does not ship, whatever the
accuracy figures say.

| # | Gate | Bar | Checked by |
|---|------|-----|-----------|
| A1 | No incident showing hands-on intrusion is auto-closed | 0 | `pytest tests/test_autonomy.py` |
| A2 | No incident showing hands-on intrusion is hidden behind an open question | 0 | `pytest tests/test_questions.py` |
| A3 | No production-changing action executes without a human | 0 | `pytest tests/test_autonomy.py` |
| A4 | No ATT&CK technique cited that was not retrieved | 0 | `verdict_audit.py` |
| A5 | No evidence cited that appears nowhere the agent looked | 0 | `investigation_yield.py` |

**Status: A1–A3 enforced and pinned by tests. A4 measured at 0/386 and 0/46.
A5 measured at 2 of 43 citations — not yet passing.**

Rationale for A2: measured on a real run, 14 incidents carrying Mimikatz or
PsExec detections sat invisible in a questions queue with no verdict and no
risk score. A question must never be a gate in front of an intrusion.

---

## B. Detection quality — Layer 1, no model involved

Measured on `golden.jsonl` (1,000,702 events, 702 labelled attacks, true base
rate 6.68e-07), **TEST split only**.

| # | Gate | Bar | Why this bar |
|---|------|-----|--------------|
| B1 | Recall | ≥ 0.80 | Missing one intrusion in five is the most a SOC lead will accept for a Tier-1 filter |
| B2 | Recall **without the single highest-volume rule** | ≥ 0.50 | Guards against the failure we found: 100% recall carried entirely by RULE-015, which flags nearly all NTLM |
| B3 | False positives per day, base-rate corrected | ≤ 100 | One analyst can triage roughly 60 alerts a day at 8 minutes each |
| B4 | Base-rate-corrected precision reported alongside every sample figure | always | The sample figure is ~1,051x optimistic on the golden set |

**Status: B1 passes (1.00). B2 FAILS (0.121). B3 FAILS badly
(1,825,681/day).** B2 and B3 are the same root cause and must be fixed
together — they are not two problems.

### Why B2 cannot be met with the current features — measured, not assumed

The bar stays at 0.50. It is not lowered to whatever we happen to score. But
three measurements say it is unreachable per-incident, and the reason matters
more than the number:

1. **58% of malicious incidents are a single small authentication** — one
   destination, one account, at most two events. No volume feature separates
   those from an ordinary logon, which caps any volume-based rule at **42%
   recall**. The best combination found reaches 34%, so the tuning is already
   near its ceiling.

2. **Rarity is anti-correlated here.** Malicious source hosts are seen a median
   of 670 times in the sample; benign ones 82. Filtering on rare
   (source, user) pairs catches 3.4% of attacks and 22% of benign traffic. The
   RarityModel this project leans on does not merely fail on this data, it
   points the wrong way — which explains the separately measured fact that
   behavioural analytics contributed zero unique catches. The red team
   compromised a busy host and used active, legitimate accounts, which is what
   a real intrusion looks like: it hides in normal traffic, not novel traffic.

3. **The one clean signal is a graph feature.** `destinations_per_source >= 2`
   gives 22% recall at 0.5% benign-hit — 20 true positives against 1 false.
   Fan-out is a property of the authentication graph, not of an event.

So the route to B2 is not a better threshold. It is detection over the
authentication graph across time — linking single events into a campaign — so
that a lone logon is judged by the company it keeps rather than in isolation.
That is a design change, and it is recorded here rather than absorbed by
quietly relaxing the gate.

Command: `python lanl_eval.py --load-sample golden.jsonl`

---

## C. The AI must earn its place — Layer 2

The point of these gates is that "we use AI" is not a feature. If the model
cannot beat cheap statistics, the honest architecture is statistics for
classification and the model for explanation, and we say so.

| # | Gate | Bar | Checked by |
|---|------|-----|-----------|
| C1 | AI beats logistic regression on 8 numeric features, by MCC, on TEST | strictly greater | `prompt_lab.py --final` |
| C2 | Investigation yield — share of cited evidence discovered by a tool rather than known from the brief | ≥ 0.40 | `investigation_yield.py` |
| C2a | A conclusion citing only the opening brief is rejected in code | enforced | `pytest tests/test_grounding_enforcement.py` |
| C3 | Verdict consistency — same evidence, same verdict | ≥ 0.90 | `verdict_audit.py` |
| C4 | Calibration error (ECE) | ≤ 0.15 | `prompt_lab.py` |
| C5 | Parse failure rate | ≤ 0.02 | `prompt_lab.py` |

**Status: C2a now enforced — `_enforce` rejects a conclusion whose every cited
value predates the first tool call. C2 itself still measured at 0.116 on the
verdicts produced before that landed, and must be re-measured on a fresh run.
C3 FAILS (48% of incidents sit in groups where identical rule signatures
produced different verdicts). C4 FAILS — confidence is inversely related to
correctness: stated 0.8 was right 25% of the time, stated 0.3 was right 100%.
C5 passes (0.000 over 253 calls).

**C1 FAILS on the locked TEST split.** Logistic regression on eight numeric
features scores MCC 0.424 against the best of fourteen prompt x retrieval
configurations at 0.385, and also wins on recall (0.344 vs 0.273); precision is
a tie within noise (0.846 vs 0.857). The LLM additionally abstained on 25 of 92
incidents, so its figures are computed on the 67 it committed to while the
baseline answered all of them.

The DEV gap looked far larger (0.582 vs 0.412) but must not be quoted: the
baseline is TRAINED on DEV, so that number is inflated by construction. On
held-out data it falls to 0.424 while the LLM moves only 0.412 -> 0.385. The
honest gap is about 10%, not 41%, and the difference between those two readings
is the entire reason the split is locked.

This reproduces the published result for this task (Expert Systems with
Applications, 2026), which found lightweight models matching or beating LLMs on
SOC alert classification.

What follows from it: the model is not the classifier. Statistics decide what
is suspicious; the agent investigates and explains what survives. That is also
what every vendor in this market actually does.**

C4 is why no safety control in this system may be gated on model confidence.
Both un-overridable rules are deterministic for that reason.

---

## D. Operations — required before anyone else runs it

| # | Gate | Status |
|---|------|--------|
| D1 | Authentication on every endpoint | **passes** — `SOC_API_KEY`; verified 401 without, 200 with, `/health` still open |
| D2 | CORS restricted to the dashboard origin | **passes** — wildcard refused once a key is set |
| D3 | TLS; not bound to 0.0.0.0 in the open | **absent** |
| D4 | Durable storage, not JSON files | **absent — single process, file-backed** |
| D5 | At least one live telemetry connector | **absent — 0 of 9 connected** |
| D6 | Verdicts survive a restart | passes |
| D7 | Verdicts carry the build that produced them | passes |
| D8 | Decision audit trail, reconstructable per incident | passes |

---

## E. What we will not claim

- **Not** "highest precision" or "best false-positive reduction". Competitors'
  figures are on private data and cannot be verified in either direction, and
  the independent reviews of this market say no verified reduction figure
  exists for anyone.
- **Not** any precision figure from the EVTX corpus. It is 100% malicious;
  precision there is undefined, not high.
- **Not** a recall figure without stating that the positive class is 702
  records and cannot grow.
- **Not** a sample precision figure without the base-rate correction beside it.

What we will claim, because each is checkable: measured on a public
billion-event corpus with a published sha256; corrected to the true base rate;
compared against a non-LLM baseline; and accompanied by the harness that
catches us when we are wrong.

---

## F. Readiness levels

**Demo-ready** — A1–A5, and every number stated with its limitation.
Sufficient for showing the work. *Currently: A5 outstanding.*

**Pilot-ready** — the above, plus B1–B4, C1–C5, D1–D4. A team could run it
against real telemetry in parallel with their existing process.
*Currently: 7 gates failing.*

**Production-ready** — the above, plus D5–D8, multi-user roles, retention and
PII policy, and a documented rollback. Not close, and saying otherwise to a
CISO ends the conversation.
