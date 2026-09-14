# SOC Sentinel — video script

Three parts. **Part 1** is the introduction and tab tour. **Part 2** is where you
stop reading and drive the import live. **Part 3** is the closing, where you say
what is not finished.

Stage directions are in `[brackets]`. Everything else is spoken.

Every number in this script was measured on the running system. If a number on
screen differs from the one here, **say the number on screen** — the whole
argument of Part 3 is that you report what you find.

---

## PART 1 — Introduction (≈3 minutes)

`[Dashboard open on Live Logs, corpus already cleared. Do not import yet.]`

Hi. I'm Jems. This is SOC Sentinel — an agentic AI platform for security
operations triage.

The problem it addresses is the one every SOC has: far more alerts arrive than
anyone can look at, so alerts get closed unread, and the one that mattered gets
closed with them. The usual answer is to write better rules. Better rules raise
fewer alerts, but they also raise fewer true ones, and you find out which
afterwards.

My approach is two layers, and the split between them is the whole design.

**Layer one is deterministic.** Detection rules and behavioural analytics run
over every single event. Fifteen rules, plus sliding-window analytics for things
like a user touching an unusual number of hosts. No model involved. It is fast,
it is auditable, and it is the same answer every time you run it.

**Layer two is an agent.** It takes only what layer one surfaced, and it
investigates — it calls tools, reads the results, decides what to check next,
and writes a verdict with its reasoning attached.

The reason for the split is arithmetic. Twenty thousand events through a
fourteen-billion-parameter model, at eighty-five seconds each, is nineteen days
of GPU time. The funnel takes twenty thousand events down to a couple of hundred
incidents — a ninety-fold reduction — and that is what makes reasoning
affordable at all.

Everything runs locally. Qwen 2.5 14B on a single Tesla V100. Nothing leaves the
machine, no API keys, no vendor. For anyone who cannot send logs to a third
party, that is not a nice-to-have.

Let me walk the tabs, because each one answers a different question.

`[Click Live Logs]`

**Live Logs** is every record that came in. Twenty thousand rows, but the
browser never holds them — the server filters and pages, because a real estate
produces more logs in a day than a browser can hold. Each row has a stable ID
derived from its content, so you can paste `LOG-AEED61BA21` into a ticket and it
still resolves next week. Timestamps are UTC, deliberately — the wall clock of
whoever opened the browser is not the timeline a SOC reasons in.

The search box takes plain English. You can ask for a host, an account, an event
ID, or a time window — "from this time to this time" — and it tells you what it
understood before it shows you results, so you are never guessing whether the
filter ran.

`[Click into one row, briefly]`

Open any record and you get the raw log line first, then the platform's
interpretation of it. That order is on purpose. An analyst checking the AI's
work needs the original, not my summary of it.

`[Click Alerts]`

**Alerts** is what layer one made of those logs — which events matched a rule,
and how they were grouped into incidents. Grouping is by host, account,
technique and time window. Deterministic, no model.

`[Click AI Investigation]`

**AI Investigation** is the agent's own work. Every finished case is listed with
its conclusion in plain words — *malicious, escalated* or *not malicious,
closed*. Click one and you get why it decided that, what it recommends you do,
the specific evidence fields it relied on, and how confident it is.

Underneath that there's a collapsed section: *how I got there*. Every tool call,
in order, with the reasoning before each one. It's collapsed because the verdict
is the answer and the trace is the audit — but it is always there, because a
verdict nobody can check is worth nothing.

One design decision I want to call out. Early on, the agent could park a case
and ask a human a question. I removed that. It looks like diligence and behaves
like an outage — the case leaves the queue, nothing is concluded, and the
backlog grows. If the evidence doesn't settle it, the honest output is a
low-confidence verdict that names what's missing. That is still a decision, and
you can disagree with it.

`[Click Sent by Analyst]`

**Sent by Analyst** is the reverse direction. Any log you send from Live Logs
comes here, gets its own AI evaluation, and the result stays attached to the
log. This is the human asking the machine, rather than the machine asking the
human.

`[Click Accuracy]`

**Accuracy** is the tab I'd look at first if I were you, and it's the one most
demos don't have. Every other tab reports what happened. This one reports
whether it was right, against labelled ground truth.

`[Click Evidence Graph, then Response, briefly]`

**Evidence Graph** shows the entities an incident connects — which accounts and
hosts, and how. **Response** is the action side, with approval gating: high-risk
actions require a human, and that gate is deterministic. It is never decided by
model confidence.

One more thing that matters more than any tab. Every ATT&CK technique the AI
cites is checked against what it actually retrieved. There's a knowledge base of
about seven hundred and fifty chunks — the full ATT&CK enterprise matrix,
Windows event ID references, LOLBAS entries, and my own detection rules. If the
model names a technique it never looked up, the interface says so and marks the
attribution unverified. Models are confident when they are wrong; this is the
part that catches it.

`[Pause]`

That's the tour. Let me load real data.

---

## PART 2 — The demo (you drive; not scripted)

`[Import golden_sample.jsonl and narrate what happens.]`

Suggested beats, in the order the system will actually produce them:

1. **Import** — 20,200 events from the Los Alamos National Laboratory
   authentication dataset. Real enterprise telemetry, 200 of the records are
   labelled red-team activity.
2. **Live Logs fills first**, then Alerts. Both are deterministic and land in
   seconds.
3. **The AI starts investigating** while ingestion is still finishing — point
   this out, it's the concurrency working.
4. **A verdict lands.** Open it. Read the reasoning aloud. Show the collapsed
   trace.
5. **Accuracy tab** — the numbers below.

**Say only what is on screen.** At the time of writing, the current run shows:

| | |
|---|---|
| Events | 20,200 |
| Labelled malicious | 200 (0.99%) |
| Incidents | 223 (90.6× reduction) |
| Layer 1 recall | **100%** — 200 of 200 caught, 0 missed |
| Layer 1 false alarms | 1,611 |
| Precision on this sample | 11.0% |
| Precision at the real base rate | **0.0008%** |

When you reach that last row, stop and explain it, because it is the most
important sentence in the video:

> Attacks are over-represented in this corpus by about fifteen thousand times
> compared to a real network. So the eleven percent precision figure — the one
> a vendor would put on a slide — is inflated by roughly that factor. Corrected
> to a real base rate, these rules would raise around twenty-four million false
> alarms across an estate that size. I built the tab to show both numbers
> because showing only the first one would be the most misleading thing this
> dashboard could do.

That paragraph is the strongest thing in the demo. A CISO has been shown the
flattering number by every vendor who has ever walked in. Being the person who
volunteers the unflattering one is the differentiator.

---

## PART 3 — Closing: what is not finished (≈2 minutes)

`[Back to the Accuracy tab, or straight to camera.]`

I want to end with what this is not, because I would rather you hear it from me
than find it yourself.

**One. The AI layer is not yet scored.** Layer one I can defend — a hundred
percent recall against labelled ground truth. Layer two I cannot, yet. In the
runs so far the agent has correctly closed benign incidents, but it has not yet
been handed a confirmed attack, so its precision and recall are genuinely
undefined. Not good, not bad — undefined. An agent that has only ever said "no"
has shown it can say no. That is the next measurement, and until it exists I
won't claim a number.

**Two. Precision is not deployable as it stands.** A hundred percent recall with
twenty-four million projected false alarms is not a product, it is a smoke
alarm wired to a fog machine. The recall proves the pipeline surfaces attacks.
The precision says the funnel needs far more discriminating features before this
runs against a live estate.

**Three. I measured the published technique and it fell short.** I ran new-edge
detection — first-time-seen authentication pairs, the standard approach for this
dataset — over the full one-point-oh-five billion event corpus. Twenty-eight
percent recall at a false-positive rate under a tenth of a percent. On a small
sample it looked like fifty-five percent, and that was an artifact of sampling.
Single features do not get you to ninety. It needs a scored combination, and
that is my next piece of work.

**Four. It is slow.** Eighty-five seconds per investigation, one at a time.
I benchmarked the options: running three cases at once gives thirty-seven
percent more throughput with byte-identical output. Four-bit quantisation was
actually slower on this GPU. vLLM would be the right answer and it has dropped
support for this hardware generation. So: a real path to improvement, measured,
not yet implemented.

**Five. It is a single-node prototype, not production infrastructure.**
Authentication is off by default. There is no role-based access control, no
multi-tenancy, no SIEM integration, and no exported audit trail. The process
supervisor recovers from a crash, but it is not a system service and it does not
survive the host. Those are known, scoped, and none of them are research
problems.

**Six. One labelled corpus.** Everything measured here is authentication
telemetry. Process execution, network, and email are wired through the same
pipeline but I have no labelled ground truth for them, so I am not going to
quote accuracy on them.

`[Beat]`

What I think this demonstrates is not a finished product. It is that I can build
a two-layer AI system end to end, measure it honestly against ground truth,
and tell the difference between a number that means something and a number that
flatters me. The things on that list are the things I am working on next.

Thanks for watching.

---

## Before you record — checklist

- [ ] `./soc.sh status` shows supervisor and api running, `model_loaded=True`
- [ ] Corpus cleared, so the import is live on camera
- [ ] Hard-refresh the browser once (Ctrl+Shift+R)
- [ ] Accuracy tab loads and says `ground_truth: true`
- [ ] Do a silent dry run of Part 2 first — the import timing is the only
      unscripted part
- [ ] Close the terminal, or make sure nothing on screen shows a stack trace

## Do not say on camera

- Any Layer 2 accuracy figure — it is undefined until the agent sees an attack
- "Production ready", "enterprise grade", or a false-positive rate for the
  process/network/email paths
- The 11% precision figure without the corrected one in the same breath
