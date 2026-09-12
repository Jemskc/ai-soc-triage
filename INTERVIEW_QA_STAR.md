# SOC Sentinel — Interview Q&A (STAR Method)
### Cyber + AI Engineering Interview Prep

---

> **How to use this doc:**
> Each answer is structured as **S**ituation → **T**ask → **A**ction → **R**esult.
> Read each block out loud 2–3 times. The goal is to internalize the story, not memorize it word-for-word.
> Sections: Architecture | AI/LLM Engineering | Security Domain | Problem Solving | Design Decisions | Behavioral

---

## SECTION 1 — ARCHITECTURE & SYSTEM DESIGN

---

### Q1. Walk me through the architecture of this system.

**Situation:**
Security Operations Center analysts were spending 80% of their time manually correlating Windows Event Logs, reading through thousands of raw events to find threats — with no AI assistance and no unified interface.

**Task:**
Design and build a full-stack AI-powered SOC dashboard that could ingest raw Windows logs, automatically detect threats, and let analysts ask natural language questions about alerts and incidents — all running on-premise with no data leaving the network.

**Action:**
I built a two-tier system. The backend (`ai-soc-triage`) is Python-based: it uses `python-evtx` to parse binary Windows Event Log files, normalizes them into a structured DataFrame, then passes events through a YAML-defined rule engine that produces alerts mapped to MITRE ATT&CK techniques. Those alerts are then enriched by a local LLM (Qwen2.5-14B) via a FastAPI server. The frontend (`soc-sentinel`) is React 18 with Vite — it handles client-side log parsing, real-time AI chat via Server-Sent Events streaming, and multiple analysis views: Overview, Alerts, Logs Explorer, Email Analysis, Investigations, and Threat Hunting.

The data flow is:
```
EVTX File → Ingestor → Normalized Events
                              ↓
                        Rule Engine → Alerts (MITRE-tagged)
                              ↓
                        LLM Enrichment → AI Triage Analysis
                              ↓
                        FastAPI ← React Frontend ← Analyst
```

**Result:**
A working end-to-end system where an analyst can drop an EVTX file, get categorized alerts with severity scores within seconds, and ask follow-up questions in natural language — with all inference happening locally on GPU. The system detected 10 distinct attack patterns across brute force, credential dumping, lateral movement, and persistence categories.

---

### Q2. Why did you choose a local LLM instead of using the OpenAI or Claude API?

**Situation:**
During design, I had to decide whether to call a cloud API like OpenAI or run a model locally. For a general app, cloud APIs are the obvious choice. But this is a security tool.

**Task:**
Choose the right inference approach given the data sensitivity and operational requirements of a SOC environment.

**Action:**
I evaluated three factors. First, **data sensitivity** — SOC logs contain internal IP addresses, usernames, hostnames, and infrastructure details. Sending that to an external API means confidential security telemetry leaves the network, which is a compliance and security risk. Second, **cost at scale** — SOC analysts run hundreds of queries per shift. Per-token cloud API costs would be prohibitive at that volume. Third, **latency and reliability** — a SOC tool can't depend on external internet connectivity during an active incident. I selected Qwen2.5-14B-Instruct running on local GPU via HuggingFace `transformers`, using `bfloat16` precision to fit within 24GB VRAM while maintaining accuracy. The FastAPI server loads the model at startup and keeps it warm in memory.

**Result:**
Zero data egress, zero per-query cost, and inference latency of ~2–4 seconds for structured analysis tasks. The model is less capable than GPT-4 in general, but for narrow, structured tasks like IOC extraction and MITRE mapping with a well-engineered prompt, it performs well. I documented this trade-off explicitly in the architecture.

---

### Q3. How does the AI assistant know what is on the dashboard without the user having to explain it?

**Situation:**
The AI chat panel needed to behave like a knowledgeable colleague who could see the same data the analyst was looking at — not a generic chatbot that knew nothing about the current incident.

**Task:**
Inject real-time dashboard state into the AI context without flooding the conversation with raw data, and without hardcoding anything about the UI structure.

**Action:**
I built a `buildDashboardContext()` function that runs on every message send. It reads the current React state — which tab is active, how many events are loaded, what the critical/high/medium/low breakdown is, which rules have fired the most, which source IPs have the most activity, which users are most targeted — and compresses it into a compact text summary that is injected into the system prompt. The system prompt instructs the model to only reference this dashboard data when the user asks about the dashboard, alerts, or logs — so it behaves like ChatGPT for general security questions and like a contextual analyst for incident-specific questions. Critically, I derived the tab list from `navConfig.js` automatically, so if a new tab is ever added, the AI context updates with zero manual changes.

**Result:**
An analyst can switch to the Alerts tab, click on a brute-force alert, and ask "Why is this critical?" — and the model responds with context about that specific rule, the attacker IP, the targeted user, and the severity, without the analyst typing any of that. The DRY design means the AI panel and the sidebar never go out of sync.

---

## SECTION 2 — AI / LLM ENGINEERING

---

### Q4. What optimizations did you apply to make local LLM inference faster?

**Situation:**
Running a 14-billion parameter model locally means every latency optimization matters. The first time I loaded the model unoptimized, structured analysis responses were taking 15–20 seconds — too slow for an interactive tool.

**Task:**
Reduce inference latency to under 5 seconds for structured tasks without sacrificing output quality.

**Action:**
I applied four key optimizations. First, **`torch.inference_mode()`** instead of `torch.no_grad()` — inference mode additionally disables version tracking and view tracking in autograd, which is faster since we never backpropagate. Second, **deterministic decoding** (`do_sample=False`, greedy decoding) — sampling adds overhead and introduces non-determinism; for structured JSON outputs like alert triage, I want the same answer every time. Third, **per-action token budgets** — instead of one large `max_new_tokens` for everything, I defined tight budgets per action type: `explain: 300`, `investigate: 450`, `chat: 650`, `email_draft: 280`. This prevents the model from rambling and stops generation early. Fourth, **bfloat16 precision** — this matches the native tensor core format on modern NVIDIA GPUs (A100, 3090, etc.), giving full GPU throughput without the numerical instability of float16.

**Result:**
Structured triage responses dropped to 3–6 seconds. Streaming chat feels near-instant because the first token arrives in about 1 second. The token budget design also improved output quality — the model stays focused instead of padding answers.

---

### Q5. How did you implement streaming responses, and why does it matter for UX?

**Situation:**
Without streaming, the AI chat would show a loading spinner for 10–15 seconds and then dump the full response — which feels slow and unresponsive. Analysts would think the system was broken.

**Task:**
Implement end-to-end token streaming from the GPU inference layer through the API to the browser, with a clean typing-cursor UI effect.

**Action:**
I built a three-layer streaming pipeline. In the backend, I use HuggingFace's `TextIteratorStreamer` — it runs `model.generate()` in a **daemon thread** and yields tokens to the main thread via a queue. The FastAPI endpoint wraps this in a `StreamingResponse` with `media_type="text/event-stream"`, formatting each token as `data: "token"\n\n` (SSE protocol) and terminating with `data: [DONE]\n\n`. On the frontend, I deliberately used `fetch()` with `response.body.getReader()` instead of the native `EventSource` API — EventSource doesn't support POST requests with JSON bodies, which I need to send context. The React component updates state per token using the functional `setMessages(prev => ...)` form to avoid stale closure bugs. While streaming, a blinking cursor span (`animate-pulse`) is attached to the last message bubble and removed on `[DONE]`.

**Result:**
The first word appears in the UI within ~1 second of sending a message. The experience feels like ChatGPT — progressive text building — which is dramatically better than a loading spinner. Analysts trust the system more because they can see it working.

---

### Q6. Tell me about the hardest bug you debugged in this project.

**Situation:**
I integrated Qwen3 as a model option (newer than Qwen2.5). After switching to it, every response was unexpectedly long — 3–4× more tokens than Qwen2.5 — and responses started with strange internal reasoning text like "Let me think about this step by step..." before the actual answer. This was wasting GPU time and breaking structured JSON outputs.

**Task:**
Understand why Qwen3 behaved differently, and suppress the thinking mode to get clean, fast, structured outputs.

**Action:**
The root cause was that Qwen3 has a built-in Chain-of-Thought "thinking mode" enabled by default — it generates 100–400 internal reasoning tokens inside `<think>...</think>` tags before its final answer. I discovered this by logging raw model output before any post-processing. I then built a three-layer suppression strategy. **Layer 1:** Try `enable_thinking=False` in the chat template call (requires `transformers >= 4.51`). **Layer 2:** If that raises `TypeError` (older transformers), inject `/no_think` into the last user message — but this must go in the user turn, not the system prompt, or it's silently ignored. **Layer 3:** Post-process the output with a regex strip of any `<think>.*?</think>` blocks as a safety net. For streaming, I couldn't use regex on the full output — I had to implement a **state machine** that reads the stream token by token, tracks whether we're inside a `<think>` block, buffers 7 characters to handle cases where the tag is split across two tokens, and only yields clean text. There was also a model-detection ordering bug: my pattern matching checked `"qwen"` before `"qwen3"`, so Qwen3 was being misidentified as the older Qwen family and getting the wrong chat template. Fixing the check order resolved the template mismatch.

**Result:**
Qwen3 responses dropped from 400+ tokens to under 150 tokens for structured tasks. The state machine streaming stripper worked correctly even when `</think>` arrived split as `</th` + `ink>`. Structured JSON output was clean and parseable again. This bug taught me that model-specific quirks require defensive, layered handling — you can't assume a single fix covers all edge cases.

---

### Q7. How does your LLM handle cases where the output is not valid JSON?

**Situation:**
The AI triage flow requires the model to return a JSON object with exactly 8 fields — severity, summary, false-positive likelihood, recommended actions, MITRE technique, urgency score, and investigation steps. But LLMs don't always produce clean JSON, especially under time pressure or with complex inputs.

**Task:**
Make JSON parsing resilient so one bad LLM response doesn't crash the entire triage pipeline.

**Action:**
I implemented a two-level fallback. The primary parse attempts `json.loads()` on the raw response. If that fails, `_safe_json_parse()` uses a regex to find the first `{...}` block in the output — this handles cases where the model wraps JSON in a markdown fence like \`\`\`json ... \`\`\` or adds a sentence before the JSON object. After extracting the JSON, I run a normalization pass: ensure all 8 required fields are present, coerce values to correct types (e.g., `urgency_score` to int), and fill missing fields with sensible defaults. If both JSON strategies fail, I return a deterministic fallback response built from the rule's known severity and metadata — so the alert still appears in the UI with partial AI analysis rather than an error.

**Result:**
The triage pipeline processed all test alerts without a single crash, even when the model occasionally added preamble text or omitted a field. The deterministic fallback meant analysts always saw a response, and I logged which alerts used fallbacks so I could improve the prompt for those edge cases.

---

## SECTION 3 — SECURITY DOMAIN

---

### Q8. Explain how your detection engine works and how you mapped detections to MITRE ATT&CK.

**Situation:**
Raw Windows Event Log events are just timestamped entries with event IDs and parameters. Security analysts need these translated into meaningful alerts with threat context — what technique was used, how severe it is, what to do next.

**Task:**
Build a detection layer that is both flexible (easy to add new rules) and semantically rich (connected to industry-standard threat frameworks).

**Action:**
I designed a YAML-based rule engine with two detection types. **Pattern rules** evaluate field-level conditions using operators like `equals`, `contains`, `regex`, `in`, and `outside_business_hours` — all conditions are AND-logic. For example, Rule-003 detects suspicious PowerShell by matching `command_line` against a regex covering `-EncodedCommand`, `IEX`, `Invoke-Expression`, `DownloadString`, and similar patterns. **Threshold rules** use a sliding window algorithm to detect volume-based attacks: for brute-force (Rule-001), I sort failed login events (Event ID 4625) by timestamp, group by source IP, and use two pointers to find windows where more than 5 failures occur within 60 seconds. Each rule definition includes a `mitre_technique` field (e.g., `T1110 - Brute Force`) and a severity. The `create_alert` function packages the matching event with the rule metadata, a UUID alert ID, and the MITRE mapping into a standardized dict. I covered 10 rules total: brute force (T1110), credential dumping via Mimikatz (T1003), encoded PowerShell (T1059.001), new admin accounts (T1136), scheduled tasks (T1053), PsExec lateral movement (T1021), known malware processes (T1059), high-risk port connections (T1071), registry run key modifications (T1547), and shadow copy deletion (T1490).

**Result:**
The engine fires correctly on the EVTX attack sample dataset (sourced from the public `EVTX-ATTACK-SAMPLES` repository). The MITRE tags are surfaced in the UI as clickable links to the official ATT&CK website, giving analysts immediate access to technique documentation without leaving the dashboard.

---

### Q9. How does the email phishing analysis module work?

**Situation:**
Phishing is one of the top initial access vectors, but analyzing a suspicious email requires checking multiple signals simultaneously: authentication headers, URL reputation, reply-to mismatches, attachment risk, and sender spoofing. Analysts were doing this manually.

**Task:**
Build an automated email analysis tool that computes a risk score, surfaces all signals in a structured way, and lets the AI assistant provide verdict reasoning.

**Action:**
The `EmailAnalysis` React component accepts a raw `.eml` file or pasted headers and parses it client-side. I built a risk scoring algorithm that weights different signals: SPF failure adds 30 points, DKIM failure adds 20 points, DMARC failure adds 15 points, each suspicious URL adds 10 points (capped at 30), a Reply-To mismatch adds 20 points, and each attachment adds 5 points (capped at 20). The score drives a risk tier (Low/Medium/High/Critical). The UI presents a 7-tab interface: Overview shows the score breakdown, Headers shows SPF/DKIM/DMARC parsed results, Body renders the text/HTML safely, URLs shows external links with classification, Attachments shows risk indicators, IOCs shows extracted indicators, and AI Assessment sends the full email object to `/email-analyze` which prompts the LLM with action types: `email_explain` for phishing verdict, `email_iocs` for indicator extraction, `email_headers` for authentication deep-dive, and `email_draft` for generating a professional analyst note.

**Result:**
An analyst can upload a suspicious `.eml` file and in under 10 seconds have a structured risk breakdown, an AI-generated phishing verdict with the attack technique named, a list of extracted IOCs, and a ready-to-paste analyst note for their ticketing system.

---

### Q10. Explain the log search functionality and why you chose not to use the LLM for it.

**Situation:**
Analysts need to search thousands of log events quickly. The obvious approach — send every search query to the LLM and have it find matching events — would add 3–5 seconds of latency to every search and put GPU load on an interactive lookup.

**Task:**
Build fast, intelligent log search that handles natural language queries without requiring LLM inference.

**Action:**
I built a two-phase hybrid parser that runs entirely client-side. Phase 1 is a structured parser: it normalizes multi-word field aliases first (`src ip → sourceIP`, `event type → rule`) because multi-word aliases must be resolved before single-word pattern matching or they get partially consumed. Then it applies regex to extract `field:value`, `field = value`, and `field == value` patterns, including quoted strings. Phase 2 is an NLP parser that handles content not captured by Phase 1: it detects IP addresses via regex, matches usernames and hostnames against the actual loaded dataset (so it knows what's real), maps severity keywords (`critical`, `warning`), translates event patterns (`failed login → message contains "fail"`), and resolves natural language time references (`last hour`, `this morning`, `yesterday`). The two phases merge with structured filters taking priority over NLP results. All filtering is done in-memory against the loaded React state, so results appear instantly.

**Result:**
A query like `"src ip = 10.0.0.1 failed logins last hour"` is parsed to two structured filters and a time range in under 5 milliseconds, with zero server calls. The LLM is reserved for the AI panel where analysts need analysis and explanation, not filtering. This separation keeps the search UX snappy and the AI assistant focused.

---

## SECTION 4 — DESIGN DECISIONS & TRADE-OFFS

---

### Q11. Tell me about a design decision you made that you're proud of and why.

**Situation:**
As the dashboard grew, the navigation tab list appeared in two places: the sidebar (for rendering) and the AI context builder (for telling the model which tabs exist). Every time I added a tab, I had to update both places — and once I forgot, causing the AI to describe a tab that didn't exist in the UI.

**Task:**
Eliminate the duplication without over-engineering the solution.

**Action:**
I created `navConfig.js` as a single export — an array of tab objects each with `id`, `icon`, and `label`. The sidebar imports this array and renders it directly. The AI context builder also imports it and derives the tab label string by mapping over the same array. I added a `NAV_LABELS` lookup object exported from the same file so any component can resolve a tab ID to a human-readable name without re-doing the map.

**Result:**
Adding a new tab is now a one-line change in `navConfig.js`. The sidebar, the AI system prompt, and any future component that references tabs all update automatically. This is a small decision but it demonstrates the DRY principle applied to the boundary between UI and AI context — a place most developers wouldn't think to look.

---

### Q12. What would you do differently if you were building this for a production enterprise environment?

**Situation:**
The current system is designed as a working prototype and portfolio project — it demonstrates the architecture but makes concessions for simplicity.

**Task:**
Think critically about what gaps exist before this would be production-ready.

**Action:**
Four main areas. First, **async inference** — the current FastAPI endpoint blocks on model inference. In production I would use a task queue (Celery + Redis) so multiple analysts can submit requests concurrently without one blocking another. Second, **model serving** — I'd replace the raw HuggingFace `transformers` inference with `vLLM`, which implements PagedAttention for 5–10× throughput improvement and handles concurrent requests natively. Third, **authentication and RBAC** — right now there's no auth. A real SOC tool needs identity-aware access, with tier-based permissions (analyst vs. lead vs. admin) because not everyone should see all alerts or be able to trigger AI enrichment. Fourth, **alert persistence and case management** — today alerts exist only for the duration of a session. A production system needs a database (PostgreSQL) with alert lifecycle tracking, analyst assignment, comment threads, and integration with ticketing systems like JIRA or ServiceNow via webhooks.

**Result:**
These four changes would transform the current 1-analyst prototype into a multi-tenant, multi-analyst platform. I'd also add a feedback loop where analysts can mark AI triage as correct/incorrect, feeding a fine-tuning dataset to improve the model over time for the organization's specific environment.

---

## SECTION 5 — BEHAVIORAL / COLLABORATION

---

### Q13. Describe a time you had to balance speed of delivery with code quality.

**Situation:**
While building the streaming chat feature, I had two implementation options. The quick path was to buffer the entire LLM response and return it as a single JSON response — 30 minutes of work. The right path was to implement true SSE streaming with a state machine for think-tag stripping — 2–3 days of work.

**Task:**
Decide which to ship first and why, and then follow through on the decision.

**Action:**
I shipped the buffered version first as a working baseline — it proved the full pipeline worked end-to-end and let me test prompt quality without being blocked on streaming. I documented the limitation clearly (a `TODO: implement streaming` comment with the reasoning). Once the core prompt logic was validated, I implemented the full streaming pipeline: `TextIteratorStreamer`, daemon thread, SSE format, think-tag state machine, and the React SSE reader. I wrote the streaming version by first getting non-streaming state correct, then layering streaming on top — which meant the state machine was isolated and testable independently.

**Result:**
The buffered version took 30 minutes and validated the pipeline. The streaming version took 2 days and delivered the ChatGPT-like UX. The sequence mattered — if I'd started with streaming before the prompt was right, I would have been debugging the prompt through a stream, which is significantly harder. Shipping in phases also meant the system was never broken — it was always functional, just improving.

---

### Q14. How did you approach learning the security domain knowledge needed for this project?

**Situation:**
I have a strong software engineering background but came into this project without deep SOC analyst knowledge. I needed to understand Windows event IDs, MITRE ATT&CK techniques, phishing header analysis, and what makes a triage decision "good enough to act on."

**Task:**
Build sufficient domain knowledge to make defensible engineering decisions — what to detect, how to prioritize severity, what an analyst actually needs.

**Action:**
I took a structured approach. I studied the MITRE ATT&CK framework directly — read the technique pages for each of the 10 rules I wrote, so I understood what real-world attacker behavior each one maps to. I used the `EVTX-ATTACK-SAMPLES` public dataset to get real Windows logs from actual attack scenarios, then traced each event manually before writing the detection rule for it — so the rule reflected the real signal, not my assumption about it. For phishing, I read through RFC 7208 (SPF), RFC 6376 (DKIM), and RFC 7489 (DMARC) at a high level to understand what the authentication failures actually mean. I also read SOC analyst job descriptions and interview prep material to understand how analysts prioritize — which helped me design the urgency score (1–10) and the false-positive likelihood field in the AI triage output.

**Result:**
The detection rules and AI prompt structure reflect real analyst workflows. The MITRE mappings are accurate, the severity assignments are defensible, and the AI output fields match what an analyst would write in an incident report. Interviewers with SOC backgrounds have told me the system "thinks like an analyst."

---

### Q15. Tell me about a time you made a technical decision that turned out to be wrong, and how you fixed it.

**Situation:**
Early in the project, the log search feature included an AI explanation banner — every time a user searched, the system sent the query to the LLM and displayed a natural language explanation of what the search was doing.

**Task:**
Decide whether to keep or remove the feature once I saw how it worked in practice.

**Action:**
After testing, I realized the explanation banner violated the single responsibility principle and created a bad UX loop: the user typed a search, waited 3–5 seconds for the LLM explanation, and then the results appeared — but the explanation rarely added useful information ("You searched for failed logins from 10.0.0.1"). It was LLM usage for its own sake. I removed the feature entirely. The search results speak for themselves — if an analyst wants an explanation, they can ask the AI panel. I also noted in the code that this was a deliberate removal, not an oversight.

**Result:**
Search became instant (client-side filtering, ~5ms). The AI panel remained the single place for LLM interaction. The system felt more coherent — tools do one thing well. This was a good reminder that AI features need to provide genuine value, not just demonstrate that AI is involved.

---

## SECTION 6 — QUICK-FIRE TECHNICAL DEPTH

> These are sharp one-to-two paragraph answers for rapid-fire technical questions.

---

### Q16. What is `bfloat16` and why did you use it?

**Situation/Task:** Choose the right floating-point precision for GPU inference.

**Action/Result:** `bfloat16` (Brain Float 16) has the same 8-bit exponent as `float32` but only 7 mantissa bits instead of 23. This gives it the same numerical range as full 32-bit float — it can represent very large and very small values without overflow/underflow — while using half the memory. `float16` has a narrower exponent range and is prone to overflow during inference. Modern NVIDIA GPUs (Ampere, Ada Lovelace) have tensor cores optimized for `bfloat16`, so it runs at native hardware speed with no accuracy loss for inference. This is why HuggingFace recommends `torch_dtype=torch.bfloat16` for transformer models.

---

### Q17. What is `device_map="auto"` and what does it do?

**Situation/Task:** Load a 14B parameter model that may not fit entirely on one GPU.

**Action/Result:** `device_map="auto"` activates HuggingFace `accelerate`'s automatic model sharding. It reads the model architecture, estimates layer memory requirements, and distributes layers across available GPUs — and falls back to CPU RAM if GPU VRAM is exhausted. For a 14B model in bfloat16 (≈28GB), if you have a single 24GB GPU, it places as many layers as fit on GPU and spills the rest to CPU, handling the cross-device tensor transfers transparently. This is essential for running large models without manually calculating layer assignments.

---

### Q18. What is Server-Sent Events (SSE) and how does it differ from WebSockets?

**Situation/Task:** Choose the right protocol for streaming AI responses to the browser.

**Action/Result:** SSE is a one-directional, HTTP-based streaming protocol — the server pushes data to the client over a persistent HTTP connection. Each message is formatted as `data: ...\n\n`. WebSockets are bidirectional and require a protocol upgrade. For AI response streaming, SSE is the correct choice: the data only flows server→client (the model generates tokens, the browser displays them), SSE works over standard HTTP/2, it automatically reconnects, and it requires no special server infrastructure. I used `fetch()` with a manual `ReadableStream` reader instead of the native `EventSource` API because `EventSource` only supports GET requests — I needed POST to send JSON context with each message.

---

### Q19. What is a sliding window algorithm and where did you use it?

**Situation/Task:** Detect brute-force login attacks where the signal is volume over time, not a single event.

**Action/Result:** A sliding window maintains two pointers (left, right) over a time-sorted event list. The right pointer advances event by event. For each new right position, if the time span `events[right].timestamp - events[left].timestamp > window_seconds`, advance the left pointer until the window fits. The count of events in the window is `right - left + 1`. In Rule-001, I apply this per source IP: if any IP accumulates more than 5 failed logins (Event ID 4625) within 60 seconds, a Critical brute-force alert fires. This is O(n) per IP group — both pointers only move forward — which is efficient on large event datasets.

---

### Q20. If an interviewer asks "what is MITRE ATT&CK?" — how do you explain it?

**Situation/Task:** Communicate a security framework concept clearly and connect it to your work.

**Action/Result:** MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a publicly maintained knowledge base of how real-world attackers operate, organized into a matrix. Each **Tactic** is a high-level goal (e.g., *Initial Access*, *Persistence*, *Lateral Movement*, *Exfiltration*). Each **Technique** is a specific method to achieve that goal (e.g., T1110 — Brute Force is under *Credential Access*). In my system, every detection rule is tagged with the MITRE technique it maps to. This gives analysts immediate context: when a brute-force alert fires, they know they're in the *Credential Access* tactic phase of a potential attack chain, what other techniques typically follow (T1003 Credential Dumping), and what mitigations MITRE recommends. It also lets security teams measure coverage — which techniques in the matrix can we currently detect versus which are blind spots.

---

## CHEAT SHEET — KEY NUMBERS TO REMEMBER

| Fact | Value |
|------|-------|
| Number of detection rules | 10 |
| MITRE techniques covered | T1110, T1003, T1059.001, T1136, T1053, T1021, T1059, T1071, T1547, T1490 |
| LLM model used | Qwen2.5-14B-Instruct (also Qwen3-4B option) |
| API server framework | FastAPI |
| Frontend stack | React 18, Vite 5, Tailwind CSS 3, Recharts |
| Log format parsed | Windows EVTX (binary Event Log) |
| GPU precision | bfloat16 |
| Brute-force threshold | 5 failed logins / 60 seconds / same IP |
| AI triage output fields | 8 (severity, summary, FP likelihood, FP reason, actions, MITRE, urgency score, steps) |
| Email risk scoring | SPF fail: 30, DKIM fail: 20, DMARC fail: 15, per URL: 10 (max 30), reply-to mismatch: 20, per attachment: 5 (max 20) |
| Streaming buffer size | 7 characters (handles split `</think>` tokens) |

---

## CLOSING ADVICE

- **Lead with the problem, not the technology.** Interviewers care about why you made choices, not just what you used.
- **Know your trade-offs.** For every decision (local LLM, SSE vs WebSocket, client-side search), be ready to explain what you gave up and why it was worth it.
- **Have the debugging story ready.** The Qwen3 thinking mode bug (Q6) demonstrates multi-layer debugging, reading raw model output, defensive coding, and version compatibility awareness — all signals of engineering depth.
- **Security domain credibility.** When discussing alerts, use the MITRE technique names naturally. "This fires on T1059.001 — PowerShell encoded commands" signals you know the domain.
- **End with what you'd build next.** Showing a roadmap (async queue, vLLM, RBAC, alert persistence) signals production-systems thinking.

---

*Document prepared for: SOC Sentinel — AI-Powered Security Operations Center Dashboard*
*Role target: Cyber + AI Engineering*
