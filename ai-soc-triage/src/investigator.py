"""The investigating agent.

A loop, not a form. The model is given an incident and a set of tools, and it
decides what to ask. Each answer changes what it asks next. It stops when it can
justify a conclusion or when its budget runs out — and a budget-exhausted
investigation reports itself as incomplete rather than guessing.

    incident
      -> "who is this account and is this normal for it?"   query_identity
      -> "it reached 6 hosts; is that unusual?"              check_baseline
      -> "unusual. what ran on those hosts afterwards?"      query_endpoint
      -> "credential tooling. does this host matter?"        query_asset
      -> "domain controller."                                conclude: escalate

Three properties this is built around:

**Every step is recorded.** The trace is the audit trail. In a regulated
environment an AI verdict nobody can reconstruct is worthless, so the tool
calls, arguments and observations are all kept and rendered in the UI.

**The transcript is bounded.** Observations accumulate and prompt length costs
attention memory quadratically on a V100. Older steps are compacted so a long
investigation cannot OOM the card halfway through.

**Budget exhaustion is a real outcome.** An agent that always concludes will
manufacture a conclusion. Running out of steps produces an explicit
`INCOMPLETE` verdict that routes to a human.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import prompts
from agent_tools import AskedHuman, ToolBox

# A hard ceiling on reasoning steps. Most investigations settle in 4-6; the
# limit exists so one pathological case cannot monopolise the GPU.
DEFAULT_MAX_STEPS = 10

# Steps kept verbatim in the prompt. Older ones are compacted to one line each.
VERBATIM_STEPS = 4

IDENTITY = (
    "You are a senior SOC analyst investigating a security incident. You have "
    "tools that query the organisation's telemetry. Work like an analyst: form "
    "a hypothesis, check it, and follow what you find."
)

RULES = """\
HOW TO WORK:

1. ONE action per response. Return a single JSON object, nothing else.
2. Ask for what you actually need next. Do not call tools at random, and do not
   re-call a tool with the same arguments — you already have that answer.
3. You MUST call query_asset on the affected host or account before you
   conclude. Urgency is meaningless without knowing what the asset is: the
   same activity on a domain controller and on a test machine are different
   findings. A conclusion without it will be rejected.
4. You may only cite an ATT&CK technique that came back from search_knowledge.
   Never recall one from memory. If retrieval gives you nothing, say UNKNOWN.
5. Check find_similar_cases before concluding. This may be a pattern already
   ruled benign, and re-raising it wastes an analyst's day.
6. Conclude as soon as you can justify it. Do not pad the investigation.
7. If the evidence genuinely does not support a conclusion, conclude anyway
   with verdict UNKNOWN and say what you would need. That is a valid outcome.

RESPOND WITH EXACTLY ONE OF THESE:

{"thought": "<why you need this>", "action": "<tool>", "args": {...}}

{"thought": "<your reasoning>", "action": "conclude", "verdict": {
   "verdict": "ESCALATE | SUPPRESS | UNKNOWN",
   "urgency_score": <0-10>,
   "confidence": <0.0-1.0>,
   "analyst_summary": "<2 sentences: what happened and why it matters>",
   "evidence": [{"field": "...", "value": "...", "why": "..."}],
   "mitre_technique": "<from retrieved knowledge only, or UNKNOWN>",
   "business_impact": "<what is at stake, given asset criticality>",
   "recommended_actions": ["...", "...", "..."],
   "sources": ["<knowledge chunk ids you used>"]
}}"""


@dataclass
class Investigation:
    incident_id: str
    awaiting_human: dict[str, Any] | None = None
    steps: list[dict[str, Any]] = field(default_factory=list)
    verdict: dict[str, Any] | None = None
    grounded_in: list[dict[str, Any]] = field(default_factory=list)
    ungrounded_citations: list[str] = field(default_factory=list)
    complete: bool = False
    stopped_reason: str = ""
    elapsed: float = 0.0
    model_calls: int = 0
    parse_failures: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "awaiting_human": self.awaiting_human,
            "complete": self.complete,
            "stopped_reason": self.stopped_reason,
            "steps": self.steps,
            "step_count": len(self.steps),
            "verdict": self.verdict,
            "grounded_in": self.grounded_in,
            "ungrounded_citations": self.ungrounded_citations,
            "elapsed_seconds": round(self.elapsed, 1),
            "model_calls": self.model_calls,
            "parse_failures": self.parse_failures,
        }


class Investigator:
    """Runs one incident to a conclusion."""

    def __init__(self, backend, toolbox: ToolBox,
                 max_steps: int = DEFAULT_MAX_STEPS,
                 on_step=None) -> None:
        self.backend = backend
        self.tools = toolbox
        self.max_steps = max_steps
        # Called after every step so the UI can render the investigation as it
        # happens rather than after it finishes.
        self.on_step = on_step

    # -- prompt ------------------------------------------------------------

    def _system(self) -> str:
        return "\n\n".join([
            IDENTITY,
            "TOOLS AVAILABLE:\n" + self.tools.catalogue(),
            RULES,
        ])

    def _user(self, incident: dict[str, Any], transcript: list[dict[str, Any]],
              step: int, used_tools: set[str] | None = None) -> str:
        used_tools = used_tools or set()
        brief = {
            "incident_id": incident.get("incident_id"),
            "first_seen": incident.get("first_seen"),
            "hosts": incident.get("hosts", [])[:5],
            "accounts": incident.get("users", [])[:5],
            "alert_count": incident.get("alert_count"),
            "rule_severity": incident.get("severity"),
            "rules_fired": [r.get("rule") for r in incident.get("rules_fired", [])][:4],
            "event_ids": incident.get("event_ids", [])[:8],
            "processes": [str(p).rsplit("\\", 1)[-1]
                          for p in incident.get("processes", [])][:6],
            "why_flagged": [s.get("reason") for s in incident.get("signals", [])][:4],
        }

        parts = ["INCIDENT:\n" + json.dumps(brief, indent=1, default=str)]

        if transcript:
            # Compact older steps; keep the most recent verbatim. An unbounded
            # transcript is what makes long investigations run out of memory.
            older = transcript[:-VERBATIM_STEPS]
            recent = transcript[-VERBATIM_STEPS:]
            if older:
                parts.append("EARLIER STEPS (summarised):\n" + "\n".join(
                    f"  {s['step']}. {s['tool']}({json.dumps(s['args'], default=str)[:80]}) "
                    f"-> {s['summary']}" for s in older
                ))
            parts.append("RECENT STEPS:\n" + "\n\n".join(
                f"  Step {s['step']}: {s['tool']}({json.dumps(s['args'], default=str)[:120]})\n"
                f"  Result: {s['observation']}" for s in recent
            ))

        unused = [t for t in self.tools.names() if t not in used_tools]
        if unused:
            parts.append("TOOLS YOU HAVE NOT USED YET: " + ", ".join(unused))

        remaining = self.max_steps - step
        if remaining <= 2:
            parts.append(
                f"BUDGET: {remaining} step(s) left. Conclude now with what you "
                "have. If it is not enough, conclude UNKNOWN and say what is missing."
            )
        else:
            parts.append(f"BUDGET: {remaining} of {self.max_steps} steps remaining.")

        parts.append("What is your next action? Respond with one JSON object.")
        return "\n\n".join(parts)

    # -- loop --------------------------------------------------------------

    def run(self, incident: dict[str, Any],
            resume: dict[str, Any] | None = None) -> Investigation:
        """
        resume: state from a previously parked investigation, plus the
            analyst's answer. Resuming replays the transcript rather than
            re-running the tools, so the GPU time already spent is not wasted.
        """
        result = Investigation(incident_id=incident.get("incident_id", "unknown"))
        # Everything search_knowledge actually returned. A verdict may only
        # cite from this: the prompt asks for that, but asking is not enforcing,
        # and an unenforced grounding rule is the honour system.
        retrieved: list[dict[str, Any]] = list((resume or {}).get("retrieved", []))
        transcript: list[dict[str, Any]] = list((resume or {}).get("transcript", []))
        started = time.time()
        seen_calls: set[str] = set((resume or {}).get("seen_calls", []))
        used_tools: set[str] = set((resume or {}).get("used_tools", []))
        asset_checked = bool((resume or {}).get("asset_checked"))
        result.steps = list((resume or {}).get("steps", []))

        if resume and resume.get("answer"):
            transcript.append({
                "step": len(transcript) + 1,
                "tool": "ask_analyst",
                "args": {"question": resume.get("question", "")},
                "observation": f"The analyst answered: {resume['answer']}",
                "summary": "analyst answered",
            })

        first_step = len(result.steps) + 1
        for step in range(first_step, self.max_steps + 1):
            raw = self.backend.generate_text(
                system=self._system(),
                user=self._user(incident, transcript, step, used_tools),
                # Action steps are a small JSON object; only the final verdict
                # needs room. Budgeting per step rather than uniformly is most
                # of the runtime saving.
                max_tokens=700 if step >= self.max_steps - 1 else 350,
            )
            result.model_calls += 1

            try:
                action = prompts.extract_json(raw)
            except prompts.SchemaViolation:
                result.parse_failures += 1
                transcript.append({
                    "step": step, "tool": "(unparseable)", "args": {},
                    "observation": "Your last response was not valid JSON. "
                                   "Respond with exactly one JSON object.",
                    "summary": "unparseable response",
                })
                continue

            name = str(action.get("action", "")).strip()
            thought = str(action.get("thought", ""))

            # -- terminal ---------------------------------------------------
            if name == "conclude":
                verdict = action.get("verdict") or {}
                # Refused once, not forever: if it insists after being told, the
                # investigation still ends rather than burning the whole budget
                # arguing about process.
                if (verdict and not asset_checked
                        and step < self.max_steps - 1
                        and "asset_refusal" not in seen_calls):
                    seen_calls.add("asset_refusal")
                    targets = (incident.get("hosts") or incident.get("users") or ["?"])[0]
                    nudge = (
                        "You have not established what this asset is. Call "
                        f"query_asset(name=\"{targets}\") first — urgency depends "
                        "on whether this is a domain controller or a test machine."
                    )
                    transcript.append({
                        "step": step, "tool": "conclude", "args": {},
                        "observation": nudge, "summary": "conclusion deferred: no asset context",
                    })
                    self._record(result, step, "conclude", {}, thought, nudge)
                    continue
                if isinstance(verdict, dict) and verdict:
                    rejection = self._enforce(verdict, retrieved, step, seen_calls)
                    if rejection:
                        transcript.append({
                            "step": step, "tool": "conclude", "args": {},
                            "observation": rejection, "summary": "conclusion rejected",
                        })
                        self._record(result, step, "conclude", {}, thought, rejection)
                        continue

                    result.verdict = verdict
                    result.grounded_in = [
                        {"id": c.get("id"), "title": c.get("title", "")}
                        for c in {c.get("id"): c for c in retrieved}.values()
                    ]
                    result.ungrounded_citations = prompts.check_grounding(
                        verdict, retrieved)
                    result.complete = True
                    result.stopped_reason = "concluded"
                    self._record(result, step, "conclude", {}, thought,
                                 json.dumps(verdict, default=str)[:200])
                    break
                transcript.append({
                    "step": step, "tool": "conclude", "args": {},
                    "observation": "conclude requires a populated 'verdict' object.",
                    "summary": "empty verdict rejected",
                })
                continue

            # -- tool call --------------------------------------------------
            args = action.get("args") or {}
            fingerprint = f"{name}:{json.dumps(args, sort_keys=True, default=str)}"
            if fingerprint in seen_calls:
                unused = [t for t in self.tools.names() if t not in used_tools]
                nudge = (
                    f"You already ran {name} with those arguments and have the "
                    "answer above. Do not repeat a call. "
                    + (f"Unused tools: {', '.join(unused)}. " if unused else "")
                    + "Either ask something new or conclude."
                )
                transcript.append({
                    "step": step, "tool": name, "args": args,
                    "observation": nudge, "summary": "duplicate refused",
                })
                self._record(result, step, name, args, thought, nudge)
                continue
            seen_calls.add(fingerprint)
            used_tools.add(name)
            if name == "query_asset":
                asset_checked = True

            try:
                call = self.tools.run(step, name, args)
            except AskedHuman as asked:
                # Park with everything needed to pick up where it stopped.
                result.awaiting_human = {
                    "question": asked.question,
                    "why": asked.why,
                    "options": asked.options,
                    "resume_state": {
                        "retrieved": retrieved,
                        "transcript": transcript,
                        "steps": result.steps,
                        "seen_calls": sorted(seen_calls),
                        "used_tools": sorted(used_tools),
                        "asset_checked": asset_checked,
                        "question": asked.question,
                    },
                }
                result.stopped_reason = "awaiting analyst"
                self._record(result, step, "ask_analyst",
                             {"question": asked.question}, thought,
                             f"Paused — asked the analyst: {asked.question}")
                result.elapsed = time.time() - started
                return result

            # Accumulate what retrieval actually returned. The verdict is
            # checked against exactly this, so a technique cited without a
            # matching chunk here is recalled from weights, not evidenced.
            if name == "search_knowledge" and not call.error:
                retrieved.extend(call.result.get("results") or [])

            observation = call.observation()
            transcript.append({
                "step": step, "tool": name, "args": args,
                "observation": observation,
                "summary": (call.error or observation)[:110],
            })
            self._record(result, step, name, args, thought, observation,
                         elapsed=call.elapsed, error=call.error)

        result.elapsed = time.time() - started

        if not result.complete:
            # An agent that always concludes will invent a conclusion. Running
            # out of budget is reported as what it is, and routes to a human.
            result.stopped_reason = "step budget exhausted"
            result.verdict = {
                "verdict": "UNKNOWN",
                "urgency_score": 5,
                "confidence": 0.0,
                "analyst_summary": (
                    f"Investigation did not reach a conclusion within "
                    f"{self.max_steps} steps. Needs an analyst."
                ),
                "evidence": [],
                "mitre_technique": "UNKNOWN",
                "business_impact": "undetermined",
                "recommended_actions": ["Review the investigation trace and continue manually"],
                "sources": [],
                "incomplete": True,
            }
        return result

    def _enforce(self, verdict: dict[str, Any], retrieved: list[dict[str, Any]],
                 step: int, seen: set[str]) -> str | None:
        """Check the conclusion against its contract. Returns a rejection, or None.

        The prompt asks the model to cite only retrieved techniques and to
        produce a fixed shape. Neither was checked in this path — the whole
        anti-hallucination design lived in the single-shot engine this replaced.
        Rejections fire once each, so a stubborn model ends the investigation
        rather than burning the budget arguing.
        """
        # 1. Schema.
        required = {"verdict", "urgency_score", "confidence", "analyst_summary",
                    "mitre_technique"}
        missing = required - set(verdict)
        if missing and "schema_rejection" not in seen:
            seen.add("schema_rejection")
            return (f"Your verdict is missing required fields: {sorted(missing)}. "
                    "Return the full object.")

        # 2. Grounding. A technique cited without retrieval behind it is
        #    recalled from weights and unverifiable.
        ungrounded = prompts.check_grounding(verdict, retrieved)
        if ungrounded and "grounding_rejection" not in seen:
            seen.add("grounding_rejection")
            if not retrieved:
                return (
                    f"You cited {', '.join(ungrounded)} but never called "
                    "search_knowledge, so nothing supports it. Either call "
                    "search_knowledge to retrieve the technique, or set "
                    'mitre_technique to "UNKNOWN".'
                )
            available = sorted({c.get("id", "") for c in retrieved})
            return (
                f"You cited {', '.join(ungrounded)}, which did not come back "
                f"from retrieval. Available: {', '.join(available)}. Cite one "
                'of those or use "UNKNOWN".'
            )
        return None

    def _record(self, result: Investigation, step: int, tool: str,
                args: dict[str, Any], thought: str, observation: str,
                elapsed: float = 0.0, error: str = "") -> None:
        entry = {
            "step": step,
            "thought": thought,
            "tool": tool,
            "args": args,
            "observation": observation[:800],
            "elapsed_seconds": round(elapsed, 2),
            "error": error,
        }
        result.steps.append(entry)
        if self.on_step:
            try:
                self.on_step(entry)
            except Exception:  # noqa: BLE001 — UI must not break the investigation
                pass
