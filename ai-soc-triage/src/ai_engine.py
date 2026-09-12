"""The contract-driven analysis engine.

One entry point per scope:
    analyze_incident(incident, tab_id)  — per-incident tabs (alerts, playbooks)
    analyze_campaign(incidents, tab_id) — whole-run tabs (overview, hunting, ...)

Both follow the same path: retrieve grounding from the knowledge base, compose a
prompt from the tab's contract, call the model, then validate the response and
check that nothing was cited which was not retrieved. A failure is recorded as a
failure — never silently replaced with a default, because a quiet fallback would
fabricate benchmark results.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import correlator
import prompts
from knowledge_base import KnowledgeBase, get_kb
from llm_backend import get_llm_backend
from tab_contracts import TabContract, get_contract


@dataclass
class AnalysisResult:
    """The outcome of one model call, successful or not."""

    tab_id: str
    ok: bool
    payload: dict[str, Any] | None = None
    knowledge: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    ungrounded_techniques: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    raw_response: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tab_id": self.tab_id,
            "ok": self.ok,
            "payload": self.payload,
            "error": self.error,
            "ungrounded_techniques": self.ungrounded_techniques,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "knowledge_used": [
                {"id": c["id"], "title": c.get("title", "")} for c in self.knowledge
            ],
        }


class EngineStats:
    """Counters that keep the pipeline honest.

    parse_failures and ungrounded_citations are reported rather than hidden: if
    the model cannot hold its contract, that is a finding about the system, not
    something to paper over.
    """

    def __init__(self) -> None:
        self.calls = 0
        self.parse_failures = 0
        self.schema_failures = 0
        self.ungrounded_citations = 0
        self.empty_retrievals = 0
        self.total_seconds = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "parse_failures": self.parse_failures,
            "schema_failures": self.schema_failures,
            "ungrounded_citations": self.ungrounded_citations,
            "empty_retrievals": self.empty_retrievals,
            "total_seconds": round(self.total_seconds, 1),
            "mean_seconds": round(self.total_seconds / self.calls, 2) if self.calls else 0,
        }


class AIEngine:
    def __init__(
        self,
        kb: KnowledgeBase | None = None,
        backend: Any | None = None,
        use_rag: bool = True,
        two_pass: bool = True,
    ) -> None:
        # use_rag=False is not a convenience switch; it is the control arm of the
        # ablation that shows whether retrieval is doing any work.
        self.use_rag = use_rag
        self.two_pass = two_pass
        self.kb = kb if kb is not None else (get_kb() if use_rag else None)
        self.backend = backend if backend is not None else get_llm_backend()
        if self.backend is None:
            raise RuntimeError(
                "No LLM backend. Set LOCAL_MODEL_NAME in ai-soc-triage/.env"
            )
        self.stats = EngineStats()

    # -- retrieval ---------------------------------------------------------

    def _retrieve(
        self, contract: TabContract, keys: dict[str, list[str]], top_k: int = 6
    ) -> list[dict[str, Any]]:
        if not self.use_rag or self.kb is None:
            return []
        chunks = self.kb.search_structured(
            event_ids=keys.get("event_ids"),
            processes=keys.get("processes"),
            terms=keys.get("terms"),
            hints=contract.retrieval_hints,
            top_k=top_k,
        )
        if not chunks:
            self.stats.empty_retrievals += 1
        return chunks

    # -- model call --------------------------------------------------------

    def _call(
        self, contract: TabContract, evidence: dict[str, Any], knowledge: list[dict]
    ) -> AnalysisResult:
        system = prompts.build_system_prompt(contract)
        user = prompts.build_user_prompt(contract, evidence, knowledge)

        started = time.time()
        raw = self.backend.generate_text(
            system=system, user=user, max_tokens=contract.token_budget
        )
        elapsed = time.time() - started

        self.stats.calls += 1
        self.stats.total_seconds += elapsed

        result = AnalysisResult(
            tab_id=contract.tab_id,
            ok=False,
            knowledge=knowledge,
            elapsed_seconds=elapsed,
            raw_response=raw,
        )

        try:
            payload = prompts.extract_json(raw)
        except prompts.SchemaViolation as exc:
            self.stats.parse_failures += 1
            result.error = f"parse: {exc}"
            return result

        try:
            prompts.validate(contract, payload)
        except prompts.SchemaViolation as exc:
            self.stats.schema_failures += 1
            result.error = f"schema: {exc}"
            result.payload = payload  # keep it; partial output is still evidence
            return result

        ungrounded = prompts.check_grounding(payload, knowledge)
        if ungrounded:
            self.stats.ungrounded_citations += 1
            result.ungrounded_techniques = ungrounded

        result.ok = True
        result.payload = payload
        return result

    # -- two-pass evidence extraction --------------------------------------

    def _evidence_pass(self, evidence: dict[str, Any]) -> dict[str, Any] | None:
        """Ask what happened and what to look up, before asking for judgement."""
        system, user = prompts.build_evidence_pass(evidence)
        started = time.time()
        raw = self.backend.generate_text(system=system, user=user, max_tokens=400)
        self.stats.calls += 1
        self.stats.total_seconds += time.time() - started
        try:
            return prompts.extract_json(raw)
        except prompts.SchemaViolation:
            self.stats.parse_failures += 1
            return None

    # -- public API --------------------------------------------------------

    def analyze_incident(
        self, incident: dict[str, Any], tab_id: str = "alerts"
    ) -> AnalysisResult:
        contract = get_contract(tab_id)
        evidence = correlator.evidence_for_model(incident)
        keys = correlator.retrieval_keys(incident)

        # Pass A lets the model name its own lookup terms, which retrieves
        # better than the rule metadata alone — it reads the command lines.
        if self.two_pass:
            if extracted := self._evidence_pass(evidence):
                extra = [str(t) for t in extracted.get("lookup_terms", []) if t]
                if extra:
                    keys["terms"] = (keys.get("terms") or []) + extra[:4]
                evidence["preliminary_reading"] = {
                    "what_happened": extracted.get("what_happened", ""),
                    "key_fields": extracted.get("key_fields", []),
                }

        knowledge = self._retrieve(contract, keys)
        return self._call(contract, evidence, knowledge)

    def analyze_campaign(
        self, incidents: list[dict[str, Any]], tab_id: str, verdicts: dict | None = None
    ) -> AnalysisResult:
        contract = get_contract(tab_id)

        # Campaign tabs reason over summaries, not raw events: the whole point
        # is the shape across incidents.
        summaries = []
        for inc in incidents:
            entry = {
                "incident_id": inc["incident_id"],
                "severity": inc["severity"],
                "alert_count": inc["alert_count"],
                "first_seen": inc["first_seen"],
                "hosts": inc["hosts"],
                "users": inc["users"],
                "techniques": [t["technique"] for t in inc.get("techniques_suspected", [])][:3],
                "rules": [r["rule"] for r in inc.get("rules_fired", [])][:3],
            }
            if verdicts and (v := verdicts.get(inc["incident_id"])):
                if payload := v.get("payload"):
                    entry["ai_verdict"] = payload.get("verdict")
                    entry["ai_urgency"] = payload.get("urgency_score")
                    entry["ai_summary"] = payload.get("analyst_summary")
            summaries.append(entry)

        keys = {
            "event_ids": [],
            "processes": [],
            "terms": sorted(
                {t for inc in incidents for t in
                 [x["technique"] for x in inc.get("techniques_suspected", [])]}
            )[:6],
        }
        knowledge = self._retrieve(contract, keys, top_k=5)

        evidence = {"incident_count": len(incidents), "incidents": summaries}
        return self._call(contract, evidence, knowledge)
