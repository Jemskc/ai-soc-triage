"""Triage Agent — is this real, how urgent, what do I do in the next ten minutes."""

from __future__ import annotations

import correlator
from tab_contracts import get_contract

from .base import Agent, AgentResult, Finding

SEVERITY_FROM_URGENCY = [
    (9, "critical"), (7, "high"), (4, "medium"), (0, "low"),
]


def _severity(urgency) -> str:
    try:
        score = float(urgency)
    except (TypeError, ValueError):
        return "info"
    for threshold, label in SEVERITY_FROM_URGENCY:
        if score >= threshold:
            return label
    return "low"


class TriageAgent(Agent):
    name = "triage"
    description = "Judges whether an incident is a real threat and how urgent it is."

    def run(self, case) -> AgentResult:
        incident = case.incident
        evidence = correlator.evidence_for_model(incident)
        keys = correlator.retrieval_keys(incident)

        # Two-pass: let the model name its own lookup terms from the command
        # lines before retrieving, then judge with that knowledge in hand.
        if self.engine.two_pass:
            if extracted := self.engine._evidence_pass(evidence):
                extra = [str(t) for t in extracted.get("lookup_terms", []) if t]
                if extra:
                    keys["terms"] = (keys.get("terms") or []) + extra[:4]
                evidence["preliminary_reading"] = {
                    "what_happened": extracted.get("what_happened", ""),
                    "key_fields": extracted.get("key_fields", []),
                }

        # Cross-domain evidence gathered before judging, so the verdict accounts
        # for identity and network context rather than the rule hit alone.
        if case.domain_summary:
            evidence["cross_domain_evidence"] = case.domain_summary

        contract = get_contract("alerts")
        knowledge = self.engine._retrieve(contract, keys)
        case.knowledge.extend(knowledge)

        payload, error, ungrounded, elapsed = self._ask(contract, evidence, knowledge)
        if payload is None:
            return AgentResult(self.name, False, error=error, elapsed_seconds=elapsed,
                               knowledge=knowledge)

        finding = Finding(
            agent=self.name,
            kind="triage_verdict",
            summary=payload.get("analyst_summary", ""),
            severity=_severity(payload.get("urgency_score")),
            confidence=float(payload.get("confidence") or 0.0),
            evidence=payload.get("evidence") or [],
            sources=payload.get("sources") or [],
            data=payload,
        )
        return AgentResult(self.name, not error, [finding], error, elapsed, ungrounded, knowledge)
