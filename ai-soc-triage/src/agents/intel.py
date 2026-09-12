"""Intel Agent — what is known about this technique, and what usually follows it.

Deliberately does not judge the incident. Its job is to supply grounded context
the other agents and the Risk Engine consume: what the technique is, what an
adversary typically does next, and how confident we can be in the attribution.
"""

from __future__ import annotations

from tab_contracts import SCOPE_INCIDENT, TabContract

from .base import Agent, AgentResult, Finding

INTEL_CONTRACT = TabContract(
    tab_id="intel",
    label="Threat Intel",
    scope=SCOPE_INCIDENT,
    analyst_question=(
        "What is this activity, what does the adversary typically do next, and "
        "how strong is the attribution?"
    ),
    output_schema={
        "technique_assessment": "the best-supported ATT&CK technique from the retrieved "
                                "context in the form 'T1003.001 - LSASS Memory', or UNKNOWN",
        "attribution_strength": "one of strong, moderate, weak — how well the evidence "
                                "supports that technique",
        "what_this_is": "2 sentences explaining the technique in plain English",
        "likely_next_steps": "array of 2-4 things an adversary typically does after this, "
                             "each grounded in the retrieved context",
        "detection_gaps": "array of up to 3 data sources that would confirm or rule this out",
        "confidence": "float 0.0-1.0",
        "sources": "array of knowledge-base chunk ids you actually used",
    },
    retrieval_hints=[
        "attack technique detection guidance",
        "attack tactic sequencing",
        "technique relationships",
    ],
    token_budget=550,
)

STRENGTH_SEVERITY = {"strong": "high", "moderate": "medium", "weak": "low"}


class IntelAgent(Agent):
    name = "intel"
    description = "Supplies grounded ATT&CK context and likely adversary next steps."

    def run(self, case) -> AgentResult:
        incident = case.incident

        evidence = {
            "techniques_suspected": incident.get("techniques_suspected", []),
            "rules_fired": incident.get("rules_fired", []),
            "event_ids": incident.get("event_ids", [])[:8],
            "processes": incident.get("processes", [])[:8],
            "command_lines": incident.get("command_lines", [])[:3],
        }
        if case.domain_summary:
            evidence["cross_domain_evidence"] = case.domain_summary

        keys = {
            "event_ids": incident.get("event_ids", [])[:5],
            "processes": incident.get("processes", [])[:5],
            "terms": [t["technique"] for t in incident.get("techniques_suspected", [])][:4],
        }
        knowledge = self.engine._retrieve(INTEL_CONTRACT, keys, top_k=6)
        case.knowledge.extend(knowledge)

        payload, error, ungrounded, elapsed = self._ask(INTEL_CONTRACT, evidence, knowledge)
        if payload is None:
            return AgentResult(self.name, False, error=error, elapsed_seconds=elapsed,
                               knowledge=knowledge)

        finding = Finding(
            agent=self.name,
            kind="intel_context",
            summary=payload.get("what_this_is", ""),
            severity=STRENGTH_SEVERITY.get(
                str(payload.get("attribution_strength", "")).lower(), "info"
            ),
            confidence=float(payload.get("confidence") or 0.0),
            sources=payload.get("sources") or [],
            data=payload,
        )
        return AgentResult(self.name, not error, [finding], error, elapsed, ungrounded, knowledge)
