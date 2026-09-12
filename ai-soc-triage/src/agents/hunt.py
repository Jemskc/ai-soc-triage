"""Hunt Agent — what should we look for that the rules did not catch.

Runs against the whole case set rather than one incident: hunting leads come
from the shape across incidents, and from the domains where the Evidence Engine
found nothing but should have.
"""

from __future__ import annotations

from tab_contracts import get_contract

from .base import Agent, AgentResult, Finding


class HuntAgent(Agent):
    name = "hunt"
    description = "Generates hunting hypotheses grounded in ATT&CK detection guidance."

    def run_over_cases(self, cases, coverage) -> AgentResult:
        contract = get_contract("hunting")

        summaries = []
        for case in cases:
            verdict = case.agent_payload("triage")
            intel = case.agent_payload("intel")
            summaries.append({
                "incident_id": case.incident["incident_id"],
                "hosts": case.incident.get("hosts", [])[:3],
                "users": case.incident.get("users", [])[:3],
                "techniques": [t["technique"] for t in
                               case.incident.get("techniques_suspected", [])][:2],
                "verdict": (verdict or {}).get("verdict"),
                "urgency": (verdict or {}).get("urgency_score"),
                "likely_next_steps": (intel or {}).get("likely_next_steps", [])[:2],
            })

        evidence = {
            "incident_count": len(cases),
            "incidents": summaries,
            # Unconnected domains are hunting leads in themselves: they are
            # where an adversary could operate unobserved.
            "telemetry_coverage": coverage,
        }

        terms = sorted({
            t for case in cases
            for t in [x["technique"] for x in case.incident.get("techniques_suspected", [])]
        })[:6]
        knowledge = self.engine._retrieve(
            contract, {"event_ids": [], "processes": [], "terms": terms}, top_k=5
        )

        payload, error, ungrounded, elapsed = self._ask(contract, evidence, knowledge)
        if payload is None:
            return AgentResult(self.name, False, error=error, elapsed_seconds=elapsed,
                               knowledge=knowledge)

        findings = [
            Finding(
                agent=self.name,
                kind="hunt_lead",
                summary=h.get("hypothesis", ""),
                severity="medium",
                confidence=float(payload.get("confidence") or 0.0),
                sources=payload.get("sources") or [],
                data=h,
            )
            for h in (payload.get("hypotheses") or [])
        ]
        return AgentResult(self.name, not error, findings, error, elapsed, ungrounded, knowledge)

    def run(self, case) -> AgentResult:
        return self.run_over_cases([case], {})
