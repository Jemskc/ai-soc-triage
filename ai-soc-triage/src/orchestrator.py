"""Agent Orchestrator — the AI SOC core.

Coordinates the specialists over a set of correlated incidents:

    incidents
      └─ Evidence Engine        gather cross-domain evidence per incident
      └─ Intel Agent            what is this, what usually follows
      └─ Triage Agent           is it real, how urgent, what now
      └─ Risk / Verdict Engine  deterministic fusion -> score + action
      └─ Response Agent         proposed steps, gated on approval
      └─ Hunt Agent             leads across the whole case set

Order is not arbitrary. Evidence is gathered before any agent reasons, so the
agents see cross-domain context rather than a single rule hit. Intel runs
before Triage so the triage judgement can rest on a grounded technique. The
Risk Engine runs after both, because fusing judgements is only meaningful once
they exist. Response runs last, because what you do depends on the score.

Agents run sequentially: they share one GPU, so parallelism would contend for
the same weights rather than buy throughput.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

import pandas as pd

import autonomy
import risk_engine
from agents.base import AgentResult
from agents.hunt import HuntAgent
from agents.intel import IntelAgent
from agents.response import ResponseAgent
from agents.triage import TriageAgent
from evidence_engine import EvidenceEngine


@dataclass
class Case:
    """Everything known about one incident as it moves through the agents."""

    incident: dict[str, Any]
    domain_evidence: dict[str, Any] = field(default_factory=dict)
    domain_summary: dict[str, Any] = field(default_factory=dict)
    agent_results: dict[str, AgentResult] = field(default_factory=dict)
    knowledge: list[dict[str, Any]] = field(default_factory=list)
    risk: risk_engine.RiskVerdict | None = None
    # The agentic investigation: every tool call, the reasoning behind it, and
    # what came back. This is the audit trail.
    investigation: dict[str, Any] | None = None
    autonomy: dict[str, Any] | None = None
    asset_criticality: str = "standard"

    def agent_payload(self, agent_name: str) -> dict[str, Any] | None:
        # The investigator supersedes the single-shot triage agent when it ran,
        # so downstream scoring reads its verdict rather than a stale one.
        if agent_name == "triage" and self.investigation:
            return self.investigation.get("verdict")
        result = self.agent_results.get(agent_name)
        if not result or not result.findings:
            return None
        return result.findings[0].data

    def to_dict(self) -> dict[str, Any]:
        seen, unique_knowledge = set(), []
        for chunk in self.knowledge:
            if chunk["id"] not in seen:
                seen.add(chunk["id"])
                unique_knowledge.append({"id": chunk["id"], "title": chunk.get("title", "")})

        return {
            "incident_id": self.incident["incident_id"],
            "incident": self.incident,
            "risk": self.risk.to_dict() if self.risk else None,
            "investigation": self.investigation,
            "autonomy": self.autonomy,
            "asset_criticality": self.asset_criticality,
            "agents": {n: r.to_dict() for n, r in self.agent_results.items()},
            "evidence_by_domain": {
                d: e.to_dict() for d, e in self.domain_evidence.items()
            },
            "domain_summary": self.domain_summary,
            "knowledge_used": unique_knowledge,
            # Flattened for the UI, which mostly wants the triage verdict.
            "payload": self.agent_payload("triage"),
        }


class Orchestrator:
    def __init__(self, engine, df: pd.DataFrame | None = None,
                 agentic: bool = True, inventory=None, memory=None,
                 stream_stats=None, on_step=None) -> None:
        """
        agentic: run a tool-calling investigation instead of the fixed
            Intel -> Triage sequence. The fixed path is retained because it is
            roughly 2.5x faster, which matters when the queue is deep.
        """
        self.engine = engine
        self.df = df
        self.agentic = agentic
        self.on_step = on_step
        self.inventory = inventory
        self.memory = memory
        # Triage's own evidence-extraction pass is redundant here: the Intel
        # Agent has already run and supplied grounded context. Dropping it
        # removes one model call per case for no loss of grounding.
        engine.two_pass = False
        self.evidence = EvidenceEngine(df)
        if stream_stats is not None:
            # Tools need the behavioural baselines to answer "is this normal?"
            self.evidence.stream_stats = stream_stats
        self.triage = TriageAgent(engine)
        self.intel = IntelAgent(engine)
        self.hunt = HuntAgent(engine)
        self.response = ResponseAgent(engine)

    # -- per incident ------------------------------------------------------

    def run_case(self, incident: dict[str, Any], with_response: bool = True,
                 resume: dict[str, Any] | None = None) -> Case:
        case = Case(incident=incident)

        # 1. Evidence first — agents should reason over cross-domain context.
        case.domain_evidence = self.evidence.investigate(incident)
        case.domain_summary = self.evidence.summarize(case.domain_evidence)

        # 2. Business context, so urgency can account for what is at stake.
        if self.inventory is not None:
            case.asset_criticality = self.inventory.criticality_of(
                incident.get("hosts", []) + incident.get("users", [])
            )

        if self.agentic:
            # 3. A tool-calling investigation: the agent decides what to ask.
            from agent_tools import ToolBox
            from investigator import Investigator

            toolbox = ToolBox(
                self.evidence, self.engine.kb, df=self.df,
                assets=self.inventory, case_memory=self.memory,
            )
            investigator = Investigator(
                self.engine.backend, toolbox, max_steps=8, on_step=self.on_step
            )
            outcome = investigator.run(incident, resume=resume)
            case.investigation = outcome.to_dict()
            if outcome.awaiting_human:
                # Parked: no verdict yet, so nothing downstream should score it.
                return case
            self.engine.stats.calls += outcome.model_calls
            self.engine.stats.parse_failures += outcome.parse_failures
        else:
            case.agent_results["intel"] = self.intel.run(case)
            case.agent_results["triage"] = self.triage.run(case)

        # 4. Deterministic fusion.
        case.risk = risk_engine.score_case(case)

        # 5. How much the agent is allowed to decide alone.
        precedent = None
        precedent_confirmed = False
        if self.memory is not None:
            found = self.memory.search("", incident)
            # Only a ruling a human stood behind can unlock auto-close.
            if found.get("confirmed_outcome"):
                precedent = found["confirmed_outcome"]
                precedent_confirmed = True
            elif found.get("precedents"):
                precedent = found["precedents"][0]["outcome"]
        case.autonomy = autonomy.decide(
            case.risk.to_dict() if case.risk else None,
            case.agent_payload("triage"),
            case.asset_criticality,
            precedent,
            precedent_confirmed_by_human=precedent_confirmed,
        ).to_dict()

        # 6. Response, scoped by the risk band.
        if with_response and case.risk.band in ("critical", "high"):
            case.agent_results["response"] = self.response.run(case)
            plan = case.agent_payload("response") or {}
            if plan.get("actions"):
                # Re-gate against the autonomy decision: destructive steps stay
                # human-approved regardless of how confident the agent was.
                band = autonomy.Band(case.autonomy["band"])
                plan["actions"] = autonomy.gate_actions(
                    plan["actions"],
                    autonomy.Decision(band,
                                      requires_approval=case.autonomy["requires_approval"]),
                )

        # 7. Remember the ruling, so the next identical case is recognised.
        if self.memory is not None and case.agent_payload("triage"):
            self.memory.record(incident, case.agent_payload("triage"), decided_by="agent")

        return case

    # -- whole run ---------------------------------------------------------

    def run(
        self,
        incidents: list[dict[str, Any]],
        on_progress: Callable[[int, int, str], None] | None = None,
        with_response: bool = True,
        on_case: Callable[[list["Case"]], None] | None = None,
    ) -> dict[str, Any]:
        """
        on_case: called with every completed case so far, after each one. Lets
            the caller publish partial results — a 40-case run takes the better
            part of an hour, and a dashboard that shows nothing until the end
            is not much use while it is happening.
        """
        started = time.time()
        cases: list[Case] = []

        for i, incident in enumerate(incidents, 1):
            if on_progress:
                on_progress(i, len(incidents), incident["incident_id"])
            cases.append(self.run_case(incident, with_response=with_response))
            if on_case:
                on_case(cases)

        coverage = self.evidence.coverage()
        hunt_result = self.hunt.run_over_cases(cases, coverage)

        # Highest risk first — the queue an analyst should work top-down.
        cases.sort(key=lambda c: -(c.risk.score if c.risk else 0))

        return {
            "cases": [c.to_dict() for c in cases],
            "hunt": hunt_result.to_dict(),
            "telemetry_coverage": coverage,
            "queue": [
                {
                    "incident_id": c.incident["incident_id"],
                    "risk_score": round(c.risk.score, 1) if c.risk else 0,
                    "band": c.risk.band if c.risk else "unknown",
                    "action": c.risk.action if c.risk else "unknown",
                    "requires_approval": c.risk.requires_approval if c.risk else False,
                }
                for c in cases
            ],
            "elapsed_seconds": round(time.time() - started, 1),
            "agent_stats": self.engine.stats.as_dict(),
        }
