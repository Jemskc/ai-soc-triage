"""Base contract for SOC agents.

An agent is a specialist: it is given a case, it does one kind of thinking, and
it returns findings plus the evidence and sources behind them. It never decides
the final verdict — that is the Risk Engine's job, so that the scoring stays
deterministic and auditable rather than being another model opinion.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import prompts
from tab_contracts import TabContract


@dataclass
class Finding:
    """One thing an agent concluded, with its justification attached."""

    agent: str
    kind: str                      # e.g. "triage_verdict", "hunt_lead", "intel_context"
    summary: str
    severity: str = "info"         # info | low | medium | high | critical
    confidence: float = 0.0        # 0.0-1.0, calibrated against evidence
    evidence: list[dict[str, Any]] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "kind": self.kind,
            "summary": self.summary,
            "severity": self.severity,
            "confidence": round(float(self.confidence), 3),
            "evidence": self.evidence,
            "sources": self.sources,
            "data": self.data,
        }


@dataclass
class AgentResult:
    agent: str
    ok: bool
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    elapsed_seconds: float = 0.0
    ungrounded: list[str] = field(default_factory=list)
    knowledge: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "ok": self.ok,
            "error": self.error,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "ungrounded": self.ungrounded,
            "findings": [f.to_dict() for f in self.findings],
            "knowledge_used": [
                {"id": c["id"], "title": c.get("title", "")} for c in self.knowledge
            ],
        }


class Agent:
    """Base class. Subclasses implement `run`."""

    name = "agent"
    description = "generic agent"

    def __init__(self, engine) -> None:
        # Every agent shares the one loaded model and the one knowledge base.
        # Nine agents must not mean nine copies of a 14B model in VRAM.
        self.engine = engine

    @property
    def kb(self):
        return self.engine.kb

    def run(self, case) -> AgentResult:  # pragma: no cover - interface
        raise NotImplementedError

    # -- shared helper ----------------------------------------------------

    def _ask(
        self,
        contract: TabContract,
        evidence: dict[str, Any],
        knowledge: list[dict[str, Any]],
        extra_instruction: str = "",
    ) -> tuple[dict[str, Any] | None, str, list[str], float]:
        """Run one grounded model call against a tab contract.

        Returns (payload, error, ungrounded_techniques, elapsed).
        """
        system = prompts.build_system_prompt(contract)
        user = prompts.build_user_prompt(
            contract, evidence, knowledge, extra_instruction=extra_instruction
        )

        started = time.time()
        raw = self.engine.backend.generate_text(
            system=system, user=user, max_tokens=contract.token_budget
        )
        elapsed = time.time() - started
        self.engine.stats.calls += 1
        self.engine.stats.total_seconds += elapsed

        try:
            payload = prompts.extract_json(raw)
        except prompts.SchemaViolation as exc:
            self.engine.stats.parse_failures += 1
            return None, f"parse: {exc}", [], elapsed

        try:
            prompts.validate(contract, payload)
        except prompts.SchemaViolation as exc:
            self.engine.stats.schema_failures += 1
            return payload, f"schema: {exc}", [], elapsed

        ungrounded = prompts.check_grounding(payload, knowledge)
        if ungrounded:
            self.engine.stats.ungrounded_citations += 1
        return payload, "", ungrounded, elapsed
