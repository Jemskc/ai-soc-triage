"""Response Agent — proposes containment actions for analyst approval.

It never executes anything. Every action it returns carries the approval gate
the Risk Engine assigned, and destructive actions are marked so the UI can
require an explicit human decision. An agent that can isolate a domain
controller on its own judgement is a liability, not a feature.
"""

from __future__ import annotations

import re

from tab_contracts import get_contract

from .base import Agent, AgentResult, Finding

# Actions that change the state of production systems. These always require a
# human, regardless of how confident the agents are.
DESTRUCTIVE_KEYWORDS = (
    "isolate", "quarantine", "disable", "block", "reset", "revoke", "kill",
    "terminate", "delete", "rebuild", "shut down", "shutdown", "remove",
)


def _is_destructive(step: str) -> bool:
    return any(k in str(step).lower() for k in DESTRUCTIVE_KEYWORDS)


def _tactic_slug(tactic: str) -> str:
    return str(tactic).strip().lower().replace(" ", "-")


class ResponseAgent(Agent):
    name = "response"
    description = "Proposes contain/eradicate/recover steps, gated on analyst approval."

    def run(self, case) -> AgentResult:
        contract = get_contract("playbooks")
        incident = case.incident
        triage = case.agent_payload("triage") or {}
        intel = case.agent_payload("intel") or {}
        risk = case.risk.to_dict() if case.risk else {}

        evidence = {
            "incident_id": incident["incident_id"],
            "hosts": incident.get("hosts", [])[:5],
            "users": incident.get("users", [])[:5],
            "technique": intel.get("technique_assessment") or triage.get("mitre_technique"),
            "triage_summary": triage.get("analyst_summary"),
            "risk_band": risk.get("band"),
            "likely_next_steps": intel.get("likely_next_steps", []),
            "cross_domain_evidence": case.domain_summary,
        }

        technique = str(evidence.get("technique") or "")

        # Resolve the technique to its ATT&CK tactic and pull that tactic's
        # playbook directly. Retrieving on the phrase "incident response
        # playbook" alone matches every playbook chunk about equally, which
        # produced a Command-and-Control containment plan for a credential
        # dumping incident — perimeter blocking instead of credential rotation.
        playbook_chunk = None
        tactics: list[str] = []
        if self.kb:
            match = re.search(r"T\d{4}(?:\.\d{3})?", technique)
            if match:
                if chunk := self.kb.get(f"attack:{match.group(0)}"):
                    tactics = chunk.get("tactics", [])
            if not tactics:
                tactics = [
                    t for entry in incident.get("techniques_suspected", [])
                    for t in (self.kb.get(f"attack:{entry.get('technique','').split()[0]}")
                              or {}).get("tactics", [])
                ]
            for tactic in tactics:
                if chunk := self.kb.get(f"playbook:{_tactic_slug(tactic)}"):
                    playbook_chunk = chunk
                    break

        evidence["attack_tactic"] = tactics[0] if tactics else "unknown"

        keys = {
            "event_ids": incident.get("event_ids", [])[:4],
            "processes": incident.get("processes", [])[:4],
            "terms": [t for t in [technique, tactics[0] if tactics else "",
                                  "containment eradication recovery"] if t],
        }
        knowledge = self.engine._retrieve(contract, keys, top_k=5)

        # Put the tactic's own playbook first and guarantee it is present, so
        # the plan is anchored to the right procedure rather than whatever
        # retrieval happened to rank highest.
        if playbook_chunk:
            knowledge = [playbook_chunk] + [
                c for c in knowledge if c["id"] != playbook_chunk["id"]
            ]

        payload, error, ungrounded, elapsed = self._ask(
            contract, evidence, knowledge,
            extra_instruction=(
                "Name the actual hosts and accounts in the steps. Steps must be "
                "specific enough for an analyst to execute without further "
                "research. The plan must address the ATTACK_TACTIC in the "
                "evidence — do not substitute a procedure for a different tactic."
            ),
        )
        if payload is None:
            return AgentResult(self.name, False, error=error, elapsed_seconds=elapsed,
                               knowledge=knowledge)

        # Tag each proposed step with whether it needs a human to sign off.
        actions = []
        for phase in ("contain", "eradicate", "recover"):
            for step in payload.get(phase) or []:
                actions.append({
                    "phase": phase,
                    "step": step,
                    "destructive": _is_destructive(step),
                    "requires_approval": _is_destructive(step) or bool(
                        case.risk and case.risk.requires_approval
                    ),
                    "status": "proposed",
                })
        payload["actions"] = actions
        payload["auto_executable"] = [a for a in actions if not a["requires_approval"]]

        finding = Finding(
            agent=self.name,
            kind="response_plan",
            summary=payload.get("playbook_name", "Response plan"),
            severity=(case.risk.band if case.risk else "info"),
            confidence=float(payload.get("confidence") or 0.0),
            sources=payload.get("sources") or [],
            data=payload,
        )
        return AgentResult(self.name, not error, [finding], error, elapsed, ungrounded, knowledge)
