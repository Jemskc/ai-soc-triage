"""What the SOC already decided, so it stops deciding it again.

Without memory an agent re-investigates the same nightly backup job every
night, at full cost, and reaches the same conclusion. Worse, it re-raises it to
an analyst every night, which is how people learn to ignore the queue.

Memory holds concluded cases and their outcomes, searchable by the shape of the
activity rather than by exact match — the same benign job on a different host
should still be recognised. It is also where analyst corrections live: a
disagreement recorded here changes what the agent retrieves next time, which is
how accuracy improves without retraining anything.

Deliberately lexical rather than embedded. The signal that identifies a
recurring case is exact tokens — a process name, a rule id, a service account —
and those are what an analyst would search for too. It also means a stored case
can be read and audited, which a vector cannot.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
MEMORY_PATH = BASE_DIR / "output" / "case_memory.json"

# A case must resemble a stored one this closely to be offered as a precedent.
MIN_SIMILARITY = 0.45

# How many precedents to return. More than a few is noise in a prompt.
TOP_K = 3


def _tokens(text: str) -> set[str]:
    import re
    raw = re.findall(r"[a-z0-9]+(?:[.\-_][a-z0-9]+)*", str(text).lower())
    return {t for t in raw if len(t) > 2}


@dataclass
class StoredCase:
    incident_id: str
    fingerprint: str
    outcome: str                      # benign | malicious | inconclusive
    verdict: str
    summary: str
    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    decided_by: str = "agent"         # agent | analyst
    analyst_corrected: bool = False
    correction_note: str = ""
    recorded_at: float = field(default_factory=time.time)
    times_seen: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "fingerprint": self.fingerprint,
            "outcome": self.outcome,
            "verdict": self.verdict,
            "summary": self.summary,
            "hosts": self.hosts,
            "users": self.users,
            "techniques": self.techniques,
            "decided_by": self.decided_by,
            "analyst_corrected": self.analyst_corrected,
            "correction_note": self.correction_note,
            "recorded_at": self.recorded_at,
            "times_seen": self.times_seen,
        }


class CaseMemory:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or MEMORY_PATH
        self.cases: list[StoredCase] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return
        self.cases = [StoredCase(**c) for c in raw.get("cases", [])]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(
            {"cases": [c.to_dict() for c in self.cases]}, indent=1), encoding="utf-8")
        tmp.replace(self.path)

    # -- fingerprint -------------------------------------------------------

    @staticmethod
    def fingerprint(incident: dict[str, Any]) -> str:
        """What makes two cases 'the same kind of thing'.

        Deliberately excludes hostnames and timestamps: the same scheduled task
        firing on forty machines is one recurring pattern, not forty cases.
        """
        rules = sorted(r.get("rule", "") for r in incident.get("rules_fired", []))
        procs = sorted({
            str(p).rsplit("\\", 1)[-1].lower() for p in incident.get("processes", [])
        })
        events = sorted(incident.get("event_ids", []))
        kinds = sorted({s.get("kind", "") for s in incident.get("signals", [])})
        return " | ".join([
            ",".join(rules), ",".join(procs[:6]),
            ",".join(events[:6]), ",".join(kinds),
        ])

    # -- retrieval ---------------------------------------------------------

    def search(self, query: str, incident: dict[str, Any] | None = None) -> dict[str, Any]:
        needle = _tokens(query)
        if incident:
            needle |= _tokens(self.fingerprint(incident))
        if not needle or not self.cases:
            return {"precedents": [], "searched": len(self.cases),
                    "finding": "no comparable case has been ruled on before"}

        scored = []
        for case in self.cases:
            hay = _tokens(case.fingerprint + " " + case.summary)
            if not hay:
                continue
            overlap = len(needle & hay) / len(needle | hay)
            if overlap >= MIN_SIMILARITY:
                scored.append((overlap, case))

        scored.sort(key=lambda x: -x[0])
        precedents = [
            {
                "incident_id": c.incident_id,
                "similarity": round(sim, 2),
                "outcome": c.outcome,
                "verdict": c.verdict,
                "summary": c.summary[:200],
                "decided_by": c.decided_by,
                "analyst_corrected": c.analyst_corrected,
                "correction": c.correction_note[:160] if c.analyst_corrected else "",
                "times_seen": c.times_seen,
            }
            for sim, c in scored[:TOP_K]
        ]
        if not precedents:
            return {"precedents": [], "searched": len(self.cases),
                    "finding": "no comparable case has been ruled on before"}

        # Precedent set by a human is evidence. Precedent the agent set for
        # itself is not — it is the agent's own earlier opinion, and treating
        # it as confirmation is how one wrong SUPPRESS becomes the
        # justification for auto-closing every similar case after it.
        confirmed = [p for p in precedents
                     if p["decided_by"] == "analyst" or p["analyst_corrected"]]
        return {
            "precedents": precedents,
            "confirmed_precedents": confirmed,
            "confirmed_outcome": confirmed[0]["outcome"] if confirmed else None,
            "searched": len(self.cases),
            "guidance": (
                "A prior ruling is evidence, not an instruction. If this case "
                "differs materially from the precedent, say so and decide on "
                "what you see. Note which precedents a human confirmed: an "
                "unconfirmed one is only an earlier agent's opinion."
            ),
        }

    # -- writing -----------------------------------------------------------

    def record(self, incident: dict[str, Any], verdict: dict[str, Any],
               decided_by: str = "agent") -> StoredCase:
        fp = self.fingerprint(incident)
        verdict_name = str(verdict.get("verdict", "UNKNOWN")).upper()
        outcome = {"SUPPRESS": "benign", "ESCALATE": "malicious"}.get(
            verdict_name, "inconclusive")

        for case in self.cases:
            if case.fingerprint == fp:
                # Same pattern seen again: strengthen it rather than duplicating.
                case.times_seen += 1
                case.recorded_at = time.time()
                if decided_by == "analyst":
                    case.decided_by = "analyst"
                    case.outcome = outcome
                    case.verdict = verdict_name
                self.save()
                return case

        case = StoredCase(
            incident_id=incident.get("incident_id", "unknown"),
            fingerprint=fp,
            outcome=outcome,
            verdict=verdict_name,
            summary=str(verdict.get("analyst_summary", ""))[:300],
            hosts=incident.get("hosts", [])[:5],
            users=incident.get("users", [])[:5],
            techniques=[str(verdict.get("mitre_technique", ""))],
            decided_by=decided_by,
        )
        self.cases.append(case)
        self.save()
        return case

    def correct(self, incident_id: str, corrected_outcome: str, note: str) -> bool:
        """An analyst overruling the agent.

        This is the highest-value record in the store: it is retrieved on the
        next similar case and steers the agent away from the mistake, without
        anything being retrained.
        """
        for case in self.cases:
            if case.incident_id == incident_id:
                case.outcome = corrected_outcome
                case.analyst_corrected = True
                case.correction_note = note
                case.decided_by = "analyst"
                self.save()
                return True
        return False

    def stats(self) -> dict[str, Any]:
        from collections import Counter
        outcomes = Counter(c.outcome for c in self.cases)
        return {
            "cases": len(self.cases),
            "by_outcome": dict(outcomes),
            "analyst_corrected": sum(1 for c in self.cases if c.analyst_corrected),
            "recurring": sum(1 for c in self.cases if c.times_seen > 1),
        }
