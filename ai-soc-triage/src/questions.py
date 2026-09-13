"""Questions the agent puts to an analyst, and the answers that come back.

Autonomy without a way to ask is a false choice. An agent that must either
decide alone or give up will do one of two bad things: escalate everything
ambiguous, which recreates the queue the system exists to remove, or guess,
which is worse. Often the missing piece is one fact a human has and the
telemetry does not — "is this maintenance window expected?", "does this
contractor still work here?" — and one sentence unblocks the whole case.

A parked investigation keeps its transcript, so answering resumes it rather
than restarting. The GPU cost of the work already done is not thrown away.

Questions expire. An unanswered question is not a decision, and a case parked
indefinitely is a case nobody is triaging — on expiry it routes to a human as
an ordinary escalation rather than sitting invisible.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
QUESTIONS_PATH = BASE_DIR / "output" / "questions.json"

# After this, an unanswered question stops blocking the case.
DEFAULT_TTL_SECONDS = 4 * 3600


@dataclass
class Question:
    question_id: str
    incident_id: str
    question: str
    why_it_matters: str = ""
    options: list[str] = field(default_factory=list)
    asked_at: float = field(default_factory=time.time)
    ttl_seconds: int = DEFAULT_TTL_SECONDS

    answer: str | None = None
    answered_by: str = ""
    answered_at: float | None = None
    expired: bool = False

    # The investigation so far, so answering resumes rather than restarts.
    resume_state: dict[str, Any] = field(default_factory=dict)

    @property
    def status(self) -> str:
        if self.answer is not None:
            return "answered"
        if self.expired or (time.time() - self.asked_at) > self.ttl_seconds:
            return "expired"
        return "waiting"

    @property
    def waiting_seconds(self) -> float:
        end = self.answered_at or time.time()
        return end - self.asked_at

    def to_dict(self, include_state: bool = False) -> dict[str, Any]:
        out = {
            "question_id": self.question_id,
            "incident_id": self.incident_id,
            "question": self.question,
            "why_it_matters": self.why_it_matters,
            "options": self.options,
            "asked_at": self.asked_at,
            "status": self.status,
            "waiting_seconds": round(self.waiting_seconds, 1),
            "answer": self.answer,
            "answered_by": self.answered_by,
            "answered_at": self.answered_at,
        }
        if include_state:
            out["resume_state"] = self.resume_state
        return out


class QuestionStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or QUESTIONS_PATH
        self.questions: dict[str, Question] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return
        import dataclasses

        # to_dict() includes derived fields (status, waiting_seconds) that are
        # not constructor arguments, so a round trip through disk would fail.
        allowed = {f.name for f in dataclasses.fields(Question)}
        for record in raw.get("questions", []):
            q = Question(**{k: v for k, v in record.items() if k in allowed})
            self.questions[q.question_id] = q

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({
            "questions": [
                {**q.to_dict(include_state=True),
                 "ttl_seconds": q.ttl_seconds, "expired": q.expired}
                for q in self.questions.values()
            ]
        }, indent=1, default=str), encoding="utf-8")
        tmp.replace(self.path)

    # -- asking ------------------------------------------------------------

    def ask(self, incident_id: str, question: str, why: str = "",
            options: list[str] | None = None,
            resume_state: dict[str, Any] | None = None) -> Question:
        # One open question per incident: an agent that can queue five
        # questions about one case has not understood the case.
        for existing in self.questions.values():
            if existing.incident_id == incident_id and existing.status == "waiting":
                return existing

        q = Question(
            question_id=uuid.uuid4().hex[:10],
            incident_id=incident_id,
            question=question.strip(),
            why_it_matters=why.strip(),
            options=[str(o) for o in (options or [])][:5],
            resume_state=resume_state or {},
        )
        self.questions[q.question_id] = q
        self.save()
        return q

    # -- answering ---------------------------------------------------------

    def answer(self, question_id: str, answer: str, analyst: str = "analyst") -> Question | None:
        q = self.questions.get(question_id)
        if q is None or q.status == "answered":
            return None
        q.answer = str(answer).strip()
        q.answered_by = analyst
        q.answered_at = time.time()
        self.save()
        return q

    # -- reading -----------------------------------------------------------

    def clear(self) -> int:
        """Drop every question.

        Called when the corpus is reset: a question is always about a specific
        incident, and once those incidents are gone the question is unanswerable
        and its answer would resume an investigation that no longer exists.
        """
        n = len(self.questions)
        self.questions = {}
        self.save()
        return n

    def waiting(self) -> list[Question]:
        return sorted(
            (q for q in self.questions.values() if q.status == "waiting"),
            key=lambda q: q.asked_at,
        )

    def answered_for(self, incident_id: str) -> Question | None:
        for q in self.questions.values():
            if q.incident_id == incident_id and q.status == "answered":
                return q
        return None

    def expire_stale(self) -> list[Question]:
        """Questions nobody answered stop blocking their case."""
        newly = []
        for q in self.questions.values():
            if q.status == "expired" and not q.expired:
                q.expired = True
                newly.append(q)
        if newly:
            self.save()
        return newly

    def stats(self) -> dict[str, Any]:
        from collections import Counter
        by_status = Counter(q.status for q in self.questions.values())
        answered = [q for q in self.questions.values() if q.status == "answered"]
        median_wait = 0.0
        if answered:
            waits = sorted(q.waiting_seconds for q in answered)
            median_wait = waits[len(waits) // 2]
        return {
            "total": len(self.questions),
            "by_status": dict(by_status),
            "waiting": by_status.get("waiting", 0),
            "median_answer_seconds": round(median_wait, 1),
        }


_STORE: QuestionStore | None = None


def get_store() -> QuestionStore:
    global _STORE
    if _STORE is None:
        _STORE = QuestionStore()
    return _STORE
