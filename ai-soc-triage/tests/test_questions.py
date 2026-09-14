"""The agent asking a human, and the case resuming when answered.

Autonomy without a way to ask is a false choice: an agent that must either
decide alone or give up will escalate everything ambiguous and recreate the
queue this system exists to remove.
"""

import time

import pytest

from agent_tools import AskedHuman, ToolBox
from questions import Question, QuestionStore


@pytest.fixture
def store(tmp_path):
    return QuestionStore(tmp_path / "q.json")


# --- the tool ---------------------------------------------------------------

def test_the_agent_is_not_offered_the_question_tool_by_default():
    """The agent decides; it does not hand the decision back.

    Parking a case as a question looks like diligence and behaves like an
    outage: the incident leaves the queue, nothing is concluded, and the
    backlog grows while the GPU idles. The tool is withheld rather than
    discouraged — an agent that cannot see a tool cannot call it, which is
    more reliable than a prompt asking it not to.
    """
    tb = ToolBox(None, None)
    assert "ask_analyst" not in tb.names()
    assert "ask_analyst" not in tb.catalogue()


def test_asking_raises_rather_than_returning_when_enabled():
    """Still has to unwind the loop when it is switched back on, so the case
    is parked with its transcript rather than continuing without an answer."""
    tb = ToolBox(None, None, allow_ask_human=True)
    with pytest.raises(AskedHuman) as caught:
        tb.run(1, "ask_analyst", {"question": "Was this change window approved?",
                                  "why": "would make it routine"})
    assert "change window" in caught.value.question


def test_the_environment_can_switch_it_back_on(monkeypatch):
    monkeypatch.setenv("SOC_ALLOW_ASK_HUMAN", "1")
    assert "ask_analyst" in ToolBox(None, None).names()


def test_empty_question_is_rejected():
    tb = ToolBox(None, None, allow_ask_human=True)
    assert "error" in tb.run(1, "ask_analyst", {"question": "  "}).result


# --- the store --------------------------------------------------------------

def test_question_starts_waiting(store):
    q = store.ask("INC-1", "Is SRV01 in a maintenance window?")
    assert q.status == "waiting"
    assert store.waiting() == [q]


def test_one_open_question_per_incident(store):
    """An agent that queues five questions about one case has not understood
    the case."""
    first = store.ask("INC-1", "question one")
    second = store.ask("INC-1", "question two")
    assert first.question_id == second.question_id
    assert len(store.waiting()) == 1


def test_answering_records_who_and_when(store):
    q = store.ask("INC-1", "expected?")
    store.answer(q.question_id, "No, unexpected", analyst="jems")
    answered = store.answered_for("INC-1")
    assert answered.answer == "No, unexpected"
    assert answered.answered_by == "jems"
    assert answered.status == "answered"


def test_answering_twice_is_refused(store):
    q = store.ask("INC-1", "expected?")
    store.answer(q.question_id, "first")
    assert store.answer(q.question_id, "second") is None


def test_resume_state_survives(store):
    """Answering must resume the investigation, not restart it — the GPU time
    already spent is not thrown away."""
    q = store.ask("INC-1", "expected?", resume_state={"transcript": [{"step": 1}],
                                                      "asset_checked": True})
    store.answer(q.question_id, "yes")
    resumed = store.answered_for("INC-1")
    assert resumed.resume_state["asset_checked"] is True
    assert resumed.resume_state["transcript"] == [{"step": 1}]


def test_unanswered_questions_expire(store):
    """A case parked indefinitely is a case nobody is triaging."""
    q = store.ask("INC-1", "expected?")
    q.asked_at = time.time() - (q.ttl_seconds + 60)
    assert q.status == "expired"
    assert store.waiting() == []
    assert store.expire_stale() == [q]


def test_store_survives_restart(tmp_path):
    path = tmp_path / "q.json"
    q = QuestionStore(path).ask("INC-1", "expected?", resume_state={"transcript": []})
    reloaded = QuestionStore(path)
    assert q.question_id in reloaded.questions


def test_stats_report_the_backlog(store):
    store.ask("INC-1", "a")
    store.ask("INC-2", "b")
    answered = store.ask("INC-3", "c")
    store.answer(answered.question_id, "yes")
    stats = store.stats()
    assert stats["waiting"] == 2
    assert stats["by_status"]["answered"] == 1


# --- wiring -----------------------------------------------------------------

def test_investigator_accepts_resume_state():
    import inspect

    from investigator import Investigator

    assert "resume" in inspect.signature(Investigator.run).parameters


def test_orchestrator_threads_resume_through():
    import inspect

    from orchestrator import Orchestrator

    assert "resume" in inspect.signature(Orchestrator.run_case).parameters


def test_autopilot_can_resume_an_answered_case():
    import inspect

    import autopilot

    assert hasattr(autopilot.Autopilot, "resume_answered")
    src = inspect.getsource(autopilot.Autopilot.resume_answered)
    assert "_pending.insert(0" in src, "answered cases should jump the queue"


# ── a question must never hide an intrusion ──────────────────────────────────
# Measured on one real run: 40 of 81 incidents were parked asking a human, and
# 14 of those carried Mimikatz or PsExec detections. A parked case records no
# verdict and no risk score, so those 14 were absent from the Alerts queue
# entirely — discoverable only in a side tab. The suppression veto could not
# catch it, because parking returns from run_case before autonomy is consulted.

def test_hands_on_evidence_is_what_distinguishes_a_safe_park():
    import autonomy

    ordinary = {"rules_fired": [{"rule": "Behavioural: rare lineage"}],
                "processes": ["C:\\Windows\\System32\\svchost.exe"]}
    intrusion = {"rules_fired": [{"rule": "Mimikatz Credential Dumping Behavior"}],
                 "processes": ["C:\\Windows\\PSEXESVC.exe"]}

    # An ordinary behavioural incident may wait for an answer.
    assert autonomy.hands_on_evidence(ordinary) == []
    # One showing hands-on activity may not.
    assert autonomy.hands_on_evidence(intrusion)


def test_autopilot_escalates_a_parked_intrusion_rather_than_hiding_it():
    """The parked branch must publish a verdict when evidence is hands-on."""
    import inspect

    import autopilot

    src = inspect.getsource(autopilot.Autopilot._investigate_pending)
    # The guard exists and is keyed on hands-on evidence, not on the question.
    assert "hands_on_evidence" in src
    assert "if not hands_on:" in src
    # And the escalation path sets a verdict rather than dropping the case.
    assert '"verdict": "ESCALATE"' in src
    # The question is still asked — escalating must not silence it.
    assert "question.asked" in src


def test_veto_verdict_evidence_is_structured_and_labelled():
    """A synthesised verdict must look like every other verdict.

    Emitting the display strings verbatim ("process observed: psexesvc.exe")
    made every citation unmatchable, so the audit tooling scored the safety fix
    itself as fabricating evidence.
    """
    import inspect

    import autopilot

    src = inspect.getsource(autopilot.Autopilot._investigate_pending)
    assert '"field": "detection"' in src
    assert 'item.split(": ", 1)[-1]' in src
    # And it must declare that a rule, not the agent, decided it.
    assert '"decided_by": "deterministic_veto"' in src


def test_yield_analysis_skips_deterministic_verdicts():
    """Scoring a rule as though it were an investigation measures nothing."""
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "ai-soc-eval" / "investigation_yield.py"
    spec = importlib.util.spec_from_file_location("iy", path)
    iy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(iy)

    case = {
        "incident": {"incident_id": "INC-1"},
        "investigation": {
            "steps": [], "step_count": 0,
            "verdict": {"verdict": "ESCALATE", "decided_by": "deterministic_veto",
                        "evidence": [{"field": "detection", "value": "psexesvc.exe",
                                      "why": "process observed"}]},
        },
    }
    assert iy.audit_case(case) is None
