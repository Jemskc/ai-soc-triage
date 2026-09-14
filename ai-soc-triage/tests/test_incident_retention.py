"""Incidents must survive the batch that follows them.

The AI Investigation tab showed "Investigated (0)" beside seven finished
traces. The verdicts were intact; the incidents they referred to were not.
Each funnel batch replaced the whole incident list with its own output, so an
incident that took ninety seconds to investigate was gone from the bundle
before the verdict landed, and every tab that joins a verdict to an incident
found nothing to join to.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from autopilot import MAX_RETAINED_INCIDENTS, Autopilot  # noqa: E402


def _bare() -> Autopilot:
    """An autopilot with only the state _merge_incidents touches."""
    import threading

    ap = Autopilot.__new__(Autopilot)
    ap._lock = threading.RLock()
    ap._all_incidents = []
    ap._verdicts = {}
    return ap


def _inc(n: int) -> dict:
    return {"incident_id": f"INC-{n:06d}", "alerts": [], "evidence_weight": n}


def test_a_later_batch_does_not_erase_an_earlier_one():
    ap = _bare()
    ap._merge_incidents([_inc(1), _inc(2)])
    ap._merge_incidents([_inc(3)])

    ids = {i["incident_id"] for i in ap._all_incidents}
    assert ids == {"INC-000001", "INC-000002", "INC-000003"}


def test_an_investigated_incident_is_still_there_afterwards():
    ap = _bare()
    ap._merge_incidents([_inc(1)])
    ap._verdicts["INC-000001"] = {"verdict": "ESCALATE"}
    for n in range(2, 40):
        ap._merge_incidents([_inc(n)])

    ids = {i["incident_id"] for i in ap._all_incidents}
    assert "INC-000001" in ids, "the decided incident was dropped"


def test_a_newer_version_of_the_same_incident_wins():
    ap = _bare()
    ap._merge_incidents([{"incident_id": "INC-A", "alerts": [1]}])
    ap._merge_incidents([{"incident_id": "INC-A", "alerts": [1, 2, 3]}])

    assert len(ap._all_incidents) == 1
    assert ap._all_incidents[0]["alerts"] == [1, 2, 3]


def test_retention_evicts_undecided_before_decided():
    ap = _bare()
    over = MAX_RETAINED_INCIDENTS + 500

    # One decided incident, first in and therefore oldest.
    ap._merge_incidents([_inc(0)])
    ap._verdicts["INC-000000"] = {"verdict": "SUPPRESS"}
    ap._merge_incidents([_inc(n) for n in range(1, over)])

    ids = {i["incident_id"] for i in ap._all_incidents}
    assert len(ap._all_incidents) <= MAX_RETAINED_INCIDENTS
    assert "INC-000000" in ids, "eviction threw away a decided case"
    # And it kept the most recent undecided ones, not the stalest.
    assert f"INC-{over - 1:06d}" in ids


def test_restart_puts_the_undecided_backlog_back_in_the_queue(tmp_path, monkeypatch):
    """A restart used to abandon everything the agent had not yet reached.

    Only verdicts were restored, so after a restart the dashboard showed 223
    incidents, one verdict, `pending_cases` 0 and stage "idle" — the corpus was
    never going to be finished. Restarts happen for ordinary reasons (a deploy,
    an OOM, the supervisor recovering a crash), so the backlog evaporated on
    each one.
    """
    import json
    import threading

    import pipeline

    bundle = tmp_path / "analysis.json"
    bundle.write_text(json.dumps({"incidents": [
        {"incident_id": "INC-A", "evidence_weight": 5},
        {"incident_id": "INC-B", "evidence_weight": 9},
        {"incident_id": "INC-DONE", "evidence_weight": 1},
    ]}))
    monkeypatch.setattr(pipeline, "ANALYSIS_PATH", bundle)

    ap = _bare()
    ap._pending = []
    ap._verdicts["INC-DONE"] = {"payload": {"verdict": "SUPPRESS"}}

    class _State:
        pending_cases = 0
        incidents_total = 0

    class _Bus:
        def publish(self, *a, **k):
            pass

    ap.state, ap.bus = _State(), _Bus()

    # It must also finish: _merge_incidents takes the same non-reentrant lock,
    # and calling it inside the critical section deadlocked startup.
    done = threading.Event()
    threading.Thread(target=lambda: (ap._requeue_undecided(), done.set()),
                     daemon=True).start()
    assert done.wait(10), "restore deadlocked"

    queued = [i["incident_id"] for i in ap._pending]
    assert queued == ["INC-B", "INC-A"], "highest evidence weight first"
    assert "INC-DONE" not in queued, "a decided case was re-investigated"
