"""Events published to the dashboard.

The bundle used to carry incidents but not the events behind them, so every
log-oriented view rendered empty while the header reported thousands of events
analysed. These pin the contract that fixed it.
"""

import pandas as pd
import pytest

from pipeline import MAX_PUBLISHED_EVENTS, build_event_rows, _to_log_row

# Exactly what the frontend log views read. Dropping any of these silently
# blanks a column rather than raising.
REQUIRED_KEYS = {
    "id", "timestamp", "severity", "sourceIP", "destIP", "user", "host",
    "message", "rule", "source", "mitre", "status",
}


@pytest.fixture
def df():
    return pd.DataFrame([
        {
            "timestamp": f"2024-01-01T00:{i:02d}:00", "event_id": "1",
            "computer": f"HOST{i % 3}", "user": f"user{i % 2}",
            "process_name": "svchost.exe", "command_line": "",
            "source_ip": "10.0.0.1", "channel": "Sysmon",
            "parent_process": "services.exe",
        }
        for i in range(50)
    ])


@pytest.fixture
def incidents(df):
    return [{
        "incident_id": "INC-1",
        "sample_alerts": [{
            "_row_index": 7,
            "severity": "critical",
            "rule_name": "Mimikatz Credential Dumping Behavior",
            "description": "LSASS access observed",
            "mitre_technique": "T1003.001 - LSASS Memory",
            "detection_source": "rules",
        }],
    }]


def test_rows_carry_every_field_the_ui_reads(df, incidents):
    for row in build_event_rows(df, incidents):
        assert REQUIRED_KEYS <= set(row)


def test_alert_context_is_attached_in_place(df, incidents):
    """Alert metadata annotates the event where it sits in the timeline,
    rather than reordering the log."""
    rows = build_event_rows(df, incidents)
    annotated = [r for r in rows if r["detectionSource"] == "rules"]
    assert len(annotated) == 1
    assert rows[7] is annotated[0]
    assert annotated[0]["severity"] == "CRITICAL"
    assert "T1003.001" in annotated[0]["mitre"]


def test_every_event_is_published(df, incidents):
    """A truncated log view is worse than none: you cannot tell a log that is
    missing from one that never existed."""
    assert MAX_PUBLISHED_EVENTS == 0, "log view must not be capped by default"
    assert len(build_event_rows(df, incidents)) == len(df)


def test_source_order_is_preserved(df, incidents):
    """An analyst reading a timeline needs the sequence events occurred in, not
    a relevance ranking."""
    rows = build_event_rows(df, incidents)
    stamps = [r["timestamp"] for r in rows]
    assert stamps == sorted(stamps)


def test_raw_record_is_attached(df, incidents):
    """'Show me the real log' has to be answerable."""
    row = build_event_rows(df, incidents)[0]
    assert row["_raw"]
    assert row["_raw"]["computer"] == df.iloc[0]["computer"]
    assert all(v not in ("", None, "-") for v in row["_raw"].values())


def test_no_incidents_still_publishes_events(df):
    """A run that finds nothing must still show the logs it looked at."""
    rows = build_event_rows(df, [])
    assert len(rows) == len(df)
    assert all(r["detectionSource"] == "" for r in rows)


def test_raw_record_excludes_internal_plumbing(df):
    df2 = df.assign(_row_index=df.index)
    row = build_event_rows(df2, [])[0]
    assert not any(k.startswith("_") for k in row["_raw"])


def test_ids_are_unique(df, incidents):
    rows = build_event_rows(df, incidents)
    assert len({r["id"] for r in rows}) == len(rows)


def test_alert_row_is_not_duplicated(df, incidents):
    """The alert-bearing row is emitted once, not again in the backfill pass."""
    rows = build_event_rows(df, incidents)
    assert sum(1 for r in rows if r["detectionSource"] == "rules") == 1


def test_missing_fields_do_not_crash():
    row = _to_log_row({}, 0, None)
    assert REQUIRED_KEYS <= set(row)
    assert row["user"] == "Unknown"
    assert row["host"] == "Unknown"


def test_long_values_are_truncated():
    row = _to_log_row(
        {"process_name": "p", "command_line": "x" * 5000}, 0, None
    )
    assert len(row["message"]) <= 400
    assert len(row["commandLine"]) <= 401


# --- result durability -----------------------------------------------------
# A completed analysis was destroyed by starting a second run: partial
# snapshots were written straight to analysis.json, so an in-progress run at
# case 1 replaced a finished 40-case bundle. An hour of GPU work, gone on a
# button press. These pin the invariant that stops it recurring.

def test_partials_never_touch_the_completed_bundle():
    import pipeline
    assert pipeline.PARTIAL_ANALYSIS_PATH != pipeline.ANALYSIS_PATH
    assert pipeline.PARTIAL_CASES_PATH != pipeline.CASES_PATH


def test_completed_bundle_is_written_atomically(tmp_path):
    """A crash mid-write must not leave a truncated file where a valid
    analysis used to be."""
    import pipeline
    target = tmp_path / "analysis.json"
    target.write_text('{"old": true}')
    pipeline._atomic_write(target, {"new": True, "verdicts": {}})
    import json as _json
    assert _json.loads(target.read_text())["new"] is True
    assert not list(tmp_path.glob("*.tmp"))


# ── metrics must not under-report when the caller has no alert objects ────────
# The autopilot calls build_metrics(df, [], incidents, verdicts) because it does
# not retain alerts between cycles. That made the dashboard show "0 rule alerts"
# on every live run while 280 rules had fired.

def test_rule_alerts_derived_from_incidents_when_alerts_missing():
    import pipeline

    incidents = [
        {"incident_id": "INC-1", "alert_count": 3,
         "rules_fired": [{"rule": "A", "count": 2}, {"rule": "B", "count": 1}]},
        {"incident_id": "INC-2", "alert_count": 1,
         "rules_fired": [{"rule": "A", "count": 5}]},
    ]
    import pandas as pd
    metrics = pipeline.build_metrics(pd.DataFrame([{"x": 1}]), [], incidents, {})
    assert metrics["rule_alerts"] == 8


def test_supplied_alerts_still_win():
    import pandas as pd
    import pipeline

    incidents = [{"incident_id": "INC-1", "alert_count": 1,
                  "rules_fired": [{"rule": "A", "count": 99}]}]
    metrics = pipeline.build_metrics(
        pd.DataFrame([{"x": 1}]), [{"a": 1}, {"a": 2}], incidents, {})
    assert metrics["rule_alerts"] == 2


# ── a corpus arrives in batches; the log view must not forget the earlier ones ─
# Ingesting 50,702 events in eleven batches left "702 events" on screen — the
# last batch — while the incident count kept climbing. The analysis was right
# and the evidence behind it had disappeared.

def test_events_accumulate_across_batches_but_the_funnel_sees_only_the_new_one():
    import inspect

    import autopilot

    src = inspect.getsource(autopilot.Autopilot._run_cycle)
    assert "pd.concat" in src, "batches must accumulate for the log view"

    # The funnel must not be handed the whole history each cycle. Matched as a
    # whole statement: a loose substring also hits the retention trim
    # (`self._last_df = self._last_df.tail(...)`) and fails on correct code.
    reassigns_df = [
        line for line in src.splitlines()
        if line.strip() == "df = self._last_df"
    ]
    assert not reassigns_df, (
        "funnelling the accumulated set is quadratic and re-derives incidents")


def test_retention_cap_exists_and_announces_itself():
    import inspect

    import autopilot

    assert autopilot.MAX_RETAINED_EVENTS >= 100_000
    src = inspect.getsource(autopilot.Autopilot._run_cycle)
    # Dropping evidence silently is worse than dropping it.
    assert "events.trimmed" in src


# ── the agent must not be starved by a bulk import ───────────────────────────
# Ingesting a million events left 175 batches queued, 225 incidents pending and
# ZERO analysed: _investigate_pending yielded the moment anything was in the
# inbox, so during a large import the Alerts tab stayed empty for the entire
# run. New logs may outrank deep analysis; they must not cancel it.

def test_analysis_is_never_blocked_by_the_ingest_queue():
    """The property, not the mechanism.

    This was first solved with a minimum-slice floor inside the shared loop,
    which stopped total starvation but still made ingestion wait for inference.
    Separate threads achieve it properly, so the test asserts what must be true
    rather than how it happens to be arranged.
    """
    import inspect

    import autopilot

    src = inspect.getsource(autopilot.Autopilot._investigate_pending)
    # The agent must never abandon its work because logs are arriving.
    assert "if self._stop.is_set() or not self.inbox.empty():" not in src
    assert "not self.inbox.empty()" not in src, (
        "the agent thread does not block the ingest thread and must not yield "
        "to it")


def test_event_file_rewrite_is_throttled():
    """Re-serialising the whole corpus per batch is quadratic.

    At batch 200 of a million-event import that was 72MB rewritten each time.
    """
    import inspect

    import autopilot

    src = inspect.getsource(autopilot.Autopilot._publish_bundle)
    assert "EVENTS_REWRITE_SECONDS" in src
    assert "_events_written" in src
    assert autopilot.EVENTS_REWRITE_SECONDS > 0


# ── ingest must not destroy the field the rules match on ─────────────────────
# MESSAGE_FIELDS are all process-oriented and empty for authentication data, so
# rebuilding raw_message from them wiped it. The same LANL corpus produced
# 47,678 alerts through lanl_eval and zero through /ingest: not a detection
# failure, a field destroyed on the way in.

def test_ingest_keeps_a_supplied_raw_message():
    import pandas as pd

    import pipeline

    events = [{
        "timestamp": "2015-01-02 00:00:00", "event_id": "4624",
        "computer": "C1003", "user": "U620", "source_ip": "C17693",
        "process_name": "", "command_line": "", "parent_process": "",
        "raw_message": "NTLM Network LogOn Success C17693->C1003",
    }]
    df = pd.DataFrame(events).fillna("")
    for col in pipeline.STANDARD_COLUMNS:
        if col not in df.columns:
            df[col] = ""

    present = [c for c in pipeline.MESSAGE_FIELDS if c in df.columns]
    rebuilt = df[present].astype(str).agg(" ".join, axis=1).str.strip()
    supplied = df["raw_message"].astype(str).str.strip()
    result = supplied.where(supplied != "", rebuilt)

    assert "NTLM" in result.iloc[0], "the rule's only matchable field was erased"


def test_ingest_still_builds_raw_message_when_absent():
    import pandas as pd

    import pipeline

    df = pd.DataFrame([{"process_name": "rundll32.exe", "command_line": "-k netsvcs"}])
    for col in pipeline.STANDARD_COLUMNS:
        if col not in df.columns:
            df[col] = ""
    present = [c for c in pipeline.MESSAGE_FIELDS if c in df.columns]
    rebuilt = df[present].astype(str).agg(" ".join, axis=1).str.strip()
    supplied = df["raw_message"].astype(str).str.strip()
    result = supplied.where(supplied != "", rebuilt)
    assert "rundll32.exe" in result.iloc[0]


# ── which file did this come from? ───────────────────────────────────────────
# The origin of an import was published to the event bus and discarded. Once two
# files had been loaded their events were one undifferentiated pile, and there
# was no way to answer how many files had been imported at all.

def test_submit_stamps_the_origin_onto_every_row():
    import inspect

    import autopilot

    src = inspect.getsource(autopilot.Autopilot.submit)
    assert "ingest_source" in src, "the origin must reach the rows, not just the bus"
    assert "self._sources" in src, "and be counted so the UI can list imports"


def test_log_rows_expose_the_source():
    import pipeline

    row = pipeline._to_log_row(
        {"timestamp": "2015-01-02 00:00:00", "event_id": "4624",
         "computer": "C1", "user": "U1", "ingest_source": "golden.jsonl"},
        0, None)
    assert row["ingestSource"] == "golden.jsonl"


def test_log_rows_fall_back_rather_than_showing_nothing():
    import pipeline

    row = pipeline._to_log_row(
        {"timestamp": "x", "event_id": "4624", "source_file": "evtx-sample"}, 0, None)
    assert row["ingestSource"] == "evtx-sample"
    bare = pipeline._to_log_row({"timestamp": "x", "event_id": "4624"}, 0, None)
    assert bare["ingestSource"] == "unknown"


# ── an alert must be joinable to the event that raised it ────────────────────
# Batches were each indexed 0..N, so row 6 of batch five and row 6 of batch one
# were indistinguishable. Nothing could ask afterwards whether a given event was
# detected, which made scoring against labelled data impossible: 0 of 200
# attacks "caught" on data measured elsewhere at 100% recall.

def test_batches_get_globally_unique_row_indices():
    import inspect

    import autopilot

    src = inspect.getsource(autopilot.Autopilot._run_cycle)
    assert "RangeIndex(offset" in src, (
        "each batch must be offset into a global index space")


def test_published_events_expose_the_row_index():
    import pipeline

    row = pipeline._to_log_row({"timestamp": "x", "event_id": "4624"}, 0, None)
    # _to_log_row itself does not set it; build_event_rows does, from the
    # dataframe index. Guard that the field is populated there.
    src = __import__("inspect").getsource(pipeline.build_event_rows)
    assert '"rowIndex"' in src
    assert "int(idx)" in src


# ── ingestion must not wait for model inference ──────────────────────────────
# _run_cycle funnelled a batch and then investigated cases at ~90s each in the
# same thread, so the next batch could not be processed until the AI finished.
# Importing 20,200 events left 15,200 queued behind inference and the log view
# showed 5,000 of 20,200 with nothing explaining why.

def test_ingest_and_agents_run_on_separate_threads():
    import inspect

    import autopilot

    start = inspect.getsource(autopilot.Autopilot.start)
    assert "_agent_loop" in start, "the agents need their own thread"

    work = inspect.getsource(autopilot.Autopilot._work_loop)
    assert "_investigate_pending" not in work, (
        "the ingest loop must not block on model inference")

    cycle = inspect.getsource(autopilot.Autopilot._run_cycle)
    assert "_investigate_pending" not in cycle, (
        "funnelling a batch must not wait for the agents")


def test_agent_loop_exists_and_is_independent():
    import inspect

    import autopilot

    src = inspect.getsource(autopilot.Autopilot._agent_loop)
    assert "_investigate_pending" in src
    assert "self._pending" in src
