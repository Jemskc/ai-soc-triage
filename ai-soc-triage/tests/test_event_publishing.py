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
