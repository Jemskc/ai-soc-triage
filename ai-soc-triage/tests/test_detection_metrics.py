"""Rule performance, and the backtest that makes a tuning change safe.

The property that matters most here: a proposed exclusion must be blocked if it
would have removed a detection that mattered. A rule change is uniquely
dangerous because a deleted detection is invisible — nothing alerts you that
you stopped looking.
"""

import pandas as pd
import pytest

import detection_metrics as dm


RULES = [
    {"id": "R-NOISY", "name": "Noisy", "severity": "medium",
     "mitre_technique": "T1059 - Command and Scripting Interpreter",
     "type": "pattern",
     "conditions": [{"field": "raw_message", "operator": "regex", "value": "(?i)backup"}]},
    {"id": "R-GOOD", "name": "Good", "severity": "critical",
     "mitre_technique": "T1003.001 - LSASS Memory", "type": "pattern",
     "conditions": [{"field": "raw_message", "operator": "regex", "value": "(?i)lsass"}]},
    {"id": "R-SILENT", "name": "Silent", "severity": "high",
     "mitre_technique": "T1486 - Data Encrypted for Impact", "type": "pattern",
     "conditions": [{"field": "raw_message", "operator": "regex", "value": "(?i)ransomware"}]},
]


def alert(rule_id, row_index, source="s.evtx"):
    return {"rule_id": rule_id, "_row_index": row_index, "source_file": source}


def incident(iid, rule_ids, rows):
    return {"incident_id": iid,
            "sample_alerts": [alert(r, i) for r, i in zip(rule_ids, rows)],
            "hosts": ["H1"], "users": ["u1"]}


# --- deterministic metrics --------------------------------------------------

def test_silent_rule_is_identified():
    out = dm.compute(RULES, [alert("R-GOOD", 0)], [incident("I1", ["R-GOOD"], [0])], {})
    assert "R-SILENT" in out["summary"]["silent"]
    silent = next(r for r in out["rules"] if r["rule_id"] == "R-SILENT")
    assert silent["verdict"]["label"] == "silent"


def test_redundant_rule_is_identified():
    """A rule that never caught anything alone is redundant however often it
    fires."""
    alerts = [alert("R-NOISY", 0), alert("R-GOOD", 0)]
    incidents = [{"incident_id": "I1",
                  "sample_alerts": [alert("R-NOISY", 0), alert("R-GOOD", 0)]}]
    out = dm.compute(RULES, alerts, incidents, {})
    noisy = next(r for r in out["rules"] if r["rule_id"] == "R-NOISY")
    assert noisy["unique_contribution"] == 0
    assert noisy["verdict"]["label"] == "redundant"


def test_unique_contribution_counted():
    out = dm.compute(RULES, [alert("R-GOOD", 0)], [incident("I1", ["R-GOOD"], [0])], {})
    good = next(r for r in out["rules"] if r["rule_id"] == "R-GOOD")
    assert good["unique_contribution"] == 1


# --- the honesty rule -------------------------------------------------------

def test_precision_is_none_without_analyst_decisions():
    """The agent's own verdicts must never produce a precision figure: tuning a
    rule away on the agent's say-so turns one wrong suppression into a
    permanent blind spot."""
    verdicts = {"I1": {"payload": {"verdict": "SUPPRESS"}}}
    out = dm.compute(RULES, [alert("R-NOISY", 0)],
                     [incident("I1", ["R-NOISY"], [0])], verdicts)
    noisy = next(r for r in out["rules"] if r["rule_id"] == "R-NOISY")
    assert noisy["precision"] is None
    assert "not evidence for tuning" in noisy["precision_basis"]


def test_agent_suppression_is_flagged_as_low_confidence():
    verdicts = {f"I{i}": {"payload": {"verdict": "SUPPRESS"}} for i in range(6)}
    incidents = [incident(f"I{i}", ["R-NOISY"], [i]) for i in range(6)]
    out = dm.compute(RULES, [alert("R-NOISY", i) for i in range(6)], incidents, verdicts)
    noisy = next(r for r in out["rules"] if r["rule_id"] == "R-NOISY")
    assert noisy["verdict"]["label"] == "possibly noisy"
    assert noisy["verdict"]["confidence"] == "low"
    assert "analyst" in noisy["verdict"]["action"]


def test_analyst_confirmation_produces_a_real_precision():
    class FakeCase:
        def __init__(self, iid, outcome):
            self.incident_id, self.outcome = iid, outcome
            self.decided_by, self.analyst_corrected = "analyst", True

    class FakeMemory:
        cases = [FakeCase(f"I{i}", "benign") for i in range(6)]

    incidents = [incident(f"I{i}", ["R-NOISY"], [i]) for i in range(6)]
    out = dm.compute(RULES, [alert("R-NOISY", i) for i in range(6)],
                     incidents, {}, case_memory=FakeMemory())
    noisy = next(r for r in out["rules"] if r["rule_id"] == "R-NOISY")
    assert noisy["precision"] == 0.0
    assert noisy["precision_basis"] == "analyst-confirmed"
    assert noisy["verdict"]["label"] == "noisy"


# --- the backtest -----------------------------------------------------------

@pytest.fixture
def df():
    rows = []
    for i in range(10):
        rows.append({"raw_message": "nightly backup lsass scan", "user": "svc_backup",
                     "computer": "SRV01", "process_name": "backup.exe",
                     "command_line": "", "parent_process": "services.exe",
                     "event_id": "1", "timestamp": f"2024-01-01T0{i}:00:00"})
    rows.append({"raw_message": "mimikatz lsass dump", "user": "attacker",
                 "computer": "DC1", "process_name": "mimikatz.exe",
                 "command_line": "sekurlsa", "parent_process": "cmd.exe",
                 "event_id": "10", "timestamp": "2024-01-01T09:00:00"})
    frame = pd.DataFrame(rows)
    return frame.assign(_row_index=frame.index)


def test_backtest_blocks_an_exclusion_that_loses_a_real_detection(df):
    """The headline safety property. 'Exclude lsass, removes 91% of the noise'
    looks like a great proposal and would make credential dumping invisible."""
    incidents = [{"incident_id": "REAL",
                  "sample_alerts": [alert("R-GOOD", 10)]}]
    verdicts = {"REAL": {"payload": {"verdict": "ESCALATE"}}}
    result = dm.backtest_exclusion(df, RULES, "R-GOOD", "raw_message", "lsass",
                                   incidents=incidents, verdicts=verdicts)
    assert result["safe"] is False
    assert result["escalated_incidents_lost"]
    assert "do not apply" in result["assessment"].lower()


def test_backtest_allows_a_targeted_exclusion(df):
    incidents = [{"incident_id": "REAL", "sample_alerts": [alert("R-GOOD", 10)]}]
    verdicts = {"REAL": {"payload": {"verdict": "ESCALATE"}}}
    result = dm.backtest_exclusion(df, RULES, "R-GOOD", "user", "svc_backup",
                                   incidents=incidents, verdicts=verdicts)
    assert result["safe"] is True
    assert result["alerts_removed"] == 10
    assert result["escalated_incidents_lost"] == []


def test_backtest_reports_noise_reduction(df):
    result = dm.backtest_exclusion(df, RULES, "R-GOOD", "user", "svc_backup")
    assert result["alerts_before"] == 11
    assert result["alerts_after"] == 1
    assert result["noise_reduction"] == pytest.approx(10 / 11, abs=0.01)


def test_backtest_rejects_an_invalid_pattern(df):
    assert "error" in dm.backtest_exclusion(df, RULES, "R-GOOD", "user", "[unclosed")


def test_backtest_rejects_unknown_rule(df):
    assert "error" in dm.backtest_exclusion(df, RULES, "NOPE", "user", "x")


# ── an exclusion on a field that does not exist must not read as "safe" ───────
# Backtesting `field="process"` when the column is `process_name` matched
# nothing and returned safe:True with 0 removed — the same output a genuinely
# harmless exclusion produces. That is the worst possible way to be wrong here,
# because the whole point of the backtest is to stop an unsafe rule change.

def test_backtest_rejects_a_field_the_events_do_not_have():
    import pandas as pd
    import detection_metrics as dm

    df = pd.DataFrame([{"process_name": "lsass.exe", "user": "u1", "host": "h1"}])
    rules = [{"id": "RULE-X", "name": "x", "severity": "high",
              "match": {"process_name": ".*"}}]
    out = dm.backtest_exclusion(df, rules, "RULE-X", "process", "lsass")
    assert "error" in out
    assert "unknown field" in out["error"]
    # and it must not have quietly reported a safe verdict
    assert "safe" not in out
    assert "process_name" in out.get("did_you_mean", [])
