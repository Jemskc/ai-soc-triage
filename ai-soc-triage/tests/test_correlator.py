"""Correlation is what makes LLM analysis affordable, so its grouping
behaviour needs pinning: too tight and the GPU cost returns, too loose and
distinct attacks get merged into one case and hidden.
"""

from datetime import datetime, timedelta

import correlator


def alert(ts, host="PC01", user="alice", mitre="T1003", rule="Cred Dump",
          severity="critical", alert_id=None, event_id="10"):
    return {
        "alert_id": alert_id or f"a{ts}",
        "timestamp": ts,
        "computer": host,
        "user": user,
        "mitre_id": mitre,
        "mitre_technique": f"{mitre} - test",
        "rule_name": rule,
        "severity": severity,
        "event_id": event_id,
        "process_name": "lsass.exe",
        "command_line": "",
        "attack_folder": "Credential Access",
        "event_data": {"computer": host, "user": user},
    }


def t(minutes):
    return (datetime(2024, 1, 1, 12, 0) + timedelta(minutes=minutes)).isoformat()


def test_empty_input():
    assert correlator.correlate([]) == []


def test_same_host_technique_within_window_merges():
    incidents = correlator.correlate([alert(t(0)), alert(t(2)), alert(t(4))])
    assert len(incidents) == 1
    assert incidents[0]["alert_count"] == 3


def test_distant_events_on_different_assets_stay_separate():
    incidents = correlator.correlate([
        alert(t(0), host="PC01", user="alice"),
        alert(t(600), host="PC99", user="bob"),
    ])
    assert len(incidents) == 2


def test_shared_host_merges_across_techniques():
    """One intrusion spanning several techniques should be one case, not one
    case per technique."""
    incidents = correlator.correlate([
        alert(t(0), mitre="T1003", rule="Cred Dump"),
        alert(t(5), mitre="T1021", rule="PsExec"),
    ])
    assert len(incidents) == 1
    assert len(incidents[0]["techniques_suspected"]) == 2


def test_peak_severity_wins():
    incidents = correlator.correlate([
        alert(t(0), severity="low"),
        alert(t(1), severity="critical"),
    ])
    assert incidents[0]["severity"] == "critical"


def test_incident_id_is_stable():
    """Ids must be reproducible so cached triage survives a re-run."""
    a = correlator.correlate([alert(t(0)), alert(t(1))])
    b = correlator.correlate([alert(t(0)), alert(t(1))])
    assert a[0]["incident_id"] == b[0]["incident_id"]


def test_ground_truth_never_reaches_the_model():
    """Corpus labels are for scoring only; leaking them into the prompt would
    make the benchmark meaningless."""
    incidents = correlator.correlate([alert(t(0))])
    assert incidents[0]["ground_truth_tactics"] == ["Credential Access"]
    evidence = correlator.evidence_for_model(incidents[0])
    assert "ground_truth_tactics" not in evidence
    assert "Credential Access" not in str(evidence.get("rules_fired", ""))


def test_evidence_is_bounded():
    """Prompt length costs quadratic attention memory on a V100, so the
    evidence passed to the model must stay bounded regardless of input size."""
    many = [alert(t(i / 10.0), alert_id=f"a{i}") for i in range(200)]
    incidents = correlator.correlate(many)
    evidence = correlator.evidence_for_model(incidents[0])
    assert len(evidence["sample_events"]) <= 2
    assert len(evidence["command_lines"]) <= 3
    assert len(evidence["event_ids"]) <= 8


def test_malformed_timestamps_do_not_crash():
    incidents = correlator.correlate([
        alert(""), alert("not-a-date"), alert(t(0)),
    ])
    assert incidents


def test_sorted_by_severity_then_volume():
    incidents = correlator.correlate([
        alert(t(0), host="A", severity="low"),
        alert(t(500), host="B", severity="critical"),
    ])
    assert incidents[0]["severity"] == "critical"


def test_retrieval_keys_extracted():
    incidents = correlator.correlate([alert(t(0))])
    keys = correlator.retrieval_keys(incidents[0])
    assert "10" in keys["event_ids"]
    assert any("lsass" in p for p in keys["processes"])
