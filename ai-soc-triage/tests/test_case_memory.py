"""Case memory — so the SOC stops re-deciding what it already decided."""

import tempfile
from pathlib import Path

import pytest

from case_memory import CaseMemory


@pytest.fixture
def memory(tmp_path):
    return CaseMemory(tmp_path / "mem.json")


def incident(iid="INC-1", rule="Scheduled Task Created", proc="backup.exe",
             event="4698", host="SRV01"):
    return {
        "incident_id": iid,
        "rules_fired": [{"rule": rule}],
        "processes": [f"C:\\\\Windows\\\\System32\\\\{proc}"],
        "event_ids": [event],
        "signals": [{"kind": "rare_process"}],
        "hosts": [host], "users": ["svc_backup"],
    }


def test_recurring_pattern_is_recognised_on_a_different_host(memory):
    """The same scheduled task on forty machines is one pattern, not forty
    cases — so the fingerprint must exclude the hostname."""
    memory.record(incident(), {"verdict": "SUPPRESS", "analyst_summary": "Nightly backup."})
    hits = memory.search("scheduled task backup", incident("INC-2", host="SRV99"))
    assert hits["precedents"]
    assert hits["precedents"][0]["outcome"] == "benign"


def test_unrelated_case_finds_nothing(memory):
    memory.record(incident(), {"verdict": "SUPPRESS", "analyst_summary": "Nightly backup."})
    other = incident("INC-3", rule="Mimikatz Credential Dumping",
                     proc="lsass.exe", event="10")
    assert memory.search("lsass credential dumping", other)["precedents"] == []


def test_empty_memory_says_so(memory):
    assert "no comparable case" in memory.search("anything")["finding"]


def test_analyst_correction_overrides_the_agent(memory):
    """The highest-value record in the store: it steers the next similar case
    without retraining anything."""
    memory.record(incident(), {"verdict": "SUPPRESS", "analyst_summary": "Nightly backup."})
    assert memory.correct("INC-1", "malicious", "Attacker-created scheduler entry.")
    hit = memory.search("scheduled task backup", incident("INC-4", host="SRV42"))["precedents"][0]
    assert hit["outcome"] == "malicious"
    assert hit["analyst_corrected"] is True
    assert "Attacker-created" in hit["correction"]


def test_repeat_strengthens_rather_than_duplicating(memory):
    for i in range(4):
        memory.record(incident(f"INC-{i}"), {"verdict": "SUPPRESS", "analyst_summary": "x"})
    assert len(memory.cases) == 1
    assert memory.cases[0].times_seen == 4


def test_precedent_is_offered_as_evidence_not_instruction(memory):
    memory.record(incident(), {"verdict": "SUPPRESS", "analyst_summary": "Nightly backup."})
    hits = memory.search("scheduled task backup", incident("INC-5"))
    assert "not an instruction" in hits["guidance"]


def test_memory_survives_a_restart(tmp_path):
    path = tmp_path / "mem.json"
    CaseMemory(path).record(incident(), {"verdict": "SUPPRESS", "analyst_summary": "x"})
    assert len(CaseMemory(path).cases) == 1


def test_stats_report_corrections(memory):
    memory.record(incident(), {"verdict": "SUPPRESS", "analyst_summary": "x"})
    memory.correct("INC-1", "malicious", "wrong")
    assert memory.stats()["analyst_corrected"] == 1


def test_agent_rulings_are_not_reported_as_confirmed(memory):
    memory.record(incident(), {"verdict": "SUPPRESS", "analyst_summary": "Looks fine."},
                  decided_by="agent")
    found = memory.search("scheduled task backup", incident("INC-9"))
    assert found["precedents"], "the precedent should still be visible"
    assert found["confirmed_outcome"] is None, "but not as human-confirmed"
    assert found["confirmed_precedents"] == []


def test_analyst_confirmation_promotes_a_precedent(memory):
    memory.record(incident(), {"verdict": "SUPPRESS", "analyst_summary": "Looks fine."},
                  decided_by="agent")
    memory.correct("INC-1", "benign", "Verified nightly backup.")
    found = memory.search("scheduled task backup", incident("INC-10"))
    assert found["confirmed_outcome"] == "benign"


def test_guidance_warns_about_unconfirmed_precedent(memory):
    memory.record(incident(), {"verdict": "SUPPRESS", "analyst_summary": "x"})
    found = memory.search("scheduled task backup", incident("INC-11"))
    assert "earlier agent's opinion" in found["guidance"]
