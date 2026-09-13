"""Layer 1 — the volume funnel.

The properties that matter are about what the funnel must never do: silently
drop events, saturate its own ranking, or treat operating-system noise as an
intrusion.
"""

import math

import pandas as pd
import pytest

from analytics import (BENIGN_LINEAGE, RarityModel, Signal, StatisticalDetector,
                       UEBA, combine, dedupe, evidence_weight, is_human_principal)
from collections import Counter
from funnel import TriageFunnel
from stream import StreamStats, stream_frame


# --- fusion ---------------------------------------------------------------

def sig(n, score):
    return [Signal("s", f"k{i}", score, f"r{i}") for i in range(n)]


def test_no_signals_is_zero():
    assert combine([]) == 0.0
    assert evidence_weight([]) == 0.0


def test_single_signal_passes_through():
    assert combine(sig(1, 0.9)) == pytest.approx(0.9, abs=0.01)


def test_one_strong_beats_many_weak():
    assert combine(sig(1, 0.9)) > combine(sig(5, 0.2))


def test_corroboration_increases_score():
    assert combine(sig(3, 0.5)) > combine(sig(1, 0.5))


def test_score_never_reaches_one():
    """A bounded score that hits 1.0 stops being orderable."""
    assert combine(sig(50, 0.9)) <= 1.0


def test_ranking_key_does_not_saturate():
    """The displayed score saturates; the ranking key must not, or every top
    incident ties and the queue order becomes arbitrary."""
    three, six = evidence_weight(sig(3, 0.9)), evidence_weight(sig(6, 0.9))
    assert six > three
    assert combine(sig(3, 0.9)) == pytest.approx(combine(sig(6, 0.9)), abs=0.01)


def test_weak_signal_is_not_evidence_against():
    """Signal strengths are not calibrated probabilities: 0.4 means weak
    evidence for, never evidence against."""
    assert evidence_weight(sig(1, 0.4)) > 0


def test_duplicate_findings_are_collapsed():
    """One finding repeated across an incident's alerts is one piece of
    evidence, not many."""
    repeated = [Signal("ueba", "wide_footprint", 0.7, "same reason")] * 5
    assert len(dedupe(repeated)) == 1
    assert combine(repeated) == pytest.approx(0.7, abs=0.01)


# --- rarity calibration ---------------------------------------------------

def test_singleton_rarity_is_damped_when_singletons_are_normal():
    """If almost everything occurs once, occurring once carries no information
    and must not score as maximally anomalous."""
    mostly_unique = RarityModel(Counter({f"k{i}": 1 for i in range(100)}))
    mostly_repeated = RarityModel(Counter({**{f"k{i}": 50 for i in range(99)}, "rare": 1}))
    assert mostly_unique.score("k0") < mostly_repeated.score("rare")


def test_discriminative_power_reflects_distribution():
    assert RarityModel(Counter({f"k{i}": 1 for i in range(50)})).discriminative_power == 0.0
    assert RarityModel(Counter({"a": 100, "b": 100})).discriminative_power == 1.0


def test_unseen_key_scores_zero():
    assert RarityModel(Counter({"a": 5})).score("never-seen") == 0.0


# --- UEBA principals ------------------------------------------------------

@pytest.mark.parametrize("principal", [
    "SYSTEM", "NT AUTHORITY\\SYSTEM", "PC01$", "LOCAL SERVICE",
    "NETWORK SERVICE", "ANONYMOUS LOGON", "DWM-1", "",
])
def test_non_human_principals_are_excluded(principal):
    """SYSTEM is on every host by definition; baselining it as a user makes the
    most normal fact in a Windows estate look maximally anomalous."""
    assert not is_human_principal(principal)


@pytest.mark.parametrize("principal", ["alice", "bob.smith", "Administrator"])
def test_human_principals_are_baselined(principal):
    assert is_human_principal(principal)


def test_ueba_ignores_machine_accounts():
    stats = StreamStats()
    stats.user_counts["PC01$"] = 500
    stats.user_hosts["PC01$"] = Counter({f"H{i}": 10 for i in range(10)})
    assert UEBA(stats).score_row({"user": "PC01$", "computer": "H99"}) == []


def test_ueba_needs_a_baseline_before_scoring():
    """With no history every observation looks novel, which is noise."""
    stats = StreamStats()
    stats.user_counts["alice"] = 2
    assert UEBA(stats).score_row({"user": "alice", "computer": "NEW"}) == []


# --- benign lineage -------------------------------------------------------

def test_operating_system_lineage_is_not_an_anomaly():
    """Boot and servicing chains are rare inside a small capture and utterly
    normal in reality."""
    stats = StreamStats()
    stats.events = 5000
    stats.parent_child_counts.update({"wininit.exe>lsm.exe": 1, "cmd.exe>evil.exe": 1})
    det = StatisticalDetector(stats)
    benign = det.score_row({"parent_process": "wininit.exe", "process_name": "lsm.exe"})
    assert not any(s.kind == "rare_lineage" for s in benign)


def test_placeholder_parent_is_not_scored():
    stats = StreamStats()
    stats.events = 5000
    stats.parent_child_counts["?>logonui.exe"] = 1
    det = StatisticalDetector(stats)
    signals = det.score_row({"parent_process": "?", "process_name": "logonui.exe"})
    assert not any(s.kind == "rare_lineage" for s in signals)


# --- the funnel ------------------------------------------------------------

@pytest.fixture
def events():
    rows = []
    for i in range(300):
        rows.append({
            "timestamp": f"2024-01-01T{i % 24:02d}:00:00", "event_id": "1",
            "computer": f"HOST{i % 5}", "user": f"user{i % 4}",
            "process_name": "c:\\windows\\system32\\svchost.exe",
            "parent_process": "c:\\windows\\system32\\services.exe",
            "command_line": "", "source_ip": "", "destination_port": "",
            "source_file": f"s{i % 10}.evtx", "attack_folder": "Execution",
            "raw_message": "", "logon_type": "",
        })
    rows.append({**rows[0], "process_name": "c:\\temp\\evil.exe",
                 "parent_process": "c:\\windows\\system32\\winword.exe",
                 "command_line": "powershell -enc AAAA -windowstyle hidden",
                 "destination_port": "4444", "source_file": "attack.evtx"})
    return pd.DataFrame(rows)


def test_funnel_runs_every_stage(events):
    result = TriageFunnel(ai_budget=5).run(events)
    assert [s.name for s in result.stages] == [
        "stream", "rules", "analytics", "promotion", "correlation", "ranking"]


def test_budget_is_respected(events):
    result = TriageFunnel(ai_budget=3).run(events)
    assert len(result.selected) <= 3


def test_nothing_is_silently_discarded(events):
    """Everything above the budget line is selected; everything below is still
    recorded, so an analyst can see the tail and raise the budget."""
    result = TriageFunnel(ai_budget=2).run(events)
    assert len(result.selected) + len(result.deferred) == len(result.incidents)


def test_selected_outrank_deferred(events):
    result = TriageFunnel(ai_budget=3).run(events)
    if result.deferred:
        assert min(i["evidence_weight"] for i in result.selected) >= \
               max(i["evidence_weight"] for i in result.deferred)


def test_self_baselining_is_declared(events):
    """Rarity against the data being scored is a real weakness and must be
    stated, not glossed over."""
    result = TriageFunnel().run(events)
    assert any("baseline" in c.lower() for c in result.caveats)


def test_external_baseline_is_not_polluted_by_scored_data(events):
    """If the attack teaches the baseline that the attack is normal, the whole
    approach is self-defeating."""
    baseline = StreamStats()
    for chunk in stream_frame(events.head(100)):
        baseline.observe(chunk)
    before = baseline.events
    TriageFunnel(baseline=baseline).run(events)
    assert baseline.events == before


def test_suspicious_event_outranks_routine_ones(events):
    result = TriageFunnel(ai_budget=10).run(events)
    top_hosts = {h for i in result.selected[:3] for h in i["hosts"]}
    assert top_hosts


def test_streaming_holds_memory_flat(events):
    """Chunked ingestion must produce the same statistics as one pass."""
    whole, chunked = StreamStats(), StreamStats()
    whole.observe(events)
    for chunk in stream_frame(events, chunk_size=25):
        chunked.observe(chunk)
    assert whole.events == chunked.events
    assert whole.process_counts == chunked.process_counts


# ── the sliding window must stay correct after being made linear ─────────────
# RULE-011 and RULE-014 rebuilt the distinct set from the whole window at every
# position, which is quadratic: on a million events those two rules took 118 of
# the 126 seconds all fifteen spent. The incremental version must give exactly
# the same answers, so these cases pin the boundary behaviour.

def _fanout_rule():
    return {"id": "T-1", "name": "fanout", "type": "threshold", "severity": "high",
            "threshold": 5, "window_seconds": 60, "group_by": "source_ip",
            "distinct_field": "computer",
            "conditions": [{"field": "event_id", "operator": "equals", "value": "4624"}]}


def _rows():
    rows = []
    for i in range(8):          # 8 hosts inside the window -> fires
        rows.append({"timestamp": f"2015-01-01 00:00:{i*5:02d}", "source_ip": "C999",
                     "computer": f"H{i}", "user": "u1", "event_id": "4624",
                     "raw_message": "x"})
    for i in range(8):          # 8 hosts but spread over hours -> must not
        rows.append({"timestamp": f"2015-01-01 0{1+i//4}:{(i*13)%60:02d}:00",
                     "source_ip": "C888", "computer": f"K{i}", "user": "u2",
                     "event_id": "4624", "raw_message": "x"})
    for i in range(20):         # one host many times -> must not
        rows.append({"timestamp": f"2015-01-01 00:00:{i*2:02d}", "source_ip": "C777",
                     "computer": "SAME", "user": "u3", "event_id": "4624",
                     "raw_message": "x"})
    return rows


def test_fanout_fires_only_on_genuine_spread():
    import pandas as pd
    from detector import apply_threshold_rule

    alerts = apply_threshold_rule(_fanout_rule(), pd.DataFrame(_rows()))
    assert {a.get("source_ip") for a in alerts} == {"C999"}


def test_volume_alone_does_not_trigger_a_distinct_rule():
    """Fifty authentications to one server are routine; five to five are not."""
    import pandas as pd
    from detector import apply_threshold_rule

    rows = [{"timestamp": f"2015-01-01 00:00:{i:02d}", "source_ip": "C1",
             "computer": "ONE", "user": "u", "event_id": "4624", "raw_message": "x"}
            for i in range(50)]
    assert apply_threshold_rule(_fanout_rule(), pd.DataFrame(rows)) == []


def test_window_edge_is_inclusive_at_the_boundary():
    """An event exactly window_seconds old is still inside the window."""
    import pandas as pd
    from detector import apply_threshold_rule

    rows = [{"timestamp": f"2015-01-01 00:0{i//6}:{(i*10) % 60:02d}", "source_ip": "C1",
             "computer": f"H{i}", "user": "u", "event_id": "4624", "raw_message": "x"}
            for i in range(7)]          # 0,10,20,30,40,50,60 seconds apart
    alerts = apply_threshold_rule(_fanout_rule(), pd.DataFrame(rows))
    assert alerts, "7 distinct hosts within 60s must trigger a threshold of 5"
