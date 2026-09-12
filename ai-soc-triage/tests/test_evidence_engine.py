"""Evidence Engine.

The property that matters most here is the distinction between "checked and
found nothing" and "cannot see this domain at all".
"""

import pandas as pd
import pytest

from evidence_engine import DOMAINS, EvidenceEngine


@pytest.fixture
def df():
    return pd.DataFrame([
        {"timestamp": "2024-01-01T12:00:00", "event_id": "4624", "computer": "PC01",
         "user": "alice", "source_ip": "10.0.0.5", "logon_type": "3",
         "process_name": "", "command_line": "", "share_name": ""},
        {"timestamp": "2024-01-01T12:01:00", "event_id": "1", "computer": "PC01",
         "user": "alice", "source_ip": "", "logon_type": "",
         "process_name": "powershell.exe", "command_line": "-enc AAA", "share_name": ""},
        {"timestamp": "2024-01-01T12:02:00", "event_id": "5145", "computer": "PC01",
         "user": "alice", "source_ip": "10.0.0.9", "logon_type": "",
         "process_name": "", "command_line": "", "share_name": "ADMIN$"},
        {"timestamp": "2024-01-01T12:03:00", "event_id": "4720", "computer": "PC01",
         "user": "alice", "source_ip": "", "logon_type": "",
         "process_name": "", "command_line": "", "share_name": ""},
    ])


@pytest.fixture
def incident():
    return {"incident_id": "INC-1", "hosts": ["PC01"], "users": ["alice"],
            "first_seen": "2024-01-01T12:00:00", "last_seen": "2024-01-01T12:03:00"}


def test_all_architecture_domains_are_represented():
    engine = EvidenceEngine()
    assert set(engine.adapters) == set(DOMAINS)


def test_unconnected_domains_are_declared_not_empty(incident):
    """An empty result and an absent source must not look the same."""
    result = EvidenceEngine(None).investigate(incident)
    for evidence in result.values():
        assert evidence.connected is False
        assert "No data source connected" in evidence.summary
        assert evidence.note


def test_connected_domains_return_evidence(df, incident):
    result = EvidenceEngine(df).investigate(incident)
    assert result["endpoint"].connected and result["endpoint"].records
    assert result["identity"].connected and result["identity"].records
    assert result["network"].connected and result["network"].records
    assert result["ad"].connected and result["ad"].records


def test_domains_without_a_connector_stay_unconnected(df, incident):
    result = EvidenceEngine(df).investigate(incident)
    for domain in ("cloud", "saas", "firewall", "dns", "email"):
        assert result[domain].connected is False


def test_coverage_reports_blind_spots(df):
    coverage = EvidenceEngine(df).coverage()
    assert set(coverage["connected"]) == {"endpoint", "identity", "network", "ad"}
    assert set(coverage["not_connected"]) == {"cloud", "saas", "firewall", "dns", "email"}
    assert 0 < coverage["coverage_ratio"] < 1


def test_scope_excludes_unrelated_assets(df, incident):
    other = dict(incident, hosts=["PC99"], users=["bob"])
    result = EvidenceEngine(df).investigate(other)
    assert not result["endpoint"].records


def test_summary_separates_no_findings_from_no_connector(df, incident):
    engine = EvidenceEngine(df)
    summary = engine.summarize(engine.investigate(incident))
    assert "endpoint" in summary["domains_with_evidence"]
    assert set(summary["domains_not_connected"]) >= {"cloud", "saas"}
    assert "cloud" not in summary["domains_with_evidence"]


def test_identity_adapter_surfaces_failed_logons(incident):
    df = pd.DataFrame([
        {"timestamp": "2024-01-01T12:00:00", "event_id": "4625", "computer": "PC01",
         "user": "alice", "source_ip": "10.0.0.5", "logon_type": "3",
         "process_name": "", "command_line": "", "share_name": ""}
    ] * 5)
    result = EvidenceEngine(df).investigate(incident)
    assert "failed logon" in result["identity"].summary
