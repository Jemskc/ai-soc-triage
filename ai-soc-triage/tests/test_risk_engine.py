"""The Risk Engine is deterministic, so it is the part that must be provable.

These tests pin the properties the scoring depends on: reproducibility, the
inability of any one factor to escalate a case alone, and honest degradation
when agents fail.
"""

import pytest

import risk_engine
from orchestrator import Case


def make_case(severity="critical", urgency=8, confidence=0.9,
              attribution="strong", technique="T1003.001 - LSASS Memory",
              domains=("endpoint", "identity", "network"),
              hosts=("HOST1",), users=("user1",), alerts=10):
    case = Case(incident={
        "incident_id": "INC-TEST",
        "severity": severity,
        "hosts": list(hosts),
        "users": list(users),
        "alert_count": alerts,
    })
    case.domain_summary = {
        "domains_with_evidence": {d: "" for d in domains},
        "domains_not_connected": [],
    }
    case.agent_results = {}
    case._payloads = {
        "triage": {"urgency_score": urgency, "confidence": confidence},
        "intel": {"attribution_strength": attribution,
                  "technique_assessment": technique, "confidence": confidence},
    }
    case.agent_payload = lambda name: case._payloads.get(name)
    return case


def test_weights_sum_to_100():
    assert sum(risk_engine.WEIGHTS.values()) == 100


def test_scoring_is_deterministic():
    """Same inputs must always produce the same score, or an analyst cannot
    trust a change in score to mean a change in evidence."""
    scores = {risk_engine.score_case(make_case()).score for _ in range(5)}
    assert len(scores) == 1


def test_score_within_bounds():
    high = risk_engine.score_case(make_case())
    low = risk_engine.score_case(make_case(
        severity="low", urgency=0, confidence=0.0,
        attribution="weak", technique="UNKNOWN", domains=(), alerts=1))
    assert 0 <= low.score <= high.score <= 100


def test_no_single_factor_can_escalate_alone():
    """A maxed-out rule severity with nothing else must not reach critical."""
    case = make_case(severity="critical", urgency=0, confidence=0.0,
                     attribution="weak", technique="UNKNOWN",
                     domains=(), hosts=("H",), users=("u",), alerts=1)
    verdict = risk_engine.score_case(case)
    assert verdict.band != "critical"


def test_cross_domain_corroboration_raises_score():
    one = risk_engine.score_case(make_case(domains=("endpoint",)))
    three = risk_engine.score_case(make_case(domains=("endpoint", "identity", "network")))
    assert three.score > one.score


def test_low_confidence_damps_but_does_not_erase_urgency():
    """Under-reacting to a possible intrusion is the worse error, so a
    low-confidence high-urgency call must still contribute."""
    unsure = risk_engine.score_case(make_case(urgency=9, confidence=0.0))
    sure = risk_engine.score_case(make_case(urgency=9, confidence=1.0))
    unsure_pts = next(f.points for f in unsure.factors if f.name == "triage_urgency")
    sure_pts = next(f.points for f in sure.factors if f.name == "triage_urgency")
    assert 0 < unsure_pts < sure_pts


def test_unknown_technique_caps_attribution():
    verdict = risk_engine.score_case(make_case(attribution="strong", technique="UNKNOWN"))
    attribution = next(f for f in verdict.factors if f.name == "intel_attribution")
    assert attribution.normalized <= 0.25
    assert any("technique" in c.lower() for c in verdict.caveats)


def test_missing_agent_output_degrades_gracefully():
    """A failed agent must lower the score and raise a caveat, never crash."""
    case = Case(incident={"incident_id": "INC-X", "severity": "high",
                          "hosts": [], "users": [], "alert_count": 1})
    case.domain_summary = {"domains_with_evidence": {}, "domains_not_connected": ["cloud"]}
    case.agent_payload = lambda name: None
    verdict = risk_engine.score_case(case)
    assert verdict.score >= 0
    assert verdict.caveats


def test_factor_points_sum_to_score():
    """The decomposition shown in the UI must actually add up to the score."""
    verdict = risk_engine.score_case(make_case())
    assert verdict.score == pytest.approx(sum(f.points for f in verdict.factors))


def test_unconnected_domains_raise_a_caveat():
    case = make_case()
    case.domain_summary["domains_not_connected"] = ["cloud", "saas"]
    verdict = risk_engine.score_case(case)
    assert any("connector" in c for c in verdict.caveats)


@pytest.mark.parametrize("score,expected", [(95, "critical"), (70, "high"),
                                            (40, "medium"), (10, "low")])
def test_bands_are_ordered(score, expected):
    band = next(b for threshold, b, _, _ in risk_engine.BANDS if score >= threshold)
    assert band == expected
