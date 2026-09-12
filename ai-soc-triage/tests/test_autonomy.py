"""Graduated autonomy.

These encode the two rules an org must be able to rely on absolutely: a
crown-jewel asset is never auto-closed, and nothing that changes production
state happens without a person. Everything else is tunable policy; these two
are not, and a test failing here is a governance failure, not a bug.
"""

from pathlib import Path

import pytest

import autonomy
from autonomy import Band, Policy, classify_action, decide, gate_actions


def d(risk=0.0, verdict="ESCALATE", confidence=0.8, crit="standard", prior=None,
      policy=None, confirmed=True):
    """confirmed defaults to True so tests exercising banding are not all
    blocked by the precedent rule; the precedent tests set it explicitly."""
    return decide({"risk_score": risk}, {"verdict": verdict, "confidence": confidence},
                  crit, prior, policy, precedent_confirmed_by_human=confirmed)


# --- the two non-negotiables ----------------------------------------------

def test_crown_jewel_is_never_auto_closed():
    """On a domain controller the cost of a wrong close is not proportional to
    its likelihood, however confident the agent is."""
    decision = d(risk=1.0, verdict="SUPPRESS", confidence=1.0,
                 crit="crown_jewel", prior="benign")
    assert decision.band is not Band.AUTO_CLOSE
    assert any("crown-jewel" in o for o in decision.overrides)


@pytest.mark.parametrize("step", [
    "Isolate host PC01 from the network",
    "Disable the account svc_backup",
    "Reset credentials for Administrator",
    "Block 10.0.0.5 at the perimeter",
    "Kill the process tree on DC1",
    "Rebuild the affected server",
])
def test_state_changing_actions_always_need_a_human(step):
    permissive = decide({"risk_score": 5}, {"verdict": "SUPPRESS", "confidence": 0.99},
                        "low", "benign", precedent_confirmed_by_human=True)
    assert permissive.band is Band.AUTO_CLOSE
    assert permissive.requires_approval is False
    # ...and yet:
    gated = gate_actions([{"phase": "contain", "step": step}], permissive)[0]
    assert gated["destructive"] is True
    assert gated["requires_approval"] is True


def test_non_destructive_actions_follow_the_band():
    permissive = decide({"risk_score": 5}, {"verdict": "SUPPRESS", "confidence": 0.99},
                        "low", "benign", precedent_confirmed_by_human=True)
    gated = gate_actions([{"phase": "recover", "step": "Document the finding"}],
                         permissive)[0]
    assert gated["destructive"] is False
    assert gated["requires_approval"] is False


# --- banding ---------------------------------------------------------------

def test_auto_close_requires_confidence_low_risk_and_precedent():
    assert d(risk=10, verdict="SUPPRESS", confidence=0.9, prior="benign").band \
        is Band.AUTO_CLOSE
    # each condition removed in turn must block it
    assert d(risk=90, verdict="SUPPRESS", confidence=0.9, prior="benign").band \
        is not Band.AUTO_CLOSE
    assert d(risk=10, verdict="SUPPRESS", confidence=0.2, prior="benign").band \
        is not Band.AUTO_CLOSE
    assert d(risk=10, verdict="SUPPRESS", confidence=0.9, prior=None).band \
        is not Band.AUTO_CLOSE


def test_blocked_auto_close_explains_itself():
    """An analyst asking 'why wasn't this closed?' needs a specific reason."""
    decision = d(risk=10, verdict="SUPPRESS", confidence=0.9, prior=None)
    assert decision.overrides
    assert any("previously ruled case" in o for o in decision.overrides)


def test_crown_jewel_escalates_even_at_modest_risk():
    decision = d(risk=30, verdict="ESCALATE", confidence=0.5, crit="crown_jewel")
    assert decision.band is Band.ESCALATE
    assert "on_call" in decision.notify


def test_high_risk_escalates_regardless_of_asset():
    assert d(risk=85, crit="low").band is Band.ESCALATE


def test_low_confidence_defers_to_a_human_either_way():
    """An agent that is unsure must not act in either direction."""
    decision = d(risk=45, verdict="ESCALATE", confidence=0.2)
    assert decision.band is Band.AUTO_ENRICH
    assert any("confidence" in r for r in decision.reasons)


def test_default_is_enrich_not_act():
    assert d(risk=40, verdict="ESCALATE", confidence=0.6).band is Band.AUTO_ENRICH


def test_every_decision_carries_a_reason():
    for kwargs in ({}, {"risk": 90}, {"verdict": "SUPPRESS", "prior": "benign", "risk": 5},
                   {"crit": "crown_jewel"}, {"confidence": 0.1}):
        assert d(**kwargs).reasons, f"no reason given for {kwargs}"


def test_policy_is_tunable_but_overrides_are_not():
    loose = Policy(auto_close_max_risk=65.0, auto_close_min_confidence=0.1,
                   auto_close_requires_prior_case=False)
    # policy can be loosened...
    assert d(risk=60, verdict="SUPPRESS", confidence=0.2, policy=loose).band \
        is Band.AUTO_CLOSE
    # ...but not past the crown-jewel rule
    assert d(risk=60, verdict="SUPPRESS", confidence=0.2, crit="crown_jewel",
             policy=loose).band is not Band.AUTO_CLOSE


def test_high_risk_outranks_a_low_confidence_suppression():
    """A deterministic risk of 90 beats the agent saying 'probably fine' at 20%
    confidence. The fused score is evidence the agent does not get to discard."""
    assert d(risk=90, verdict="SUPPRESS", confidence=0.2).band is Band.ESCALATE


# --- precedent poisoning ----------------------------------------------------
# The agent records its own rulings to case memory, and auto-close requires a
# matching precedent. Without separating human-confirmed rulings from the
# agent's own, one wrong SUPPRESS becomes the justification for auto-closing
# every similar case after it — the system bootstraps a mistake into policy.

def test_agents_own_precedent_cannot_unlock_auto_close():
    decision = decide({"risk_score": 5}, {"verdict": "SUPPRESS", "confidence": 0.99},
                      "standard", "benign", precedent_confirmed_by_human=False)
    assert decision.band is not Band.AUTO_CLOSE
    assert any("agent itself" in o for o in decision.overrides)


def test_human_confirmed_precedent_does_unlock_auto_close():
    decision = decide({"risk_score": 5}, {"verdict": "SUPPRESS", "confidence": 0.99},
                      "standard", "benign", precedent_confirmed_by_human=True)
    assert decision.band is Band.AUTO_CLOSE
    assert any("analyst-confirmed" in r for r in decision.reasons)


def test_confirmation_does_not_bypass_the_crown_jewel_rule():
    decision = decide({"risk_score": 5}, {"verdict": "SUPPRESS", "confidence": 0.99},
                      "crown_jewel", "benign", precedent_confirmed_by_human=True)
    assert decision.band is not Band.AUTO_CLOSE


# ── the suppression veto ──────────────────────────────────────────────────────
# Measured on 12 suppressions from a real run: 6 hid genuine attack evidence.
# The agent's confidence did not separate them — 0.6 appeared on three misses
# and five correct closures — so the judgement is removed rather than tuned.

_MIMIKATZ_INCIDENT = {
    "incident_id": "INC-TEST",
    "rules_fired": [
        {"rule": "Mimikatz Credential Dumping Behavior", "count": 2},
        {"rule": "Lateral Movement via PsExec", "count": 1},
    ],
    "processes": ["C:\\Windows\\PSEXESVC.exe", "C:\\Windows\\System32\\lsass.exe"],
}


def test_suppression_is_overturned_when_detections_say_hands_on():
    decision = autonomy.decide(
        {"risk_score": 20.0},
        {"verdict": "SUPPRESS", "confidence": 0.95},
        asset_criticality="standard",
        similar_case_outcome="benign",
        precedent_confirmed_by_human=True,
        incident=_MIMIKATZ_INCIDENT,
    )
    # Even at 95% confidence with a human-confirmed precedent — every door to
    # auto-close open — the case must reach a person.
    assert decision.band is autonomy.Band.ESCALATE
    assert decision.requires_approval
    assert any("overridden" in o for o in decision.overrides)


def test_veto_does_not_fire_on_behavioural_only_incidents():
    # The five misses that carried no runtime signal are indistinguishable from
    # correct suppressions. The veto must not pretend otherwise by firing on
    # ordinary behavioural rarity — that would just block every closure.
    decision = autonomy.decide(
        {"risk_score": 20.0},
        {"verdict": "SUPPRESS", "confidence": 0.8},
        asset_criticality="standard",
        similar_case_outcome="benign",
        precedent_confirmed_by_human=True,
        incident={"rules_fired": [{"rule": "Behavioural: rare lineage"}],
                  "processes": ["C:\\Windows\\System32\\svchost.exe"]},
    )
    assert decision.band is autonomy.Band.AUTO_CLOSE


def test_hands_on_evidence_reads_rules_and_processes():
    found = autonomy.hands_on_evidence(_MIMIKATZ_INCIDENT)
    assert any("Mimikatz" in f for f in found)
    assert any("psexesvc.exe" in f for f in found)
    assert autonomy.hands_on_evidence({}) == []
    assert autonomy.hands_on_evidence(None) == []


def test_veto_uses_only_signals_available_at_inference_time():
    # Guards against label leakage: the corpus tactic column separates these
    # cases far better, but it is ground truth and does not exist at runtime.
    src = (Path(__file__).resolve().parents[1] / "src" / "autonomy.py").read_text()
    assert "EVTX_Tactic" not in src
