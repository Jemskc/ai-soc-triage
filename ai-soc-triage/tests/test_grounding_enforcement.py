"""Grounding enforced, not merely requested.

The agentic path shipped with the grounding rule written into its prompt and
nothing checking it — the whole anti-hallucination design lived in the
single-shot engine it replaced. A rule the model is asked to follow, with no
check, is the honour system. These pin the check.
"""

import json

import pytest

from agent_tools import ToolBox
from investigator import Investigator


class ScriptedBackend:
    """Replays fixed responses so the loop can be tested without a GPU."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.prompts_seen = []

    def generate_text(self, system, user, max_tokens=0, history=None):
        self.prompts_seen.append(user)
        return self.responses.pop(0) if self.responses else json.dumps({
            "thought": "done", "action": "conclude",
            "verdict": {"verdict": "UNKNOWN", "urgency_score": 1, "confidence": 0.1,
                        "analyst_summary": "fallback", "mitre_technique": "UNKNOWN"},
        })


def conclude(technique, **extra):
    return json.dumps({
        "thought": "concluding", "action": "conclude",
        "verdict": {"verdict": "ESCALATE", "urgency_score": 8, "confidence": 0.9,
                    "analyst_summary": "something happened",
                    "mitre_technique": technique, **extra},
    })


INCIDENT = {"incident_id": "INC-T", "hosts": ["H1"], "users": ["u1"],
            "event_ids": ["10"], "processes": ["lsass.exe"], "signals": []}


class FakeKB:
    def search(self, query, top_k=5):
        return [{"id": "attack:T1003.001", "title": "T1003.001 — LSASS Memory",
                 "text": "T1003.001 adversaries dump credentials from LSASS."}]


# The investigator also refuses to conclude before establishing asset context,
# so every scripted run satisfies that gate first — otherwise it would consume
# the response under test.
ASSET_STEP = json.dumps({"thought": "what is this host",
                         "action": "query_asset", "args": {"name": "H1"}})


def build(responses, kb=None):
    tools = ToolBox(None, kb, allow_ask_human=False, assets=FakeInventory())
    return Investigator(ScriptedBackend([ASSET_STEP] + list(responses)),
                        tools, max_steps=8), tools


class FakeInventory:
    def lookup(self, name):
        return {"found": True, "name": name, "criticality": "standard",
                "role": "workstation"}


def test_citation_without_any_retrieval_is_rejected():
    """The agent never called search_knowledge, so nothing supports the claim."""
    agent, _ = build([conclude("T1486 - Data Encrypted for Impact"),
                      conclude("UNKNOWN")])
    result = agent.run(INCIDENT)
    rejected = [s for s in result.steps if "never called" in str(s.get("observation", ""))]
    assert rejected, "a citation with no retrieval should be rejected"
    assert result.verdict["mitre_technique"] == "UNKNOWN"


def test_rejection_names_what_was_retrieved():
    """A refusal has to be actionable: tell the agent what it may cite."""
    search = json.dumps({"thought": "look", "action": "search_knowledge",
                         "args": {"query": "lsass"}})
    agent, _ = build([search, conclude("T1486 - Data Encrypted"),
                      conclude("T1003.001 - LSASS Memory")], kb=FakeKB())
    result = agent.run(INCIDENT)
    rejection = next(s for s in result.steps
                     if "did not come back" in str(s.get("observation", "")))
    assert "attack:T1003.001" in rejection["observation"]


def test_citation_backed_by_retrieval_is_accepted():
    search = json.dumps({"thought": "look it up", "action": "search_knowledge",
                         "args": {"query": "lsass credential dumping"}})
    agent, _ = build([search, conclude("T1003.001 - LSASS Memory")], kb=FakeKB())
    result = agent.run(INCIDENT)
    assert result.complete
    assert result.verdict["mitre_technique"].startswith("T1003.001")
    assert result.ungrounded_citations == []
    assert any(c["id"] == "attack:T1003.001" for c in result.grounded_in)


def test_citing_something_other_than_what_was_retrieved_is_rejected():
    search = json.dumps({"thought": "look it up", "action": "search_knowledge",
                         "args": {"query": "lsass"}})
    agent, _ = build([search, conclude("T1486 - Data Encrypted for Impact"),
                      conclude("T1003.001 - LSASS Memory")], kb=FakeKB())
    result = agent.run(INCIDENT)
    assert result.verdict["mitre_technique"].startswith("T1003.001")


def test_unknown_is_always_acceptable():
    """Declining to attribute must never be blocked — it is the honest answer
    when retrieval gives nothing."""
    agent, _ = build([conclude("UNKNOWN")])
    result = agent.run(INCIDENT)
    assert result.complete
    assert result.ungrounded_citations == []


def test_incomplete_verdict_is_rejected_once():
    bad = json.dumps({"thought": "x", "action": "conclude",
                      "verdict": {"verdict": "ESCALATE"}})
    agent, _ = build([bad, conclude("UNKNOWN")])
    result = agent.run(INCIDENT)
    assert result.complete
    assert any("missing required fields" in str(s.get("observation", ""))
               for s in result.steps)


def test_enforcement_does_not_loop_forever():
    """A stubborn model must end the investigation, not burn the whole budget
    being told the same thing."""
    agent, _ = build([conclude("T1486")] * 6)
    result = agent.run(INCIDENT)
    rejections = [s for s in result.steps
                  if "did not come back" in str(s.get("observation", ""))
                  or "never called" in str(s.get("observation", ""))]
    assert len(rejections) <= 1, "each rejection should fire at most once"


def test_grounding_is_reported_on_the_result():
    search = json.dumps({"thought": "x", "action": "search_knowledge",
                         "args": {"query": "lsass"}})
    agent, _ = build([search, conclude("T1003.001 - LSASS Memory")], kb=FakeKB())
    payload = agent.run(INCIDENT).to_dict()
    assert "grounded_in" in payload and "ungrounded_citations" in payload


# --- step budget ------------------------------------------------------------
# Measured failure: 8 tools against an 8-step budget meant a thorough agent
# spent every step gathering and had none left to conclude. 28 of 40 real
# investigations hit the cap and were forced to UNKNOWN despite having gathered
# ample evidence — the product looked broken because of an arithmetic mistake
# in the budget, not because the model was weak.

def test_budget_exceeds_the_number_of_tools():
    """A thorough agent must be able to use every tool and still conclude."""
    from agent_tools import ToolBox
    from investigator import CONCLUDE_RESERVE, DEFAULT_MAX_STEPS

    tool_count = len(ToolBox(None, None).names())
    assert DEFAULT_MAX_STEPS - CONCLUDE_RESERVE >= tool_count, (
        f"{DEFAULT_MAX_STEPS} steps minus {CONCLUDE_RESERVE} reserved leaves "
        f"fewer than the {tool_count} available tools"
    )


def test_tools_are_withdrawn_in_the_reserve_window():
    """Telling a model it is low on budget is advice it can ignore, and did.
    Removing the tool list is what actually forces a conclusion."""
    from agent_tools import ToolBox
    from investigator import Investigator

    agent = Investigator(ScriptedBackend([]), ToolBox(None, None), max_steps=6)
    normal = agent._system(must_conclude=False)
    forced = agent._system(must_conclude=True)
    assert "query_identity" in normal
    assert "query_identity" not in forced
    assert "conclude" in forced.lower()


def test_a_tool_call_in_the_reserve_window_is_refused():
    from agent_tools import ToolBox
    from investigator import Investigator

    tool_call = json.dumps({"thought": "one more", "action": "query_identity",
                            "args": {"user": "u"}})
    responses = [ASSET_STEP] + [tool_call] * 8 + [conclude("UNKNOWN")]
    agent = Investigator(ScriptedBackend(responses),
                         ToolBox(None, None, allow_ask_human=False,
                                 assets=FakeInventory()),
                         max_steps=6)
    result = agent.run(INCIDENT)
    assert any("No tools remain" in str(s.get("observation", ""))
               for s in result.steps)


def test_orchestrator_gives_the_agent_enough_steps():
    import inspect

    from orchestrator import Orchestrator

    source = inspect.getsource(Orchestrator.run_case)
    assert "max_steps=12" in source, "orchestrator must not re-impose a tight budget"


# ── verdict provenance ────────────────────────────────────────────────────────
# Verdicts survive restarts via Autopilot._restore, so a result set can span two
# builds without anything on the record saying so. That actually happened: 7
# verdicts read "within 8 steps" while the code said 12, and they were being
# reported as current behaviour.

def test_verdict_records_the_build_that_produced_it():
    from investigator import CODE_VERSION, Investigation

    result = Investigation(incident_id="INC-1", max_steps=12)
    payload = result.to_dict()
    assert payload["produced_by"]["code_version"] == CODE_VERSION
    assert payload["produced_by"]["max_steps"] == 12


def test_provenance_lets_a_stale_verdict_be_rejected():
    from investigator import CODE_VERSION, Investigation

    fresh = Investigation(incident_id="INC-1", max_steps=12)
    stale = {"produced_by": {"code_version": "2026.09.12-8step", "max_steps": 8}}

    rows = [fresh.to_dict(), stale]
    current = [r for r in rows
               if (r.get("produced_by") or {}).get("code_version") == CODE_VERSION]
    assert len(current) == 1
