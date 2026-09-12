"""The anti-hallucination gate.

A technique cited without retrieval support is the failure mode this whole
design exists to prevent, so it is checked in code rather than trusted to the
prompt.
"""

import pytest

import prompts
from tab_contracts import get_contract

KNOWLEDGE = [
    {"id": "attack:T1003.001", "title": "T1003.001 — LSASS Memory",
     "text": "T1003.001 Adversaries may attempt to access credential material "
             "stored in LSASS process memory."},
]


def test_cited_technique_present_in_knowledge_passes():
    payload = {"mitre_technique": "T1003.001 - LSASS Memory"}
    assert prompts.check_grounding(payload, KNOWLEDGE) == []


def test_cited_technique_absent_from_knowledge_is_flagged():
    payload = {"mitre_technique": "T1486 - Data Encrypted for Impact"}
    assert prompts.check_grounding(payload, KNOWLEDGE) == ["T1486"]


def test_no_knowledge_means_any_citation_is_ungrounded():
    """With retrieval empty the model must say UNKNOWN; anything else is
    recalled from weights and unverifiable."""
    assert prompts.check_grounding({"mitre_technique": "T1055"}, []) == ["T1055"]


def test_unknown_is_not_flagged():
    assert prompts.check_grounding({"mitre_technique": "UNKNOWN"}, []) == []


def test_grounding_checks_nested_fields():
    payload = {"recommended_actions": ["Check for T1486 ransomware activity"]}
    assert "T1486" in prompts.check_grounding(payload, KNOWLEDGE)


def test_empty_knowledge_block_instructs_unknown():
    block = prompts._knowledge_block([])
    assert "UNKNOWN" in block


def test_knowledge_block_is_truncated():
    """Full ATT&CK entries run to 7.5k characters; six untruncated chunks
    overflow the attention budget and OOM the card."""
    fat = [{"id": f"attack:T{1000+i}", "title": "t", "text": "word " * 2000}
           for i in range(6)]
    block = prompts._knowledge_block(fat)
    assert len(block) < 6000


def test_only_max_chunks_are_injected():
    many = [{"id": f"attack:T{1000+i}", "title": "t", "text": "short"} for i in range(10)]
    block = prompts._knowledge_block(many)
    assert block.count("[attack:") == prompts.MAX_CHUNKS


def test_extract_json_handles_code_fences():
    assert prompts.extract_json('```json\n{"a": 1}\n```') == {"a": 1}


def test_extract_json_handles_leading_prose():
    assert prompts.extract_json('Here you go:\n{"a": 1}') == {"a": 1}


def test_extract_json_raises_rather_than_defaulting():
    """A silent fallback here would quietly fabricate benchmark results."""
    with pytest.raises(prompts.SchemaViolation):
        prompts.extract_json("no json at all")


def test_validate_rejects_missing_keys():
    contract = get_contract("alerts")
    with pytest.raises(prompts.SchemaViolation):
        prompts.validate(contract, {"verdict": "ESCALATE"})


def test_system_prompt_names_every_tab():
    """The model is told the whole product surface exists — that is what makes
    it one engine rather than nine disconnected calls."""
    system = prompts.build_system_prompt(get_contract("alerts"))
    for label in ("Alerts", "Overview", "Investigations", "Playbooks"):
        assert label in system
