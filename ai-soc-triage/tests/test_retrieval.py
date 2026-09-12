"""Retrieval quality gates.

Grounding is only as good as what comes back, so these pin the two behaviours
that took the most tuning: landing on the right technique, and returning
nothing rather than noise.
"""

import pytest

import correlator
from knowledge_base import KnowledgeBase, tokenize


@pytest.fixture(scope="module")
def kb():
    try:
        return KnowledgeBase(use_dense=False)
    except FileNotFoundError:
        pytest.skip("knowledge base not built; run scripts/build_kb.py")


def test_security_identifiers_survive_tokenization():
    """Splitting on dots would destroy sub-technique ids and file names."""
    tokens = tokenize("T1003.001 lsass.exe rundll32.exe 4625")
    assert "t1003.001" in tokens
    assert "lsass.exe" in tokens
    assert "4625" in tokens


@pytest.mark.parametrize("keys,expected", [
    (dict(event_ids=["10", "1"], processes=["lsass.exe", "mimikatz.exe"],
          terms=["credential dumping lsass memory"]), "T1003"),
    (dict(event_ids=["5145", "7045"], processes=["psexec.exe"],
          terms=["remote service creation admin share lateral movement"]), "T1021"),
    (dict(event_ids=["1"], processes=["powershell.exe"],
          terms=["encoded base64 powershell command"]), "T1059"),
    (dict(event_ids=["13"], terms=["registry run key persistence autostart"]), "T1547"),
    (dict(event_ids=["4769"], terms=["kerberos service ticket rc4 kerberoasting"]), "T1558"),
])
def test_incident_retrieves_correct_technique(kb, keys, expected):
    ids = [c["id"] for c in kb.search_structured(top_k=6, **keys)]
    assert any(expected in i for i in ids), f"expected {expected}, got {ids}"


def test_irrelevant_query_returns_nothing(kb):
    """Retrieving nothing is the correct outcome for an unrecognised incident:
    the grounding rule turns it into UNKNOWN rather than a fabricated citation."""
    assert kb.search("zzzz qqqq gibberish", top_k=3) == []


def test_single_term_match_is_not_grounding(kb):
    """A chunk matching one rare term can outscore a chunk matching three
    relevant ones, which is how an unrelated technique gets presented as
    evidence. Coverage, not score, is what rules it out."""
    results = kb.search_structured(terms=["zzzz qqqq gibberish"], top_k=3)
    assert results == []


def test_event_id_lookup_finds_the_event_reference(kb):
    ids = [c["id"] for c in kb.search("event id 5145 network share access", top_k=5)]
    assert "winevent:5145" in ids


def test_every_technique_chunk_carries_its_tactics(kb):
    """The Response Agent resolves technique -> tactic -> playbook, so tactics
    must be populated or it falls back to the wrong procedure."""
    techniques = [c for c in kb.chunks if c["kind"] == "attack_technique"]
    assert len(techniques) > 500
    with_tactics = [c for c in techniques if c.get("tactics")]
    assert len(with_tactics) / len(techniques) > 0.95


def test_playbook_exists_for_every_tactic_seen(kb):
    """Every tactic the corpus can produce needs a matching playbook chunk."""
    tactics = {t for c in kb.chunks if c["kind"] == "attack_technique"
               for t in c.get("tactics", [])}
    covered = {c["id"].split(":", 1)[1] for c in kb.chunks if c["kind"] == "playbook"}
    core = {"credential access", "lateral movement", "persistence",
            "privilege escalation", "defense evasion", "command and control",
            "execution", "discovery"}
    for tactic in core & tactics:
        assert tactic.replace(" ", "-") in covered, f"no playbook for {tactic}"


def test_scores_are_comparable_across_queries(kb):
    """search_structured merges sub-queries, so it needs an absolute signal;
    a pure rank score would make weak hits outrank strong ones."""
    hits = kb.search("credential dumping lsass memory", top_k=3)
    assert all("lexical" in h for h in hits)
    assert hits[0]["lexical"] > 0


# ── command-line retrieval terms ──────────────────────────────────────────────
# The command line is where the LOLBAS signal lives. Before this, /enrich/event
# sent a fixed query string to the knowledge base, so `rundll32.exe
# advpack.dll,RegisterOCX` retrieved five unrelated Windows event chunks and the
# model — correctly — said it had nothing to go on.

def test_commandline_terms_surface_lolbas_tokens():
    terms = correlator.commandline_terms(
        r"rundll32.exe advpack.dll,RegisterOCX payload.dll")
    assert "rundll32.exe" in terms
    assert "advpack.dll" in terms
    assert "registerocx" in terms


def test_commandline_terms_strip_path_noise():
    terms = correlator.commandline_terms(r'"C:\Windows\System32\cmd.exe" /c whoami')
    assert "whoami" in terms
    # Path scaffolding carries no retrieval signal and would crowd out the rest.
    assert "windows" not in terms and "system32" not in terms


def test_commandline_terms_empty_input_yields_nothing():
    # The caller falls back to the contract hint; it must not get [''] instead.
    assert correlator.commandline_terms("") == []


def test_commandline_terms_are_bounded_and_unique():
    terms = correlator.commandline_terms(" ".join(f"tok{i}.exe" for i in range(30)))
    assert len(terms) <= 6
    assert len(terms) == len(set(terms))
