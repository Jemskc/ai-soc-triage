"""Single source of truth for what the AI must produce for each dashboard tab.

The frontend already treats `soc-sentinel/src/data/navConfig.js` as the one place
tabs are declared. This is the server-side counterpart: every tab that renders AI
output declares here the question it answers, the exact JSON it needs back, and
what knowledge should be retrieved before the model answers.

Adding a tab means adding a contract. The prompt builder, the pipeline and the
response validator all read from this registry, so nothing else needs to change.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

# How often a contract is evaluated.
#   INCIDENT — once per correlated incident (fan-out across all incidents)
#   CAMPAIGN — once per analysis run, over the set of incident summaries
SCOPE_INCIDENT = "incident"
SCOPE_CAMPAIGN = "campaign"


@dataclass(frozen=True)
class TabContract:
    """What one dashboard tab needs from the AI."""

    tab_id: str
    label: str
    scope: str
    analyst_question: str
    output_schema: dict[str, str]
    retrieval_hints: list[str] = field(default_factory=list)
    token_budget: int = 700
    few_shot: list[dict[str, Any]] = field(default_factory=list)

    def schema_block(self) -> str:
        """Render the schema as an annotated JSON skeleton for the prompt."""
        lines = ["{"]
        items = list(self.output_schema.items())
        for i, (key, description) in enumerate(items):
            comma = "," if i < len(items) - 1 else ""
            lines.append(f'  "{key}": <{description}>{comma}')
        lines.append("}")
        return "\n".join(lines)

    def required_keys(self) -> set[str]:
        return set(self.output_schema)


# --- Shared schema fragments -------------------------------------------------
# Every verdict-bearing contract carries these, so the UI can render grounding
# and confidence uniformly and the validator can enforce them in one place.

_GROUNDING = {
    "confidence": "float 0.0-1.0, how certain you are given the evidence",
    "sources": "array of knowledge-base chunk ids you actually used, e.g. [\"attack:T1003.001\"]",
}


TAB_CONTRACTS: dict[str, TabContract] = {
    "alerts": TabContract(
        tab_id="alerts",
        label="Alerts",
        scope=SCOPE_INCIDENT,
        analyst_question=(
            "Is this incident a real threat or noise, how urgent is it, and what "
            "should the analyst do in the next ten minutes?"
        ),
        output_schema={
            "verdict": "one of ESCALATE, SUPPRESS, UNKNOWN",
            "urgency_score": "integer 0-10, 10 = active hands-on-keyboard intrusion",
            "severity_confirmed": "one of critical, high, medium, low",
            "analyst_summary": "2 sentences, plain English: what happened and why it matters",
            "evidence": "array of the specific log fields that justify the verdict, each as "
                        "{\"field\": name, \"value\": observed value, \"why\": significance}",
            "false_positive_likelihood": "one of high, medium, low",
            "false_positive_reason": "brief reason, or empty string",
            "mitre_technique": "technique in the form 'T1003.001 - LSASS Memory', taken from the "
                               "retrieved context only. Use the technique ID, never the chunk id "
                               "prefix. If the retrieved context does not cover it, write UNKNOWN",
            "recommended_actions": "array of 3 concrete actions, most urgent first",
            "investigation_steps": "array of 3 next steps to confirm or rule out",
            **_GROUNDING,
        },
        retrieval_hints=[
            "attack technique detection guidance",
            "windows event id meaning and benign baseline",
            "lolbas binary abuse",
        ],
        token_budget=750,
    ),
    "overview": TabContract(
        tab_id="overview",
        label="Overview",
        scope=SCOPE_CAMPAIGN,
        analyst_question=(
            "If I just walked in, what is going on across this environment right now "
            "and what do I deal with first?"
        ),
        output_schema={
            "headline": "one sentence a CISO would accept as the situation summary",
            "campaign_narrative": "3-5 sentences telling the story across incidents in order",
            "is_single_campaign": "true if these incidents look like one intrusion, else false",
            "top_priorities": "array of 3 {\"incident_id\", \"why\", \"action\"}, most urgent first",
            "blast_radius": "{\"hosts\": [], \"users\": [], \"assessment\": \"one sentence\"}",
            **_GROUNDING,
        },
        retrieval_hints=["attack tactic sequencing", "kill chain phases"],
        token_budget=800,
    ),
    # A second Overview framing, written for a reader with no security
    # background: an executive, an asset owner, someone on call at 3am. Kept as
    # a separate contract rather than a rewrite of "overview" because the
    # technical summary and the plain-language one serve different readers and
    # both are wanted on the same screen.
    "overview_plain": TabContract(
        tab_id="overview_plain",
        label="Plain-Language Summary",
        scope=SCOPE_CAMPAIGN,
        analyst_question=(
            "Explain what is happening to someone with no security background, "
            "so they understand the situation and what is being asked of them."
        ),
        output_schema={
            "one_line": "the whole situation in one sentence a non-technical "
                        "reader understands, no jargon, no acronyms",
            "what_happened": "3-4 sentences in plain English. Use analogies to "
                             "everyday things where they genuinely help. Never use "
                             "MITRE IDs, tool names, or security jargon here",
            "how_bad_is_it": "one of 'routine', 'worth watching', 'serious', "
                             "'urgent' — plus one sentence explaining the choice",
            "what_it_means_for_us": "2 sentences on the practical consequence: what "
                                    "could stop working, what information is at risk",
            "what_we_are_doing": "array of 2-3 plain-English actions already underway",
            "what_we_need_from_you": "array of 0-3 decisions or approvals needed from "
                                     "the reader, in plain English. Empty if none",
            "confidence_in_plain_english": "one sentence on how sure we are and why, "
                                           "avoiding percentages",
            **_GROUNDING,
        },
        retrieval_hints=["attack mitigations"],
        token_budget=800,
    ),
    "investigations": TabContract(
        tab_id="investigations",
        label="Investigations",
        scope=SCOPE_CAMPAIGN,
        analyst_question="How did the attacker get in, what did they do, and in what order?",
        output_schema={
            "chain": "array of kill-chain stages in time order, each "
                     "{\"stage\", \"tactic\", \"technique\", \"incident_id\", \"narrative\", \"timestamp\"}",
            "entry_point": "the earliest attacker action you can evidence, or UNKNOWN",
            "current_stage": "how far along the kill chain the attacker reached",
            "pivots": "array of 3 suggested pivots: what to look at next and why",
            **_GROUNDING,
        },
        retrieval_hints=["attack tactic sequencing", "technique relationships"],
        token_budget=1000,
    ),
    "hunting": TabContract(
        tab_id="hunting",
        label="Threat Hunting",
        scope=SCOPE_CAMPAIGN,
        analyst_question="What should I go looking for that the rules did not already catch?",
        output_schema={
            "hypotheses": "array of 4 {\"hypothesis\", \"rationale\", \"query\", \"technique\"} "
                          "where query uses the dashboard syntax, e.g. host = DC01 severity = high",
            **_GROUNDING,
        },
        retrieval_hints=["attack technique detection guidance", "data sources for detection"],
        token_budget=800,
    ),
    "assets": TabContract(
        tab_id="assets",
        label="Assets",
        scope=SCOPE_CAMPAIGN,
        analyst_question="Which machines and accounts are most at risk, and why?",
        output_schema={
            "assets": "array of {\"name\", \"kind\": host|user, \"risk_score\": 0-10, "
                      "\"reason\": one sentence, \"incident_ids\": []} sorted by risk",
            **_GROUNDING,
        },
        retrieval_hints=["privilege escalation", "lateral movement", "credential access"],
        token_budget=800,
    ),
    "playbooks": TabContract(
        tab_id="playbooks",
        label="Playbooks",
        scope=SCOPE_INCIDENT,
        analyst_question="What is the response procedure for this specific incident?",
        output_schema={
            "playbook_name": "short name for the procedure",
            "contain": "array of immediate containment steps",
            "eradicate": "array of steps to remove attacker access",
            "recover": "array of steps to restore normal operation",
            "escalate_to": "who to notify, e.g. IR lead, legal, asset owner",
            **_GROUNDING,
        },
        retrieval_hints=["incident response playbook", "attack mitigations"],
        token_budget=550,
    ),
    "reports": TabContract(
        tab_id="reports",
        label="Reports",
        scope=SCOPE_CAMPAIGN,
        analyst_question="What do I tell leadership about this, in language they act on?",
        output_schema={
            "executive_summary": "4-6 sentences, no jargon, impact-focused",
            "what_happened": "array of 3-5 factual bullets",
            "business_impact": "2 sentences on what this means operationally",
            "recommendations": "array of 3 prioritised recommendations",
            **_GROUNDING,
        },
        retrieval_hints=["attack mitigations"],
        token_budget=900,
    ),
    "logs": TabContract(
        tab_id="logs",
        label="Logs Explorer",
        scope=SCOPE_INCIDENT,
        analyst_question="What does this individual log event actually mean?",
        output_schema={
            "significance": "one of noteworthy, routine, unknown",
            "explanation": "2 sentences explaining the event in plain English",
            "benign_explanation": "the most likely innocent cause, or empty string",
            **_GROUNDING,
        },
        retrieval_hints=["windows event id meaning and benign baseline"],
        token_budget=400,
    ),
    "email": TabContract(
        tab_id="email",
        label="Email Analysis",
        scope=SCOPE_INCIDENT,
        analyst_question="Is this email a phishing attempt, and did anyone act on it?",
        output_schema={
            "verdict": "one of PHISHING, SUSPICIOUS, BENIGN, UNKNOWN",
            "risk_score": "integer 0-100",
            "indicators": "array of {\"indicator\", \"why\"} drawn from headers, body or URLs",
            "linked_host_activity": "array of incident_ids that plausibly followed this email, or []",
            "recommended_actions": "array of 3 actions",
            **_GROUNDING,
        },
        retrieval_hints=["phishing", "initial access", "user execution"],
        token_budget=700,
    ),
}


def get_contract(tab_id: str) -> TabContract:
    if tab_id not in TAB_CONTRACTS:
        known = ", ".join(sorted(TAB_CONTRACTS))
        raise KeyError(f"No AI contract for tab '{tab_id}'. Known tabs: {known}")
    return TAB_CONTRACTS[tab_id]


def contracts_for_scope(scope: str) -> list[TabContract]:
    return [c for c in TAB_CONTRACTS.values() if c.scope == scope]


def product_surface_block() -> str:
    """Describe every tab to the model, so it knows where its output lands.

    This is what turns nine independent prompt calls into one engine with a view
    of the whole product.
    """
    lines = [
        "You power a SOC dashboard. Your output is rendered directly in these tabs:",
    ]
    for c in TAB_CONTRACTS.values():
        lines.append(f"  - {c.label} ({c.scope}-level): {c.analyst_question}")
    lines.append(
        "An analyst reads your answer and acts on it. Anything you invent will be "
        "acted on as if it were evidence."
    )
    return "\n".join(lines)


def as_json() -> str:
    """Expose the registry to the frontend so tabs can render schema-driven."""
    return json.dumps(
        {
            tid: {
                "tab_id": c.tab_id,
                "label": c.label,
                "scope": c.scope,
                "analyst_question": c.analyst_question,
                "keys": sorted(c.required_keys()),
            }
            for tid, c in TAB_CONTRACTS.items()
        },
        indent=2,
    )
