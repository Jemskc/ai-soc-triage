"""Prompt assembly for the tab-aware SOC engine.

Every model call is composed from the same layers rather than hand-written:

    IDENTITY + PRODUCT SURFACE + GROUND RULES
      + RETRIEVED KNOWLEDGE + EVIDENCE + TAB TASK + SCHEMA + FEW SHOT

Keeping assembly in one place means a ground rule added here applies to every
tab at once, and a tab's output shape is only ever declared in tab_contracts.py.
"""

from __future__ import annotations

import json
import re
from typing import Any

from tab_contracts import TabContract, product_surface_block

# --- Layer 1: who the model is ----------------------------------------------

IDENTITY = (
    "You are the analysis engine inside a Security Operations Center platform. "
    "You do the work of a senior Tier-2 SOC analyst: you read security telemetry, "
    "decide what is a real threat, and tell the analyst what to do about it."
)

# --- Layer 2: the rules that keep it honest ---------------------------------
# These exist because the system they replaced defaulted every unrecognised event
# to T1190, presenting a guess as an attribution.

GROUND_RULES = """\
NON-NEGOTIABLE RULES:

1. GROUNDING. You may only cite an ATT&CK technique ID that appears verbatim in
   the KNOWLEDGE section below. If the technique you have in mind is not there,
   output "UNKNOWN". Never recall a technique ID from memory. A wrong ID is worse
   than no ID, because the analyst will act on it.

2. EVIDENCE. Every judgement must point at specific log fields from the EVIDENCE
   section. Quote the actual field name and observed value. If you cannot point at
   a field, you do not have grounds for the judgement.

3. ADMIT UNCERTAINTY. If the evidence does not support a conclusion, say UNKNOWN
   and state what additional data you would need. An honest UNKNOWN is a correct
   answer. A confident guess is a failure.

4. CITE. Populate "sources" with the exact chunk ids from the KNOWLEDGE section
   that you actually used. Do not list a source you did not rely on.

5. CALIBRATE. "confidence" reflects the evidence, not your fluency. Thin evidence
   means low confidence even when the story is plausible.

6. OUTPUT. Return one valid JSON object and nothing else. No markdown fences, no
   commentary before or after, no trailing text.\
"""


# Knowledge is stored in full because BM25 scores better with the complete text,
# but injected truncated. Full ATT&CK entries run to 7.5k characters and six of
# them overflow the attention budget: a V100 has no flash-attention kernel, so
# SDPA materialises the whole attention matrix and a ~11k-token prompt tries to
# allocate 9 GiB in one go. The head of a technique entry carries the
# identification signal; the tail is mostly procedure examples.
MAX_CHUNK_CHARS = 900
MAX_CHUNKS = 4
MAX_EVIDENCE_CHARS = 4000


def _truncate(text: str, limit: int) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    # Prefer a sentence boundary so the model never reads a severed clause.
    boundary = max(cut.rfind(". "), cut.rfind("\n"))
    if boundary > limit * 0.6:
        cut = cut[: boundary + 1]
    return cut.rstrip() + " […]"


def _knowledge_block(chunks: list[dict[str, Any]]) -> str:
    """Render retrieved KB chunks with the ids the model must cite."""
    if not chunks:
        return (
            "KNOWLEDGE:\n"
            "(nothing retrieved — you therefore may not cite any technique ID; "
            "use UNKNOWN)"
        )
    parts = ["KNOWLEDGE (the only facts you may cite):"]
    for c in chunks[:MAX_CHUNKS]:
        text = _truncate(c.get("text", ""), MAX_CHUNK_CHARS)
        parts.append(f"\n[{c['id']}] {c.get('title', '')}\n{text}")
    return "\n".join(parts)


def _evidence_block(evidence: dict[str, Any]) -> str:
    rendered = json.dumps(evidence, indent=2, default=str)
    return "EVIDENCE:\n" + _truncate(rendered, MAX_EVIDENCE_CHARS)


def _few_shot_block(contract: TabContract) -> str:
    if not contract.few_shot:
        return ""
    parts = ["EXAMPLES:"]
    for ex in contract.few_shot:
        parts.append(
            f"Input: {json.dumps(ex.get('input'), default=str)}\n"
            f"Output: {json.dumps(ex.get('output'), default=str)}"
        )
    return "\n\n".join(parts)


def build_system_prompt(contract: TabContract) -> str:
    """The system turn: identity, the product it drives, and the rules."""
    return "\n\n".join(
        [IDENTITY, product_surface_block(), GROUND_RULES]
    )


def build_user_prompt(
    contract: TabContract,
    evidence: dict[str, Any],
    knowledge: list[dict[str, Any]] | None = None,
    extra_instruction: str = "",
) -> str:
    """The user turn: knowledge, evidence, the task, and the required shape."""
    sections = [
        _knowledge_block(knowledge or []),
        _evidence_block(evidence),
        f"TASK ({contract.label} tab):\n{contract.analyst_question}",
    ]
    if extra_instruction:
        sections.append(extra_instruction)
    few_shot = _few_shot_block(contract)
    if few_shot:
        sections.append(few_shot)
    sections.append(
        "Respond with exactly this JSON object:\n" + contract.schema_block()
    )
    return "\n\n".join(sections)


# --- Two-pass reasoning (#5) -------------------------------------------------
# Pass A extracts what matters and says what it needs to look up; the retrieval
# layer uses that to fetch better knowledge; pass B judges with that knowledge in
# hand. Cheap at incident scale and markedly better than one-shot.

EVIDENCE_PASS_SYSTEM = (
    IDENTITY
    + "\n\nYou are doing the first of two passes: evidence extraction. You are not "
    "judging yet. Extract what happened and say what you need to look up."
)

EVIDENCE_PASS_SCHEMA = """\
{
  "what_happened": <2 sentences, strictly factual, no interpretation>,
  "key_fields": <array of the log field names that carry the signal>,
  "actors": {"hosts": [], "users": [], "processes": []},
  "lookup_terms": <array of 3-6 search terms for the knowledge base: event ids,
                   process names, technique names, suspicious command tokens>
}\
"""


def build_evidence_pass(evidence: dict[str, Any]) -> tuple[str, str]:
    user = "\n\n".join(
        [
            _evidence_block(evidence),
            "Extract the facts and name what should be looked up.",
            "Respond with exactly this JSON object:\n" + EVIDENCE_PASS_SCHEMA,
            "Return one valid JSON object and nothing else.",
        ]
    )
    return EVIDENCE_PASS_SYSTEM, user


# --- Response parsing and schema enforcement (#40) ---------------------------


class SchemaViolation(ValueError):
    """Raised when a model response does not satisfy its tab contract."""


_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)


def extract_json(raw: str) -> dict[str, Any]:
    """Pull a JSON object out of a model response.

    Tolerates code fences and leading prose, because a strict parse failure that
    silently falls back to a default would quietly fabricate benchmark results.
    """
    text = _FENCE.sub("", raw.strip())
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    if start == -1:
        raise SchemaViolation(f"no JSON object in response: {raw[:200]!r}")

    depth, in_string, escaped = 0, False, False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start : i + 1])
                except json.JSONDecodeError as exc:
                    raise SchemaViolation(f"malformed JSON object: {exc}") from exc
    raise SchemaViolation(f"unterminated JSON object in response: {raw[:200]!r}")


def validate(contract: TabContract, payload: dict[str, Any]) -> dict[str, Any]:
    """Enforce the tab contract. Raises rather than filling in defaults."""
    missing = contract.required_keys() - set(payload)
    if missing:
        raise SchemaViolation(
            f"{contract.tab_id}: missing required keys {sorted(missing)}"
        )
    return payload


def check_grounding(
    payload: dict[str, Any], knowledge: list[dict[str, Any]]
) -> list[str]:
    """Return technique IDs cited that were not in the retrieved knowledge.

    This is the anti-hallucination gate. A non-empty return means the model broke
    ground rule 1 and the verdict's attribution cannot be trusted.
    """
    allowed = set()
    for chunk in knowledge or []:
        allowed.update(re.findall(r"T\d{4}(?:\.\d{3})?", chunk.get("text", "")))
        allowed.update(re.findall(r"T\d{4}(?:\.\d{3})?", chunk.get("id", "")))
        allowed.update(re.findall(r"T\d{4}(?:\.\d{3})?", chunk.get("title", "")))

    cited = set(re.findall(r"T\d{4}(?:\.\d{3})?", json.dumps(payload, default=str)))
    return sorted(cited - allowed)
