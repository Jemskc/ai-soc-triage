"""How well each detection rule is actually doing, and what a change would cost.

Rule tuning is permanent work in a real SOC, and it is done badly almost
everywhere because the feedback loop is missing: nobody knows which rules earn
their noise. This computes that, and then lets a proposed fix be tested before
anyone applies it.

Two things are kept strictly apart:

**Counting is deterministic.** Fire counts, overlap, silence and coverage are
arithmetic and must be exact and reproducible. No model touches them.

**Precision needs labels, and the agent's own opinion is not a label.** If the
agent suppresses a rule's alerts and that counts as evidence the rule is noisy,
the agent's mistake becomes a rule change that blinds detection permanently —
the same trap as precedent poisoning in case memory, with worse consequences
because a deleted detection is invisible. Precision is therefore computed from
analyst-confirmed outcomes only, and anything else is reported as provisional.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

# Below this many analyst decisions, a precision figure is noise.
MIN_CONFIRMED_FOR_PRECISION = 5

# A rule firing more than this share of all alerts is carrying the queue.
DOMINANCE_THRESHOLD = 0.30


@dataclass
class RuleStats:
    rule_id: str
    name: str = ""
    severity: str = ""
    technique: str = ""

    fired: int = 0
    incidents: set[str] = field(default_factory=set)
    sole_detector: set[str] = field(default_factory=set)
    co_fires_with: Counter = field(default_factory=Counter)

    escalated: int = 0
    suppressed: int = 0
    unknown: int = 0

    analyst_confirmed_malicious: int = 0
    analyst_confirmed_benign: int = 0

    def to_dict(self) -> dict[str, Any]:
        confirmed = self.analyst_confirmed_malicious + self.analyst_confirmed_benign
        judged = self.escalated + self.suppressed

        record: dict[str, Any] = {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "technique": self.technique,
            "fired": self.fired,
            "incidents": len(self.incidents),
            # Incidents no other rule caught. A rule with zero unique
            # contribution is redundant however often it fires.
            "unique_contribution": len(self.sole_detector),
            "overlaps_with": [r for r, _ in self.co_fires_with.most_common(3)],
            "agent_escalated": self.escalated,
            "agent_suppressed": self.suppressed,
            "analyst_confirmed": confirmed,
        }

        if confirmed >= MIN_CONFIRMED_FOR_PRECISION:
            record["precision"] = round(
                self.analyst_confirmed_malicious / confirmed, 3)
            record["precision_basis"] = "analyst-confirmed"
        else:
            record["precision"] = None
            record["precision_basis"] = (
                f"provisional — only {confirmed} analyst decision(s); the "
                "agent's own verdicts are not evidence for tuning"
            )
            if judged:
                record["agent_suppression_rate"] = round(self.suppressed / judged, 3)

        record["verdict"] = self._assess(confirmed, judged)
        return record

    def _assess(self, confirmed: int, judged: int) -> dict[str, Any]:
        """A plain reading, with the confidence it deserves."""
        if self.fired == 0:
            return {
                "label": "silent",
                "detail": "never fired — either broken, or nothing in this "
                          "estate matches it. Worth confirming which.",
                "confidence": "high",
                "action": "review",
            }
        if len(self.sole_detector) == 0 and len(self.incidents) > 0:
            return {
                "label": "redundant",
                "detail": f"every incident it caught was also caught by "
                          f"{', '.join(list(self.co_fires_with)[:2]) or 'another rule'}",
                "confidence": "high",
                "action": "consider retiring",
            }
        if confirmed >= MIN_CONFIRMED_FOR_PRECISION:
            precision = self.analyst_confirmed_malicious / confirmed
            if precision < 0.2:
                return {"label": "noisy", "confidence": "high", "action": "tune",
                        "detail": f"analysts ruled {self.analyst_confirmed_benign} "
                                  f"of {confirmed} benign"}
            if precision > 0.8:
                return {"label": "high value", "confidence": "high", "action": "keep",
                        "detail": f"analysts confirmed {self.analyst_confirmed_malicious} "
                                  f"of {confirmed} malicious"}
            return {"label": "mixed", "confidence": "medium", "action": "review",
                    "detail": f"precision {precision:.0%} over {confirmed} decisions"}
        if judged and self.suppressed / judged > 0.8:
            return {
                "label": "possibly noisy",
                "detail": f"the agent suppressed {self.suppressed} of {judged}, "
                          "but no analyst has confirmed any of them",
                "confidence": "low",
                "action": "get analyst review before tuning",
            }
        return {"label": "insufficient data", "confidence": "low", "action": "wait",
                "detail": f"{self.fired} firings, {confirmed} analyst decisions"}


def compute(rules: list[dict[str, Any]], alerts: list[dict[str, Any]],
            incidents: list[dict[str, Any]], verdicts: dict[str, Any],
            case_memory=None) -> dict[str, Any]:
    """Per-rule performance across one analysis run."""
    stats: dict[str, RuleStats] = {
        r["id"]: RuleStats(r["id"], r.get("name", ""),
                           str(r.get("severity", "")),
                           r.get("mitre_technique", ""))
        for r in rules
    }

    for alert in alerts:
        rid = alert.get("rule_id")
        if rid in stats:
            stats[rid].fired += 1

    confirmed_outcomes: dict[str, str] = {}
    if case_memory is not None:
        for case in getattr(case_memory, "cases", []):
            if case.decided_by == "analyst" or case.analyst_corrected:
                confirmed_outcomes[case.incident_id] = case.outcome

    for incident in incidents:
        iid = incident["incident_id"]
        rule_ids = {a.get("rule_id") for a in incident.get("sample_alerts", [])
                    if a.get("rule_id") in stats}
        if not rule_ids:
            continue

        payload = (verdicts.get(iid) or {}).get("payload") or {}
        verdict = str(payload.get("verdict", "")).upper()
        confirmed = confirmed_outcomes.get(iid)

        for rid in rule_ids:
            entry = stats[rid]
            entry.incidents.add(iid)
            if len(rule_ids) == 1:
                entry.sole_detector.add(iid)
            for other in rule_ids - {rid}:
                entry.co_fires_with[other] += 1

            if verdict == "ESCALATE":
                entry.escalated += 1
            elif verdict == "SUPPRESS":
                entry.suppressed += 1
            elif verdict:
                entry.unknown += 1

            if confirmed == "malicious":
                entry.analyst_confirmed_malicious += 1
            elif confirmed == "benign":
                entry.analyst_confirmed_benign += 1

    records = [s.to_dict() for s in stats.values()]
    records.sort(key=lambda r: -r["fired"])

    total_alerts = sum(r["fired"] for r in records) or 1
    dominant = [r for r in records if r["fired"] / total_alerts > DOMINANCE_THRESHOLD]

    return {
        "rules": records,
        "summary": {
            "total_rules": len(records),
            "fired": sum(1 for r in records if r["fired"]),
            "silent": [r["rule_id"] for r in records if r["fired"] == 0],
            "redundant": [r["rule_id"] for r in records
                          if r["verdict"]["label"] == "redundant"],
            "needs_tuning": [r["rule_id"] for r in records
                             if r["verdict"]["action"] == "tune"],
            "dominant": [{"rule_id": r["rule_id"],
                          "share": round(r["fired"] / total_alerts, 3)}
                         for r in dominant],
            "analyst_decisions_available": sum(r["analyst_confirmed"] for r in records),
        },
        "caveat": (
            "Precision is only reported where analysts have confirmed outcomes. "
            "The agent's own verdicts are excluded deliberately: tuning a rule "
            "away on the agent's say-so turns one wrong suppression into a "
            "permanent blind spot."
        ),
    }


# --------------------------------------------------------------------------
# Backtest
# --------------------------------------------------------------------------

def backtest_exclusion(df, rules: list[dict[str, Any]], rule_id: str,
                       field_name: str, pattern: str,
                       incidents: list[dict[str, Any]] | None = None,
                       verdicts: dict[str, Any] | None = None) -> dict[str, Any]:
    """What would this exclusion have cost?

    The question that makes a tuning proposal trustworthy. A change that removes
    90% of a rule's noise is only safe if it does not also remove the firings
    that mattered — and that is answerable against history rather than opinion.
    """
    from detector import _event_matches_rule

    rule = next((r for r in rules if r["id"] == rule_id), None)
    if rule is None:
        return {"error": f"unknown rule {rule_id}"}

    try:
        matcher = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        return {"error": f"invalid pattern: {exc}"}

    # A field the events do not have matches nothing, which previously came
    # back as "removes 0 firings, safe: True" — indistinguishable from a
    # genuinely harmless exclusion. A detection engineer could ship a typo
    # believing the backtest had cleared it. Refuse instead, and say which
    # fields exist.
    if field_name not in df.columns:
        close = sorted(c for c in df.columns
                       if field_name.lower().replace("_", "") in
                       str(c).lower().replace("_", ""))
        return {
            "error": f"unknown field '{field_name}' — the events have no such "
                     f"column, so this exclusion would match nothing",
            "did_you_mean": close[:5],
            "available_fields": sorted(str(c) for c in df.columns)[:40],
        }

    records = df.fillna("").to_dict(orient="records")
    matched = [e for e in records if _event_matches_rule(e, rule)]
    excluded = [e for e in matched
                if matcher.search(str(e.get(field_name, "")))]
    remaining = len(matched) - len(excluded)

    # Which incidents would lose this rule's contribution entirely, and did any
    # of them matter? This is the part that stops a plausible-looking exclusion
    # from deleting a real detection.
    lost_incidents: list[dict[str, Any]] = []
    if incidents:
        excluded_rows = {e.get("_row_index") for e in excluded}
        surviving_rows = {e.get("_row_index") for e in matched} - excluded_rows
        for incident in incidents:
            rows = {a.get("_row_index") for a in incident.get("sample_alerts", [])
                    if a.get("rule_id") == rule_id}
            if rows and not (rows & surviving_rows):
                payload = ((verdicts or {}).get(incident["incident_id"]) or {}).get("payload") or {}
                lost_incidents.append({
                    "incident_id": incident["incident_id"],
                    "verdict": payload.get("verdict"),
                    "hosts": incident.get("hosts", [])[:2],
                })

    escalated_lost = [i for i in lost_incidents
                      if str(i.get("verdict", "")).upper() == "ESCALATE"]

    return {
        "rule_id": rule_id,
        "exclusion": {"field": field_name, "pattern": pattern},
        "alerts_before": len(matched),
        "alerts_removed": len(excluded),
        "alerts_after": remaining,
        "noise_reduction": round(len(excluded) / len(matched), 3) if matched else 0.0,
        "incidents_lost": lost_incidents,
        "escalated_incidents_lost": escalated_lost,
        "safe": not escalated_lost,
        "assessment": (
            f"Removes {len(excluded)} of {len(matched)} firings"
            + (f" but would have lost {len(escalated_lost)} escalated incident(s) — "
               "do not apply" if escalated_lost
               else " and loses no escalated incident.")
        ),
        "sample_excluded": [
            {k: str(v)[:80] for k, v in e.items()
             if k in ("timestamp", "computer", "user", "process_name", "command_line")
             and v}
            for e in excluded[:4]
        ],
    }


def coverage_gaps(rules: list[dict[str, Any]], kb, df) -> dict[str, Any]:
    """ATT&CK techniques with no rule, where the telemetry could support one.

    Listing every uncovered technique is useless — most need data the estate
    does not collect. Only gaps that are actually actionable are reported.
    """
    covered = set()
    for rule in rules:
        for match in re.findall(r"T\d{4}(?:\.\d{3})?", str(rule.get("mitre_technique", ""))):
            covered.add(match)

    observed_events = {str(e) for e in df.get("event_id", [])} if df is not None else set()
    have_process = bool(df is not None and (df.get("process_name", "").astype(str).str.len() > 0).any())
    have_auth = bool(observed_events & {"4624", "4625", "4768", "4769"})

    gaps = []
    for chunk in getattr(kb, "chunks", []):
        tid = chunk.get("technique_id")
        if not tid or tid in covered or chunk.get("kind") != "attack_technique":
            continue
        text = chunk.get("text", "").lower()
        # Only techniques the available telemetry could plausibly detect.
        actionable = (
            (have_process and any(w in text for w in
                                  ("process", "command", "execut", "powershell")))
            or (have_auth and any(w in text for w in
                                  ("logon", "credential", "authentic", "kerberos")))
        )
        if actionable:
            gaps.append({
                "technique_id": tid,
                "title": chunk.get("title", ""),
                "tactics": chunk.get("tactics", []),
            })

    return {
        "covered_techniques": sorted(covered),
        "actionable_gaps": gaps[:25],
        "gap_count": len(gaps),
        "note": (
            "Only techniques the currently-collected telemetry could plausibly "
            "detect are listed. A gap needing data the estate does not collect "
            "is a logging problem, not a rule problem."
        ),
    }
