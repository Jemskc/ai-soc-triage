"""Ground-truth performance measurement, per feature.

Every tab that makes a claim gets scored against labels, so the dashboard can
show accuracy, precision, recall, F1, false positives/negatives and confidence
calibration rather than asserting that it works.

The honest part, stated in the output and not buried:

    This corpus is 100% malicious. Every event comes from an attack sample.
    That makes RECALL computable (did we catch the attack?) but PRECISION is
    NOT (we have no benign traffic, so a false positive is undefined here).
    Any tool reporting a precision or F1 for binary detection on this data is
    reporting a number it cannot know.

What IS fully computable is multi-class tactic attribution: given that an
incident is an attack of tactic X, did we say X? That has real precision,
recall and F1 per class, because a wrong class is a genuine false positive for
that class. Those are reported without caveat.

Feeding in benign logs makes the binary metrics computable too; `benign_events`
switches them on automatically.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

# Metrics we cannot compute are reported as unavailable, with the reason,
# rather than silently omitted or filled with a plausible number.
NOT_COMPUTABLE = "not_computable"


@dataclass
class ClassMetrics:
    label: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    support: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "tp": self.tp, "fp": self.fp, "fn": self.fn,
            "support": self.support,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1": round(self.f1, 3),
        }


def _macro(classes: Iterable[ClassMetrics]) -> dict[str, float]:
    items = list(classes)
    if not items:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    return {
        "precision": round(sum(c.precision for c in items) / len(items), 3),
        "recall": round(sum(c.recall for c in items) / len(items), 3),
        "f1": round(sum(c.f1 for c in items) / len(items), 3),
    }


def _weighted(classes: Iterable[ClassMetrics]) -> dict[str, float]:
    items = [c for c in classes if c.support]
    total = sum(c.support for c in items)
    if not total:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    return {
        k: round(sum(getattr(c, k) * c.support for c in items) / total, 3)
        for k in ("precision", "recall", "f1")
    }


# The corpus was labelled against the 2019 ATT&CK tactic list; the knowledge
# base is built from the current spec, which split "Defense Evasion" into
# "stealth" and "defense impairment". Comparing the two vocabularies directly
# scores every correct defense-evasion attribution as wrong — a label-space
# mismatch masquerading as a model failure. Both sides are normalised to one
# canonical space before anything is compared.
TACTIC_ALIASES = {
    "stealth": "defense evasion",
    "defense impairment": "defense evasion",
    "defence evasion": "defense evasion",
    "privilege-escalation": "privilege escalation",
    "credential-access": "credential access",
    "lateral-movement": "lateral movement",
    "command and control": "command and control",
    "command-and-control": "command and control",
}


def normalize_tactic(value: str) -> str:
    name = str(value or "").strip().lower().replace("-", " ").replace("_", " ")
    return TACTIC_ALIASES.get(name, name)


# --------------------------------------------------------------------------
# Detection coverage — did the funnel surface the attack at all?
# --------------------------------------------------------------------------

def score_detection(
    df,
    incidents: list[dict[str, Any]],
    benign_sample_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Recall at attack-sample level; precision only if benign data exists.

    This is the ceiling on everything downstream: an attack the funnel never
    surfaces cannot be triaged, attributed or responded to, however good the
    agents are.
    """
    all_samples = set(df["source_file"].dropna().unique()) if "source_file" in df else set()
    benign = benign_sample_ids or set()
    attack_samples = all_samples - benign

    detected_by: dict[str, set[str]] = {"rules": set(), "analytics": set()}
    for inc in incidents:
        for alert in inc.get("sample_alerts", []):
            src = alert.get("source_file")
            if not src:
                continue
            key = "analytics" if alert.get("detection_source") == "analytics" else "rules"
            detected_by[key].add(src)

    detected = detected_by["rules"] | detected_by["analytics"]
    tp = len(detected & attack_samples)
    fn = len(attack_samples - detected)
    fp = len(detected & benign)

    result = {
        "unit": "attack sample (EVTX file)",
        "attack_samples": len(attack_samples),
        "detected": tp,
        "missed": fn,
        "recall": round(tp / len(attack_samples), 3) if attack_samples else 0.0,
        "by_source": {
            "rules_only": len(detected_by["rules"] - detected_by["analytics"]),
            "analytics_only": len(detected_by["analytics"] - detected_by["rules"]),
            "both": len(detected_by["rules"] & detected_by["analytics"]),
        },
        "rules_recall": round(len(detected_by["rules"] & attack_samples) /
                              len(attack_samples), 3) if attack_samples else 0.0,
    }

    if benign:
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = result["recall"]
        result.update({
            "benign_samples": len(benign),
            "false_positives": fp,
            "precision": round(precision, 3),
            "f1": round(2 * precision * recall / (precision + recall), 3)
            if (precision + recall) else 0.0,
        })
    else:
        result.update({
            "precision": NOT_COMPUTABLE,
            "f1": NOT_COMPUTABLE,
            "false_positives": NOT_COMPUTABLE,
            "why": (
                "Every sample in this corpus is malicious, so there is no "
                "benign traffic against which a false positive could occur. "
                "Precision and F1 become computable as soon as benign logs are "
                "ingested."
            ),
        })
    return result


# --------------------------------------------------------------------------
# Tactic attribution — fully computable, multi-class
# --------------------------------------------------------------------------

def score_tactic_attribution(
    incidents: list[dict[str, Any]],
    verdicts: dict[str, Any],
    technique_tactics: dict[str, list[str]],
) -> dict[str, Any]:
    """Per-tactic precision/recall/F1 and a confusion matrix.

    Genuinely computable: predicting 'credential access' for a lateral movement
    incident is a real false positive for credential access, no benign data
    required.
    """
    import re

    classes: dict[str, ClassMetrics] = defaultdict(lambda: ClassMetrics(""))
    confusion: Counter = Counter()
    unattributed = 0
    not_analysed = 0
    scored = 0

    for inc in incidents:
        truth = [normalize_tactic(t) for t in inc.get("ground_truth_tactics", [])]
        if not truth:
            continue

        record = verdicts.get(inc["incident_id"])
        # An incident the AI never looked at is pending, not wrong. Counting it
        # as a miss would report a model failure for work that was never
        # attempted — the exact kind of misleading metric this module exists to
        # prevent. Excluded from the denominator and reported separately.
        if not record or not (record.get("payload") or {}):
            not_analysed += 1
            continue

        primary = truth[0]
        classes[primary].label = primary
        classes[primary].support += 1

        payload = record.get("payload") or {}
        match = re.search(r"T\d{4}(?:\.\d{3})?", str(payload.get("mitre_technique", "")))
        if not match:
            # Analysed, but declined to attribute — a real UNKNOWN, which is a
            # miss for the true class but not a false positive for any other.
            unattributed += 1
            classes[primary].fn += 1
            confusion[(primary, "unattributed")] += 1
            continue

        predicted = [normalize_tactic(t) for t in technique_tactics.get(match.group(0), [])]
        scored += 1
        if any(p in truth for p in predicted):
            classes[primary].tp += 1
            confusion[(primary, primary)] += 1
        else:
            classes[primary].fn += 1
            wrong = predicted[0] if predicted else "unknown"
            classes[wrong].label = wrong
            classes[wrong].fp += 1
            confusion[(primary, wrong)] += 1

    per_class = [c.to_dict() for c in sorted(classes.values(), key=lambda c: -c.support)]
    total_tp = sum(c.tp for c in classes.values())
    total = sum(c.support for c in classes.values())

    return {
        "unit": "incident",
        "label_granularity": "sample-level",
        "metric_is_a_proxy": True,
        "why": (
            "Ground truth is the tactic folder each EVTX sample is filed under, "
            "which describes the attack's overall goal. The AI attributes the "
            "technique visible in the specific correlated events. These "
            "legitimately differ: a sample filed under Persistence that achieves "
            "it by dumping credentials contains genuine credential-access "
            "events, and calling them that is correct even though it scores as "
            "a miss here. Read the confusion matrix as a diagnostic, not as an "
            "accuracy figure. A fair score needs event-level technique labels, "
            "which this corpus does not carry."
        ),
        "scored": scored,
        "unattributed": unattributed,
        "not_analysed": not_analysed,
        "coverage": round(
            (scored + unattributed) / max(1, scored + unattributed + not_analysed), 3
        ),
        "accuracy": round(total_tp / total, 3) if total else 0.0,
        "macro": _macro(classes.values()),
        "weighted": _weighted(classes.values()),
        "per_class": per_class,
        "confusion": [
            {"truth": t, "predicted": p, "count": n}
            for (t, p), n in confusion.most_common()
        ],
    }


# --------------------------------------------------------------------------
# Triage verdicts
# --------------------------------------------------------------------------

def score_triage(
    incidents: list[dict[str, Any]],
    verdicts: dict[str, Any],
    benign_incident_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Escalation behaviour against ground truth."""
    benign = benign_incident_ids or set()
    counts = Counter()
    not_analysed = 0
    tp = fp = fn = tn = 0

    for inc in incidents:
        record = verdicts.get(inc["incident_id"])
        if not record or not (record.get("payload") or {}):
            not_analysed += 1
            continue
        payload = record.get("payload") or {}
        verdict = str(payload.get("verdict", "")).upper() or "NO_VERDICT"
        counts[verdict] += 1
        is_attack = inc["incident_id"] not in benign
        escalated = verdict == "ESCALATE"
        if is_attack and escalated:
            tp += 1
        elif is_attack and not escalated:
            fn += 1
        elif not is_attack and escalated:
            fp += 1
        else:
            tn += 1

    attacks = tp + fn
    result = {
        "unit": "incident",
        "verdicts": dict(counts),
        "not_analysed": not_analysed,
        "coverage": round(
            sum(counts.values()) / max(1, sum(counts.values()) + not_analysed), 3
        ),
        "attacks": attacks,
        "escalated_attacks": tp,
        "missed_attacks": fn,
        "recall": round(tp / attacks, 3) if attacks else 0.0,
    }
    if benign:
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = result["recall"]
        result.update({
            "benign_incidents": len(benign),
            "false_positives": fp,
            "true_negatives": tn,
            "precision": round(precision, 3),
            "f1": round(2 * precision * recall / (precision + recall), 3)
            if (precision + recall) else 0.0,
            "accuracy": round((tp + tn) / (tp + tn + fp + fn), 3)
            if (tp + tn + fp + fn) else 0.0,
        })
    else:
        result.update({
            "precision": NOT_COMPUTABLE,
            "f1": NOT_COMPUTABLE,
            "suppression_rate": round(counts.get("SUPPRESS", 0) / max(1, sum(counts.values())), 3),
            "why": (
                "No benign incidents in this corpus, so an escalation can never "
                "be wrong here and precision is undefined. The suppression rate "
                "is reported instead and needs a human spot-check to interpret."
            ),
        })
    return result


# --------------------------------------------------------------------------
# Confidence calibration
# --------------------------------------------------------------------------

def score_calibration(
    incidents: list[dict[str, Any]],
    verdicts: dict[str, Any],
    technique_tactics: dict[str, list[str]],
    bins: int = 5,
) -> dict[str, Any]:
    """Is stated confidence worth anything?

    A model that says 90% and is right 90% of the time is useful; one that says
    90% and is right half the time is worse than one that says nothing, because
    an analyst will defer to it. Brier score plus reliability bins.
    """
    import re

    points: list[tuple[float, int]] = []
    for inc in incidents:
        truth = [normalize_tactic(t) for t in inc.get("ground_truth_tactics", [])]
        record = verdicts.get(inc["incident_id"])
        if not record:
            continue
        payload = record.get("payload") or {}
        confidence = payload.get("confidence")
        if not truth or confidence is None:
            continue
        try:
            conf = max(0.0, min(1.0, float(confidence)))
        except (TypeError, ValueError):
            continue
        match = re.search(r"T\d{4}(?:\.\d{3})?", str(payload.get("mitre_technique", "")))
        predicted = [normalize_tactic(t) for t in
                     technique_tactics.get(match.group(0), [])] if match else []
        correct = int(any(p in truth for p in predicted))
        points.append((conf, correct))

    if not points:
        return {"available": False, "why": "no verdicts carried a usable confidence"}

    brier = sum((c - o) ** 2 for c, o in points) / len(points)
    buckets: list[dict[str, Any]] = []
    for i in range(bins):
        lo, hi = i / bins, (i + 1) / bins
        chunk = [(c, o) for c, o in points if (lo <= c < hi or (i == bins - 1 and c == 1.0))]
        if not chunk:
            continue
        mean_conf = sum(c for c, _ in chunk) / len(chunk)
        actual = sum(o for _, o in chunk) / len(chunk)
        buckets.append({
            "range": f"{lo:.0%}-{hi:.0%}",
            "n": len(chunk),
            "stated_confidence": round(mean_conf, 3),
            "actual_accuracy": round(actual, 3),
            "gap": round(mean_conf - actual, 3),
        })

    overconfidence = sum(b["gap"] * b["n"] for b in buckets) / len(points)
    return {
        "available": True,
        "samples": len(points),
        "brier_score": round(brier, 4),
        "overconfidence": round(overconfidence, 3),
        "interpretation": (
            "positive overconfidence means stated confidence exceeds measured "
            "accuracy; 0 is perfectly calibrated"
        ),
        "bins": buckets,
    }


# --------------------------------------------------------------------------
# Grounding integrity
# --------------------------------------------------------------------------

def score_grounding(verdicts: dict[str, Any], cases: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """How often the anti-hallucination rule actually held."""
    total = ungrounded = no_sources = 0
    for record in verdicts.values():
        total += 1
        if record.get("ungrounded_techniques"):
            ungrounded += 1
        payload = record.get("payload") or {}
        if not payload.get("sources"):
            no_sources += 1

    for case in cases or []:
        for agent in (case.get("agents") or {}).values():
            if agent.get("ungrounded"):
                ungrounded += 1

    return {
        "verdicts": total,
        "ungrounded_citations": ungrounded,
        "verdicts_without_sources": no_sources,
        "grounding_rate": round(1 - ungrounded / total, 3) if total else 1.0,
    }


# --------------------------------------------------------------------------

def score_all(
    df,
    incidents: list[dict[str, Any]],
    verdicts: dict[str, Any],
    technique_tactics: dict[str, list[str]],
    cases: list[dict[str, Any]] | None = None,
    benign_sample_ids: set[str] | None = None,
    benign_incident_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Per-feature scorecard, keyed by the tab it belongs to."""
    has_benign = bool(benign_sample_ids or benign_incident_ids)
    return {
        "has_benign_baseline": has_benign,
        "caveat": None if has_benign else (
            "No benign logs have been ingested. Recall and multi-class tactic "
            "metrics are exact; binary precision and F1 are marked "
            "not_computable rather than estimated."
        ),
        "by_feature": {
            "detection": score_detection(df, incidents, benign_sample_ids),
            "triage": score_triage(incidents, verdicts, benign_incident_ids),
            # Reported as a diagnostic: see `metric_is_a_proxy` on the result.
            "mitre": score_tactic_attribution(incidents, verdicts, technique_tactics),
            "confidence": score_calibration(incidents, verdicts, technique_tactics),
            "grounding": score_grounding(verdicts, cases),
        },
    }
