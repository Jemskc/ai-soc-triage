"""Did the two layers actually do a good job on the data that was imported?

THE PROBLEM THIS SOLVES
-----------------------
A dashboard showing "43 incidents, 401 alerts, 12 verdicts" tells an analyst
how much happened, not whether any of it was right. Those are activity
counters, and activity is not accuracy. The existing /scorecard scored against
the bundled demo corpus regardless of what had been ingested, so after
importing a real file it graded the wrong exam.

WHAT CAN AND CANNOT BE KNOWN
----------------------------
It depends entirely on whether the imported events carry ground truth.

  LABELLED (a corpus like LANL, where red-team activity is marked)
      Everything is computable: recall, precision, base-rate-corrected
      precision, false alarms per day, and whether the AI escalated the
      incidents that actually contained attacks.

  UNLABELLED (a company's real logs)
      None of it is computable, and no amount of dashboard design changes
      that. What can be shown are operational facts — how much was reduced,
      how much reached the model, what it decided — plus whatever analysts
      have since confirmed or overturned. Anything else would be a number
      with nothing behind it.

The distinction is reported explicitly rather than inferred, because a
precision figure with no ground truth under it is the single most misleading
thing this product could display.
"""

from __future__ import annotations

from typing import Any

# Ground-truth markers a corpus may carry. Extended as datasets are added; a
# corpus with none of them is simply unlabelled, which is the normal case.
_ATTACK_MARKERS = ("golden-red", "lanl-auth-red", "-red")
_BENIGN_MARKERS = ("golden-benign", "lanl-auth-benign", "-benign")

SECONDS_PER_DAY = 86400


def _label_of(row: dict[str, Any]) -> int | None:
    """1 attack, 0 benign, None unlabelled.

    A per-row label is read first. Only a corpus that carries none falls back
    to the filename convention — which was the sole method here, so a corpus
    labelled row by row (as golden_sample.jsonl is) was reported as having no
    ground truth at all.
    """
    raw = row.get("_raw") or {}
    for key in ("label", "ground_truth", "is_attack", "malicious"):
        value = row.get(key, raw.get(key))
        if value in (None, "", "nan"):
            continue
        text = str(value).strip().lower()
        if text in ("1", "true", "yes", "attack", "malicious", "red"):
            return 1
        if text in ("0", "false", "no", "benign", "normal"):
            return 0

    marker = str(raw.get("source_file") or row.get("ingestSource") or "").lower()
    if not marker:
        return None
    if any(m in marker for m in _ATTACK_MARKERS):
        return 1
    if any(m in marker for m in _BENIGN_MARKERS):
        return 0
    return None


def _rate(num: int, den: int) -> float | None:
    return num / den if den else None


def score(events: list[dict[str, Any]],
          incidents: list[dict[str, Any]],
          verdicts: dict[str, Any],
          span_days: float = 1.0,
          base_rate: float | None = None) -> dict[str, Any]:
    """Grade both layers against whatever ground truth the events carry."""
    labelled = [(e, lab) for e in events if (lab := _label_of(e)) is not None]
    attacks = sum(1 for _, lab in labelled if lab == 1)

    operational = {
        "events": len(events),
        "incidents": len(incidents),
        "verdicts": len(verdicts),
        "reduction_events_to_incidents": (
            round(len(events) / len(incidents), 1) if incidents else None),
        "share_of_events_reaching_the_model": (
            round(len(verdicts) / len(events), 6) if events else None),
    }

    # Labelled but no attacks yet is NOT the same as unlabelled. Reporting
    # "carries no attack labels" while the corpus is labelled and the attack
    # batch simply has not been published yet is a false statement about the
    # data, and it would send someone looking for a labelling problem that does
    # not exist.
    if labelled and not attacks:
        return {
            "ground_truth": True,
            "attacks_in_data": 0,
            "why": (
                f"{len(labelled):,} labelled events so far and none of them are "
                "attacks. Recall is undefined until at least one attack has been "
                "ingested; anything flagged so far is a false alarm by "
                "definition."
            ),
            "operational": operational,
            "false_alarms_so_far": sum(
                1 for inc in incidents for _ in (inc.get("sample_alerts") or [])),
            "note": "Ingestion may still be in progress — attacks can arrive in a later batch.",
        }

    if not labelled:
        return {
            "ground_truth": False,
            "why": (
                "The imported events carry no attack labels, so recall and "
                "precision are not computable — not low, not unknown-but-"
                "probably-fine: undefined. What follows is what happened, not "
                "how well it went."
            ),
            "operational": operational,
            "how_to_get_a_score": (
                "Import a labelled corpus (ai-soc-eval/golden.jsonl marks "
                "red-team records) or confirm verdicts in the Alerts tab — "
                "analyst decisions become ground truth over time."
            ),
        }

    # ---- Layer 1: did detection surface the attacks at all? --------------
    # Matching is on content, not position.
    #
    # member_row_indices are offsets into the funnel's per-batch dataframe,
    # while EV-N counts cumulatively across every batch. Index 6 of batch five
    # and index 6 of batch one are different rows, so comparing the two spaces
    # reported 0 of 200 attacks caught on data a separate harness had just
    # measured at 100% recall. The identity of an event is what it says, not
    # where it happened to sit in an array.
    # member_row_indices holds EVERY contributing row; sample_alerts is capped
    # at five per incident for prompt size. Scoring against the sample alone
    # under-counts detection massively — a mistake already made once in this
    # project, which reported 0% recall while the rules were firing on every
    # red-team event.
    alerted_rows: set[int] = set()
    for inc in incidents:
        for rid in inc.get("member_row_indices") or []:
            if isinstance(rid, int):
                alerted_rows.add(rid)
        for alert in inc.get("sample_alerts") or []:
            rid = alert.get("_row_index")
            if isinstance(rid, int):
                alerted_rows.add(rid)

    tp = fp = tn = fn = 0
    for event, lab in labelled:
        rid = event.get("rowIndex")
        flagged = isinstance(rid, int) and rid in alerted_rows
        if lab == 1 and flagged: tp += 1
        elif lab == 1: fn += 1
        elif flagged: fp += 1
        else: tn += 1

    precision = _rate(tp, tp + fp)
    recall = _rate(tp, tp + fn)
    layer1 = {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "attacks_in_data": attacks,
        "attacks_caught": tp,
        "attacks_missed": fn,
        "recall": round(recall, 4) if recall is not None else None,
        "sample_precision": round(precision, 4) if precision is not None else None,
        "false_alarms_per_day": round(fp / max(span_days, 1e-9), 1),
    }

    # The correction that decides whether a figure means anything. Malicious
    # events are over-represented in any sampled corpus, so sample precision
    # flatters the detector by roughly the sampling factor.
    if base_rate and precision is not None and tp:
        observed_rate = attacks / len(labelled)
        if observed_rate > 0:
            factor = observed_rate / base_rate
            projected_fp = fp * factor
            corrected = _rate(tp, int(tp + projected_fp))
            layer1["base_rate_corrected"] = {
                "true_base_rate": base_rate,
                "over_represented_by": round(factor, 1),
                "precision": round(corrected, 8) if corrected else None,
                "projected_false_alarms": int(projected_fp),
                "note": ("Sample precision is optimistic by roughly the "
                         "over-representation factor and should never be "
                         "quoted on its own."),
            }

    # ---- Layer 2: did the AI escalate the incidents that mattered? -------
    attack_rows = {r for e, lab in labelled if lab == 1
                   and isinstance(r := e.get("rowIndex"), int)}
    a_tp = a_fp = a_tn = a_fn = 0
    undecided = 0
    for inc in incidents:
        inc_rows = {r for r in (inc.get("member_row_indices") or [])
                    if isinstance(r, int)}
        for alert in inc.get("sample_alerts") or []:
            if isinstance(rid := alert.get("_row_index"), int):
                inc_rows.add(rid)
        is_attack = bool(inc_rows & attack_rows)

        record = verdicts.get(inc.get("incident_id")) or {}
        call = str((record.get("payload") or {}).get("verdict", "")).upper()
        if not call:
            undecided += 1
            continue
        if call == "ESCALATE":
            if is_attack: a_tp += 1
            else: a_fp += 1
        elif call == "SUPPRESS":
            if is_attack: a_fn += 1
            else: a_tn += 1
        else:
            undecided += 1

    a_prec = _rate(a_tp, a_tp + a_fp)
    a_rec = _rate(a_tp, a_tp + a_fn)
    layer2 = {
        "incidents_with_a_verdict": a_tp + a_fp + a_tn + a_fn,
        "incidents_undecided": undecided,
        "escalated_and_real": a_tp,
        "escalated_but_benign": a_fp,
        "suppressed_and_benign": a_tn,
        "SUPPRESSED_BUT_REAL": a_fn,
        "precision": round(a_prec, 4) if a_prec is not None else None,
        "recall": round(a_rec, 4) if a_rec is not None else None,
        "note": ("suppressed_but_real is the number that matters: an intrusion "
                 "the AI closed. Everything else costs time; this costs the "
                 "breach."),
    }

    return {
        "ground_truth": True,
        "labelled_events": len(labelled),
        "operational": operational,
        "layer1_detection": layer1,
        "layer2_ai": layer2,
    }
