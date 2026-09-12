#!/usr/bin/env python
"""Score the AI triage engine against ground truth, with a RAG ablation.

The sample corpus (data/raw_logs/evtx_data.csv) carries a MITRE tactic label per
event, giving 4,633 labelled attack events across 8 tactics. That makes three
things measurable:

  1. Escalation recall — of incidents built from known-attack events, how many
     does the engine escalate rather than dismiss? Missing a real attack is the
     failure a SOC cares about most.
  2. Tactic accuracy — does the cited technique map to the labelled tactic?
  3. Grounding integrity — how often does it cite a technique that was not in
     the retrieved knowledge, i.e. break the anti-hallucination rule?

And it runs twice, with retrieval on and off, so the contribution of RAG is a
measured number rather than a claim.

IMPORTANT LIMITATION, reported in the output and meant to stay there: every
event in this corpus is malicious. There is no benign traffic, so a true
false-positive rate CANNOT be computed from it. What is reported instead is a
suppression rate, which needs a human spot-check to interpret.

Usage:
    python scripts/benchmark.py [--limit N] [--no-ablation]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "src"))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(BASE_DIR / ".env")

import correlator  # noqa: E402
from ai_engine import AIEngine  # noqa: E402
from detector import run_detection  # noqa: E402
from knowledge_base import get_kb  # noqa: E402
from funnel import TriageFunnel  # noqa: E402
from pipeline import load_corpus_dataframe  # noqa: E402

OUTPUT_PATH = BASE_DIR / "output" / "benchmark.json"


def normalize_tactic(name: str) -> str:
    return str(name or "").strip().lower().replace("-", " ").replace("_", " ")


def build_technique_tactic_map() -> dict[str, list[str]]:
    """technique id -> tactics, taken from the knowledge base itself."""
    kb = get_kb()
    mapping: dict[str, list[str]] = {}
    for chunk in kb.chunks:
        tid = chunk.get("technique_id")
        if tid:
            mapping[tid] = [normalize_tactic(t) for t in chunk.get("tactics", [])]
    return mapping


def extract_technique_id(value: str) -> str | None:
    import re

    match = re.search(r"T\d{4}(?:\.\d{3})?", str(value or ""))
    return match.group(0) if match else None


def score_run(
    incidents: list[dict],
    engine: AIEngine,
    tactic_map: dict[str, list[str]],
    label: str,
) -> dict:
    """Run the engine over every incident and score the results."""
    verdicts = Counter()
    tactic_correct = 0
    tactic_scored = 0
    per_tactic = defaultdict(lambda: {"total": 0, "correct": 0, "escalated": 0})
    confusion: list[dict] = []
    unknown_technique = 0
    results = []

    started = time.time()
    for i, incident in enumerate(incidents, 1):
        print(f"  [{label}] incident {i}/{len(incidents)}", flush=True)
        result = engine.analyze_incident(incident, tab_id="alerts")
        payload = result.payload or {}

        verdict = str(payload.get("verdict", "")).upper() or "PARSE_FAILURE"
        verdicts[verdict] += 1

        truth = [normalize_tactic(t) for t in incident.get("ground_truth_tactics", [])]
        primary_truth = truth[0] if truth else ""

        predicted_id = extract_technique_id(payload.get("mitre_technique", ""))
        predicted_tactics = tactic_map.get(predicted_id or "", [])

        if primary_truth:
            per_tactic[primary_truth]["total"] += 1
            if verdict == "ESCALATE":
                per_tactic[primary_truth]["escalated"] += 1

            if predicted_id is None:
                unknown_technique += 1
            else:
                tactic_scored += 1
                hit = any(pt in truth for pt in predicted_tactics)
                if hit:
                    tactic_correct += 1
                    per_tactic[primary_truth]["correct"] += 1
                else:
                    confusion.append(
                        {
                            "incident_id": incident["incident_id"],
                            "truth": primary_truth,
                            "predicted_technique": predicted_id,
                            "predicted_tactics": predicted_tactics,
                        }
                    )

        results.append(
            {
                "incident_id": incident["incident_id"],
                "truth_tactics": truth,
                "verdict": verdict,
                "urgency": payload.get("urgency_score"),
                "confidence": payload.get("confidence"),
                "technique": payload.get("mitre_technique"),
                "technique_id": predicted_id,
                "ok": result.ok,
                "error": result.error,
                "ungrounded": result.ungrounded_techniques,
                "knowledge_ids": [c["id"] for c in result.knowledge],
                "elapsed": round(result.elapsed_seconds, 1),
            }
        )

    elapsed = time.time() - started
    total = len(incidents)
    escalated = verdicts.get("ESCALATE", 0)

    return {
        "label": label,
        "use_rag": engine.use_rag,
        "incidents_scored": total,
        "verdicts": dict(verdicts),
        # Every incident here is built from known-attack events, so escalation
        # recall is the share of real attacks the engine did not dismiss.
        "escalation_recall": round(escalated / total, 3) if total else 0,
        "suppression_rate": round(verdicts.get("SUPPRESS", 0) / total, 3) if total else 0,
        "tactic_accuracy": round(tactic_correct / tactic_scored, 3) if tactic_scored else 0,
        "tactic_scored": tactic_scored,
        "tactic_correct": tactic_correct,
        "unknown_technique": unknown_technique,
        "per_tactic": {
            k: {
                **v,
                "accuracy": round(v["correct"] / v["total"], 3) if v["total"] else 0,
                "escalation_rate": round(v["escalated"] / v["total"], 3) if v["total"] else 0,
            }
            for k, v in sorted(per_tactic.items())
        },
        "confusions": confusion[:25],
        "engine_stats": engine.stats.as_dict(),
        "throughput": {
            "total_seconds": round(elapsed, 1),
            "seconds_per_incident": round(elapsed / total, 1) if total else 0,
        },
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None,
                        help="score only the first N incidents")
    parser.add_argument("--no-ablation", action="store_true",
                        help="skip the RAG-off control run")
    args = parser.parse_args()

    print("[+] Loading corpus...")
    df = load_corpus_dataframe()

    # Score the architecture that actually ships. Running detection directly
    # would benchmark a path the product no longer uses, and would miss the
    # whole point of the funnel: the incidents that reach the AI without any
    # rule firing.
    funnel = TriageFunnel(ai_budget=args.limit or 40)
    outcome = funnel.run(df)
    incidents = outcome.selected
    alerts = []

    # Detection-path coverage, measured at the attack-sample level. This is the
    # ceiling on what the AI can possibly triage, and it is the number that
    # justifies adding behavioural analytics at all.
    total_samples = df["source_file"].nunique()
    rule_samples, analytic_samples = set(), set()
    for inc in outcome.incidents:
        for a in inc.get("sample_alerts", []):
            src = a.get("source_file")
            if not src:
                continue
            if a.get("detection_source") == "analytics":
                analytic_samples.add(src)
            else:
                rule_samples.add(src)
    coverage = {
        "attack_samples": int(total_samples),
        "reached_by_rules": len(rule_samples),
        "reached_by_analytics_only": len(analytic_samples - rule_samples),
        "reached_by_either": len(rule_samples | analytic_samples),
        "rule_coverage": round(len(rule_samples) / total_samples, 3),
        "funnel_coverage": round(len(rule_samples | analytic_samples) / total_samples, 3),
    }

    labelled = [i for i in incidents if i.get("ground_truth_tactics")]
    print(f"[+] {len(df):,} events -> {len(outcome.incidents)} incidents -> "
          f"{len(incidents)} selected ({len(labelled)} labelled)")
    print(f"[+] attack-sample coverage: rules {coverage['rule_coverage']:.1%} "
          f"-> funnel {coverage['funnel_coverage']:.1%} "
          f"(+{coverage['reached_by_analytics_only']} recovered by analytics)")

    tactic_map = build_technique_tactic_map()
    print(f"[+] technique->tactic map: {len(tactic_map)} techniques")

    runs = {}

    print("\n[+] Run 1: RAG enabled")
    engine_rag = AIEngine(use_rag=True)
    runs["rag_on"] = score_run(incidents, engine_rag, tactic_map, "rag_on")

    if not args.no_ablation:
        print("\n[+] Run 2: RAG disabled (ablation control)")
        engine_plain = AIEngine(use_rag=False, two_pass=engine_rag.two_pass)
        engine_plain.backend = engine_rag.backend  # same weights, same machine
        runs["rag_off"] = score_run(incidents, engine_plain, tactic_map, "rag_off")

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "dataset": {
            "source": "EVTX-ATTACK-SAMPLES (data/raw_logs/evtx_data.csv)",
            "events": int(len(df)),
            "incidents_total": len(outcome.incidents),
            "incidents_scored": len(incidents),
            "labelled_incidents": len(labelled),
        },
        "detection_coverage": coverage,
        "funnel": outcome.to_dict(),
        "runs": runs,
        "limitations": [
            "Every event in this corpus is malicious. There is no benign "
            "traffic, so a true false-positive rate cannot be computed from it. "
            "The suppression rate below is NOT a false-positive rate.",
            "Escalation recall is measured at incident level, not event level: "
            "incidents are built by correlating rule alerts, so attacks that "
            "fire no rule never reach the AI and are not counted here.",
            "Detection coverage is the ceiling on what the AI can triage: an "
            "attack that reaches no stage of the funnel is never scored here, "
            "so escalation recall is conditional on detection, not absolute.",
            "Rarity was computed against the same corpus being scored, since no "
            "separate benign baseline was supplied. 'Rare' therefore means rare "
            "within this capture rather than rare for a real environment.",
            "Tactic accuracy credits a prediction when the cited technique maps "
            "to any tactic labelled for that incident, since several techniques "
            "legitimately span multiple tactics.",
        ],
    }

    if "rag_off" in runs:
        on, off = runs["rag_on"], runs["rag_off"]
        report["ablation"] = {
            "tactic_accuracy_delta": round(
                on["tactic_accuracy"] - off["tactic_accuracy"], 3
            ),
            "escalation_recall_delta": round(
                on["escalation_recall"] - off["escalation_recall"], 3
            ),
            "ungrounded_citations_rag_on": on["engine_stats"]["ungrounded_citations"],
            "ungrounded_citations_rag_off": off["engine_stats"]["ungrounded_citations"],
            "note": (
                "RAG-off cites techniques purely from model memory; every such "
                "citation is ungrounded by definition."
            ),
        }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(report, indent=1, default=str), encoding="utf-8")

    print("\n" + "=" * 66)
    print(f"detection  rules {coverage['rule_coverage']:.1%} -> "
          f"funnel {coverage['funnel_coverage']:.1%}")
    for name, run in runs.items():
        print(f"{name:8s}  escalation recall {run['escalation_recall']:.1%}  "
              f"tactic accuracy {run['tactic_accuracy']:.1%}  "
              f"({run['tactic_correct']}/{run['tactic_scored']})  "
              f"{run['throughput']['seconds_per_incident']}s/incident")
    if "ablation" in report:
        print(f"\nRAG contribution: tactic accuracy "
              f"{report['ablation']['tactic_accuracy_delta']:+.3f}")
    print(f"\n[+] Wrote {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
