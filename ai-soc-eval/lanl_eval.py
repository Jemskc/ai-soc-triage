#!/usr/bin/env python
"""Standalone evaluation of the SOC AI against LANL Cyber-1 ground truth.

Why this dataset: it is real enterprise authentication traffic (~1.05 billion
auth events over 58 days) with 749 known red-team compromise events labelled
in redteam.txt. Unlike an all-malicious sample corpus it contains genuine
benign activity, which is what makes precision, F1 and false-positive rate
computable at all.

The methodological point this harness exists to enforce
------------------------------------------------------
The red team accounts for roughly 7 events in every 10 million. Evaluate on a
balanced sample and you will measure ~99% precision and learn nothing, because
at the real base rate the same detector drowns the SOC. Every precision figure
here is therefore reported twice:

    sample precision    — measured on the evaluated subset
    base-rate precision — corrected to the true prevalence in the full corpus

and alongside them the number an operations lead actually decides on:
**false positives per day**. A detector with 99% sample precision that fires
50,000 times a day is unusable, and only the corrected numbers show it.

Usage
-----
    python lanl_eval.py --auth auth.txt.gz --redteam redteam.txt.gz
    python lanl_eval.py --auth auth.txt.gz --redteam redteam.txt.gz \\
        --benign-sample 200000 --ai-budget 40
    python lanl_eval.py --self-test        # synthetic data, no download needed

Download (registration required, CC0 licensed):
    https://csr.lanl.gov/data/cyber1/
"""

from __future__ import annotations

import argparse
import gzip
import json
import random
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

BASE_DIR = Path(__file__).resolve().parent
PROJECT_SRC = BASE_DIR.parent / "ai-soc-triage" / "src"
sys.path.insert(0, str(PROJECT_SRC))

# LANL runs for 58 days; used to convert alert counts into a daily rate.
LANL_DAYS = 58
SECONDS_PER_DAY = 86400

# Pre-registered pass/fail bars, declared before seeing results so the
# evaluation cannot be rationalised after the fact.
GATES = {
    "recall": 0.60,                    # catch most compromise events
    "base_rate_precision": 0.01,       # 1 in 100 alerts real, at true prevalence
    "false_positives_per_day": 100.0,  # what one analyst can actually work
    "grounding_rate": 0.95,            # citations must be retrieved, not recalled
    "parse_failure_rate": 0.02,        # the model must hold its output contract
}


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def _open(path: Path):
    return gzip.open(path, "rt", errors="replace") if str(path).endswith(".gz") \
        else open(path, "r", errors="replace")


def load_redteam(path: Path) -> set[tuple[str, str, str, str]]:
    """Ground truth: (time, user, src, dst) tuples of red-team activity."""
    labels = set()
    with _open(path) as fh:
        for line in fh:
            parts = line.strip().split(",")
            if len(parts) >= 4:
                labels.add((parts[0], parts[1], parts[2], parts[3]))
    return labels


def stream_auth(
    path: Path,
    redteam: set[tuple[str, str, str, str]],
    benign_sample: int,
    seed: int = 1337,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """One pass over auth.txt: keep every red-team event, sample the rest.

    Reservoir-samples benign events so the retained set is unbiased with
    respect to position in the file, and records the true totals needed for
    base-rate correction.
    """
    rng = random.Random(seed)
    reservoir: list[dict[str, Any]] = []
    malicious: list[dict[str, Any]] = []
    total = 0
    benign_total = 0
    max_time = 0

    with _open(path) as fh:
        for line in fh:
            parts = line.rstrip("\n").split(",")
            if len(parts) < 9:
                continue
            total += 1
            t, su, du, sc, dc, atype, ltype, orient, outcome = parts[:9]
            try:
                max_time = max(max_time, int(t))
            except ValueError:
                pass

            is_red = (t, su, sc, dc) in redteam
            row = _to_event(t, su, du, sc, dc, atype, ltype, orient, outcome, is_red)

            if is_red:
                malicious.append(row)
                continue

            benign_total += 1
            if len(reservoir) < benign_sample:
                reservoir.append(row)
            else:
                j = rng.randrange(benign_total)
                if j < benign_sample:
                    reservoir[j] = row

    events = malicious + reservoir
    events.sort(key=lambda e: int(e["_t"]))
    stats = {
        "auth_events_total": total,
        "benign_total": benign_total,
        "malicious_total": len(malicious),
        "benign_sampled": len(reservoir),
        "sampling_fraction": len(reservoir) / benign_total if benign_total else 0.0,
        "true_base_rate": len(malicious) / total if total else 0.0,
        "span_days": max(1.0, max_time / SECONDS_PER_DAY),
    }
    return events, stats


def _to_event(t, su, du, sc, dc, atype, ltype, orient, outcome, is_red) -> dict[str, Any]:
    """Map a LANL auth record onto the platform's normalised schema.

    LANL carries authentication only — no process names or command lines — so
    the process-oriented detection rules cannot fire here by construction. What
    is being evaluated on this data is the UEBA layer, the correlation, and the
    agents' judgement, which is what LANL is a good test of.
    """
    failed = outcome.strip().lower() == "failure"
    return {
        "timestamp": _to_iso(t),
        "_t": t,
        "event_id": "4625" if failed else "4624",
        "computer": dc,
        "user": su.split("@")[0],
        "target_user": du.split("@")[0],
        "source_ip": sc,
        "process_name": "",
        "parent_process": "",
        "command_line": "",
        "logon_type": _logon_type(ltype),
        "channel": "Security",
        "source_file": f"lanl-auth-{'red' if is_red else 'benign'}",
        "attack_folder": "Lateral Movement" if is_red else "",
        "destination_port": "",
        "task_name": "", "object_name": "", "service_name": "",
        "image_path": "", "share_name": "", "relative_target_name": "",
        "raw_data": "",
        "raw_message": f"{atype} {ltype} {orient} {outcome} {sc}->{dc}",
        "_label": 1 if is_red else 0,
        "_auth_type": atype,
        "_orientation": orient,
    }


_LOGON_TYPES = {
    "Network": "3", "Batch": "4", "Service": "5", "Interactive": "2",
    "NetworkCleartext": "8", "NewCredentials": "9", "RemoteInteractive": "10",
    "CachedInteractive": "11", "Unlock": "7",
}


def _logon_type(value: str) -> str:
    return _LOGON_TYPES.get(value.strip(), "")


def _to_iso(seconds: str) -> str:
    """LANL timestamps are seconds since an arbitrary epoch; anchor them so the
    correlator's time-window logic works."""
    try:
        base = 1_500_000_000  # arbitrary but fixed, keeps runs comparable
        ts = time.gmtime(base + int(seconds))
        return time.strftime("%Y-%m-%dT%H:%M:%S", ts)
    except (ValueError, OverflowError):
        return "1970-01-01T00:00:00"


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

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

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positive_rate": round(self.fpr, 6),
        }


def base_rate_correct(cm: Confusion, sampling_fraction: float) -> dict[str, Any]:
    """Project sample metrics onto the full corpus.

    Benign events were sampled at `sampling_fraction`, so each retained benign
    event stands for 1/fraction real ones. Recall is unaffected (every
    malicious event was kept); precision is not, and this is where a
    balanced-sample evaluation quietly lies.
    """
    if sampling_fraction <= 0:
        return {"available": False, "why": "no benign events were sampled"}

    scale = 1.0 / sampling_fraction
    projected_fp = cm.fp * scale
    precision = cm.tp / (cm.tp + projected_fp) if (cm.tp + projected_fp) else 0.0
    recall = cm.recall
    return {
        "available": True,
        "scale_factor": round(scale, 1),
        "projected_false_positives": int(projected_fp),
        "precision": round(precision, 6),
        "f1": round(2 * precision * recall / (precision + recall), 6)
        if (precision + recall) else 0.0,
        "note": (
            "Precision corrected to the corpus base rate. The sample figure is "
            "optimistic by roughly the sampling factor and should never be "
            "quoted on its own."
        ),
    }


def operational_load(projected_fp: float, tp: int, span_days: float) -> dict[str, Any]:
    """The numbers an operations lead decides on."""
    per_day = (projected_fp + tp) / max(1.0, span_days)
    return {
        "alerts_per_day": round(per_day, 1),
        "false_positives_per_day": round(projected_fp / max(1.0, span_days), 1),
        "true_positives_per_day": round(tp / max(1.0, span_days), 2),
        "analyst_hours_per_day_at_8min": round(per_day * 8 / 60, 1),
        "note": "8 minutes of manual triage per alert is an assumption, not a measurement.",
    }


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate(events: list[dict[str, Any]], stats: dict[str, Any],
             ai_budget: int, use_ai: bool) -> dict[str, Any]:
    import pandas as pd
    from funnel import TriageFunnel

    df = pd.DataFrame(events)
    labels = df["_label"].tolist()

    print(f"[+] {len(df):,} events "
          f"({sum(labels)} red-team, {len(labels)-sum(labels):,} benign)", flush=True)

    started = time.time()
    funnel = TriageFunnel(ai_budget=ai_budget)
    outcome = funnel.run(df)
    funnel_seconds = time.time() - started
    print(f"[+] funnel: {len(outcome.incidents)} incidents in {funnel_seconds:.1f}s", flush=True)

    # --- Layer 1: did detection surface the compromise at all? -------------
    red_rows = set(df.index[df["_label"] == 1])
    flagged_rows: set[int] = set()
    for inc in outcome.incidents:
        # member_row_indices is every contributing row. sample_alerts is capped
        # at five for prompt size, and measuring coverage against it reported
        # 0% recall while the rules were in fact firing on every red-team event.
        flagged_rows.update(inc.get("member_row_indices", []))
        for alert in inc.get("sample_alerts", []):
            idx = alert.get("_row_index")
            if idx is not None:
                flagged_rows.add(idx)

    detection = Confusion(
        tp=len(flagged_rows & red_rows),
        fp=len(flagged_rows - red_rows),
        fn=len(red_rows - flagged_rows),
        tn=len(set(df.index) - red_rows - flagged_rows),
    )

    result: dict[str, Any] = {
        "dataset": stats,
        "funnel": outcome.to_dict(),
        "layer1_detection": {
            "sample": detection.to_dict(),
            "base_rate_corrected": base_rate_correct(detection, stats["sampling_fraction"]),
            "operational": operational_load(
                detection.fp / max(1e-9, stats["sampling_fraction"]),
                detection.tp, stats["span_days"]),
        },
        "timing": {"funnel_seconds": round(funnel_seconds, 2)},
    }

    if not use_ai:
        result["layer2_ai"] = {"skipped": True}
        return result

    # --- Layer 2: agent triage on the ranked incidents ---------------------
    from ai_engine import AIEngine
    from orchestrator import Orchestrator

    engine = AIEngine()
    orchestrator = Orchestrator(engine, df)

    triage = Confusion()
    confidences: list[tuple[float, int]] = []
    ungrounded = 0
    started = time.time()

    for i, incident in enumerate(outcome.selected, 1):
        print(f"  [ai] case {i}/{len(outcome.selected)}", flush=True)
        case = orchestrator.run_case(incident)
        payload = case.agent_payload("triage") or {}

        member_rows = set(incident.get("member_row_indices", [])) | {
            a.get("_row_index") for a in incident.get("sample_alerts", [])
        }
        is_attack = bool(member_rows & red_rows)
        escalated = str(payload.get("verdict", "")).upper() == "ESCALATE"

        if is_attack and escalated:
            triage.tp += 1
        elif is_attack:
            triage.fn += 1
        elif escalated:
            triage.fp += 1
        else:
            triage.tn += 1

        conf = payload.get("confidence")
        if conf is not None:
            try:
                confidences.append((float(conf), int(escalated == is_attack)))
            except (TypeError, ValueError):
                pass
        for agent in case.agent_results.values():
            if agent.ungrounded:
                ungrounded += 1

    elapsed = time.time() - started
    calls = engine.stats.calls or 1
    result["layer2_ai"] = {
        "cases_analysed": len(outcome.selected),
        "verdict_quality": triage.to_dict(),
        "engine": engine.stats.as_dict(),
        "parse_failure_rate": round(engine.stats.parse_failures / calls, 4),
        "grounding_rate": round(1 - ungrounded / max(1, len(outcome.selected)), 4),
        "calibration": _calibration(confidences),
        "seconds_per_case": round(elapsed / max(1, len(outcome.selected)), 1),
    }
    return result


def _calibration(points: list[tuple[float, int]], bins: int = 5) -> dict[str, Any]:
    if not points:
        return {"available": False}
    brier = sum((c - o) ** 2 for c, o in points) / len(points)
    out = []
    for i in range(bins):
        lo, hi = i / bins, (i + 1) / bins
        chunk = [(c, o) for c, o in points
                 if lo <= c < hi or (i == bins - 1 and c == 1.0)]
        if chunk:
            out.append({
                "range": f"{lo:.0%}-{hi:.0%}", "n": len(chunk),
                "stated": round(sum(c for c, _ in chunk) / len(chunk), 3),
                "actual": round(sum(o for _, o in chunk) / len(chunk), 3),
            })
    return {"available": True, "brier_score": round(brier, 4), "bins": out}


def apply_gates(result: dict[str, Any]) -> dict[str, Any]:
    """Score against the bars declared at the top of this file."""
    d = result["layer1_detection"]
    ai = result.get("layer2_ai", {})
    measured = {
        "recall": d["sample"]["recall"],
        "base_rate_precision": (d["base_rate_corrected"] or {}).get("precision", 0.0),
        "false_positives_per_day": d["operational"]["false_positives_per_day"],
        "grounding_rate": ai.get("grounding_rate", 0.0) if not ai.get("skipped") else None,
        "parse_failure_rate": ai.get("parse_failure_rate", 1.0) if not ai.get("skipped") else None,
    }
    checks = {}
    for name, bar in GATES.items():
        got = measured.get(name)
        if got is None:
            checks[name] = {"bar": bar, "measured": None, "passed": None,
                            "why": "AI layer not run"}
            continue
        passed = got <= bar if name in ("false_positives_per_day", "parse_failure_rate") \
            else got >= bar
        checks[name] = {"bar": bar, "measured": got, "passed": bool(passed)}
    decided = [c for c in checks.values() if c["passed"] is not None]
    return {
        "checks": checks,
        "passed": all(c["passed"] for c in decided) if decided else False,
        "note": "Bars are pre-registered in GATES and were fixed before any run.",
    }


# ---------------------------------------------------------------------------

def _self_test(tmp: Path) -> tuple[Path, Path]:
    """Synthetic LANL-format data, so the harness is provably correct before
    anyone spends an hour downloading 7 GB."""
    rng = random.Random(7)
    users = [f"U{i}" for i in range(60)]
    comps = [f"C{i}" for i in range(40)]
    auth, red = tmp / "auth_sample.txt", tmp / "redteam_sample.txt"

    red_events = []
    with open(auth, "w") as fh:
        for t in range(1, 20001):
            u, sc, dc = rng.choice(users), rng.choice(comps), rng.choice(comps)
            outcome = "Success" if rng.random() > 0.05 else "Failure"
            fh.write(f"{t},{u}@DOM1,{u}@DOM1,{sc},{dc},Negotiate,Network,LogOn,{outcome}\n")
            # A compromised account sweeping many hosts — the LANL red-team shape.
            if t % 900 == 0:
                ru, rsc = "U999", "C1"
                rdc = rng.choice(comps)
                fh.write(f"{t},{ru}@DOM1,{ru}@DOM1,{rsc},{rdc},NTLM,Network,LogOn,Success\n")
                red_events.append(f"{t},{ru}@DOM1,{rsc},{rdc}")
    red.write_text("\n".join(red_events) + "\n")
    print(f"[self-test] wrote {auth.name} and {red.name} "
          f"({len(red_events)} red-team events)")
    return auth, red


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--auth", type=Path, help="auth.txt or auth.txt.gz")
    ap.add_argument("--redteam", type=Path, help="redteam.txt or redteam.txt.gz")
    ap.add_argument("--benign-sample", type=int, default=100_000,
                    help="benign events to retain (default 100000)")
    ap.add_argument("--ai-budget", type=int, default=25,
                    help="incidents sent to the agents (default 25)")
    ap.add_argument("--no-ai", action="store_true",
                    help="Layer 1 only; no GPU needed")
    ap.add_argument("--self-test", action="store_true",
                    help="run on synthetic data to verify the harness")
    ap.add_argument("--out", type=Path, default=BASE_DIR / "lanl_results.json")
    args = ap.parse_args()

    if args.self_test:
        tmp = BASE_DIR / "selftest"
        tmp.mkdir(exist_ok=True)
        args.auth, args.redteam = _self_test(tmp)
        args.benign_sample = min(args.benign_sample, 5000)

    if not args.auth or not args.redteam:
        ap.error("--auth and --redteam are required (or use --self-test)")
    for p in (args.auth, args.redteam):
        if not p.exists():
            ap.error(f"missing file: {p}\nDownload from https://csr.lanl.gov/data/cyber1/")

    print(f"[+] loading ground truth from {args.redteam}", flush=True)
    redteam = load_redteam(args.redteam)
    print(f"[+] {len(redteam)} red-team events labelled", flush=True)

    print(f"[+] streaming {args.auth} (one pass, reservoir sampling)", flush=True)
    events, stats = stream_auth(args.auth, redteam, args.benign_sample)
    print(f"[+] {stats['auth_events_total']:,} auth events; "
          f"true base rate {stats['true_base_rate']:.2e}", flush=True)

    result = evaluate(events, stats, args.ai_budget, use_ai=not args.no_ai)
    result["gates"] = apply_gates(result)
    args.out.write_text(json.dumps(result, indent=1, default=str))

    d = result["layer1_detection"]
    print("\n" + "=" * 70)
    print(f"  events            {stats['auth_events_total']:,} "
          f"({stats['malicious_total']} red-team, base rate {stats['true_base_rate']:.2e})")
    print(f"  DETECTION  recall {d['sample']['recall']:.1%}  "
          f"sample precision {d['sample']['precision']:.1%}")
    brc = d["base_rate_corrected"]
    if brc.get("available"):
        print(f"             base-rate precision {brc['precision']:.4%}  "
              f"(sample figure is {brc['scale_factor']:.0f}x optimistic)")
    print(f"             {d['operational']['false_positives_per_day']:.0f} false "
          f"positives/day, {d['operational']['analyst_hours_per_day_at_8min']:.1f} analyst-hours/day")
    ai = result.get("layer2_ai", {})
    if not ai.get("skipped"):
        v = ai["verdict_quality"]
        print(f"  AI TRIAGE  P {v['precision']:.1%}  R {v['recall']:.1%}  F1 {v['f1']:.1%}"
              f"   grounding {ai['grounding_rate']:.1%}  {ai['seconds_per_case']}s/case")
    print("\n  GATES")
    for name, c in result["gates"]["checks"].items():
        mark = "  ?  " if c["passed"] is None else (" PASS" if c["passed"] else " FAIL")
        print(f"   {mark}  {name:26s} bar {c['bar']:<8} measured {c['measured']}")
    print(f"\n  OVERALL: {'PASS' if result['gates']['passed'] else 'FAIL'}")
    print(f"\n[+] full results -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
