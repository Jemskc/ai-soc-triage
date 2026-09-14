#!/work/aiw642/conda_envs/falcon3-7b/bin/python
"""Walk the whole chain and report every break at once.

WHY THIS EXISTS
---------------
Bugs in this pipeline were found one at a time, each by a person using the
dashboard and hitting the next broken link: the import did not reach the
server, then the fields did not match the rules, then nothing published when
nothing was detected, then ingestion blocked on inference, then the tab read
the wrong source. Every individual fix was verified in isolation and every one
of them left the next link broken.

Verifying a link proves nothing about the chain. This walks the chain: reset,
ingest a corpus with known ground truth, wait, and then check the exact data
each tab reads — reporting everything that is wrong in one pass instead of one
bug per round trip.

Usage:
    ./scripts/audit_endtoend.py
    ./scripts/audit_endtoend.py --wait 300
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
SAMPLE = BASE.parent / "ai-soc-eval" / "golden_sample.jsonl"
URL = "http://localhost:8000"

FAILURES: list[str] = []
WARNINGS: list[str] = []


def get(path: str, timeout: int = 40):
    try:
        with urllib.request.urlopen(f"{URL}{path}", timeout=timeout) as r:
            return json.loads(r.read())
    except Exception as exc:  # noqa: BLE001
        return {"__error__": str(exc)}


def post(path: str, payload: dict, timeout: int = 60):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(f"{URL}{path}", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception as exc:  # noqa: BLE001
        return {"__error__": str(exc)}


def check(name: str, ok: bool, detail: str = "", warn: bool = False) -> bool:
    mark = "PASS" if ok else ("WARN" if warn else "FAIL")
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        (WARNINGS if warn else FAILURES).append(f"{name}: {detail}")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--wait", type=int, default=240,
                    help="seconds to let the pipeline work before checking")
    ap.add_argument("--skip-ingest", action="store_true",
                    help="audit whatever is already loaded")
    args = ap.parse_args()

    print("=" * 74)
    print("  END-TO-END AUDIT")
    print("=" * 74)

    # ---- 0. is anything running at all ---------------------------------
    print("\n0. Server")
    health = get("/health", timeout=10)
    if "__error__" in health:
        check("API reachable", False, health["__error__"])
        print("\nNothing else can be checked. Start the server first.")
        return 1
    check("API reachable", True, health.get("model_short", ""))
    check("model loaded", bool(health.get("model_loaded")),
          "the agents cannot run without it")

    if not args.skip_ingest:
        # ---- 1. clean slate --------------------------------------------
        print("\n1. Reset")
        r = post("/reset", {"confirm": True})
        check("reset accepted", "__error__" not in r, r.get("__error__", ""))
        after = get("/analysis")
        check("state is empty after reset",
              not (after.get("incidents") or []) and not (after.get("verdicts") or {}),
              f"{len(after.get('incidents') or [])} incidents remain")

        # ---- 2. ingest --------------------------------------------------
        print("\n2. Ingest")
        if not SAMPLE.exists():
            check("sample corpus present", False, str(SAMPLE))
            return 1
        expected = sum(1 for line in SAMPLE.open() if line.strip())
        attacks = sum(1 for line in SAMPLE.open() if '"label":1' in line)
        out = subprocess.run(
            [str(BASE / "scripts" / "ingest_golden.py"), "--golden", str(SAMPLE)],
            capture_output=True, text=True, timeout=600)
        check("ingest script succeeded", out.returncode == 0,
              out.stderr.strip()[:120])
        print(f"       corpus: {expected:,} events, {attacks} labelled attacks")

        print(f"\n3. Waiting {args.wait}s for the pipeline")
        deadline = time.time() + args.wait
        while time.time() < deadline:
            st = get("/autopilot/status", timeout=15)
            q = st.get("queued_batches", "?")
            print(f"       queued={q} incidents={st.get('incidents_total')} "
                  f"analysed={st.get('cases_analysed')} stage={st.get('stage')}",
                  flush=True)
            if q == 0 and (st.get("cases_analysed") or 0) > 0:
                break
            time.sleep(30)
    else:
        expected = attacks = None

    # ---- 4. every tab's actual data source ------------------------------
    print("\n4. What each tab reads")
    bundle = get("/analysis")
    incidents = bundle.get("incidents") or []
    verdicts = bundle.get("verdicts") or {}
    metrics = bundle.get("metrics") or {}
    events_total = bundle.get("event_total") or 0

    sources = get("/sources")
    ingested = sum(s.get("events_ingested", 0) for s in sources.get("sources", []))

    check("Live Logs — events published", events_total > 0,
          f"{events_total:,} in the log view")
    if expected:
        # Publishing lags ingestion while batches are still funnelling; that is
        # only acceptable if the queue has actually drained.
        st = get("/autopilot/status")
        drained = (st.get("queued_batches") or 0) == 0
        check("Live Logs — all ingested events are visible",
              events_total >= ingested or not drained,
              f"{events_total:,} visible of {ingested:,} ingested "
              f"(queue {'drained' if drained else 'still working'})",
              warn=not drained)

    page = get("/events?limit=5")
    check("Live Logs — /events returns rows",
          bool(page.get("events")), f"total={page.get('total')}")
    if page.get("events"):
        row = page["events"][0]
        check("Live Logs — rows carry a source",
              bool(row.get("ingestSource")), str(row.get("ingestSource")))
        check("Live Logs — rows carry a join key",
              row.get("rowIndex") is not None,
              "needed to score detection against ground truth")

    check("Alerts — incidents exist", bool(incidents), f"{len(incidents)}")
    check("Alerts — rule alerts counted", (metrics.get("rule_alerts") or 0) > 0,
          f"{metrics.get('rule_alerts')} (0 means the rules matched nothing)")
    check("Alerts — incidents carry fired rules",
          any(i.get("rules_fired") for i in incidents),
          "an incident with no rule is not explainable")

    check("AI Investigation — verdicts exist", bool(verdicts), f"{len(verdicts)}")
    cases = get("/cases")
    queue = cases.get("queue") or []
    check("AI Investigation — case queue populated", bool(queue), f"{len(queue)}")
    if queue:
        detail = get(f"/cases/{queue[0]['incident_id']}")
        inv = detail.get("investigation") or {}
        check("AI Investigation — traces have steps",
              bool(inv.get("steps")), f"{len(inv.get('steps') or [])} steps")
        check("AI Investigation — traces have a verdict",
              bool(inv.get("verdict")), "")

    ev_graph = [i for i in incidents if i.get("hosts") or i.get("users")]
    check("Evidence Graph — incidents have entities", bool(ev_graph),
          f"{len(ev_graph)} with hosts or accounts")

    check("Response — queue exposes approval state",
          all("requires_approval" in q for q in queue) if queue else False,
          "gating is what the tab is for")

    # ---- 5. is it actually right ---------------------------------------
    print("\n5. Was it correct")
    score = get("/scorecard/live", timeout=90)
    if "__error__" in score:
        check("scorecard reachable", False, score["__error__"])
    elif not score.get("ground_truth"):
        check("scorecard has ground truth", False,
              score.get("why", "")[:90], warn=True)
    else:
        l1 = score.get("layer1_detection") or {}
        if l1:
            got, missed = l1.get("attacks_caught"), l1.get("attacks_missed")
            check("Layer 1 caught attacks", (got or 0) > 0,
                  f"{got} caught, {missed} missed, recall {l1.get('recall')}")
        l2 = score.get("layer2_ai") or {}
        if l2:
            check("Layer 2 suppressed no real attack",
                  (l2.get("SUPPRESSED_BUT_REAL") or 0) == 0,
                  f"{l2.get('SUPPRESSED_BUT_REAL')} real intrusions closed by the AI")

    # ---- verdict --------------------------------------------------------
    print("\n" + "=" * 74)
    if FAILURES:
        print(f"  {len(FAILURES)} BROKEN")
        for f in FAILURES:
            print(f"    - {f}")
    else:
        print("  Every link in the chain works.")
    if WARNINGS:
        print(f"\n  {len(WARNINGS)} in progress or not yet measurable")
        for w in WARNINGS:
            print(f"    - {w}")
    print("=" * 74)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
