#!/work/aiw642/conda_envs/falcon3-7b/bin/python
"""Does a faster model reach the same conclusions as the one it replaces?

Speed is easy to measure and easy to be wrong about. A model that decodes
twice as fast and disagrees with the 14B on a quarter of its verdicts has not
made the SOC faster — it has made it wrong at speed, and nobody would notice
until the verdicts were audited.

Incident ids are derived from host|user|technique|first_seen, so the same
corpus produces the same ids under any model. That makes a direct A/B possible:
snapshot the verdicts, change the model, re-run the same corpus, and compare
incident by incident.

    ./scripts/model_ab.py snapshot baseline-14b     # after a run completes
    #   ... change LOCAL_MODEL_NAME, ./soc.sh restart, re-ingest, wait ...
    ./scripts/model_ab.py snapshot candidate-nf4
    ./scripts/model_ab.py compare baseline-14b candidate-nf4
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
SNAPS = BASE / "output" / "ab"
CASES = BASE / "output" / "cases.json"


def snapshot(name: str) -> int:
    if not CASES.exists():
        print(f"no {CASES} — nothing has been investigated yet")
        return 1
    blob = json.loads(CASES.read_text())
    rows = {}
    for c in blob.get("cases", []):
        inv = c.get("investigation") or {}
        v = inv.get("verdict") or {}
        rows[c["incident_id"]] = {
            "verdict": v.get("verdict"),
            "urgency": v.get("urgency_score"),
            "confidence": v.get("confidence"),
            "steps": inv.get("step_count") or len(inv.get("steps") or []),
            "elapsed": inv.get("elapsed_seconds"),
            "technique": v.get("mitre_technique"),
        }
    SNAPS.mkdir(parents=True, exist_ok=True)
    out = SNAPS / f"{name}.json"
    out.write_text(json.dumps(rows, indent=1))
    secs = [r["elapsed"] for r in rows.values() if r["elapsed"]]
    print(f"[+] {len(rows)} verdicts -> {out}")
    if secs:
        print(f"    median {sorted(secs)[len(secs)//2]:.1f}s per investigation")
    return 0


def compare(a: str, b: str) -> int:
    ra = json.loads((SNAPS / f"{a}.json").read_text())
    rb = json.loads((SNAPS / f"{b}.json").read_text())
    shared = sorted(set(ra) & set(rb))
    if not shared:
        print("no incidents in common — was the same corpus ingested both times?")
        return 1

    agree = [i for i in shared if ra[i]["verdict"] == rb[i]["verdict"]]
    # Disagreeing towards ESCALATE is a different kind of error from
    # disagreeing towards SUPPRESS: one wastes an analyst's time, the other
    # closes something real. They are not interchangeable and are not summed.
    missed = [i for i in shared
              if ra[i]["verdict"] == "ESCALATE" and rb[i]["verdict"] != "ESCALATE"]
    added = [i for i in shared
             if ra[i]["verdict"] != "ESCALATE" and rb[i]["verdict"] == "ESCALATE"]

    def med(rows, key):
        vals = [r[key] for r in rows.values() if r.get(key)]
        return sorted(vals)[len(vals) // 2] if vals else 0

    print(f"compared on {len(shared)} incidents present in both runs\n")
    print(f"  verdict agreement : {len(agree)}/{len(shared)} "
          f"({100*len(agree)/len(shared):.1f}%)")
    print(f"  {b} downgraded an ESCALATE : {len(missed)}  <- the dangerous direction")
    print(f"  {b} raised a new ESCALATE  : {len(added)}")
    print(f"\n  median seconds : {a} {med(ra,'elapsed'):.1f}  ->  {b} {med(rb,'elapsed'):.1f}")
    print(f"  median steps   : {a} {med(ra,'steps')}  ->  {b} {med(rb,'steps')}")

    if missed:
        print("\n  incidents the candidate stopped escalating:")
        for i in missed[:10]:
            print(f"    {i}  {ra[i]['verdict']} -> {rb[i]['verdict']}")
    return 0


def main() -> int:
    if len(sys.argv) >= 3 and sys.argv[1] == "snapshot":
        return snapshot(sys.argv[2])
    if len(sys.argv) >= 4 and sys.argv[1] == "compare":
        return compare(sys.argv[2], sys.argv[3])
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
