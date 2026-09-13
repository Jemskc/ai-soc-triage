"""Did the investigation change the answer, or just precede it?

THE QUESTION THIS EXISTS TO ANSWER
----------------------------------
The agent runs a hypothesis -> tool -> observe -> refine loop, ten or more
steps, eleven model calls, a minute or two of GPU per case. It produces a
readable trace. None of that establishes that the investigation did any work:
a verdict can be reached from the incident brief alone and then decorated with
a plausible-looking trace after the fact.

If an analyst has to read every trace to find out which happened, the system
has saved nobody any time. So the trace has to be measurable, not just
readable.

WHAT IS MEASURED
----------------
Every piece of evidence a verdict cites is traced to where it could have come
from:

  brief   the value was already in the incident brief before any tool ran.
          Citing it is not wrong, but it is not a finding either.
  tool    the value appears in a tool observation and NOT in the brief. This
          is the investigation earning its cost — something discovered.
  absent  the value appears in neither. The verdict is citing evidence that
          does not exist in anything the agent saw.

INVESTIGATION YIELD is the share of citations in the `tool` class. A yield near
zero means the loop is ceremony: the same verdict would have been reached by a
single call on the brief, in one step instead of eleven.

This does not measure whether the verdict is RIGHT — verdict_audit.py does
that. It measures whether the reasoning is load-bearing.

Usage:
    python investigation_yield.py
    python investigation_yield.py --cases ../ai-soc-triage/output/cases.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
PROJECT = BASE_DIR.parent / "ai-soc-triage"
sys.path.insert(0, str(PROJECT / "src"))

CASES = PROJECT / "output" / "cases.json"

# Values too generic to attribute. "critical" appears in every severity field
# in the corpus; counting it as a discovery would inflate every yield figure.
GENERIC = {
    "critical", "high", "medium", "low", "true", "false", "none", "unknown",
    "normal", "yes", "no", "0", "1", "2", "3", "n/a", "success", "failure",
}


def norm(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value)).strip().lower()


def brief_text(incident: dict[str, Any]) -> str:
    """Everything the agent knew before its first tool call.

    Mirrors Investigator._user's brief. If a citation's value is in here, the
    agent did not need to investigate to produce it.
    """
    parts = [
        str(incident.get("incident_id", "")),
        str(incident.get("first_seen", "")),
        str(incident.get("alert_count", "")),
        str(incident.get("severity", "")),
        " ".join(str(h) for h in incident.get("hosts", [])),
        " ".join(str(u) for u in incident.get("users", [])),
        " ".join(str(e) for e in incident.get("event_ids", [])),
        " ".join(str(p) for p in incident.get("processes", [])),
        " ".join(str(r.get("rule", "")) for r in incident.get("rules_fired", [])),
        " ".join(str(s.get("reason", "")) for s in incident.get("signals", [])),
        " ".join(str(t.get("technique", ""))
                 for t in incident.get("techniques_suspected", [])),
    ]
    return norm(" ".join(parts))


def observations_text(investigation: dict[str, Any]) -> str:
    return norm(" ".join(
        str(s.get("observation", "")) for s in investigation.get("steps", [])))


def _atoms(value: Any) -> list[str]:
    """Split a citation into individually checkable values.

    A verdict often cites several things in one string — "ppldump.exe,
    lsass.exe" — or wraps a list — "[4765]". Matching those verbatim finds
    nothing and scores them as fabricated, which is a bug in the measurement
    rather than a finding about the model.
    """
    text = norm(value).strip("[](){}")
    parts = [p.strip(" '\"[](){}") for p in re.split(r"[,;/]| and ", text)]
    return [p for p in parts if p]


def classify(value: Any, brief: str, obs: str) -> str:
    atoms = _atoms(value)
    meaningful = [a for a in atoms if a not in GENERIC and len(a) >= 3]
    if not meaningful:
        return "generic"
    # A citation counts as discovered only if EVERY checkable part of it is
    # traceable, and at least one part came from a tool rather than the brief.
    origins = []
    for a in meaningful:
        if a in obs and a not in brief:
            origins.append("tool")
        elif a in brief or a in obs:
            origins.append("brief")
        else:
            origins.append("absent")
    if "absent" in origins:
        return "absent"
    return "tool" if "tool" in origins else "brief"


def audit_case(case: dict[str, Any]) -> dict[str, Any] | None:
    inv = case.get("investigation") or {}
    verdict = inv.get("verdict") or {}
    if not verdict:
        return None
    # A verdict produced by the deterministic veto never ran an investigation,
    # so it has no yield to measure. Including it would score a rule as though
    # it were reasoning and drag the metric down for the wrong reason.
    if verdict.get("decided_by") == "deterministic_veto":
        return None
    incident = case.get("incident") or {}
    brief = brief_text(incident)
    obs = observations_text(inv)

    counts = Counter()
    detail = []
    for item in verdict.get("evidence") or []:
        value = item.get("value") if isinstance(item, dict) else item
        kind = classify(value, brief, obs)
        counts[kind] += 1
        detail.append({"value": str(value)[:60], "origin": kind,
                       "field": item.get("field") if isinstance(item, dict) else None})

    attributable = counts["brief"] + counts["tool"] + counts["absent"]
    return {
        "incident_id": incident.get("incident_id") or case.get("incident_id"),
        "verdict": verdict.get("verdict"),
        "confidence": verdict.get("confidence"),
        "steps": inv.get("step_count"),
        "model_calls": inv.get("model_calls"),
        "elapsed_seconds": inv.get("elapsed_seconds"),
        "citations": dict(counts),
        "yield": round(counts["tool"] / attributable, 4) if attributable else None,
        "detail": detail,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cases", type=Path, default=CASES)
    ap.add_argument("--show", type=int, default=6)
    ap.add_argument("--out", type=Path, default=BASE_DIR / "investigation_yield.json")
    args = ap.parse_args()

    if not args.cases.exists():
        print(f"no cases at {args.cases}")
        return 1
    blob = json.loads(args.cases.read_text())
    # cases.json is {"cases": [...], "queue": [...]}; older runs wrote a bare
    # list. Accept both rather than silently analysing the queue.
    if isinstance(blob, dict):
        cases = blob.get("cases") or []
    else:
        cases = blob
    if not isinstance(cases, list):
        print(f"unexpected shape in {args.cases}")
        return 1

    rows = [r for r in (audit_case(c) for c in cases) if r]
    if not rows:
        print("no investigations with verdicts found")
        return 1

    total = Counter()
    for r in rows:
        total.update(r["citations"])
    attributable = total["brief"] + total["tool"] + total["absent"]
    overall = total["tool"] / attributable if attributable else None

    zero = [r for r in rows if r["yield"] == 0.0]
    steps = [r["steps"] or 0 for r in rows]
    secs = [r["elapsed_seconds"] or 0 for r in rows]

    report = {
        "cases": len(rows),
        "citations": dict(total),
        "investigation_yield": round(overall, 4) if overall is not None else None,
        "cases_with_zero_yield": len(zero),
        "zero_yield_share": round(len(zero) / len(rows), 4),
        "mean_steps": round(sum(steps) / len(steps), 1),
        "mean_seconds": round(sum(secs) / len(secs), 1),
        "interpretation": (
            "Yield is the share of cited evidence that came from a tool "
            "observation rather than from the incident brief the agent started "
            "with. A low yield does not mean the verdict is wrong; it means the "
            "loop did not contribute to it, and the same answer was available "
            "in one call instead of eleven."
        ),
        "rows": rows,
    }
    args.out.write_text(json.dumps(report, indent=1, default=str))

    print("\n" + "=" * 72)
    print(f"  investigations analysed   {len(rows)}")
    print(f"  mean steps / seconds      {report['mean_steps']} / {report['mean_seconds']}s")
    print()
    print(f"  citations from the BRIEF  {total['brief']:4d}   (known before any tool ran)")
    print(f"  citations from a TOOL     {total['tool']:4d}   (discovered by investigating)")
    print(f"  citations ABSENT          {total['absent']:4d}   (in neither)")
    print(f"  citations too generic     {total['generic']:4d}   (not attributable)")
    print()
    print(f"  INVESTIGATION YIELD       "
          f"{'n/a' if overall is None else f'{overall:.1%}'}")
    print(f"  cases citing nothing they found   "
          f"{len(zero)}/{len(rows)}  ({report['zero_yield_share']:.0%})")

    if zero:
        print("\n  CASES WHERE THE LOOP CHANGED NOTHING")
        for r in zero[:args.show]:
            print(f"   {r['incident_id']}  {r['verdict']} conf {r['confidence']}  "
                  f"{r['steps']} steps, {r['elapsed_seconds']}s")
            for d in r["detail"][:3]:
                print(f"     cited {d['field']}={d['value']!r} -> {d['origin']}")

    print(f"\n[+] {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
