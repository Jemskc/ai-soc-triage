"""Check AI verdicts against the events they were actually made from.

The project has never had an accuracy number for its AI layer. Every figure it
quotes — 100% recall, 73% base-rate precision, 8 FP/day — comes from Layer 1,
the deterministic funnel, where no model runs. This closes that gap as far as
the corpus honestly allows.

WHAT THIS CORPUS CAN AND CANNOT PROVE
-------------------------------------
evtx_data.csv is 100% malicious: 4,633 events captured from attack samples,
each labelled with the tactic it belongs to. That asymmetry decides which
metrics mean anything here.

  COMPUTABLE   wrongful suppression. Every incident is drawn from attack
               telemetry, so an incident whose evidence carries a hands-on
               tactic and which the agent SUPPRESSED is a miss. Missing a real
               intrusion is the failure a SOC actually cares about, and it is
               measurable here.

  COMPUTABLE   evidence fidelity. GROUND_RULES require every verdict to quote
               the specific log fields that justify it. Those quotes can be
               checked against the incident's own rows. A verdict citing a
               process that never appears is confabulating its evidence, and
               that is a defect regardless of whether the verdict is right.

  NOT COMPUTABLE  precision, specificity, false-positive rate. There are no
               benign incidents to get wrong. Anything claiming a precision
               figure from this corpus is inventing it, so this tool reports
               those as None rather than producing a flattering number.

Usage:
    python verdict_audit.py                     # audit every current verdict
    python verdict_audit.py --sample 20         # a stratified sample
    python verdict_audit.py --strict-version    # reject stale-build verdicts
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
PROJECT = BASE_DIR.parent / "ai-soc-triage"
sys.path.insert(0, str(PROJECT / "src"))

ANALYSIS = PROJECT / "output" / "analysis.json"
CORPUS = PROJECT / "data" / "raw_logs" / "evtx_data.csv"

# Tactics that mean an adversary already has execution or credentials on the
# host. Suppressing one of these is not a judgement call.
HANDS_ON_TACTICS = {
    "credential access",
    "lateral movement",
    "privilege escalation",
    "command and control",
    "exfiltration",
    "impact",
}

# Process names that are themselves the finding. A verdict that suppresses an
# incident containing these is wrong on the face of it.
DECISIVE_ARTEFACTS = {
    "mimikatz.exe", "psexesvc.exe", "psexec.exe", "procdump.exe",
    "pwdump.exe", "wce.exe", "ppldump.exe", "nc.exe", "ncat.exe",
    "uacbypass.exe", "secretsdump", "lazagne.exe",
}


# Every executable/script basename appearing anywhere in the corpus. A citation
# missing from this set was invented; one merely missing from the incident's own
# rows was found by the agent's own search tools, which is what they are for.
CORPUS_VOCAB: set[str] = set()


def build_vocab(corpus_text: dict[int, str]) -> set[str]:
    vocab = set()
    for text in corpus_text.values():
        for raw in text.replace(",", " ").replace('"', " ").split():
            tok = raw.strip("().;:[]<>").lower()
            if tok.endswith((".exe", ".dll", ".ps1", ".bat", ".vbs")):
                vocab.add(tok.rsplit("\\", 1)[-1].rsplit("/", 1)[-1])
    return vocab


def load_corpus():
    import pandas as pd
    return pd.read_csv(CORPUS, low_memory=False)


def row_text(row) -> str:
    """Everything about a row that a verdict could legitimately quote."""
    fields = [
        "Image", "ProcessName", "NewProcessName", "ParentImage", "CommandLine",
        "ParentCommandLine", "TargetFilename", "ImageLoaded", "Computer",
        "User", "SubjectUserName", "TargetUserName", "EventID", "ServiceName",
        "TaskName", "ObjectName", "SourceImage", "TargetImage", "QueryName",
        "DestinationIp", "SourceIp", "ShareName", "RelativeTargetName",
    ]
    parts = []
    for f in fields:
        v = row.get(f)
        if v is not None and str(v) not in ("nan", "", "None"):
            parts.append(str(v))
    return " ".join(parts).lower()


def audit_one(incident: dict[str, Any], verdict: dict[str, Any],
              df, corpus_text: dict[int, str]) -> dict[str, Any]:
    payload = verdict.get("payload") or {}
    call = str(payload.get("verdict", "")).upper()

    rows = sorted(set(incident.get("member_row_indices") or []))
    if not rows:
        rows = sorted({a.get("_row_index") for a in incident.get("sample_alerts", [])
                       if a.get("_row_index") is not None})

    tactics = Counter()
    blob_parts = []
    for r in rows:
        if r in corpus_text:
            blob_parts.append(corpus_text[r])
        try:
            t = df.at[r, "EVTX_Tactic"]
            if isinstance(t, str):
                tactics[t.strip().lower()] += 1
        except (KeyError, ValueError):
            pass
    blob = " ".join(blob_parts)

    hands_on = sorted(t for t in tactics if t in HANDS_ON_TACTICS)
    artefacts = sorted(a for a in DECISIVE_ARTEFACTS if a in blob)

    # --- wrongful suppression -------------------------------------------
    wrongful = None
    if call == "SUPPRESS":
        wrongful = bool(hands_on or artefacts)

    # --- evidence fidelity ----------------------------------------------
    # Each quoted field must appear in the incident's own rows. Only tokens
    # specific enough to check are tested: a verdict saying "the host" is vague
    # rather than wrong, and flagging that as fabrication would be noise.
    # Two tiers, because they mean different things. The agent's tools search
    # the whole corpus, so citing something outside this incident's own rows is
    # legitimate pivoting, not invention. Only a name that appears NOWHERE in
    # the corpus is fabricated.
    quoted, outside_incident, fabricated = [], [], []
    evidence_items = payload.get("evidence") or []
    for item in evidence_items:
        text = item if isinstance(item, str) else json.dumps(item)
        for tok in _checkable_tokens(text):
            quoted.append(tok)
            if tok in blob:
                continue
            if tok in CORPUS_VOCAB:
                outside_incident.append(tok)
            else:
                fabricated.append(tok)

    return {
        "incident_id": incident.get("incident_id"),
        "verdict": call,
        "confidence": payload.get("confidence"),
        "rows": len(rows),
        "tactics": dict(tactics),
        "hands_on_tactics": hands_on,
        "decisive_artefacts": artefacts,
        "wrongful_suppression": wrongful,
        "quoted_tokens": len(quoted),
        "cited_outside_incident": sorted(set(outside_incident)),
        "fabricated_tokens": sorted(set(fabricated)),
        "produced_by": (verdict.get("investigation") or {}).get("produced_by"),
        "summary": str(payload.get("analyst_summary") or "")[:200],
    }


def _normalise(text: str) -> str:
    """Collapse escaping differences before comparing.

    Evidence items are serialised with json.dumps, which doubles every
    backslash, while the corpus holds single ones. Comparing the two raw made
    every path-shaped citation look fabricated — an artifact that produced a
    61.7% "fabrication rate" on a first run and was entirely my own bug.
    """
    return text.replace("\\\\", "\\").lower()


def _checkable_tokens(text: str) -> list[str]:
    """Tokens concrete enough that their absence would mean fabrication.

    Only the basename is compared. A verdict naming `lsass.exe` when the row
    holds `C:\\Windows\\System32\\lsass.exe` is quoting it correctly, and
    path-prefix differences say nothing about truthfulness.
    """
    out = []
    cleaned = _normalise(text).replace(",", " ").replace("'", " ").replace('"', " ")
    for raw in cleaned.split():
        tok = raw.strip("().;:[]<>").lower()
        if tok.endswith((".exe", ".dll", ".ps1", ".bat", ".vbs")) and len(tok) > 4:
            out.append(tok.rsplit("\\", 1)[-1].rsplit("/", 1)[-1])
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sample", type=int, default=0,
                    help="audit a stratified sample of N verdicts (default: all)")
    ap.add_argument("--strict-version", action="store_true",
                    help="only audit verdicts from the current code version")
    ap.add_argument("--show", type=int, default=6,
                    help="print this many individual cases")
    ap.add_argument("--out", type=Path, default=BASE_DIR / "verdict_audit.json")
    args = ap.parse_args()

    if not ANALYSIS.exists():
        print(f"no analysis at {ANALYSIS}")
        return 1
    bundle = json.loads(ANALYSIS.read_text())
    verdicts = bundle.get("verdicts") or {}
    incidents = {i["incident_id"]: i for i in bundle.get("incidents", [])}
    if not verdicts:
        print("no verdicts yet — the AI has not analysed anything")
        return 1

    from investigator import CODE_VERSION
    rows = []
    stale = 0
    for iid, rec in verdicts.items():
        inc = incidents.get(iid)
        if not inc:
            continue
        pb = (rec.get("investigation") or {}).get("produced_by") or {}
        if pb.get("code_version") != CODE_VERSION:
            stale += 1
            if args.strict_version:
                continue
        rows.append((inc, rec))

    if not rows:
        print(f"no verdicts from the current build ({CODE_VERSION}); "
              f"{stale} stale. Re-run the analysis.")
        return 1

    if args.sample and args.sample < len(rows):
        by_verdict = defaultdict(list)
        for inc, rec in rows:
            by_verdict[str((rec.get("payload") or {}).get("verdict", "")).upper()].append((inc, rec))
        rng = random.Random(1337)
        picked, per = [], max(1, args.sample // max(1, len(by_verdict)))
        for group in by_verdict.values():
            rng.shuffle(group)
            picked.extend(group[:per])
        rows = picked[:args.sample]

    print(f"[+] loading corpus {CORPUS.name}", flush=True)
    df = load_corpus()
    corpus_text = {i: row_text(r) for i, r in df.iterrows()}
    global CORPUS_VOCAB
    CORPUS_VOCAB = build_vocab(corpus_text)
    print(f"[+] {len(CORPUS_VOCAB)} distinct executables in corpus", flush=True)

    results = [audit_one(inc, rec, df, corpus_text) for inc, rec in rows]

    suppressed = [r for r in results if r["verdict"] == "SUPPRESS"]
    wrongful = [r for r in suppressed if r["wrongful_suppression"]]
    with_quotes = [r for r in results if r["quoted_tokens"]]
    fabricating = [r for r in results if r["fabricated_tokens"]]
    pivoting = [r for r in results if r["cited_outside_incident"]]
    verdict_mix = Counter(r["verdict"] for r in results)

    report = {
        "code_version": CODE_VERSION,
        "audited": len(results),
        "stale_verdicts_present": stale,
        "verdict_mix": dict(verdict_mix),
        "wrongful_suppression": {
            "suppressed": len(suppressed),
            "wrongful": len(wrongful),
            "rate": round(len(wrongful) / len(suppressed), 4) if suppressed else None,
            "incidents": [r["incident_id"] for r in wrongful],
        },
        "evidence_fidelity": {
            "verdicts_quoting_checkable_fields": len(with_quotes),
            "verdicts_citing_invented_files": len(fabricating),
            "fabrication_rate": round(len(fabricating) / len(with_quotes), 4)
            if with_quotes else None,
            "verdicts_citing_beyond_their_incident": len(pivoting),
            "note": (
                "A citation absent from the incident's own rows but present in "
                "the corpus is the agent's search tools working, not invention. "
                "Only the fabrication rate is a defect."
            ),
            "examples": [
                {"incident_id": r["incident_id"], "invented": r["fabricated_tokens"][:5]}
                for r in fabricating[:5]
            ],
        },
        "not_computable": {
            "precision": "corpus is 100% malicious — no benign incidents exist",
            "specificity": "same",
            "false_positive_rate": "same",
        },
        "cases": results,
    }
    args.out.write_text(json.dumps(report, indent=1, default=str))

    print("\n" + "=" * 70)
    print(f"  build            {CODE_VERSION}")
    print(f"  audited          {len(results)} verdicts  {dict(verdict_mix)}")
    if stale:
        print(f"  STALE PRESENT    {stale} verdict(s) from another build")
    w = report["wrongful_suppression"]
    print(f"  WRONGFUL SUPPRESSION  {w['wrongful']}/{w['suppressed']} suppressed "
          f"verdicts hid hands-on attack evidence"
          + (f"  ({w['rate']:.1%})" if w["rate"] is not None else ""))
    e = report["evidence_fidelity"]
    print(f"  FABRICATED EVIDENCE   {e['verdicts_citing_invented_files']}/"
          f"{e['verdicts_quoting_checkable_fields']} verdicts cited a file that "
          f"exists nowhere in the corpus"
          + (f"  ({e['fabrication_rate']:.1%})" if e["fabrication_rate"] is not None else ""))
    print(f"  (pivoted beyond own incident: "
          f"{e['verdicts_citing_beyond_their_incident']} — tools working, not a defect)")
    print("  NOT COMPUTABLE        precision / FP-rate — corpus is 100% malicious")

    if wrongful:
        print("\n  MISSES")
        for r in wrongful[:args.show]:
            print(f"   {r['incident_id']}  conf {r['confidence']}")
            print(f"     tactics   {r['hands_on_tactics']}")
            if r["decisive_artefacts"]:
                print(f"     artefacts {r['decisive_artefacts']}")
            print(f"     said      {r['summary'][:150]}")

    print(f"\n[+] full audit -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
