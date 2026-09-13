"""Build a fixed, labelled, reproducible evaluation set from LANL Cyber-1.

WHAT THIS PRODUCES
------------------
    golden.jsonl       one labelled event per line
    golden.manifest.json   counts, checksums, base rate, provenance

Every red-team authentication record is kept. Benign records are reservoir
sampled from the full 1.05-billion-event stream with a fixed seed, so the same
command always yields byte-identical output and any two results are comparable.

WHY THE MIX IS NOT 50/50
------------------------
A balanced set would be the wrong thing to build. On this network roughly one
authentication in 1.4 million is hostile, and a detector tuned on a balanced
sample looks excellent right up to the moment it meets the real ratio and buries
the SOC. The manifest therefore records the TRUE base rate and the sampling
fraction, so precision measured here can be corrected back to what it would be
in production. That correction is the difference between a demo number and an
operational one.

WHAT THE POSITIVE CLASS CANNOT BE
---------------------------------
There are 749 labelled red-team lines in the corpus, covering 715 distinct
(time, user, src, dst) tuples. No amount of extra benign data creates more
attacks. Growing the file improves the PRECISION estimate — more opportunity to
raise a false alarm — and does nothing for recall statistics. Anyone reading
these results should size their confidence to the positive class, not the file.

Usage:
    python make_golden.py --auth ../auth.txt.gz --redteam ../redteam.txt.gz \
        --benign 1000000 --out golden.jsonl
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import random
import sys
import time
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

SECONDS_PER_DAY = 86400


def _open(path: Path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def load_redteam(path: Path) -> tuple[set[tuple[str, str, str, str]], dict[str, int]]:
    """Ground truth as (time, user, src, dst) tuples.

    749 lines collapse to 715 distinct tuples: several auth records can share a
    second, user, source and destination (a TGS, a LogOn and a LogOff, say) and
    each is labelled. Both counts go in the manifest so the recall denominator
    is never ambiguous.
    """
    labels: set[tuple[str, str, str, str]] = set()
    lines = malformed = 0
    with _open(path) as fh:
        for line in fh:
            parts = line.strip().split(",")
            if len(parts) >= 4:
                lines += 1
                labels.add((parts[0], parts[1], parts[2], parts[3]))
            elif line.strip():
                malformed += 1
    return labels, {"labelled_lines": lines, "distinct_tuples": len(labels),
                    "malformed_lines": malformed}


def to_event(parts: list[str], is_red: bool) -> dict[str, Any]:
    """One LANL auth record, normalised and labelled.

    Field names match the platform's own schema so the funnel and the agents
    can consume this file unchanged.
    """
    t, su, du, sc, dc, atype, ltype, orient, outcome = parts[:9]
    failed = outcome.strip().lower() == "failure"
    return {
        "t": int(t),
        "timestamp": t,
        "event_id": "4625" if failed else "4624",
        "user": su.split("@")[0],
        "user_domain": su,
        "target_user": du.split("@")[0],
        "source_ip": sc,          # LANL source computer
        "computer": dc,           # LANL destination computer
        "auth_type": atype,
        "logon_type": ltype,
        "orientation": orient,
        "outcome": outcome,
        "channel": "Security",
        # The label. Never shown to the model.
        "label": 1 if is_red else 0,
    }


def build(auth: Path, redteam: Path, benign_target: int, out: Path,
          seed: int = 1337) -> dict[str, Any]:
    labels, rt_stats = load_redteam(redteam)
    print(f"[+] ground truth: {rt_stats['labelled_lines']} lines -> "
          f"{rt_stats['distinct_tuples']} distinct tuples", flush=True)

    rng = random.Random(seed)
    reservoir: list[dict[str, Any]] = []
    malicious: list[dict[str, Any]] = []
    total = benign_total = 0
    max_t = 0
    started = time.time()

    print(f"[+] streaming {auth} — one pass, keeping every red-team record and "
          f"reservoir-sampling {benign_target:,} benign", flush=True)
    with _open(auth) as fh:
        for line in fh:
            parts = line.rstrip("\n").split(",")
            if len(parts) < 9:
                continue
            total += 1
            t, su, sc, dc = parts[0], parts[1], parts[3], parts[4]
            try:
                max_t = max(max_t, int(t))
            except ValueError:
                pass

            if (t, su, sc, dc) in labels:
                malicious.append(to_event(parts, True))
                continue

            benign_total += 1
            row = None
            if len(reservoir) < benign_target:
                reservoir.append(to_event(parts, False))
            else:
                # Reservoir sampling: every benign record has an equal chance of
                # being kept, so the sample is unbiased with respect to position
                # in the file. Taking the first N would sample one week of a
                # 58-day corpus.
                j = rng.randrange(benign_total)
                if j < benign_target:
                    reservoir[j] = to_event(parts, False)
            del row

            if total % 100_000_000 == 0:
                print(f"    {total:,} events read "
                      f"({time.time()-started:.0f}s)", flush=True)

    events = malicious + reservoir
    events.sort(key=lambda e: e["t"])

    print(f"[+] writing {len(events):,} events -> {out}", flush=True)
    digest = hashlib.sha256()
    with out.open("w", encoding="utf-8") as fh:
        for e in events:
            line = json.dumps(e, separators=(",", ":"))
            fh.write(line + "\n")
            digest.update(line.encode())

    span_days = max(1.0, max_t / SECONDS_PER_DAY)
    manifest = {
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "source": {"auth": str(auth), "redteam": str(redteam)},
        "seed": seed,
        "ground_truth": rt_stats,
        "corpus": {
            "auth_events_total": total,
            "benign_total": benign_total,
            "malicious_total": len(malicious),
            "true_base_rate": len(malicious) / total if total else 0.0,
            "span_days": round(span_days, 2),
        },
        "sample": {
            "events_written": len(events),
            "malicious_kept": len(malicious),
            "benign_kept": len(reservoir),
            "benign_sampling_fraction": (
                len(reservoir) / benign_total if benign_total else 0.0),
            "sample_base_rate": (
                len(malicious) / len(events) if events else 0.0),
        },
        "sha256": digest.hexdigest(),
        "how_to_read_precision": (
            "Malicious records are over-represented here by roughly "
            "1/benign_sampling_fraction. Precision measured on this file is "
            "optimistic by about that factor and must be corrected to "
            "true_base_rate before it is quoted. Recall needs no correction: "
            "every red-team record is present."
        ),
        "positive_class_warning": (
            f"The positive class is {len(malicious)} records and cannot grow — "
            "the corpus contains no more labelled attacks. Size confidence in "
            "any recall figure to that number, not to the file."
        ),
    }
    (out.parent / (out.stem + ".manifest.json")).write_text(
        json.dumps(manifest, indent=1))
    return manifest


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--auth", type=Path, default=BASE_DIR.parent / "auth.txt.gz")
    ap.add_argument("--redteam", type=Path, default=BASE_DIR.parent / "redteam.txt.gz")
    ap.add_argument("--benign", type=int, default=1_000_000)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--out", type=Path, default=BASE_DIR / "golden.jsonl")
    args = ap.parse_args()

    for p in (args.auth, args.redteam):
        if not p.exists():
            ap.error(f"missing {p}")

    m = build(args.auth, args.redteam, args.benign, args.out, args.seed)

    c, s = m["corpus"], m["sample"]
    print("\n" + "=" * 70)
    print(f"  corpus            {c['auth_events_total']:,} auth events over "
          f"{c['span_days']} days")
    print(f"  true base rate    {c['true_base_rate']:.2e}  "
          f"(1 in {int(1/c['true_base_rate']):,})")
    print(f"  written           {s['events_written']:,} events")
    print(f"    malicious       {s['malicious_kept']:,}  (all of them)")
    print(f"    benign          {s['benign_kept']:,}  "
          f"({s['benign_sampling_fraction']:.2e} of all benign)")
    print(f"  sample base rate  {s['sample_base_rate']:.2e}  "
          f"— over-represented ~{1/s['benign_sampling_fraction']:.0f}x")
    print(f"  sha256            {m['sha256'][:32]}…")
    print(f"\n[+] {args.out}")
    print(f"[+] {args.out.parent / (args.out.stem + '.manifest.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
