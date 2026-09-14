#!/work/aiw642/conda_envs/falcon3-7b/bin/python
"""New-edge detection over the FULL auth stream, not a sample.

Temporal novelty — "has this user ever reached this host before?" — is the
feature the published LANL work relies on, and it cannot be measured on a
sampled corpus. golden.jsonl keeps 1 benign event in 1,051, so a user's history
is almost entirely absent and nearly every edge looks new: measured there, the
feature showed 55.6% recall at a 20.9% false-positive rate, which says more
about the sampling than about the detector.

This makes one pass over all 1.05 billion authentications, building each
entity's history as it goes and scoring every event against the red-team
labels at the moment it occurs — no future information, the way a detector
would actually run.
"""
from __future__ import annotations
import gzip, json, sys, time
from pathlib import Path

AUTH = Path("../auth.txt.gz")
RED = Path("../redteam.txt.gz")

def main() -> int:
    labels = set()
    with gzip.open(RED, "rt") as fh:
        for line in fh:
            p = line.strip().split(",")
            if len(p) >= 4:
                labels.add((p[0], p[1], p[2], p[3]))
    print(f"[+] {len(labels)} red-team tuples", flush=True)

    seen_ud: set[tuple[str, str]] = set()   # user -> destination
    seen_sd: set[tuple[str, str]] = set()   # source -> destination
    seen_us: set[tuple[str, str]] = set()   # user -> source
    # counts: [tp, fp] per feature, plus the AND combination
    stat = {k: [0, 0] for k in ("new_ud", "new_sd", "new_us", "ud_and_sd", "any_two")}
    total = red_total = 0
    t0 = time.time()

    with gzip.open(AUTH, "rt", errors="replace") as fh:
        for line in fh:
            p = line.rstrip("\n").split(",")
            if len(p) < 9:
                continue
            t, su, du, sc, dc = p[0], p[1], p[2], p[3], p[4]
            total += 1
            is_red = (t, su, sc, dc) in labels
            red_total += is_red

            ud, sd, us = (su, dc), (sc, dc), (su, sc)
            n_ud, n_sd, n_us = ud not in seen_ud, sd not in seen_sd, us not in seen_us

            for key, hit in (("new_ud", n_ud), ("new_sd", n_sd), ("new_us", n_us),
                             ("ud_and_sd", n_ud and n_sd),
                             ("any_two", (n_ud + n_sd + n_us) >= 2)):
                if hit:
                    stat[key][0 if is_red else 1] += 1

            seen_ud.add(ud); seen_sd.add(sd); seen_us.add(us)

            if total % 200_000_000 == 0:
                print(f"    {total:,} ({time.time()-t0:.0f}s, "
                      f"{len(seen_ud):,} user-host edges)", flush=True)

    ben = total - red_total
    print(f"\n[+] {total:,} events, {red_total} red-team, {ben:,} benign")
    print(f"[+] distinct user->host edges: {len(seen_ud):,}\n")
    print(f"  {'feature':<28} {'recall':>8} {'FP rate':>10} {'alerts/day':>12}")
    out = {}
    for k, (tp, fp) in stat.items():
        rec = tp / red_total if red_total else 0
        fpr = fp / ben if ben else 0
        print(f"  {k:<28} {100*rec:7.1f}% {100*fpr:9.4f}% {fp/58:11,.0f}")
        out[k] = {"tp": tp, "fp": fp, "recall": rec, "fpr": fpr,
                  "false_alarms_per_day": fp / 58}
    Path("newedge_full.json").write_text(json.dumps(
        {"events": total, "red_team": red_total, "features": out}, indent=1))
    print("\n[+] newedge_full.json")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
