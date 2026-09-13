"""Load golden.jsonl into a running dashboard.

WHY THIS IS NOT A BROWSER UPLOAD
--------------------------------
golden.jsonl is 274 MB and a million events. Pushing that through a file input
means the browser parses it in the UI thread, holds it all in memory, and then
the log view tries to render it. The dashboard's Import screen also never
posted to the server at all — it parsed into React state, so the funnel and the
agents never saw the file and every tab stayed on whatever the server had
loaded at boot. That combination is why importing appeared to do nothing.

Large corpora belong on the server side. This streams the file to /ingest in
batches, which is the same path the autopilot's inbox uses.

ON --limit
----------
Defaults to everything. The limit existed only because the log view used to
download the whole corpus into browser memory; it now asks the server for the
page it is showing, so there is no reason to hold events back. A company with a
billion events a day is the normal case, not an edge case, and a tool that
needs the corpus trimmed to stay usable is not a SOC tool.

Where a limit is given it trims benign records only. Dropping labelled attacks
would quietly change the ground truth of whatever was measured next.

Usage:
    python scripts/ingest_golden.py                      # 50k events, all attacks
    python scripts/ingest_golden.py --limit 0            # everything, be patient
    python scripts/ingest_golden.py --url http://host:8000
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_GOLDEN = BASE_DIR.parent / "ai-soc-eval" / "golden.jsonl"
DEFAULT_KEY_FILE = BASE_DIR / "output" / ".api_key"


def to_event(g: dict) -> dict:
    """Map a golden record onto the pipeline's normalised schema.

    Field names are the pipeline's, not the file's, so renaming a column here
    cannot invalidate a dataset that has already been published against its
    sha256.
    """
    failed = str(g.get("outcome", "")).strip().lower() == "failure"
    t = int(g.get("t", 0))
    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S",
                                   time.gmtime(1420070400 + t)),
        "event_id": "4625" if failed else "4624",
        "computer": g.get("computer", ""),
        "user": g.get("user", ""),
        "target_user": g.get("target_user", ""),
        "source_ip": g.get("source_ip", ""),
        "process_name": "",
        "parent_process": "",
        "command_line": "",
        "logon_type": g.get("logon_type", ""),
        "channel": "Security",
        "source_file": f"golden-{'red' if g.get('label') else 'benign'}",
        "raw_message": (f"{g.get('auth_type','')} {g.get('logon_type','')} "
                        f"{g.get('orientation','')} {g.get('outcome','')} "
                        f"{g.get('source_ip','')}->{g.get('computer','')}"),
    }


def post(url: str, payload: dict, key: str) -> dict:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if key:
        req.add_header("X-API-Key", key)
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.loads(resp.read())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--golden", type=Path, default=DEFAULT_GOLDEN)
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--limit", type=int, default=0,
                    help="max BENIGN events to send; 0 (default) sends every "
                         "one. Attacks are always sent in full.")
    ap.add_argument("--batch", type=int, default=5_000)
    ap.add_argument("--key", default="")
    args = ap.parse_args()

    if not args.golden.exists():
        print(f"no dataset at {args.golden}")
        return 1

    key = args.key or os.environ.get("SOC_API_KEY", "")
    if not key and DEFAULT_KEY_FILE.exists():
        key = DEFAULT_KEY_FILE.read_text().strip()

    attacks, benign = [], []
    with args.golden.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            g = json.loads(line)
            # Read the whole file even when limiting: the attacks are spread
            # across all 58 days, so stopping early would silently drop most
            # of the ground truth.
            (attacks if g.get("label") else benign).append(g)

    if args.limit:
        benign = benign[:args.limit]
    events = sorted(attacks + benign, key=lambda g: int(g.get("t", 0)))

    print(f"[+] {len(events):,} events to send "
          f"({len(attacks)} labelled attacks, {len(benign):,} benign)")
    if args.limit:
        print(f"[+] benign trimmed to --limit {args.limit:,}; every attack kept")

    sent = 0
    started = time.time()
    for i in range(0, len(events), args.batch):
        chunk = [to_event(g) for g in events[i:i + args.batch]]
        try:
            r = post(f"{args.url}/ingest", {"events": chunk, "origin": "golden.jsonl"}, key)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode()[:200]
            print(f"[!] HTTP {exc.code} at batch {i//args.batch}: {detail}")
            if exc.code == 401:
                print("[!] the API requires a key — pass --key or set SOC_API_KEY")
            return 1
        except Exception as exc:  # noqa: BLE001
            print(f"[!] {exc}")
            return 1
        sent += r.get("accepted", 0)
        print(f"    {sent:,}/{len(events):,} sent "
              f"({time.time()-started:.0f}s, {r.get('queued_batches', 0)} queued)",
              flush=True)

    print(f"\n[+] {sent:,} events accepted. The autopilot picks them up from its "
          f"inbox; watch the dashboard's Live Logs and Alerts tabs.")
    print(f"[+] {len(attacks)} of them are labelled attacks — ground truth for "
          f"anything you measure next.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
