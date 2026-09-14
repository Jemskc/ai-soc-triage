"""Logs an analyst sent to the AI by hand, and what the AI made of them.

The dashboard had a "Send to AI" button that put a log into a chat panel and
nothing more. Whatever the model said scrolled away with the conversation, was
attached to no record, and could not be found again — so the one place a
person deliberately asked for a second opinion was the one place nothing was
kept.

This is that queue. A submission is durable, has a status an analyst can see
while they wait, and keeps the evaluation attached to the log it was about.

Submissions are keyed by the log's own stable id, so sending the same record
twice returns the existing review rather than paying for the same answer again.
"""

from __future__ import annotations

import json
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable

STORE = Path(__file__).resolve().parent.parent / "output" / "manual_review.json"

# An analyst can only read so many of these. The cap is here so a stuck finger
# on the Send button cannot grow the file without limit.
MAX_REVIEWS = 200


class ManualReviewQueue:
    """Submit a log, get an AI evaluation, keep it."""

    def __init__(self, analyse: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        self._analyse = analyse
        self._lock = threading.RLock()
        self._reviews: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._work: list[str] = []
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._load()

    # -- persistence -------------------------------------------------------

    def _load(self) -> None:
        if not STORE.exists():
            return
        try:
            rows = json.loads(STORE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        with self._lock:
            for row in rows:
                # A review that was mid-flight when the process died is not
                # "running" any more; saying so would be a lie the UI would
                # spin on forever.
                if row.get("status") == "running":
                    row["status"] = "queued"
                self._reviews[row["id"]] = row
                if row["status"] == "queued":
                    self._work.append(row["id"])
        if self._work:
            self._wake.set()

    def _save(self) -> None:
        try:
            STORE.parent.mkdir(parents=True, exist_ok=True)
            STORE.write_text(json.dumps(list(self._reviews.values()), indent=1,
                                        default=str), encoding="utf-8")
        except OSError:
            pass  # a review that cannot be written is still usable in memory

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        self._stop.clear()
        self._worker = threading.Thread(target=self._loop, daemon=True,
                                        name="manual-review")
        self._worker.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    # -- api ---------------------------------------------------------------

    def submit(self, event: dict[str, Any], note: str = "") -> dict[str, Any]:
        rid = str(event.get("uid") or event.get("id") or f"LOG-{int(time.time()*1000)}")
        with self._lock:
            existing = self._reviews.get(rid)
            if existing and existing["status"] in ("done", "running", "queued"):
                return {"review": existing, "already_present": True}

            review = {
                "id": rid,
                "submitted_at": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
                "status": "queued",
                "note": note,
                "event": event,
                "result": None,
                "error": None,
                "elapsed_seconds": None,
                "position": len([r for r in self._reviews.values()
                                 if r["status"] == "queued"]) + 1,
            }
            self._reviews[rid] = review
            self._reviews.move_to_end(rid)
            self._work.append(rid)
            while len(self._reviews) > MAX_REVIEWS:
                old, _ = self._reviews.popitem(last=False)
                if old in self._work:
                    self._work.remove(old)
            self._save()
        self._wake.set()
        return {"review": review, "already_present": False}

    def list(self) -> dict[str, Any]:
        with self._lock:
            rows = list(reversed(self._reviews.values()))
            counts: dict[str, int] = {}
            for r in rows:
                counts[r["status"]] = counts.get(r["status"], 0) + 1
            return {"reviews": rows, "counts": counts, "total": len(rows)}

    def get(self, rid: str) -> dict[str, Any] | None:
        with self._lock:
            return self._reviews.get(rid)

    def remove(self, rid: str) -> bool:
        with self._lock:
            gone = self._reviews.pop(rid, None) is not None
            if rid in self._work:
                self._work.remove(rid)
            if gone:
                self._save()
            return gone

    def clear(self) -> int:
        with self._lock:
            n = len(self._reviews)
            self._reviews.clear()
            self._work.clear()
            self._save()
            return n

    # -- worker ------------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                rid = self._work.pop(0) if self._work else None
            if rid is None:
                self._wake.wait(2)
                self._wake.clear()
                continue

            with self._lock:
                review = self._reviews.get(rid)
                if review is None:
                    continue
                review["status"] = "running"
                event = review["event"]
                self._save()

            started = time.time()
            try:
                result = self._analyse(event)
                ok = bool(result.get("ok")) if isinstance(result, dict) else False
                with self._lock:
                    review = self._reviews.get(rid)
                    if review is None:
                        continue
                    review["status"] = "done" if ok else "failed"
                    review["result"] = result
                    review["error"] = None if ok else (
                        (result or {}).get("error") or "the model returned nothing usable")
                    review["elapsed_seconds"] = round(time.time() - started, 1)
                    self._save()
            except Exception as exc:  # noqa: BLE001
                with self._lock:
                    review = self._reviews.get(rid)
                    if review is not None:
                        review["status"] = "failed"
                        review["error"] = str(exc)[:300]
                        review["elapsed_seconds"] = round(time.time() - started, 1)
                        self._save()
