"""Continuous, event-driven analysis. No buttons.

Logs arriving anywhere — a watched drop directory or the ingest API — enter a
queue. A background worker drains it forever: rules first, then behavioural
scoring, correlation, agent investigation, risk fusion, and finally every
dashboard surface is refreshed. Subscribers are notified as each stage lands,
so tabs update while work is still in flight.

Two design points that matter:

**Deterministic work is never queued behind the model.** Rules, statistics,
UEBA and correlation take about a second for thousands of events; agent
investigation takes a minute per case. If a single pipeline did both in order,
a new batch of logs would show nothing at all until the GPU caught up. Fast
results publish immediately and the slow enrichment lands underneath them.

**The budget applies per cycle, not per lifetime.** Each cycle sends its
highest-ranked cases to the agents and re-queues the rest, so a burst cannot
monopolise the GPU and starve later arrivals.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
INBOX_DIR = BASE_DIR / "data" / "inbox"
STATE_PATH = BASE_DIR / "output" / "autopilot_state.json"

# How often the drop directory is checked for new files.
WATCH_INTERVAL_SECONDS = 5

# Cases sent to the agents per cycle. Bounds GPU time per batch so a burst
# cannot starve whatever arrives next.
CASES_PER_CYCLE = 10

# Campaign-scope surfaces: they reason across the whole case set rather than
# one incident, so they run once the backlog is worked rather than per case.
CAMPAIGN_TABS = ("overview", "overview_plain", "investigations",
                 "assets", "hunting", "reports")

# Rebuild them again only after this many new cases, so a steady trickle of
# logs does not re-run six model calls on every single arrival.
CAMPAIGN_REFRESH_EVERY = 8


@dataclass
class Subscriber:
    """A live listener — one per open dashboard."""

    q: "queue.Queue[dict[str, Any]]" = field(default_factory=lambda: queue.Queue(maxsize=200))

    def push(self, event: dict[str, Any]) -> None:
        try:
            self.q.put_nowait(event)
        except queue.Full:
            # A slow client must never stall the pipeline.
            pass


class EventBus:
    """Fan-out to every connected dashboard."""

    def __init__(self) -> None:
        self._subs: list[Subscriber] = []
        self._lock = threading.Lock()
        self.history: list[dict[str, Any]] = []

    def subscribe(self) -> Subscriber:
        sub = Subscriber()
        with self._lock:
            self._subs.append(sub)
        return sub

    def unsubscribe(self, sub: Subscriber) -> None:
        with self._lock:
            if sub in self._subs:
                self._subs.remove(sub)

    def publish(self, kind: str, **payload: Any) -> None:
        event = {"kind": kind, "at": time.time(), **payload}
        with self._lock:
            self.history = (self.history + [event])[-200:]
            subs = list(self._subs)
        for sub in subs:
            sub.push(event)


@dataclass
class AutopilotState:
    running: bool = False
    cycles: int = 0
    events_ingested: int = 0
    incidents_total: int = 0
    cases_analysed: int = 0
    pending_cases: int = 0
    queued_batches: int = 0
    last_cycle_at: float = 0.0
    last_error: str = ""
    stage: str = "idle"

    def to_dict(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "cycles": self.cycles,
            "events_ingested": self.events_ingested,
            "incidents_total": self.incidents_total,
            "cases_analysed": self.cases_analysed,
            "pending_cases": self.pending_cases,
            "queued_batches": self.queued_batches,
            "last_cycle_at": self.last_cycle_at,
            "last_error": self.last_error,
            "stage": self.stage,
        }


class Autopilot:
    """Owns the ingest queue, the worker thread and the live event bus."""

    def __init__(self, engine_factory: Callable[[], Any] | None = None) -> None:
        self.bus = EventBus()
        self.state = AutopilotState()
        self.inbox: "queue.Queue[pd.DataFrame]" = queue.Queue()
        self._engine_factory = engine_factory
        self._engine = None
        self._worker: threading.Thread | None = None
        self._watcher: threading.Thread | None = None
        self._stop = threading.Event()
        self._seen_files: set[str] = set()
        # Incidents awaiting agent attention across cycles.
        self._pending: list[dict[str, Any]] = []
        self._all_incidents: list[dict[str, Any]] = []
        self._inventory = None
        self._memory = None
        self._stream_stats = None
        self._campaign: dict[str, Any] = {}
        self._campaign_built_at = 0
        self._verdicts: dict[str, Any] = {}
        self._last_df: pd.DataFrame | None = None
        self._lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------------

    def _restore(self) -> None:
        """Reload verdicts already on disk.

        Verdicts accumulate in memory, so a restart used to leave the dashboard
        showing an empty Alerts tab while cases.json still held the completed
        work — the analysis was there, the view had simply forgotten it.
        """
        from pipeline import CASES_PATH

        if not CASES_PATH.exists():
            return
        try:
            saved = json.loads(CASES_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return

        for case in saved.get("cases", []):
            iid = case.get("incident_id")
            payload = case.get("payload") or (case.get("investigation") or {}).get("verdict")
            if not iid or not payload:
                continue
            self._verdicts[iid] = {
                "tab_id": "alerts",
                "ok": True,
                "payload": payload,
                "risk": case.get("risk"),
                "autonomy": case.get("autonomy"),
                "asset_criticality": case.get("asset_criticality"),
                "investigation": case.get("investigation"),
                "knowledge_used": case.get("knowledge_used", []),
            }
        if self._verdicts:
            self.state.cases_analysed = len(self._verdicts)
            self.bus.publish("state.restored", verdicts=len(self._verdicts))

    def start(self, watch_inbox: bool = True) -> None:
        if self.state.running:
            return
        self._stop.clear()
        self._restore()
        self.state.running = True
        self._worker = threading.Thread(target=self._work_loop, daemon=True, name="autopilot")
        self._worker.start()
        if watch_inbox:
            INBOX_DIR.mkdir(parents=True, exist_ok=True)
            self._watcher = threading.Thread(
                target=self._watch_loop, daemon=True, name="autopilot-watch")
            self._watcher.start()
        self.bus.publish("autopilot.started", inbox=str(INBOX_DIR))

    def stop(self) -> None:
        self._stop.set()
        self.state.running = False
        self.bus.publish("autopilot.stopped")

    # -- ingestion ---------------------------------------------------------

    def submit(self, df: pd.DataFrame, origin: str = "api") -> None:
        """Hand a batch of normalised events to the pipeline."""
        self.inbox.put(df)
        self.state.queued_batches = self.inbox.qsize()
        self.bus.publish("logs.received", events=len(df), origin=origin,
                         queued_batches=self.inbox.qsize())

    def _watch_loop(self) -> None:
        """Pick up files dropped into the inbox directory."""
        from pipeline import load_corpus_dataframe

        while not self._stop.is_set():
            try:
                for path in sorted(INBOX_DIR.glob("*.csv")):
                    key = f"{path.name}:{path.stat().st_mtime}"
                    if key in self._seen_files:
                        continue
                    self._seen_files.add(key)
                    try:
                        df = load_corpus_dataframe(path)
                        self.submit(df, origin=path.name)
                    except Exception as exc:  # noqa: BLE001
                        self.bus.publish("logs.rejected", file=path.name, error=str(exc))
            except Exception as exc:  # noqa: BLE001 — a watcher must not die
                self.bus.publish("autopilot.warning", error=str(exc))
            self._stop.wait(WATCH_INTERVAL_SECONDS)

    # -- the worker --------------------------------------------------------

    def _work_loop(self) -> None:
        while not self._stop.is_set():
            try:
                batch = self.inbox.get(timeout=2)
            except queue.Empty:
                # Nothing new arrived; keep chewing through the agent backlog.
                if self._pending:
                    self._investigate_pending()
                continue
            try:
                self._run_cycle(batch)
            except Exception as exc:  # noqa: BLE001
                self.state.last_error = str(exc)
                self.bus.publish("cycle.failed", error=str(exc))
            finally:
                self.state.queued_batches = self.inbox.qsize()

    def _run_cycle(self, df: pd.DataFrame) -> None:
        """Deterministic stages first, published immediately; agents after."""
        from funnel import TriageFunnel

        # Held so the dashboard bundle can be rebuilt as each case completes.
        self._last_df = df
        self.state.cycles += 1
        self.state.events_ingested += len(df)
        self.state.stage = "funnel"
        self.bus.publish("cycle.started", cycle=self.state.cycles, events=len(df))

        funnel = TriageFunnel(ai_budget=CASES_PER_CYCLE)
        self._stream_stats = funnel.stats
        outcome = funnel.run(
            df,
            on_stage=lambda st: self.bus.publish(
                "funnel.stage", name=st.name,
                events_in=st.events_in, events_out=st.events_out,
                elapsed=round(st.elapsed, 2),
            ),
        )

        self.state.incidents_total += len(outcome.incidents)
        with self._lock:
            # Skip anything already decided: a restart should resume the queue,
            # not spend an hour of GPU redoing finished work.
            fresh = [i for i in outcome.incidents
                     if i["incident_id"] not in self._verdicts]
            skipped = len(outcome.incidents) - len(fresh)
            if skipped:
                self.bus.publish("cycle.resumed", already_analysed=skipped)
            self._pending = sorted(
                self._pending + fresh,
                key=lambda i: -i.get("evidence_weight", 0),
            )
            self.state.pending_cases = len(self._pending)

        # Rules and behavioural results are useful on their own and must not
        # wait behind a minute-per-case model.
        self.bus.publish(
            "triage.ready",
            incidents=len(outcome.incidents),
            selected=len(outcome.selected),
            deferred=len(outcome.deferred),
            coverage=outcome.to_dict().get("stream_summary", {}),
        )
        self._all_incidents = outcome.incidents

        # Business context is derived from the same telemetry when no CMDB is
        # configured, so the agent can reason about what is at stake.
        from inventory import Inventory
        self._inventory = Inventory.from_telemetry(df)
        # Publish the bundle immediately, with no verdicts yet. Every
        # log-oriented tab works off this, so it must exist the moment the
        # deterministic pass finishes rather than when the agents catch up.
        self._publish_bundle()
        self._route(outcome.incidents)
        self._investigate_pending()

    def _route(self, incidents: list[dict[str, Any]]) -> None:
        """Announce which surfaces each incident belongs on.

        Routing is derived from the evidence, not hardcoded per tab: an
        incident touching authentication events belongs on the identity view
        whether or not anyone wired that tab up.
        """
        routes: dict[str, int] = {}
        for inc in incidents:
            for tab in self._tabs_for(inc):
                routes[tab] = routes.get(tab, 0) + 1
        self.bus.publish("routing.updated", routes=routes)

    @staticmethod
    def _tabs_for(incident: dict[str, Any]) -> list[str]:
        tabs = ["alerts", "overview"]
        event_ids = set(incident.get("event_ids", []))
        if event_ids & {"4624", "4625", "4672", "4720", "4732", "4768", "4769", "4776"}:
            tabs.append("identity")
        if event_ids & {"3", "5140", "5145"}:
            tabs.append("network")
        if event_ids & {"1", "7", "10", "11", "12", "13", "4688"}:
            tabs.append("endpoint")
        if incident.get("techniques_suspected"):
            tabs.append("mitre")
        if len(incident.get("hosts", [])) > 1:
            tabs.append("investigations")
        if str(incident.get("severity", "")).lower() in ("critical", "high"):
            tabs.append("playbooks")
        return tabs

    def _investigate_pending(self) -> None:
        """Send the top of the backlog to the agents, one case at a time."""
        from orchestrator import Orchestrator

        if self._engine is None:
            if self._engine_factory is None:
                return
            try:
                self._engine = self._engine_factory()
            except Exception as exc:  # noqa: BLE001
                self.bus.publish("agents.unavailable", error=str(exc))
                return

        # The deterministic results are already published and useful. If the
        # model is unavailable the backlog simply waits — it must never take
        # down the ingest loop, or a GPU problem would stop log processing too.
        if self._engine is None:
            self.bus.publish(
                "agents.unavailable",
                error="no LLM backend; rules and behavioural analytics continue",
            )
            return

        from case_memory import CaseMemory
        if self._memory is None:
            self._memory = CaseMemory()

        try:
            orchestrator = Orchestrator(
                self._engine,
                df=self._last_df,
                agentic=True,
                inventory=self._inventory,
                memory=self._memory,
                stream_stats=self._stream_stats,
                # Each investigation step is pushed to the dashboard as it
                # happens, so an analyst watches the agent work rather than
                # waiting for a verdict to appear from nowhere.
                on_step=lambda step: self.bus.publish(
                    "investigation.step",
                    incident_id=getattr(self, "_current_case", ""),
                    step=step.get("step"),
                    tool=step.get("tool"),
                    thought=str(step.get("thought", ""))[:200],
                    args=step.get("args"),
                ),
            )
        except Exception as exc:  # noqa: BLE001
            self.bus.publish("agents.unavailable", error=str(exc))
            return

        self.state.stage = "agents"

        for _ in range(CASES_PER_CYCLE):
            if self._stop.is_set() or not self.inbox.empty():
                # New logs take priority: fast feedback beats deep analysis.
                break
            with self._lock:
                if not self._pending:
                    break
                incident = self._pending.pop(0)
                self.state.pending_cases = len(self._pending)

            self._current_case = incident.get("incident_id", "")
            self.bus.publish("investigation.started",
                             incident_id=self._current_case,
                             hosts=incident.get("hosts", [])[:3])
            try:
                case = orchestrator.run_case(incident, resume=incident.pop("_resume", None))
            except Exception as exc:  # noqa: BLE001
                self.bus.publish("case.failed",
                                 incident_id=incident.get("incident_id"), error=str(exc))
                continue

            parked = (case.investigation or {}).get("awaiting_human")
            if parked:
                import questions as _q
                asked = _q.get_store().ask(
                    incident["incident_id"], parked["question"],
                    why=parked.get("why", ""), options=parked.get("options"),
                    resume_state=parked.get("resume_state"),
                )
                self.bus.publish(
                    "question.asked",
                    incident_id=incident["incident_id"],
                    question_id=asked.question_id,
                    question=asked.question,
                    why=asked.why_it_matters,
                )
                # Not counted as analysed: nothing was decided.
                continue

            self.state.cases_analysed += 1
            payload = case.to_dict()
            self._verdicts[payload["incident_id"]] = {
                "tab_id": "alerts",
                "ok": bool(payload.get("payload")),
                "payload": payload.get("payload"),
                "risk": payload.get("risk"),
                "autonomy": payload.get("autonomy"),
                "asset_criticality": payload.get("asset_criticality"),
                "investigation": payload.get("investigation"),
                "knowledge_used": payload.get("knowledge_used", []),
                "ungrounded_techniques": (
                    payload.get("agents", {}).get("triage", {}).get("ungrounded", [])
                ),
            }
            self.bus.publish(
                "case.analysed",
                incident_id=payload["incident_id"],
                risk=payload.get("risk"),
                verdict=(payload.get("payload") or {}).get("verdict"),
                autonomy=(payload.get("autonomy") or {}).get("band"),
                asset_criticality=payload.get("asset_criticality"),
                steps=(payload.get("investigation") or {}).get("step_count"),
                tabs=self._tabs_for(incident),
                remaining=self.state.pending_cases,
            )
            self._persist(payload)
            # Refresh the dashboard bundle after every case, so tabs fill in
            # while the rest of the queue is still being worked.
            self._publish_bundle()

        # Campaign surfaces once the queue is drained, or after enough new
        # cases that the cross-incident picture has meaningfully changed.
        # Without this the Overview narrative, attack chain, asset risk and
        # hunting tabs stay permanently empty on the live path — they were only
        # ever built by the old batch pipeline.
        drained = self.state.pending_cases == 0
        moved_on = (self.state.cases_analysed - self._campaign_built_at
                    >= CAMPAIGN_REFRESH_EVERY)
        if self._verdicts and (drained or moved_on) and not self._stop.is_set():
            self._build_campaign()

        self.state.stage = "idle"
        self.state.last_cycle_at = time.time()
        self._save_state()

    def _build_campaign(self) -> None:
        """Cross-incident analysis: the narrative, kill chain, asset risk,
        hunting leads and the plain-language summary."""
        if self._engine is None or not self._all_incidents:
            return

        self.state.stage = "campaign"
        analysed = [i for i in self._all_incidents
                    if i["incident_id"] in self._verdicts]
        if not analysed:
            return

        for tab in CAMPAIGN_TABS:
            if self._stop.is_set() or not self.inbox.empty():
                # New logs outrank a narrative refresh.
                break
            try:
                result = self._engine.analyze_campaign(
                    analysed, tab, verdicts=self._verdicts)
                self._campaign[tab] = result.to_dict()
                self.bus.publish("campaign.updated", tab=tab, ok=result.ok)
            except Exception as exc:  # noqa: BLE001 — one tab must not stop the rest
                self.bus.publish("campaign.failed", tab=tab, error=str(exc))

        self._campaign_built_at = self.state.cases_analysed
        self._publish_bundle()

    def _publish_bundle(self) -> None:
        """Write the bundle every dashboard tab reads.

        The autopilot previously only wrote case files, so the dashboard kept
        rendering whatever the last batch run had left behind — live analysis
        happening in the background that no tab could see.
        """
        from pipeline import (ANALYSIS_PATH, BUNDLE_EVENT_PREVIEW, EVENTS_PATH,
                              OUTPUT_DIR, _atomic_write, build_event_rows,
                              build_metrics)

        if self._last_df is None or not self._all_incidents:
            return
        try:
            rows = build_event_rows(self._last_df, self._all_incidents)
            OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            EVENTS_PATH.write_text(json.dumps(rows, default=str), encoding="utf-8")

            bundle = {
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "live": True,
                "counts": {
                    "events": self.state.events_ingested,
                    "incidents": len(self._all_incidents),
                    "triaged": len(self._verdicts),
                    "pending": self.state.pending_cases,
                },
                "events": rows[:BUNDLE_EVENT_PREVIEW],
                "event_total": len(rows),
                "incidents": self._all_incidents,
                "verdicts": dict(self._verdicts),
                "campaign": dict(self._campaign),
                "queue": [
                    {
                        "incident_id": iid,
                        "risk_score": (v.get("risk") or {}).get("risk_score", 0),
                        "band": (v.get("risk") or {}).get("band", "unknown"),
                        "action": (v.get("risk") or {}).get("action", "unknown"),
                        "requires_approval": (v.get("risk") or {}).get("requires_approval", False),
                    }
                    for iid, v in sorted(
                        self._verdicts.items(),
                        key=lambda kv: -((kv[1].get("risk") or {}).get("risk_score") or 0),
                    )
                ],
                "telemetry_coverage": None,
                "metrics": build_metrics(
                    self._last_df, [], self._all_incidents, self._verdicts),
                "autopilot": self.state.to_dict(),
            }
            _atomic_write(ANALYSIS_PATH, bundle)
        except Exception as exc:  # noqa: BLE001 — publishing must not stop analysis
            self.bus.publish("publish.failed", error=str(exc))

    def resume_answered(self, question) -> bool:
        """Re-queue a parked case now that a human has answered.

        The investigation resumes from its stored transcript rather than
        starting over, so the tool calls already made are not repeated.
        """
        incident = next(
            (i for i in self._all_incidents
             if i["incident_id"] == question.incident_id), None)
        if incident is None:
            return False
        incident = dict(incident)
        incident["_resume"] = {
            **(question.resume_state or {}),
            "answer": question.answer,
            "question": question.question,
        }
        with self._lock:
            # Answered questions go to the front: a human is waiting on it.
            self._pending.insert(0, incident)
            self.state.pending_cases = len(self._pending)
        self.bus.publish("case.resumed", incident_id=question.incident_id)
        return True

    # -- persistence -------------------------------------------------------

    def _persist(self, case: dict[str, Any]) -> None:
        from pipeline import CASES_PATH, OUTPUT_DIR, _atomic_write

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        existing: dict[str, Any] = {"cases": [], "queue": []}
        if CASES_PATH.exists():
            try:
                existing = json.loads(CASES_PATH.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass

        cases = [c for c in existing.get("cases", [])
                 if c.get("incident_id") != case["incident_id"]] + [case]
        cases.sort(key=lambda c: -((c.get("risk") or {}).get("risk_score") or 0))
        existing["cases"] = cases
        existing["queue"] = [
            {
                "incident_id": c["incident_id"],
                "risk_score": (c.get("risk") or {}).get("risk_score", 0),
                "band": (c.get("risk") or {}).get("band", "unknown"),
                "action": (c.get("risk") or {}).get("action", "unknown"),
                "requires_approval": (c.get("risk") or {}).get("requires_approval", False),
            }
            for c in cases
        ]
        _atomic_write(CASES_PATH, existing)

    def _save_state(self) -> None:
        try:
            STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
            STATE_PATH.write_text(json.dumps(self.state.to_dict(), indent=1))
        except OSError:
            pass


_AUTOPILOT: Autopilot | None = None


def get_autopilot(engine_factory: Callable[[], Any] | None = None) -> Autopilot:
    global _AUTOPILOT
    if _AUTOPILOT is None:
        _AUTOPILOT = Autopilot(engine_factory=engine_factory)
    return _AUTOPILOT
