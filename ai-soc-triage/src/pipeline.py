"""End-to-end analysis pipeline: logs in, one analysis bundle out.

    Stage 0  normalize   EVTX or the pre-parsed corpus -> standard columns
    Stage 1  detect      YAML rules -> alerts
    Stage 2  correlate   alerts -> incidents            (no model, fast)
    Stage 3  triage      per-incident verdicts          (model + RAG)
    Stage 4  campaign    cross-incident analysis        (model + RAG)
    Stage 5  fan-out     one bundle every tab reads from

Stage 3 is cached on disk by incident id, so re-running is instant and a crashed
run resumes instead of starting over.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import pandas as pd

import correlator
from ai_engine import AIEngine
from orchestrator import Orchestrator
from detector import run_detection
from funnel import TriageFunnel
from tab_contracts import SCOPE_CAMPAIGN, TAB_CONTRACTS

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "output"
ANALYSIS_PATH = OUTPUT_DIR / "analysis.json"
CASES_PATH = OUTPUT_DIR / "cases.json"

# In-progress snapshots go to their own files. Writing them straight to
# analysis.json meant a new run destroyed the previous completed analysis on
# its very first case: an hour of results replaced by a bundle with one verdict
# in it. A run must not damage the last good result until it has produced a
# better one.
PARTIAL_ANALYSIS_PATH = OUTPUT_DIR / "analysis.partial.json"
PARTIAL_CASES_PATH = OUTPUT_DIR / "cases.partial.json"
TRIAGE_CACHE = OUTPUT_DIR / "triage_cache.json"
EVENTS_PATH = OUTPUT_DIR / "events.json"
CORPUS_CSV = BASE_DIR / "data" / "raw_logs" / "evtx_data.csv"

# Every campaign-scope tab. Each is one extra model call for the whole run, not
# one per incident, so covering all of them costs well under a minute.
DEFAULT_CAMPAIGN_TABS = ("overview", "overview_plain", "investigations",
                         "assets", "hunting", "reports")

STAGES = [
    "normalize",
    "detect",
    "correlate",
    "triage",
    "campaign",
    "fanout",
]


@dataclass
class JobState:
    job_id: str
    stage: str = "queued"
    stage_index: int = 0
    percent: float = 0.0
    message: str = ""
    done: bool = False
    error: str = ""
    counts: dict[str, int] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        elapsed = time.time() - self.started_at
        return {
            "job_id": self.job_id,
            "stage": self.stage,
            "stage_index": self.stage_index,
            "stage_count": len(STAGES),
            "percent": round(self.percent, 1),
            "message": self.message,
            "done": self.done,
            "error": self.error,
            "counts": self.counts,
            "elapsed_seconds": round(elapsed, 1),
        }


# --------------------------------------------------------------------------
# Stage 0 — normalize
# --------------------------------------------------------------------------

# The message the regex rules match against. Built from the fields that carry
# attacker-controlled or behaviourally meaningful text. Joining every column
# instead would make a rule like the LSASS regex match any row that merely
# mentions lsass somewhere, inflating alert counts.
MESSAGE_FIELDS = [
    "process_name",
    "command_line",
    "parent_process",
    "task_name",
    "object_name",
    "service_name",
    "image_path",
    "share_name",
    "relative_target_name",
]

# Several source columns can carry the same logical field, and which one is
# populated depends on the event provider: Sysmon writes Image, Security 4688
# writes NewProcessName, and older records use ProcessName. Renaming them all to
# one name and de-duplicating keeps whichever happens to come first, which threw
# away 2,140 Sysmon process names in favour of 220 from ProcessName. Coalescing
# in priority order keeps whichever is actually populated per row.
COALESCE = {
    "process_name": ["Image", "NewProcessName", "ProcessName", "SourceImage",
                     "CallerProcessName", "processPath"],
    "command_line": ["CommandLine", "ParentCommandLine"],
    "parent_process": ["ParentImage", "ParentProcessName"],
    "user": ["SubjectUserName", "User", "AccountName"],
    "target_user": ["TargetUserName"],
    "computer": ["Computer", "Hostname"],
    "source_ip": ["IpAddress", "SourceIp", "DestinationIp"],
    "destination_port": ["IpPort", "DestinationPort"],
    "event_id": ["EventID", "EventId"],
    "channel": ["Channel"],
    "timestamp": ["SystemTime", "UtcTime", "TimeCreated"],
    "logon_type": ["LogonType"],
    "task_name": ["TaskName"],
    "object_name": ["ObjectName", "TargetObject"],
    "service_name": ["ServiceName"],
    "image_path": ["ImagePath"],
    "share_name": ["ShareName"],
    "relative_target_name": ["RelativeTargetName"],
    "source_file": ["EVTX_FileName"],
    "attack_folder": ["EVTX_Tactic"],
}

STANDARD_COLUMNS = [
    "timestamp", "event_id", "computer", "channel", "user", "source_ip",
    "destination_port", "process_name", "parent_process", "command_line",
    "logon_type", "task_name", "object_name", "raw_data", "raw_message",
    "source_file", "attack_folder", "ingest_source",
]


def _clean_series(series: pd.Series) -> pd.Series:
    """Normalise a column to trimmed strings, with placeholders emptied out."""
    out = series.astype(str).str.strip()
    # Windows logs use "-" for absent; pandas float columns render ids as "3.0".
    out = out.replace({"nan": "", "None": "", "-": "", "NaN": ""})
    out = out.str.replace(r"^(\d+)\.0$", r"\1", regex=True)
    return out


def load_corpus_dataframe(csv_path: Path | None = None) -> pd.DataFrame:
    """Load the pre-parsed EVTX corpus into the detector's expected shape.

    The corpus ships already parsed with a ground-truth tactic per row, so this
    skips re-parsing 249 EVTX files for every run.
    """
    path = csv_path or CORPUS_CSV
    raw = pd.read_csv(path, low_memory=False)

    df = pd.DataFrame(index=raw.index)
    for target, candidates in COALESCE.items():
        present = [c for c in candidates if c in raw.columns]
        if not present:
            df[target] = ""
            continue
        combined = _clean_series(raw[present[0]])
        for col in present[1:]:
            combined = combined.where(combined != "", _clean_series(raw[col]))
        df[target] = combined

    for col in STANDARD_COLUMNS:
        if col not in df.columns:
            df[col] = ""

    present = [c for c in MESSAGE_FIELDS if c in df.columns]
    df["raw_message"] = (
        df[present].agg(" ".join, axis=1).str.replace(r"\s+", " ", regex=True).str.strip()
        if present
        else ""
    )
    return df


# --------------------------------------------------------------------------
# Triage cache
# --------------------------------------------------------------------------

def _atomic_write(path: Path, payload: Any) -> None:
    """Write via a temp file and rename, so a crash mid-write cannot leave a
    half-written bundle where a valid one used to be."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=1, default=str), encoding="utf-8")
    tmp.replace(path)


def _load_cache() -> dict[str, Any]:
    if TRIAGE_CACHE.exists():
        try:
            return json.loads(TRIAGE_CACHE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def _save_cache(cache: dict[str, Any]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    TRIAGE_CACHE.write_text(json.dumps(cache, indent=1), encoding="utf-8")


# --------------------------------------------------------------------------
# The pipeline
# --------------------------------------------------------------------------

def run_pipeline(
    df: pd.DataFrame | None = None,
    engine: AIEngine | None = None,
    campaign_tabs: tuple[str, ...] = DEFAULT_CAMPAIGN_TABS,
    limit_incidents: int | None = None,
    use_cache: bool = True,
    multi_agent: bool = True,
    use_funnel: bool = True,
    ai_budget: int = 40,
    on_progress: Callable[[JobState], None] | None = None,
    job: JobState | None = None,
) -> dict[str, Any]:
    """Run every stage and return the analysis bundle."""
    job = job or JobState(job_id="local")

    def advance(index: int, message: str, percent: float) -> None:
        job.stage = STAGES[index]
        job.stage_index = index
        job.message = message
        job.percent = percent
        if on_progress:
            on_progress(job)

    started = time.time()

    # Stage 0
    advance(0, "Normalizing events", 2)
    if df is None:
        df = load_corpus_dataframe()
    job.counts["events"] = len(df)

    funnel_report: dict[str, Any] = {}
    if use_funnel:
        # Layer 1: rules + statistics + UEBA + correlation, narrowed by ranking
        # against a fixed AI budget rather than by a threshold. Rules alone
        # reach 14% of the labelled attack samples; adding behavioural signal
        # more than doubles that, and nothing is discarded — what falls below
        # the budget is recorded as deferred.
        advance(1, f"Funnel: analysing {len(df):,} events", 8)
        funnel = TriageFunnel(ai_budget=ai_budget)

        funnel_stage_names = ["stream", "rules", "analytics", "promotion",
                              "correlation", "ranking"]

        def on_funnel_stage(st) -> None:
            # Funnel stages occupy the 8-20% band of overall progress; the
            # model calls after it are what actually take the time.
            position = funnel_stage_names.index(st.name) + 1
            advance(
                1 if position <= 4 else 2,
                f"{st.name}: {st.events_in:,} -> {st.events_out:,}",
                8 + 12 * position / len(funnel_stage_names),
            )

        outcome = funnel.run(df, on_stage=on_funnel_stage)
        funnel_report = outcome.to_dict()
        alerts = []
        incidents = outcome.selected
        job.counts["alerts"] = next(
            (st.events_out for st in outcome.stages if st.name == "rules"), 0
        )
        job.counts["analytic_promotions"] = next(
            (st.events_out for st in outcome.stages if st.name == "promotion"), 0
        )
        job.counts["incidents_total"] = len(outcome.incidents)
        job.counts["deferred"] = len(outcome.deferred)
    else:
        advance(1, f"Running detection rules over {len(df):,} events", 10)
        alerts = run_detection(df)
        job.counts["alerts"] = len(alerts)

        advance(2, f"Correlating {len(alerts):,} alerts into incidents", 20)
        incidents = correlator.correlate(alerts)

    if limit_incidents:
        incidents = incidents[:limit_incidents]
    job.counts["incidents"] = len(incidents)

    event_rows = build_event_rows(df, incidents)
    job.counts["published_events"] = len(event_rows)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    EVENTS_PATH.write_text(
        json.dumps(event_rows, default=str), encoding="utf-8"
    )

    # Stage 3
    engine = engine or AIEngine()
    cache = _load_cache() if use_cache else {}
    verdicts: dict[str, Any] = {}
    agent_output: dict[str, Any] = {}

    if multi_agent:
        # Multi-agent path: Evidence Engine -> Intel -> Triage -> Risk -> Response.
        orchestrator = Orchestrator(engine, df)

        def _case_progress(i: int, total: int, incident_id: str) -> None:
            advance(3, f"Agents analysing incident {i} of {total}",
                    20 + 55 * ((i - 1) / max(1, total)))

        def _publish_partial(done_cases: list) -> None:
            """Write what exists so far, so the dashboard fills in during the
            run rather than staying empty until it finishes."""
            partial_verdicts = {}
            for c in done_cases:
                d = c.to_dict()
                partial_verdicts[d["incident_id"]] = {
                    "tab_id": "alerts",
                    "ok": bool(d.get("payload")),
                    "payload": d.get("payload"),
                    "risk": d.get("risk"),
                    "knowledge_used": d.get("knowledge_used", []),
                }
            snapshot = {
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "in_progress": True,
                "events": event_rows[:BUNDLE_EVENT_PREVIEW],
                "event_total": len(event_rows),
                "counts": dict(job.counts, triaged=len(done_cases)),
                "funnel": funnel_report,
                "incidents": incidents,
                "verdicts": partial_verdicts,
                "campaign": {},
                "queue": [
                    {
                        "incident_id": c.incident["incident_id"],
                        "risk_score": round(c.risk.score, 1) if c.risk else 0,
                        "band": c.risk.band if c.risk else "unknown",
                        "action": c.risk.action if c.risk else "unknown",
                        "requires_approval": c.risk.requires_approval if c.risk else False,
                    }
                    for c in sorted(done_cases,
                                    key=lambda x: -(x.risk.score if x.risk else 0))
                ],
                "telemetry_coverage": orchestrator.evidence.coverage(),
                "metrics": build_metrics(df, [], incidents, partial_verdicts),
                "engine_stats": engine.stats.as_dict(),
            }
            OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            PARTIAL_ANALYSIS_PATH.write_text(
                json.dumps(snapshot, indent=1, default=str), encoding="utf-8"
            )
            PARTIAL_CASES_PATH.write_text(
                json.dumps({"cases": [c.to_dict() for c in done_cases],
                            "queue": snapshot["queue"],
                            "telemetry_coverage": snapshot["telemetry_coverage"]},
                           indent=1, default=str),
                encoding="utf-8",
            )

        agent_output = orchestrator.run(
            incidents, on_progress=_case_progress, on_case=_publish_partial
        )
        for case in agent_output["cases"]:
            # The triage verdict stays the UI's primary payload; the full case
            # file (every agent, evidence by domain, risk factors) sits beside it.
            verdicts[case["incident_id"]] = {
                "tab_id": "alerts",
                "ok": bool(case.get("payload")),
                "payload": case.get("payload"),
                "risk": case.get("risk"),
                "knowledge_used": case.get("knowledge_used", []),
                "ungrounded_techniques": (
                    case.get("agents", {}).get("triage", {}).get("ungrounded", [])
                ),
            }
        CASES_PATH.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(CASES_PATH, agent_output)
    else:
        for i, incident in enumerate(incidents):
            iid = incident["incident_id"]
            pct = 20 + 55 * (i / max(1, len(incidents)))
            advance(3, f"Triaging incident {i + 1} of {len(incidents)}", pct)

            if use_cache and iid in cache:
                verdicts[iid] = cache[iid]
                continue

            result = engine.analyze_incident(incident, tab_id="alerts")
            verdicts[iid] = result.to_dict()
            cache[iid] = verdicts[iid]
            if use_cache and i % 5 == 0:
                _save_cache(cache)

        if use_cache:
            _save_cache(cache)

    job.counts["triaged"] = len(verdicts)

    # Stage 4
    campaign: dict[str, Any] = {}
    for j, tab_id in enumerate(campaign_tabs):
        pct = 75 + 20 * (j / max(1, len(campaign_tabs)))
        advance(4, f"Building {TAB_CONTRACTS[tab_id].label}", pct)
        result = engine.analyze_campaign(incidents, tab_id, verdicts=verdicts)
        campaign[tab_id] = result.to_dict()

    # Stage 5
    advance(5, "Assembling analysis bundle", 97)
    bundle = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "elapsed_seconds": round(time.time() - started, 1),
        "counts": job.counts,
        "events": event_rows[:BUNDLE_EVENT_PREVIEW],
        "event_total": len(event_rows),
        "funnel": funnel_report,
        "metrics": build_metrics(df, alerts, incidents, verdicts),
        "incidents": incidents,
        "verdicts": verdicts,
        "campaign": campaign,
        "queue": agent_output.get("queue", []),
        "telemetry_coverage": agent_output.get("telemetry_coverage"),
        "hunt": agent_output.get("hunt"),
        "engine_stats": engine.stats.as_dict(),
        "retrieval_stats": dict(engine.kb.stats) if engine.kb else {},
        "config": {
            "use_rag": engine.use_rag,
            "two_pass": engine.two_pass,
            "multi_agent": multi_agent,
            "model": getattr(engine.backend, "_model_name", "unknown"),
        },
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    # Keep the previous completed run recoverable, then swap in the new one.
    if ANALYSIS_PATH.exists():
        ANALYSIS_PATH.replace(OUTPUT_DIR / "analysis.previous.json")
    _atomic_write(ANALYSIS_PATH, bundle)
    for stale in (PARTIAL_ANALYSIS_PATH, PARTIAL_CASES_PATH):
        stale.unlink(missing_ok=True)

    job.done = True
    advance(5, "Complete", 100)
    return bundle


# --------------------------------------------------------------------------

# Every event is published, not a sample. A SIEM's log view is where an analyst
# goes to check what actually happened, and a truncated view is worse than none
# because the absence is invisible — you cannot tell a log that is not there
# from a log that does not exist. The full corpus here is ~2 MB with empty
# fields dropped, so it is served whole from its own paginated endpoint rather
# than embedded in the analysis bundle.
MAX_PUBLISHED_EVENTS = 0  # 0 = no cap

# Only a slice is embedded in the bundle, so the dashboard paints immediately;
# the log view pages through /events for the rest.
BUNDLE_EVENT_PREVIEW = 500

_SEVERITY_BY_EVENT = {
    "1102": "CRITICAL", "4625": "MEDIUM", "4720": "HIGH", "4732": "HIGH",
    "4698": "HIGH", "7045": "HIGH", "4672": "MEDIUM", "4769": "MEDIUM",
}


def _raw_record(row: dict[str, Any]) -> dict[str, Any]:
    """The original event, minus empty fields.

    Kept so an analyst can open a row and read the actual record rather than
    the platform's interpretation of it. Dropping empties takes the payload
    from 3.1 MB to 2.0 MB with no information lost — the fields were blank.
    """
    return {
        k: v for k, v in row.items()
        if v not in ("", None, "-") and not k.startswith("_")
    }


def _to_log_row(row: dict[str, Any], index: int, alert: dict[str, Any] | None) -> dict[str, Any]:
    """Render one normalised event in the shape the frontend log views expect."""
    if alert is not None:
        severity = str(alert.get("severity", "medium")).upper()
        rule = alert.get("rule_name") or "Correlated alert"
        message = alert.get("description") or rule
        mitre = alert.get("mitre_technique") or ""
    else:
        severity = _SEVERITY_BY_EVENT.get(str(row.get("event_id", "")), "LOW")
        rule = f"Event {row.get('event_id', '')}".strip()
        parts = [str(row.get(f, "")) for f in ("process_name", "command_line")]
        message = " ".join(p for p in parts if p) or rule
        mitre = ""

    return {
        "id": f"EV-{index}",
        "timestamp": str(row.get("timestamp") or ""),
        "severity": severity,
        "sourceIP": str(row.get("source_ip") or "Unknown"),
        "destIP": "Unknown",
        "user": str(row.get("user") or "Unknown"),
        "host": str(row.get("computer") or "Unknown"),
        "message": message[:400],
        "rule": rule,
        "source": str(row.get("channel") or "Windows"),
        # Which import this row arrived in. Without it the log view is one
        # undifferentiated pile and an analyst cannot ask the first question
        # they always ask: which file did this come from?
        "ingestSource": str(row.get("ingest_source") or row.get("source_file") or "unknown"),
        "mitre": mitre,
        "status": "open",
        "eventId": str(row.get("event_id") or ""),
        "process": str(row.get("process_name") or ""),
        "commandLine": str(row.get("command_line") or "")[:400],
        "detectionSource": (alert or {}).get("detection_source", ""),
        # The unmodified record, so "show me the real log" is answerable.
        "_raw": _raw_record(row),
    }


def build_event_rows(df: pd.DataFrame, incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Publish every event, in source order, annotated where one raised an alert.

    Source order matters for a log view: an analyst reading a timeline needs the
    sequence the events actually occurred in, not a relevance ranking. Alert
    context is attached in place rather than by reordering.
    """
    alerts_by_index: dict[Any, dict[str, Any]] = {}
    for incident in incidents:
        for alert in incident.get("sample_alerts", []):
            idx = alert.get("_row_index")
            if idx is not None:
                alerts_by_index[idx] = alert

    rows: list[dict[str, Any]] = []
    for position, (idx, row) in enumerate(df.iterrows()):
        rows.append(_to_log_row(row.to_dict(), position, alerts_by_index.get(idx)))
        if MAX_PUBLISHED_EVENTS and len(rows) >= MAX_PUBLISHED_EVENTS:
            break
    return rows


# Minutes a Tier-1 analyst spends manually triaging one alert. Stated here and
# surfaced in the UI rather than buried, because every "hours saved" figure is
# only as credible as the assumption behind it.
MINUTES_PER_ALERT_MANUAL = 8


def build_metrics(
    df: pd.DataFrame,
    alerts: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
    verdicts: dict[str, Any],
) -> dict[str, Any]:
    """The funnel, plus a clearly-labelled effort estimate."""
    escalated = suppressed = unknown = 0
    for v in verdicts.values():
        payload = v.get("payload") or {}
        verdict = str(payload.get("verdict", "")).upper()
        if verdict == "ESCALATE":
            escalated += 1
        elif verdict == "SUPPRESS":
            suppressed += 1
        else:
            unknown += 1

    triaged_alerts = sum(
        i["alert_count"] for i in incidents if i["incident_id"] in verdicts
    )

    # The autopilot does not retain the alert objects between cycles and passed
    # an empty list, so the dashboard reported "0 rule alerts" on every live
    # run while 280 rules had in fact fired. The incidents carry the firing
    # counts, so derive rather than trust an empty argument.
    rule_alerts = len(alerts)
    if not rule_alerts:
        rule_alerts = sum(
            r.get("count", 1)
            for i in incidents
            for r in i.get("rules_fired", [])
        )
    manual_minutes = triaged_alerts * MINUTES_PER_ALERT_MANUAL

    return {
        "events_ingested": int(len(df)),
        "rule_alerts": rule_alerts,
        "incidents": len(incidents),
        "escalated": escalated,
        "suppressed": suppressed,
        "unknown": unknown,
        "reduction_events_to_incidents": (
            round(len(df) / len(incidents), 1) if incidents else 0
        ),
        "analyst_effort": {
            "assumption_minutes_per_alert": MINUTES_PER_ALERT_MANUAL,
            "alerts_covered": triaged_alerts,
            "manual_hours": round(manual_minutes / 60, 1),
            "note": (
                f"Assumes {MINUTES_PER_ALERT_MANUAL} minutes of manual Tier-1 "
                "triage per alert. This is an assumption, not a measurement."
            ),
        },
    }
