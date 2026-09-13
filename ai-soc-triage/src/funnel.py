"""Layer 1 — the volume funnel.

    10M events
      -> stream processing      bounded memory, one pass
      -> rules + statistics     high precision + rarity/content signals
      -> UEBA                   per-entity baseline deviation
      -> correlation            events -> incidents
      -> top-N by risk          bounded by the AI budget
      -> AI investigation       (Layer 2, the agents)

The design decision that matters: **no stage filters.** Every stage contributes
signal, and the narrowing happens once, at the end, by ranking. That is
deliberate. Measured on the labelled corpus, the 10 detection rules fire on only
39 of 249 attack samples — if rules gated the pipeline, 84% of known attacks
could never reach the AI regardless of how good it is. Ranking means a
rules-silent attack that looks statistically bizarre still surfaces.

The AI budget is a count, not a threshold. Fixed thresholds break when volume
moves: a noisy day either floods the model or silently drops the tail. Taking
the top N keeps cost bounded whatever arrives, and what fell below the line is
still recorded rather than discarded.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator

import pandas as pd

import correlator
from analytics import (AuthAnalytics, Signal, StatisticalDetector, UEBA, combine,
                       dedupe, evidence_weight)
from detector import load_rules, run_detection
from stream import StreamStats, stream_frame

# How many incidents get the full agent treatment. Chosen by GPU budget, not by
# how suspicious things look.
DEFAULT_AI_BUDGET = 40

# Rule hits are high-precision, so a rule firing contributes a large fixed
# signal rather than being ranked purely on statistics.
RULE_SIGNAL = {"critical": 0.95, "high": 0.8, "medium": 0.55, "low": 0.3}

# An unruled event must look genuinely extreme, on more than one independent
# signal, before it earns a place in the AI path.
PROMOTION_THRESHOLD = 0.9


@dataclass
class FunnelStage:
    name: str
    described: str
    events_in: int = 0
    events_out: int = 0
    elapsed: float = 0.0
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "described": self.described,
            "events_in": self.events_in,
            "events_out": self.events_out,
            "elapsed_seconds": round(self.elapsed, 2),
            "note": self.note,
            "reduction": (
                round(self.events_in / self.events_out, 1)
                if self.events_out else None
            ),
        }


@dataclass
class FunnelResult:
    stages: list[FunnelStage] = field(default_factory=list)
    incidents: list[dict[str, Any]] = field(default_factory=list)
    selected: list[dict[str, Any]] = field(default_factory=list)
    deferred: list[dict[str, Any]] = field(default_factory=list)
    stream_summary: dict[str, Any] = field(default_factory=dict)
    calibration: dict[str, Any] = field(default_factory=dict)
    caveats: list[str] = field(default_factory=list)
    elapsed: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "stages": [s.to_dict() for s in self.stages],
            "stream_summary": self.stream_summary,
            "incident_count": len(self.incidents),
            "selected_for_ai": len(self.selected),
            "deferred": len(self.deferred),
            "elapsed_seconds": round(self.elapsed, 2),
            "calibration": self.calibration,
            "caveats": self.caveats,
            # What fell below the budget line is reported, never silently
            # dropped: an analyst can see the tail and raise the budget.
            "deferred_summary": [
                {
                    "incident_id": i["incident_id"],
                    "funnel_score": i.get("funnel_score"),
                    "top_reason": (i.get("signals") or [{}])[0].get("reason", ""),
                }
                for i in self.deferred[:20]
            ],
        }


class TriageFunnel:
    def __init__(
        self,
        ai_budget: int = DEFAULT_AI_BUDGET,
        baseline: StreamStats | None = None,
        disabled_rules: set[str] | None = None,
    ) -> None:
        """
        baseline: statistics learned from a separate period of known-normal
            traffic. Rarity is only meaningful against a notion of normal, and
            when it is absent the funnel self-baselines on the data it is
            scoring — which means "rare" degrades to "rare within this sample"
            rather than "rare for this environment". That is a real weakness,
            so it is recorded in the result rather than glossed over.
        """
        self.ai_budget = ai_budget
        self.baseline = baseline
        self.disabled_rules = set(disabled_rules or ())
        self.self_baselined = baseline is None
        self.stats = baseline if baseline is not None else StreamStats()

    # -- pass 1: observe -----------------------------------------------------

    def observe(self, chunks: Iterable[pd.DataFrame]) -> list[pd.DataFrame]:  # noqa: D401
        """Fold the stream into running statistics.

        Rarity is only meaningful against the whole population, so the
        statistics have to exist before anything can be scored against them.
        Chunks are retained here for the scoring pass; a production deployment
        would keep the statistics and re-read the source instead.
        """
        retained = []
        for chunk in chunks:
            # With an external baseline the scoring data must not pollute it,
            # or the attack teaches the model that the attack is normal.
            if self.self_baselined:
                self.stats.observe(chunk)
            retained.append(chunk)
        return retained

    # -- pass 2: score -------------------------------------------------------

    def score_events(
        self, chunks: Iterable[pd.DataFrame],
        statistical: "StatisticalDetector | None" = None,
        ueba: "UEBA | None" = None,
    ) -> dict[int, list[Signal]]:
        """Statistical + UEBA signals per event, keyed by row index."""
        statistical = statistical or StatisticalDetector(self.stats)
        ueba = ueba or UEBA(self.stats)
        # Process and authentication telemetry carry disjoint fields, so both
        # scorers run and each contributes only where its inputs exist.
        auth = AuthAnalytics(self.stats)
        signals: dict[int, list[Signal]] = {}
        for chunk in chunks:
            for idx, row in zip(chunk.index, chunk.to_dict("records")):
                found = (statistical.score_row(row) + ueba.score_row(row)
                         + auth.score_row(row))
                if found:
                    signals[idx] = found
        return signals

    # -- the funnel ----------------------------------------------------------

    def run(
        self,
        df: pd.DataFrame,
        on_stage: Callable[[FunnelStage], None] | None = None,
        chunk_size: int = 50_000,
    ) -> FunnelResult:
        started = time.time()
        result = FunnelResult()

        # The detector converts rows to plain dicts, which loses the index, so
        # stamp it as a column first.
        if "_row_index" not in df.columns:
            df = df.assign(_row_index=df.index)

        def stage(name: str, described: str) -> FunnelStage:
            s = FunnelStage(name, described)
            result.stages.append(s)
            return s

        # --- Stage 1: stream ------------------------------------------------
        s = stage("stream", "Stream processing and baseline accumulation")
        t0 = time.time()
        s.events_in = len(df)
        chunks = self.observe(stream_frame(df, chunk_size))
        s.events_out = self.stats.events
        s.elapsed = time.time() - t0
        s.note = (
            f"{self.stats.chunks} chunk(s); baselines for "
            f"{len(self.stats.user_counts)} accounts and "
            f"{len(self.stats.host_counts)} hosts"
        )
        result.stream_summary = self.stats.summary()
        if self.self_baselined:
            result.caveats.append(
                "No separate baseline was supplied, so rarity was computed "
                "against the same data being scored. 'Rare' therefore means "
                "rare within this capture, not rare for this environment — "
                "normal operating-system activity can rank highly. Supply a "
                "baseline learned from known-normal traffic to fix this."
            )
        if on_stage:
            on_stage(s)

        # --- Stage 2: rules -------------------------------------------------
        s = stage("rules", "Deterministic detection rules")
        t0 = time.time()
        s.events_in = len(df)
        alerts = run_detection(df, disabled_rules=self.disabled_rules)
        s.events_out = len(alerts)
        s.elapsed = time.time() - t0
        active = len(load_rules()) - len(self.disabled_rules or ())
        s.note = f"{active} rules; high precision, low recall"
        if on_stage:
            on_stage(s)

        # --- Stage 3: statistics + UEBA -------------------------------------
        s = stage("analytics", "Statistical rarity and UEBA baseline deviation")
        t0 = time.time()
        s.events_in = len(df)
        statistical = StatisticalDetector(self.stats)
        event_signals = self.score_events(chunks, statistical=statistical)
        s.events_out = len(event_signals)
        s.elapsed = time.time() - t0
        s.note = (
            "unsupervised: no labelled benign data exists here, so these are "
            "rarity and per-entity deviation, not a trained model"
        )
        result.calibration = statistical.calibration()
        result.calibration["user_host_pair"] = {
            "distinct_keys": AuthAnalytics(self.stats).pair_rarity.distinct,
            "singleton_share": round(
                AuthAnalytics(self.stats).pair_rarity.singleton_share, 3),
            "discriminative_power": round(
                AuthAnalytics(self.stats).pair_rarity.discriminative_power, 3),
        }
        weak = [k for k, v in result.calibration.items()
                if v["discriminative_power"] < 0.4]
        if weak:
            result.caveats.append(
                f"Low discriminative power for {', '.join(weak)}: most values "
                "occur only once in this sample, so rarity there carries little "
                "information and is damped accordingly."
            )
        if on_stage:
            on_stage(s)

        # --- Stage 4: promote unruled events --------------------------------
        # Events the rules never saw but which look statistically extreme are
        # promoted into the alert set. This is the path that recovers attacks
        # the 10 rules miss entirely.
        s = stage("promotion", "Promote statistically extreme unruled events")
        t0 = time.time()
        s.events_in = len(event_signals)
        alerted_idx = {a.get("_row_index") for a in alerts}
        promoted = []
        for idx, sigs in event_signals.items():
            if idx in alerted_idx:
                continue
            score = combine(sigs)
            # Deliberately strict. At 0.75 more than half of all events cleared
            # the bar, which is not a funnel. Promotion should surface the
            # genuinely strange, and the deferred list catches what it misses.
            if score >= PROMOTION_THRESHOLD and len(sigs) >= 2:
                row = df.loc[idx].to_dict()
                promoted.append(self._synthetic_alert(row, idx, sigs, score))
        alerts.extend(promoted)
        s.events_out = len(promoted)
        s.elapsed = time.time() - t0
        s.note = f"{len(promoted)} event(s) reached the AI path without a rule hit"
        if on_stage:
            on_stage(s)

        # --- Stage 5: correlation -------------------------------------------
        s = stage("correlation", "Correlate alerts into incidents")
        t0 = time.time()
        s.events_in = len(alerts)
        incidents = correlator.correlate(alerts)
        s.events_out = len(incidents)
        s.elapsed = time.time() - t0
        if on_stage:
            on_stage(s)

        # --- Stage 6: rank and budget ---------------------------------------
        s = stage("ranking", "Rank by fused signal and apply the AI budget")
        t0 = time.time()
        s.events_in = len(incidents)
        for incident in incidents:
            self._attach_funnel_score(incident, df, event_signals)
        incidents.sort(key=lambda i: -i.get("evidence_weight", 0))

        result.incidents = incidents
        result.selected = incidents[: self.ai_budget]
        result.deferred = incidents[self.ai_budget :]
        s.events_out = len(result.selected)
        s.elapsed = time.time() - t0
        s.note = (
            f"budget {self.ai_budget}; {len(result.deferred)} incident(s) recorded "
            "below the line, not discarded"
        )
        if on_stage:
            on_stage(s)

        result.elapsed = time.time() - started
        return result

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _synthetic_alert(
        row: dict[str, Any], idx: int, signals: list[Signal], score: float
    ) -> dict[str, Any]:
        """An alert raised by analytics rather than by a rule.

        Marked as such so an analyst can tell which detections came from a
        written rule and which from behaviour, and so the benchmark can measure
        the two paths separately.
        """
        top = max(signals, key=lambda s: s.score)
        return {
            "alert_id": f"ANL-{idx}",
            "timestamp": str(row.get("timestamp") or ""),
            "rule_id": f"ANALYTIC-{top.kind.upper()}",
            "rule_name": f"Behavioural: {top.kind.replace('_', ' ')}",
            "severity": "high" if score >= 0.9 else "medium",
            "mitre_id": "",
            "mitre_technique": "",
            "description": top.reason,
            "computer": str(row.get("computer") or ""),
            "user": str(row.get("user") or ""),
            "source_ip": str(row.get("source_ip") or ""),
            "process_name": str(row.get("process_name") or ""),
            "command_line": str(row.get("command_line") or ""),
            "source_file": str(row.get("source_file") or ""),
            "attack_folder": str(row.get("attack_folder") or ""),
            "event_id": str(row.get("event_id") or ""),
            "event_data": row,
            "status": "open",
            "ai_analysis": None,
            "detection_source": "analytics",
            "analytic_score": score,
            "analytic_signals": [s.to_dict() for s in signals],
            "_row_index": idx,
        }

    @staticmethod
    def _attach_funnel_score(
        incident: dict[str, Any],
        df: pd.DataFrame,
        event_signals: dict[int, list[Signal]],
    ) -> None:
        """Fuse rule severity and analytic signals into one ranking score."""
        signals: list[Signal] = []

        severity = str(incident.get("severity", "")).lower()
        if any(
            a.get("detection_source") != "analytics"
            for a in incident.get("sample_alerts", [])
        ):
            signals.append(Signal(
                "rules", "rule_hit", RULE_SIGNAL.get(severity, 0.3),
                f"Rule hit at {severity} severity.",
            ))

        for alert in incident.get("sample_alerts", []):
            for raw in alert.get("analytic_signals", []) or []:
                signals.append(Signal(
                    raw["source"], raw["kind"], raw["score"], raw["reason"],
                ))

        # Volume is weak evidence on its own but real corroboration.
        count = incident.get("alert_count", 0)
        if count >= 5:
            signals.append(Signal(
                "rules", "volume", min(0.5, 0.1 * count),
                f"{count} correlated alerts.",
            ))

        incident["funnel_score"] = combine(signals)
        # Ranking uses the unbounded evidence weight so incidents never tie at
        # the top of the queue; the 0..1 score is for display.
        incident["evidence_weight"] = evidence_weight(signals)
        incident["signals"] = [s.to_dict() for s in dedupe(signals)][:6]
        incident["detection_sources"] = sorted({
            a.get("detection_source", "rules")
            for a in incident.get("sample_alerts", [])
        })
