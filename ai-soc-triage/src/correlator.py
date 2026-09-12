"""Correlate raw alerts into incidents.

This is the stage that makes AI analysis of a full log set affordable. Running
the model per alert does not scale — a few thousand alerts at ~15s each is a
day of GPU time. Grouping first collapses them into a few dozen incidents, which
is both tractable and closer to how an analyst actually works: nobody triages
forty PsExec alerts from one host individually, they triage "PsExec from PC02".

Entirely deterministic. No model involved, so it is fast, repeatable, and cheap
to explain.

Grouping happens in two passes:
  1. Bucket alerts sharing (host, user, technique) when they fall within a
     time window of each other.
  2. Merge buckets that overlap in time and share a host or a user, so one
     intrusion spanning several techniques becomes one incident rather than
     one incident per technique.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Iterable

# Alerts of the same kind on the same asset within this gap belong together.
DEFAULT_WINDOW = timedelta(minutes=10)

# Pass 2 merges buckets whose spans are within this of each other.
DEFAULT_MERGE_GAP = timedelta(minutes=30)

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0}


def _parse_ts(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    text = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                parsed = datetime.strptime(text[:26], fmt)
                break
            except ValueError:
                continue
        else:
            return None
    # Compare naive throughout; EVTX sources mix aware and naive timestamps and
    # subtracting one from the other raises.
    return parsed.replace(tzinfo=None)


def _technique_key(alert: dict[str, Any]) -> str:
    return (
        alert.get("mitre_id")
        or alert.get("mitre_technique")
        or alert.get("rule_id")
        or "unknown"
    )


def _incident_id(host: str, user: str, technique: str, start: datetime | None) -> str:
    seed = f"{host}|{user}|{technique}|{start.isoformat() if start else 'na'}"
    return "INC-" + hashlib.sha1(seed.encode()).hexdigest()[:10].upper()


class _Bucket:
    """A growing group of related alerts."""

    __slots__ = ("alerts", "start", "end", "hosts", "users", "techniques")

    def __init__(self) -> None:
        self.alerts: list[dict[str, Any]] = []
        self.start: datetime | None = None
        self.end: datetime | None = None
        self.hosts: set[str] = set()
        self.users: set[str] = set()
        self.techniques: set[str] = set()

    def add(self, alert: dict[str, Any], ts: datetime | None) -> None:
        self.alerts.append(alert)
        if ts:
            self.start = ts if self.start is None else min(self.start, ts)
            self.end = ts if self.end is None else max(self.end, ts)
        if host := alert.get("computer"):
            self.hosts.add(host)
        if user := alert.get("user"):
            self.users.add(user)
        self.techniques.add(_technique_key(alert))

    def overlaps(self, other: "_Bucket", gap: timedelta) -> bool:
        if self.start is None or other.start is None:
            return False
        return self.start - gap <= other.end and other.start - gap <= self.end

    def shares_asset(self, other: "_Bucket") -> bool:
        return bool(self.hosts & other.hosts) or bool(self.users & other.users)

    def absorb(self, other: "_Bucket") -> None:
        self.alerts.extend(other.alerts)
        if other.start:
            self.start = other.start if self.start is None else min(self.start, other.start)
        if other.end:
            self.end = other.end if self.end is None else max(self.end, other.end)
        self.hosts |= other.hosts
        self.users |= other.users
        self.techniques |= other.techniques


def _bucket_alerts(
    alerts: list[dict[str, Any]], window: timedelta
) -> list[_Bucket]:
    """Pass 1: group by (host, user, technique) within a time window."""
    keyed: dict[tuple[str, str, str], list[_Bucket]] = {}

    ordered = sorted(alerts, key=lambda a: (_parse_ts(a.get("timestamp")) or datetime.min))
    for alert in ordered:
        ts = _parse_ts(alert.get("timestamp"))
        key = (
            str(alert.get("computer") or ""),
            str(alert.get("user") or ""),
            _technique_key(alert),
        )
        buckets = keyed.setdefault(key, [])

        placed = False
        for bucket in buckets:
            if ts is None or bucket.end is None or (ts - bucket.end) <= window:
                bucket.add(alert, ts)
                placed = True
                break
        if not placed:
            bucket = _Bucket()
            bucket.add(alert, ts)
            buckets.append(bucket)

    return [b for buckets in keyed.values() for b in buckets]


def _merge_buckets(buckets: list[_Bucket], gap: timedelta) -> list[_Bucket]:
    """Pass 2: merge buckets that share an asset and overlap in time.

    Iterates to a fixed point: merging A into B can make B mergeable with C.
    """
    merged = sorted(buckets, key=lambda b: (b.start or datetime.min))
    changed = True
    while changed:
        changed = False
        result: list[_Bucket] = []
        for bucket in merged:
            for existing in result:
                if existing.shares_asset(bucket) and existing.overlaps(bucket, gap):
                    existing.absorb(bucket)
                    changed = True
                    break
            else:
                result.append(bucket)
        merged = result
    return merged


def _summarize(bucket: _Bucket) -> dict[str, Any]:
    """Build the incident record the AI and the UI both consume."""
    severities = [str(a.get("severity", "")).lower() for a in bucket.alerts]
    peak = max(severities, key=lambda s: SEVERITY_RANK.get(s, 0)) if severities else "low"

    rule_counts = Counter(a.get("rule_name", "") for a in bucket.alerts)
    technique_counts = Counter(
        a.get("mitre_technique") or a.get("mitre_id") or "" for a in bucket.alerts
    )
    event_ids = sorted({str(a.get("event_id") or "") for a in bucket.alerts} - {""})
    processes = sorted({str(a.get("process_name") or "") for a in bucket.alerts} - {""})
    commands = [str(a.get("command_line") or "") for a in bucket.alerts]
    commands = sorted({c for c in commands if c})[:5]

    host = sorted(bucket.hosts)[0] if bucket.hosts else ""
    user = sorted(bucket.users)[0] if bucket.users else ""
    primary_technique = (
        technique_counts.most_common(1)[0][0] if technique_counts else "unknown"
    )

    duration = (
        (bucket.end - bucket.start).total_seconds()
        if bucket.start and bucket.end
        else 0.0
    )

    return {
        "incident_id": _incident_id(host, user, primary_technique, bucket.start),
        "alert_count": len(bucket.alerts),
        "severity": peak,
        "first_seen": bucket.start.isoformat() if bucket.start else "",
        "last_seen": bucket.end.isoformat() if bucket.end else "",
        "duration_seconds": duration,
        "hosts": sorted(bucket.hosts),
        "users": sorted(bucket.users),
        "event_ids": event_ids,
        "processes": processes,
        "command_lines": commands,
        "rules_fired": [{"rule": r, "count": n} for r, n in rule_counts.most_common()],
        "techniques_suspected": [
            {"technique": t, "count": n} for t, n in technique_counts.most_common() if t
        ],
        # Ground-truth tactic from the sample corpus, when present. Never shown
        # to the model — it exists so the benchmark can score attribution.
        "ground_truth_tactics": sorted(
            {str(a.get("attack_folder") or "") for a in bucket.alerts} - {""}
        ),
        "alert_ids": [a.get("alert_id") for a in bucket.alerts],
        # Every source row that contributed. sample_alerts is capped for
        # prompt size, so anything measuring coverage against it silently sees
        # at most five events per incident and under-reports badly.
        "member_row_indices": sorted({
            a["_row_index"] for a in bucket.alerts if a.get("_row_index") is not None
        }),
        "sample_alerts": bucket.alerts[:5],
    }


def correlate(
    alerts: Iterable[dict[str, Any]],
    window: timedelta = DEFAULT_WINDOW,
    merge_gap: timedelta = DEFAULT_MERGE_GAP,
) -> list[dict[str, Any]]:
    """Group alerts into incidents, most severe and most recent first."""
    alert_list = list(alerts)
    if not alert_list:
        return []

    buckets = _bucket_alerts(alert_list, window)
    buckets = _merge_buckets(buckets, merge_gap)

    incidents = [_summarize(b) for b in buckets]
    incidents.sort(
        key=lambda i: (
            -SEVERITY_RANK.get(i["severity"], 0),
            -i["alert_count"],
            i["first_seen"],
        )
    )
    return incidents


# Keeping the evidence small is a correctness concern, not just a cost one. A
# V100 has no flash-attention kernel, so SDPA materialises the full attention
# matrix and prompt length costs memory quadratically — an unbounded event dump
# OOMs the card mid-run.
MAX_FIELD_CHARS = 200
MAX_EVENT_FIELDS = 14

# Fields that carry no signal for triage but plenty of characters.
_NOISE_FIELDS = {
    "raw_data", "raw_message", "Keywords", "Opcode", "Task", "ThreadID",
    "object_marking_refs", "EventRecordID", "Guid", "ProviderName",
    "_row_index",
}


def _clip(value: Any, limit: int = MAX_FIELD_CHARS) -> str:
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "…"


def _trim_event(event: dict[str, Any]) -> dict[str, Any]:
    """Keep the fields an analyst would actually read."""
    trimmed: dict[str, Any] = {}
    for key, value in event.items():
        if key in _NOISE_FIELDS or value in (None, "", "-", "0"):
            continue
        trimmed[key] = _clip(value)
        if len(trimmed) >= MAX_EVENT_FIELDS:
            break
    return trimmed


def evidence_for_model(incident: dict[str, Any]) -> dict[str, Any]:
    """Trim an incident to what the model should see.

    Excludes ground_truth_tactics — the corpus labels are for scoring, and
    leaking them into the prompt would make the benchmark meaningless.
    """
    return {
        "incident_id": incident["incident_id"],
        "alert_count": incident["alert_count"],
        "rule_severity": incident["severity"],
        "first_seen": incident["first_seen"],
        "last_seen": incident["last_seen"],
        "duration_seconds": incident["duration_seconds"],
        "hosts": incident["hosts"][:5],
        "users": incident["users"][:5],
        "event_ids": incident["event_ids"][:8],
        "processes": incident["processes"][:8],
        "command_lines": [_clip(c) for c in incident["command_lines"][:3]],
        "rules_fired": incident["rules_fired"][:5],
        "sample_events": [_trim_event(a.get("event_data") or {}) for a in
                          incident.get("sample_alerts", [])[:2]],
    }


_CMDLINE_STOP = {
    "exe", "dll", "the", "and", "for", "com", "windows", "system32", "program",
    "files", "microsoft", "true", "false", "null", "http", "https",
}


def commandline_terms(command_line: str, limit: int = 6) -> list[str]:
    """Retrieval terms from a command line.

    The command line is where the LOLBAS signal lives — `rundll32.exe
    advpack.dll,RegisterOCX` is the whole tell, and a fixed query string
    reaches none of it. Splitting on path and argument separators surfaces the
    tokens the knowledge base is actually indexed on.
    """
    tokens, seen = [], set()
    for tok in re.split(r"[\s,;/\\\"\'()=]+", command_line or ""):
        tok = tok.strip(".-").lower()
        if len(tok) < 3 or tok in _CMDLINE_STOP or tok.isdigit() or tok in seen:
            continue
        seen.add(tok)
        tokens.append(tok)
        if len(tokens) >= limit:
            break
    return tokens


def retrieval_keys(incident: dict[str, Any]) -> dict[str, list[str]]:
    """Extract the identifiers that drive knowledge-base retrieval."""
    terms: list[str] = []
    for entry in incident.get("rules_fired", []):
        if rule := entry.get("rule"):
            terms.append(rule)
    for entry in incident.get("techniques_suspected", []):
        if tech := entry.get("technique"):
            terms.append(tech)

    return {
        "event_ids": incident.get("event_ids", [])[:5],
        "processes": incident.get("processes", [])[:5],
        "terms": terms[:5],
    }
