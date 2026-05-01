"""Rule-based detection engine for SOC triage alerts."""

from __future__ import annotations

import re
import uuid
from collections import Counter, defaultdict
from datetime import datetime, time
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_RULES_PATH = BASE_DIR / "rules" / "detection_rules.yml"


def load_rules(rules_path: Path | None = None) -> list[dict[str, Any]]:
    """Load YAML detection rules.

    Args:
        rules_path: Path to YAML rules file; defaults to rules/detection_rules.yml.

    Returns:
        List of rule dicts.
    """
    target = rules_path or DEFAULT_RULES_PATH
    try:
        with target.open("r", encoding="utf-8") as fh:
            parsed = yaml.safe_load(fh) or []
    except Exception as err:
        print(f"[-] Could not load rules from {target}: {err}")
        return []
    if not isinstance(parsed, list):
        print(f"[!] Rules file did not contain a list: {target}")
        return []
    print(f"[+] Loaded {len(parsed)} detection rules")
    return parsed


def _to_lower(value: Any) -> str:
    return str(value).strip().lower()


def _parse_timestamp(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    parsed = pd.to_datetime(value, errors="coerce", utc=True)
    if pd.isna(parsed):
        return None
    return parsed.tz_convert(None).to_pydatetime()


def _parse_business_hours(value: str) -> tuple[time, time] | None:
    try:
        start_text, end_text = value.split("-", maxsplit=1)
        return (
            datetime.strptime(start_text.strip(), "%H:%M").time(),
            datetime.strptime(end_text.strip(), "%H:%M").time(),
        )
    except Exception:
        return None


def _match_condition(event_value: Any, operator: str, expected: Any) -> bool:
    """Evaluate a single condition with flexible operators."""
    if operator == "exists":
        return event_value not in (None, "", "null", "None")
    if event_value is None:
        return False
    event_str = str(event_value)
    if operator == "equals":
        return _to_lower(event_str) == _to_lower(expected)
    if operator == "not_equals":
        return _to_lower(event_str) != _to_lower(expected)
    if operator == "contains":
        return _to_lower(expected) in _to_lower(event_str)
    if operator == "regex":
        return re.search(str(expected), event_str, flags=re.IGNORECASE) is not None
    if operator == "in":
        candidates = expected if isinstance(expected, list) else [expected]
        return _to_lower(event_str) in {_to_lower(item) for item in candidates}
    if operator in {"gt", "gte", "lt", "lte"}:
        try:
            left, right = float(event_str), float(expected)
        except Exception:
            return False
        return {"gt": left > right, "gte": left >= right, "lt": left < right, "lte": left <= right}[operator]
    if operator == "outside_business_hours":
        parsed = _parse_timestamp(event_value)
        bh = _parse_business_hours(str(expected))
        if parsed is None or bh is None:
            return False
        check = parsed.time()
        return check < bh[0] or check >= bh[1]
    return False


def _event_matches_rule(event: dict[str, Any], rule: dict[str, Any]) -> bool:
    """Return True if all rule conditions match the event."""
    conditions = rule.get("conditions", [])
    if not isinstance(conditions, list):
        return False
    for cond in conditions:
        field = cond.get("field")
        operator = cond.get("operator")
        expected = cond.get("value")
        if not field or not operator:
            return False
        if not _match_condition(event.get(field), operator, expected):
            return False
    return True


def _normalize_event_data(event: dict[str, Any]) -> dict[str, Any]:
    """Convert event values to JSON-serializable types."""
    result: dict[str, Any] = {}
    for key, value in event.items():
        if isinstance(value, (pd.Timestamp, datetime)):
            result[key] = value.isoformat()
        else:
            try:
                if pd.isna(value):
                    result[key] = None
                    continue
            except Exception:
                pass
            result[key] = value
    return result


def create_alert(rule: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    """Build a standardized alert dictionary.

    Args:
        rule: Detection rule that fired.
        event: Event record that triggered the rule.

    Returns:
        Alert dict with all standard fields.
    """
    return {
        "alert_id": str(uuid.uuid4()),
        "timestamp": str(event.get("timestamp") or ""),
        "rule_id": rule.get("id", ""),
        "rule_name": rule.get("name", ""),
        "severity": str(rule.get("severity", "low")).lower(),
        "mitre_id": rule.get("mitre_id", ""),
        "mitre_name": rule.get("mitre_name", ""),
        "mitre_technique": rule.get("mitre_technique", ""),
        "description": rule.get("description", ""),
        "computer": str(event.get("computer") or ""),
        "user": str(event.get("user") or ""),
        "source_ip": str(event.get("source_ip") or ""),
        "process_name": str(event.get("process_name") or ""),
        "command_line": str(event.get("command_line") or ""),
        "source_file": str(event.get("source_file") or ""),
        "attack_folder": str(event.get("attack_folder") or ""),
        "event_id": str(event.get("event_id") or ""),
        "event_data": _normalize_event_data(event),
        "status": "open",
        "ai_analysis": None,
    }


def apply_pattern_rule(rule: dict[str, Any], df: pd.DataFrame) -> list[dict[str, Any]]:
    """Apply a single pattern-type detection rule to the events DataFrame.

    Args:
        rule: Rule dict from YAML.
        df: Full events DataFrame.

    Returns:
        List of alert dicts for each matching event.
    """
    alerts: list[dict[str, Any]] = []
    records = df.fillna("").to_dict(orient="records")
    for event in records:
        if _event_matches_rule(event, rule):
            alerts.append(create_alert(rule, event))
    return alerts


def apply_threshold_rule(rule: dict[str, Any], df: pd.DataFrame) -> list[dict[str, Any]]:
    """Apply a threshold (brute-force) detection rule.

    Groups events by source_ip and fires when the count within the rolling
    time window exceeds the threshold.

    Args:
        rule: Rule dict with threshold/window_seconds keys.
        df: Full events DataFrame.

    Returns:
        List of alert dicts, one per offending IP group.
    """
    threshold = int(rule.get("threshold", 5))
    window_seconds = int(rule.get("window_seconds", 60))
    records = df.fillna("").to_dict(orient="records")

    candidate_events = [e for e in records if _event_matches_rule(e, rule) and e.get("source_ip")]
    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in candidate_events:
        by_ip[str(event["source_ip"])].append(event)

    alerts: list[dict[str, Any]] = []
    for source_ip, events in by_ip.items():
        events.sort(key=lambda e: _parse_timestamp(e.get("timestamp")) or datetime.min)
        start_idx = 0
        hit_count = 0
        hit_ts = ""
        for end_idx in range(len(events)):
            end_time = _parse_timestamp(events[end_idx].get("timestamp"))
            if end_time is None:
                continue
            while start_idx <= end_idx:
                start_time = _parse_timestamp(events[start_idx].get("timestamp"))
                if start_time is None:
                    start_idx += 1
                    continue
                if (end_time - start_time).total_seconds() <= window_seconds:
                    break
                start_idx += 1
            current_count = end_idx - start_idx + 1
            if current_count > threshold:
                hit_count = current_count
                hit_ts = str(events[end_idx].get("timestamp") or "")

        if hit_count > threshold:
            synthetic_event = {
                "timestamp": hit_ts,
                "event_id": "4625",
                "computer": "",
                "channel": "",
                "user": "",
                "source_ip": source_ip,
                "destination_port": "",
                "process_name": "",
                "parent_process": "",
                "command_line": "",
                "logon_type": "",
                "task_name": "",
                "object_name": "",
                "raw_data": {},
                "raw_message": (
                    f"{hit_count} failed logins from {source_ip} within {window_seconds}s"
                ),
                "source_file": "aggregated",
                "attack_folder": "",
            }
            alerts.append(create_alert(rule, synthetic_event))
    return alerts


def run_detection(df: pd.DataFrame) -> list[dict[str, Any]]:
    """Load rules and run all detections against the events DataFrame.

    Args:
        df: Normalized events DataFrame from ingestor.

    Returns:
        All triggered alerts sorted by severity (critical first).
    """
    if df.empty:
        print("[!] No events available for detection.")
        return []

    rules = load_rules()
    all_alerts: list[dict[str, Any]] = []

    for rule in rules:
        rule_type = str(rule.get("type", "pattern")).lower()
        if rule_type == "threshold":
            triggered = apply_threshold_rule(rule, df)
        else:
            triggered = apply_pattern_rule(rule, df)
        if triggered:
            print(f"[+] {rule.get('id')} '{rule.get('name')}' → {len(triggered)} alert(s)")
        all_alerts.extend(triggered)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_alerts.sort(key=lambda a: severity_order.get(str(a.get("severity", "low")).lower(), 4))

    counts = Counter(a["severity"] for a in all_alerts)
    print("\n[+] Alert summary by severity:")
    for level in ["critical", "high", "medium", "low"]:
        print(f"    {level}: {counts.get(level, 0)}")

    return all_alerts


# Alias for backward-compatible imports.
detect_alerts = run_detection


def save_alerts(alerts: list[dict[str, Any]], path: str = "") -> None:
    """Persist alerts to JSON.

    Args:
        alerts: List of alert dicts.
        path: Output file path; defaults to output/alerts.json.
    """
    import json

    output_path = Path(path) if path else BASE_DIR / "output" / "alerts.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("w", encoding="utf-8") as fh:
            json.dump(alerts, fh, indent=2, default=str)
        print(f"[+] Saved {len(alerts)} alerts to {output_path}")
    except Exception as err:
        print(f"[-] Failed to save alerts: {err}")


if __name__ == "__main__":
    from ingestor import load_all_logs

    events = load_all_logs()
    alerts = run_detection(events)
    save_alerts(alerts)
    print("\n[+] First 5 alerts:")
    for a in alerts[:5]:
        print(f"  [{a['severity'].upper()}] {a['rule_name']} | {a['computer']} | {a['source_ip']}")
