"""Log ingestion module for EVTX files.

Parses Windows Event Log files into a normalized pandas DataFrame consumed by
the detector and AI triage pipeline.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import pandas as pd
from Evtx.Evtx import Evtx
from lxml import etree

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_LOG_DIR = BASE_DIR / "data" / "raw_logs"

STANDARD_COLUMNS = [
    "timestamp",
    "event_id",
    "computer",
    "channel",
    "user",
    "source_ip",
    "destination_port",
    "process_name",
    "parent_process",
    "command_line",
    "logon_type",
    "task_name",
    "object_name",
    "raw_data",
    "raw_message",
    "source_file",
    "attack_folder",
]


def _clean_text(value: Any) -> str:
    """Normalize text-like values and return empty string for missing values."""
    if value is None:
        return ""
    cleaned = str(value).strip()
    return cleaned if cleaned else ""


def _extract_named_data(xml_root: etree._Element) -> dict[str, str]:
    """Extract all named EventData/UserData fields into a lookup dictionary."""
    named_data: dict[str, str] = {}
    data_nodes = xml_root.xpath(
        ".//*[local-name()='EventData']/*[local-name()='Data']"
        "|.//*[local-name()='UserData']//*[local-name()='Data']"
    )
    for node in data_nodes:
        name = _clean_text(node.get("Name"))
        value = _clean_text(node.text)
        if name:
            named_data[name.lower()] = value
    return named_data


def _pick_first(data: dict[str, str], keys: list[str]) -> str:
    """Return first matching value from a case-normalized dictionary."""
    for key in keys:
        value = data.get(key.lower())
        if value:
            return value
    return ""


def _resolve_attack_folder(file_path: Path, log_root: Path) -> str:
    """Determine the MITRE ATT&CK category folder name from the file path."""
    try:
        relative = file_path.relative_to(log_root)
        parts = relative.parts
        if len(parts) > 1:
            return parts[0]
    except ValueError:
        pass
    return file_path.parent.name


def _parse_evtx_record(xml_text: str, source_file: Path, attack_folder: str) -> dict[str, Any]:
    """Parse a single EVTX XML record into a normalized event dictionary."""
    root = etree.fromstring(xml_text.encode("utf-8"))

    timestamp = _clean_text(
        root.xpath(
            "string(//*[local-name()='System']/*[local-name()='TimeCreated']/@SystemTime)"
        )
    )
    event_id = _clean_text(
        root.xpath("string(//*[local-name()='System']/*[local-name()='EventID'][1])")
    )
    computer = _clean_text(
        root.xpath("string(//*[local-name()='System']/*[local-name()='Computer'][1])")
    )
    channel = _clean_text(
        root.xpath("string(//*[local-name()='System']/*[local-name()='Channel'][1])")
    )
    rendered_message = _clean_text(
        root.xpath(
            "string(//*[local-name()='RenderingInfo']/*[local-name()='Message'][1])"
        )
    )

    named_data = _extract_named_data(root)

    user = _pick_first(
        named_data,
        ["SubjectUserName", "TargetUserName", "AccountName", "User", "UserName"],
    )
    source_ip = _pick_first(named_data, ["IpAddress", "SourceIp", "SourceAddress"])
    destination_port = _pick_first(named_data, ["DestinationPort", "DestPort", "dport", "Port"])
    process_name = _pick_first(
        named_data, ["NewProcessName", "ProcessName", "Image", "ExecutablePath"]
    )
    parent_process = _pick_first(named_data, ["ParentProcessName", "ParentImage"])
    command_line = _pick_first(named_data, ["CommandLine", "ProcessCommandLine", "ScriptBlockText"])
    logon_type = _pick_first(named_data, ["LogonType"])
    task_name = _pick_first(named_data, ["TaskName"])
    object_name = _pick_first(named_data, ["ObjectName"])

    # raw_data holds the full EventData key/value map for downstream rules.
    raw_data = dict(named_data)

    raw_message = rendered_message or etree.tostring(root, encoding="unicode")

    return {
        "timestamp": timestamp,
        "event_id": event_id,
        "computer": computer,
        "channel": channel,
        "user": user,
        "source_ip": source_ip,
        "destination_port": destination_port,
        "process_name": process_name,
        "parent_process": parent_process,
        "command_line": command_line,
        "logon_type": logon_type,
        "task_name": task_name,
        "object_name": object_name,
        "raw_data": raw_data,
        "raw_message": raw_message,
        "source_file": source_file.name,
        "attack_folder": attack_folder,
    }


def parse_evtx_file(filepath: str) -> list[dict]:
    """Parse all records from one EVTX file.

    Args:
        filepath: Absolute or relative path to the .evtx file.

    Returns:
        List of normalized event dicts, one per log record.
    """
    file_path = Path(filepath)
    attack_folder = file_path.parent.name
    events: list[dict] = []
    try:
        with Evtx(str(file_path)) as evtx_log:
            for record in evtx_log.records():
                try:
                    events.append(_parse_evtx_record(record.xml(), file_path, attack_folder))
                except Exception as record_error:
                    print(f"[!] Skipping record in {file_path.name}: {record_error}")
    except Exception as file_error:
        print(f"[-] Could not read {file_path.name}: {file_error}")
    return events


def load_all_logs(log_dir: str = "") -> pd.DataFrame:
    """Load all EVTX files from a directory recursively into a DataFrame.

    Args:
        log_dir: Path to the directory containing EVTX files/folders.
                 Defaults to data/raw_logs/ relative to the project root.

    Returns:
        Normalized DataFrame sorted by timestamp ascending.
    """
    target_dir = Path(log_dir) if log_dir else RAW_LOG_DIR

    if not target_dir.exists():
        print(f"[-] Log directory not found: {target_dir}")
        print("[!] Place EVTX attack samples in data/raw_logs/ and re-run.")
        return pd.DataFrame(columns=STANDARD_COLUMNS)

    evtx_files = list(target_dir.rglob("*.evtx"))
    if not evtx_files:
        print(f"[-] No .evtx files found under {target_dir}")
        print("[!] Download EVTX-ATTACK-SAMPLES and place folders inside data/raw_logs/")
        return pd.DataFrame(columns=STANDARD_COLUMNS)

    all_events: list[dict] = []
    for evtx_path in evtx_files:
        attack_folder = _resolve_attack_folder(evtx_path, target_dir)
        events = parse_evtx_file(str(evtx_path))
        print(f"[+] {evtx_path.name} ({attack_folder}) → {len(events)} events")
        all_events.extend(events)

    if not all_events:
        return pd.DataFrame(columns=STANDARD_COLUMNS)

    df = pd.DataFrame(all_events)

    # Ensure all expected columns exist.
    for col in STANDARD_COLUMNS:
        if col not in df.columns:
            df[col] = ""

    df = df[STANDARD_COLUMNS]
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df = df.sort_values("timestamp", ascending=True).reset_index(drop=True)

    print(f"\n[+] Total events loaded: {len(df)}")
    top_ids = df["event_id"].value_counts().head(10)
    print("[+] Top 10 event IDs:")
    for eid, cnt in top_ids.items():
        print(f"    EventID {eid}: {cnt}")

    return df


# Alias used by existing detector/dashboard imports.
load_events = load_all_logs


if __name__ == "__main__":
    df = load_all_logs()
    print("\n[+] Sample rows:")
    print(df[["timestamp", "event_id", "computer", "user", "source_ip", "attack_folder"]].head(10).to_string(index=False))
    print(f"\n[+] DataFrame shape: {df.shape}")
