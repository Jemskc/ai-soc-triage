"""AI chat module for conversational log analysis.

Maintains conversation history and injects live log context into every
Claude API call so the analyst gets answers grounded in real data.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from llm_backend import get_llm_backend

BASE_DIR = Path(__file__).resolve().parent.parent


def build_context_summary(df: pd.DataFrame, alerts: list[dict[str, Any]]) -> str:
    """Build a concise log-data summary to inject as system context.

    Kept under ~500 tokens to leave budget for the conversation.

    Args:
        df: Events DataFrame from the ingestor.
        alerts: Enriched alerts list from the detector/AI triage.

    Returns:
        Formatted context string.
    """
    lines: list[str] = ["=== CURRENT LOG DATA CONTEXT ==="]

    if df.empty:
        lines.append("No log data loaded.")
    else:
        lines.append(f"Total events: {len(df)}")

        # Date range.
        ts_col = pd.to_datetime(df.get("timestamp", pd.Series(dtype="object")), errors="coerce", utc=True)
        valid_ts = ts_col.dropna()
        if not valid_ts.empty:
            lines.append(f"Date range: {valid_ts.min().date()} to {valid_ts.max().date()}")

        # Top event IDs.
        if "event_id" in df.columns:
            top_eids = df["event_id"].value_counts().head(5)
            eid_parts = [f"EventID {eid}={cnt}" for eid, cnt in top_eids.items()]
            lines.append(f"Top event IDs: {', '.join(eid_parts)}")

        # Top source IPs.
        if "source_ip" in df.columns:
            top_ips = df["source_ip"].replace("", pd.NA).dropna().value_counts().head(5)
            if not top_ips.empty:
                ip_parts = [f"{ip}={cnt}" for ip, cnt in top_ips.items()]
                lines.append(f"Top source IPs: {', '.join(ip_parts)}")

        # Top computers.
        comp_col = "computer" if "computer" in df.columns else "computer_name"
        if comp_col in df.columns:
            top_comps = df[comp_col].replace("", pd.NA).dropna().value_counts().head(5)
            if not top_comps.empty:
                comp_parts = [f"{c}={n}" for c, n in top_comps.items()]
                lines.append(f"Top computers: {', '.join(comp_parts)}")

        # Attack folders.
        if "attack_folder" in df.columns:
            folders = df["attack_folder"].replace("", pd.NA).dropna().value_counts()
            if not folders.empty:
                folder_parts = [f"{f}={n}" for f, n in folders.head(5).items()]
                lines.append(f"Attack categories: {', '.join(folder_parts)}")

    lines.append("")

    if not alerts:
        lines.append("No alerts triggered yet.")
    else:
        lines.append(f"Total alerts: {len(alerts)}")
        severity_counts: dict[str, int] = {}
        for alert in alerts:
            sev = str(alert.get("severity", "low")).lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        for sev in ["critical", "high", "medium", "low"]:
            if sev in severity_counts:
                lines.append(f"  {sev.capitalize()}: {severity_counts[sev]}")

        # Most recent alerts.
        recent = alerts[:5]
        if recent:
            lines.append("Recent alerts:")
            for a in recent:
                lines.append(f"  [{a.get('severity','').upper()}] {a.get('rule_name','')} | {a.get('computer','')} | {a.get('source_ip','')}")

    return "\n".join(lines)


def build_system_prompt(context: str) -> str:
    """Build the full system prompt with injected log context.

    Args:
        context: Output from build_context_summary().

    Returns:
        System prompt string for the Claude API.
    """
    return (
        "You are an expert SOC analyst with 10 years of experience in incident response, "
        "threat hunting, and digital forensics. You have access to the analyst's current "
        "log data and alert findings.\n\n"
        f"{context}\n\n"
        "Guidelines:\n"
        "- Give concise, actionable answers grounded in the log data above.\n"
        "- Reference specific event IDs, computers, IPs, or alert names when relevant.\n"
        "- If asked about data not present in the context, say so clearly.\n"
        "- Keep responses focused and under 400 words unless detail is necessary.\n"
        "- Format lists with bullet points for readability."
    )


def chat(
    message: str,
    history: list[dict[str, Any]],
    df: pd.DataFrame,
    alerts: list[dict[str, Any]],
) -> tuple[str, list[dict[str, Any]]]:
    """Send a message and get a response with full conversation context.

    Args:
        message: Analyst's new message.
        history: Prior conversation history (internal format).
        df: Current events DataFrame.
        alerts: Current alerts list.

    Returns:
        Tuple of (response_text, updated_history).
    """
    backend = get_llm_backend()
    if backend is None:
        error_msg = "LLM backend not configured. Set LLM_BACKEND and credentials in .env."
        updated_history = history + [
            {"role": "user", "content": message, "timestamp": _now()},
            {"role": "assistant", "content": error_msg, "timestamp": _now()},
        ]
        return error_msg, updated_history

    try:
        context = build_context_summary(df, alerts)
        system_prompt = build_system_prompt(context)

        # Build prior turns for multi-turn context.
        api_history = [
            {"role": h["role"], "content": h["content"]}
            for h in history
            if h.get("role") in ("user", "assistant")
        ]

        response_text = backend.generate_text(
            system=system_prompt,
            user=message,
            max_tokens=800,
            history=api_history,
        )
    except Exception as err:
        response_text = f"AI chat error: {err}"

    updated_history = history + [
        {"role": "user", "content": message, "timestamp": _now()},
        {"role": "assistant", "content": response_text, "timestamp": _now()},
    ]
    return response_text, updated_history


def format_history_for_display(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert internal history to a display-friendly format.

    Args:
        history: Internal conversation history list.

    Returns:
        List of dicts with role, content, and timestamp keys.
    """
    return [
        {
            "role": h.get("role", "user"),
            "content": h.get("content", ""),
            "timestamp": h.get("timestamp", ""),
        }
        for h in history
    ]


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%H:%M:%S")
