"""AI enrichment module for SOC alerts using a local HuggingFace model."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from llm_backend import get_llm_backend

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_PATH = BASE_DIR / "output" / "alerts.json"

SYSTEM_PROMPT = (
    "You are an expert SOC analyst with 10 years of experience in incident response "
    "and threat hunting. Analyze the security alert and respond ONLY with a valid JSON "
    "object. No markdown, no backticks, no text outside the JSON."
)


def build_triage_prompt(alert: dict[str, Any]) -> str:
    """Build the Claude user prompt for a given alert.

    Args:
        alert: Alert dict with all standard fields.

    Returns:
        Formatted prompt string requesting structured JSON analysis.
    """
    return (
        "Analyze this security alert and return ONLY a valid JSON object with this exact schema:\n"
        "{\n"
        '  "severity_confirmed": "critical|high|medium|low",\n'
        '  "analyst_summary": "2 sentences max, plain English, what happened and why it matters",\n'
        '  "false_positive_likelihood": "high|medium|low",\n'
        '  "false_positive_reason": "brief reason if likelihood is high, else empty string",\n'
        '  "recommended_actions": ["action1", "action2", "action3"],\n'
        '  "mitre_technique": "TXXXX - Full Technique Name",\n'
        '  "urgency_score": 7,\n'
        '  "investigation_steps": ["step1", "step2", "step3"]\n'
        "}\n\n"
        f"Alert details:\n{json.dumps(alert, indent=2, default=str)}"
    )


def _extract_response_text(response: Any) -> str:
    """Pull text content from Anthropic response blocks."""
    content = getattr(response, "content", [])
    parts: list[str] = []
    if isinstance(content, list):
        for block in content:
            text = getattr(block, "text", None)
            if text:
                parts.append(text)
    return "\n".join(parts).strip()


def _safe_json_parse(text: str) -> dict[str, Any] | None:
    """Parse JSON from model output, tolerating markdown fences."""
    if not text:
        return None
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    # Extract first JSON object if extra text leaked through.
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        cleaned = match.group(0)
    try:
        parsed = json.loads(cleaned)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def _fallback_analysis(alert: dict[str, Any], reason: str) -> dict[str, Any]:
    """Return deterministic fallback when API call fails."""
    severity = str(alert.get("severity", "low")).lower()
    urgency_map = {"critical": 10, "high": 8, "medium": 5, "low": 3}
    return {
        "severity_confirmed": severity,
        "analyst_summary": (
            f"Automated AI triage could not complete for this alert. Reason: {reason}."
        ),
        "false_positive_likelihood": "medium",
        "false_positive_reason": "",
        "recommended_actions": [
            "Validate event context in SIEM",
            "Correlate with host and network telemetry",
            "Escalate to Tier 2 if activity remains suspicious",
        ],
        "mitre_technique": str(alert.get("mitre_technique", "T0000 - Unknown")),
        "urgency_score": urgency_map.get(severity, 3),
        "investigation_steps": [
            "Review raw event data in Log Explorer tab",
            "Search for related events from the same host",
            "Check source IP reputation against threat intel feeds",
        ],
    }


def _normalize_ai_output(raw: dict[str, Any], alert: dict[str, Any]) -> dict[str, Any]:
    """Ensure required output keys are present and correctly typed."""
    severity = str(raw.get("severity_confirmed", alert.get("severity", "low"))).lower()
    if severity not in {"critical", "high", "medium", "low"}:
        severity = str(alert.get("severity", "low")).lower()

    fp_likelihood = str(raw.get("false_positive_likelihood", "medium")).lower()
    if fp_likelihood not in {"high", "medium", "low"}:
        fp_likelihood = "medium"

    recommended = raw.get("recommended_actions", [])
    if not isinstance(recommended, list):
        recommended = [str(recommended)]
    recommended = [str(i) for i in recommended[:3]] or ["Review alert details"]

    investigation = raw.get("investigation_steps", [])
    if not isinstance(investigation, list):
        investigation = [str(investigation)]
    investigation = [str(i) for i in investigation[:5]] or ["Review raw event data"]

    try:
        urgency = min(10, max(1, int(raw.get("urgency_score", 5))))
    except Exception:
        urgency = 5

    return {
        "severity_confirmed": severity,
        "analyst_summary": str(
            raw.get("analyst_summary", "AI analysis returned incomplete output.")
        ),
        "false_positive_likelihood": fp_likelihood,
        "false_positive_reason": str(raw.get("false_positive_reason", "")),
        "recommended_actions": recommended,
        "mitre_technique": str(
            raw.get("mitre_technique", alert.get("mitre_technique", "T0000 - Unknown"))
        ),
        "urgency_score": urgency,
        "investigation_steps": investigation,
    }


def triage_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Enrich a single alert with AI analysis.

    Args:
        alert: Alert dict to analyse.

    Returns:
        Normalised AI analysis dict.
    """
    backend = get_llm_backend()
    if backend is None:
        return _fallback_analysis(alert, "No LLM backend configured")
    try:
        result = backend.generate_json(
            system=SYSTEM_PROMPT,
            user=build_triage_prompt(alert),
            max_tokens=650,
        )
        if result is None:
            raise ValueError("Model response was not valid JSON.")
        return _normalize_ai_output(result, alert)
    except Exception as err:
        return _fallback_analysis(alert, str(err))


def run_ai_triage(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Enrich all alerts with AI analysis.

    Args:
        alerts: List of alert dicts from the detector.

    Returns:
        Alerts with ai_analysis field populated.
    """
    backend = get_llm_backend()
    if backend is None:
        print("[!] No LLM backend configured — writing fallback analysis.")
        for alert in alerts:
            alert["ai_analysis"] = _fallback_analysis(alert, "No LLM backend configured")
        return alerts

    print(f"[+] Triaging {len(alerts)} alerts with: {backend.model_label}")
    enriched: list[dict[str, Any]] = []
    for idx, alert in enumerate(alerts, 1):
        print(f"[+] Triaging alert {idx}/{len(alerts)}: {alert.get('rule_name', '')}")
        alert_copy = dict(alert)
        alert_copy["ai_analysis"] = triage_alert(alert_copy)
        enriched.append(alert_copy)
        time.sleep(0.3)

    return enriched


def load_and_triage(alerts_path: str = "") -> list[dict[str, Any]]:
    """Load alerts from disk, run AI triage, save back.

    Args:
        alerts_path: Path to alerts JSON; defaults to output/alerts.json.

    Returns:
        Enriched alerts list.
    """
    path = Path(alerts_path) if alerts_path else DEFAULT_OUTPUT_PATH
    try:
        with path.open("r", encoding="utf-8") as fh:
            alerts = json.load(fh)
    except Exception as err:
        print(f"[-] Could not load alerts from {path}: {err}")
        return []

    enriched = run_ai_triage(alerts)

    try:
        with path.open("w", encoding="utf-8") as fh:
            json.dump(enriched, fh, indent=2, default=str)
        print(f"[+] Saved {len(enriched)} enriched alerts to {path}")
    except Exception as err:
        print(f"[-] Failed to save enriched alerts: {err}")

    return enriched


def _json_serializer(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def save_alerts(alerts: list[dict[str, Any]], output_path: Path | None = None) -> None:
    """Persist alerts to output/alerts.json."""
    destination = output_path or DEFAULT_OUTPUT_PATH
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("w", encoding="utf-8") as fh:
            json.dump(alerts, fh, indent=2, default=_json_serializer)
        print(f"[+] Saved {len(alerts)} alerts to {destination}")
    except Exception as err:
        print(f"[-] Failed to save alerts: {err}")


def enrich_alerts_with_ai(
    alerts: list[dict[str, Any]], output_path: Path | None = None
) -> list[dict[str, Any]]:
    """Enrich alerts with AI and save to disk.

    Args:
        alerts: Raw alerts from detector.
        output_path: Override for output file path.

    Returns:
        Enriched alerts list.
    """
    if not alerts:
        save_alerts([], output_path=output_path)
        print("[!] No alerts to enrich.")
        return []

    enriched: list[dict[str, Any]] = []
    backend = get_llm_backend()

    if backend is None:
        print("[!] No LLM backend configured — using fallback analysis.")
        for alert in alerts:
            ac = dict(alert)
            ac["ai_analysis"] = _fallback_analysis(alert, "No LLM backend configured")
            enriched.append(ac)
        save_alerts(enriched, output_path=output_path)
        return enriched

    backend = get_llm_backend()
    print(f"[+] Triaging {len(alerts)} alerts with: {backend.model_label if backend else 'fallback'}")
    for idx, alert in enumerate(alerts, 1):
        print(f"[+] Triaging alert {idx}/{len(alerts)}: {alert.get('rule_name', '')}")
        ac = dict(alert)
        ac["ai_analysis"] = triage_alert(ac)
        enriched.append(ac)
        time.sleep(0.3)

    save_alerts(enriched, output_path=output_path)
    print(f"[+] Enriched and saved {len(enriched)} alerts.")
    return enriched


if __name__ == "__main__":
    sample = [
        {
            "alert_id": "demo-001",
            "timestamp": "2026-01-01T00:00:00Z",
            "rule_id": "RULE-003",
            "rule_name": "Suspicious PowerShell Encoded Command",
            "severity": "high",
            "mitre_id": "T1059.001",
            "mitre_name": "PowerShell",
            "mitre_technique": "T1059.001 - PowerShell",
            "description": "Encoded PowerShell execution detected",
            "computer": "WORKSTATION-01",
            "user": "jsmith",
            "source_ip": "10.0.0.5",
            "process_name": "powershell.exe",
            "command_line": "powershell -enc SQBFAFgA...",
            "source_file": "Security.evtx",
            "attack_folder": "Defense Evasion",
            "event_id": "4104",
            "event_data": {},
            "status": "open",
            "ai_analysis": None,
        }
    ]
    enriched = enrich_alerts_with_ai(sample)
    for a in enriched[:3]:
        print(json.dumps(a.get("ai_analysis"), indent=2))
