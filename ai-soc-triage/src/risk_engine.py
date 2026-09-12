"""Risk / Verdict Engine.

Fuses the agents' findings into one score and one decision.

This is deliberately **deterministic arithmetic, not a model call**. The agents
supply judgement; this turns judgement into a number the same way every time.
Three reasons that matters:

  - the same case always scores the same, so an analyst can trust a change in
    score to mean a change in evidence
  - every point is attributable to a named factor, so "why is this an 8?" has
    an answer that does not require re-running a model
  - the weights are visible and arguable, which is how a SOC actually tunes

No factor can single-handedly escalate a case: corroboration across independent
signals is what drives the score, which is the property that makes a single
confident-but-wrong agent survivable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Weights sum to 100. Adjusting these is a policy decision, not a code change,
# so they live together and are reported alongside every score.
WEIGHTS = {
    "rule_severity": 20,       # what the deterministic rules thought
    "triage_urgency": 30,      # the triage agent's judgement
    "intel_attribution": 15,   # how well the technique is evidenced
    "cross_domain": 20,        # corroboration across independent telemetry
    "blast_radius": 15,        # how much of the estate is involved
}

RULE_SEVERITY_SCORE = {"critical": 1.0, "high": 0.75, "medium": 0.45, "low": 0.2, "": 0.0}
ATTRIBUTION_SCORE = {"strong": 1.0, "moderate": 0.6, "weak": 0.25, "unknown": 0.0}

# Score bands and the action each implies.
BANDS = [
    (80, "critical", "escalate_immediately", True),
    (60, "high", "analyst_review", True),
    (35, "medium", "analyst_review", False),
    (0, "low", "monitor", False),
]


@dataclass
class RiskFactor:
    name: str
    weight: int
    normalized: float           # 0.0-1.0
    points: float
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "weight": self.weight,
            "normalized": round(self.normalized, 3),
            "points": round(self.points, 1),
            "rationale": self.rationale,
        }


@dataclass
class RiskVerdict:
    incident_id: str
    score: float
    band: str
    action: str
    requires_approval: bool
    factors: list[RiskFactor] = field(default_factory=list)
    confidence: float = 0.0
    caveats: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "risk_score": round(self.score, 1),
            "band": self.band,
            "action": self.action,
            "requires_approval": self.requires_approval,
            "confidence": round(self.confidence, 3),
            "factors": [f.to_dict() for f in self.factors],
            "caveats": self.caveats,
            "weights": WEIGHTS,
        }


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def score_case(case) -> RiskVerdict:
    """Fuse one case's agent findings into a risk verdict."""
    incident = case.incident
    triage = case.agent_payload("triage") or {}
    intel = case.agent_payload("intel") or {}

    factors: list[RiskFactor] = []
    caveats: list[str] = []

    # 1. What the rules said.
    sev = str(incident.get("severity", "")).lower()
    norm = RULE_SEVERITY_SCORE.get(sev, 0.0)
    factors.append(RiskFactor(
        "rule_severity", WEIGHTS["rule_severity"], norm,
        norm * WEIGHTS["rule_severity"],
        f"Highest rule severity in this incident was '{sev or 'none'}'.",
    ))

    # 2. What the triage agent judged, discounted by its own confidence. A
    #    confident 9 and an unsure 9 should not score identically.
    urgency = triage.get("urgency_score")
    try:
        urgency_norm = _clamp(float(urgency) / 10.0)
    except (TypeError, ValueError):
        urgency_norm = 0.0
        caveats.append("Triage agent returned no usable urgency score.")
    triage_conf = _clamp(float(triage.get("confidence") or 0.0))
    # Floor the discount at 0.5 so a low-confidence high-urgency call is damped,
    # never erased — under-reacting to a possible intrusion is the worse error.
    adjusted = urgency_norm * (0.5 + 0.5 * triage_conf)
    factors.append(RiskFactor(
        "triage_urgency", WEIGHTS["triage_urgency"], adjusted,
        adjusted * WEIGHTS["triage_urgency"],
        f"Triage urgency {urgency}/10 at {triage_conf:.0%} confidence.",
    ))

    # 3. How well the technique attribution is evidenced.
    strength = str(intel.get("attribution_strength", "unknown")).lower()
    attr = ATTRIBUTION_SCORE.get(strength, 0.0)
    technique = intel.get("technique_assessment") or triage.get("mitre_technique") or "UNKNOWN"
    if str(technique).upper().startswith("UNKNOWN"):
        attr = min(attr, 0.25)
        caveats.append("No technique could be attributed from retrieved knowledge.")
    factors.append(RiskFactor(
        "intel_attribution", WEIGHTS["intel_attribution"], attr,
        attr * WEIGHTS["intel_attribution"],
        f"Attribution '{strength}' for {technique}.",
    ))

    # 4. Corroboration across independent telemetry domains. One domain
    #    shouting is weaker evidence than three domains agreeing.
    domains_with = list((case.domain_summary or {}).get("domains_with_evidence", {}).keys())
    corroboration = _clamp(len(domains_with) / 3.0)
    factors.append(RiskFactor(
        "cross_domain", WEIGHTS["cross_domain"], corroboration,
        corroboration * WEIGHTS["cross_domain"],
        f"Evidence in {len(domains_with)} domain(s): {', '.join(domains_with) or 'none'}.",
    ))
    not_connected = (case.domain_summary or {}).get("domains_not_connected", [])
    if not_connected:
        caveats.append(
            f"{len(not_connected)} domain(s) have no connector "
            f"({', '.join(not_connected)}); corroboration is bounded by coverage."
        )

    # 5. Blast radius.
    hosts = len(incident.get("hosts", []))
    users = len(incident.get("users", []))
    alerts = int(incident.get("alert_count", 0) or 0)
    blast = _clamp((hosts - 1) / 3.0 * 0.5 + (users - 1) / 3.0 * 0.25 + min(alerts, 20) / 20.0 * 0.25)
    factors.append(RiskFactor(
        "blast_radius", WEIGHTS["blast_radius"], blast,
        blast * WEIGHTS["blast_radius"],
        f"{hosts} host(s), {users} account(s), {alerts} correlated alert(s).",
    ))

    score = sum(f.points for f in factors)

    band, action, requires_approval = "low", "monitor", False
    for threshold, b, a, approval in BANDS:
        if score >= threshold:
            band, action, requires_approval = b, a, approval
            break

    # Overall confidence is the weakest link among the agents that contributed,
    # not their average: a case is only as trustworthy as its shakiest input.
    confidences = [c for c in (triage.get("confidence"), intel.get("confidence")) if c is not None]
    confidence = min(float(c) for c in confidences) if confidences else 0.0

    if confidence < 0.5:
        caveats.append("Low agent confidence — treat this score as provisional.")

    return RiskVerdict(
        incident_id=incident["incident_id"],
        score=score, band=band, action=action,
        requires_approval=requires_approval,
        factors=factors, confidence=confidence, caveats=caveats,
    )
