"""How much the agent is allowed to decide on its own.

A SOC serving 5,000 people cannot put a human on every case — the arithmetic
does not work, and pretending otherwise just means a growing backlog nobody
reads. But "let the AI decide" is not the alternative. The workable answer is
graduated autonomy: the agent acts alone where being wrong is cheap and
reversible, and defers where it is not.

Four bands:

    AUTO_CLOSE    close it, with evidence, fully logged and reversible
    AUTO_ENRICH   investigate and queue for an analyst  (the default)
    ESCALATE      wake someone now
    HOLD          agent has explicitly asked a human a question

Two rules override everything, and they are not configurable in code because an
org should not be able to switch them off by editing a threshold:

  * Nothing touching a crown-jewel asset is ever auto-closed. On a domain
    controller the cost of a wrong close is not proportional to its likelihood.
  * No action that changes production state is ever taken without a human.
    Proposing containment is the agent's job; performing it is not.

Everything else is policy an org owns and tunes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

CRITICALITY_ORDER = ["crown_jewel", "high", "standard", "low"]


class Band(str, Enum):
    AUTO_CLOSE = "auto_close"
    AUTO_ENRICH = "auto_enrich"
    ESCALATE = "escalate"
    HOLD = "hold_for_human"


@dataclass
class Policy:
    """Org-tunable thresholds. Defaults are deliberately conservative."""

    # Auto-close requires the agent to be both confident and unambiguous.
    auto_close_max_risk: float = 25.0
    auto_close_min_confidence: float = 0.75
    auto_close_requires_prior_case: bool = True

    escalate_min_risk: float = 70.0
    escalate_criticalities: tuple[str, ...] = ("crown_jewel",)
    escalate_verdicts: tuple[str, ...] = ("ESCALATE",)

    # Below this the agent's own view is not trusted enough to act on either way.
    min_confidence_to_act: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "auto_close_max_risk": self.auto_close_max_risk,
            "auto_close_min_confidence": self.auto_close_min_confidence,
            "auto_close_requires_prior_case": self.auto_close_requires_prior_case,
            "escalate_min_risk": self.escalate_min_risk,
            "escalate_criticalities": list(self.escalate_criticalities),
            "min_confidence_to_act": self.min_confidence_to_act,
        }


@dataclass
class Decision:
    band: Band
    reasons: list[str] = field(default_factory=list)
    overrides: list[str] = field(default_factory=list)
    requires_approval: bool = True
    notify: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "band": self.band.value,
            "reasons": self.reasons,
            "overrides_applied": self.overrides,
            "requires_approval": self.requires_approval,
            "notify": self.notify,
        }


# Anything that changes the state of a production system. Always human-gated,
# regardless of how confident the agent is.
STATE_CHANGING = (
    "isolate", "quarantine", "disable", "block", "reset", "revoke", "kill",
    "terminate", "delete", "rebuild", "shutdown", "shut down", "remove",
    "suspend", "lock",
)


def classify_action(step: str) -> bool:
    return any(word in str(step).lower() for word in STATE_CHANGING)


def decide(
    risk: dict[str, Any] | None,
    verdict: dict[str, Any] | None,
    asset_criticality: str = "standard",
    similar_case_outcome: str | None = None,
    policy: Policy | None = None,
    precedent_confirmed_by_human: bool = False,
) -> Decision:
    """Which band this case falls into, and why.

    The reasoning is returned rather than just the answer: an analyst asking
    "why was this closed without me?" needs a specific chain, and so does an
    auditor.
    """
    policy = policy or Policy()
    verdict = verdict or {}
    risk = risk or {}

    score = float(risk.get("risk_score") or 0.0)
    band_name = str(verdict.get("verdict", "")).upper()
    try:
        confidence = float(verdict.get("confidence") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0

    reasons: list[str] = []
    overrides: list[str] = []

    critical_asset = asset_criticality in policy.escalate_criticalities

    # --- escalate ---------------------------------------------------------
    if critical_asset and band_name != "SUPPRESS":
        reasons.append(
            f"asset criticality is {asset_criticality}; anything credible here "
            "goes to a human immediately"
        )
        return Decision(Band.ESCALATE, reasons, overrides, True,
                        notify=["soc_lead", "on_call"])

    if score >= policy.escalate_min_risk:
        reasons.append(f"fused risk {score:.0f} is at or above the escalation bar "
                       f"({policy.escalate_min_risk:.0f})")
        return Decision(Band.ESCALATE, reasons, overrides, True,
                        notify=["soc_lead"])

    if band_name in policy.escalate_verdicts and confidence >= 0.8:
        reasons.append(f"agent returned {band_name} at {confidence:.0%} confidence")
        return Decision(Band.ESCALATE, reasons, overrides, True, notify=["soc_lead"])

    # --- auto-close -------------------------------------------------------
    if band_name == "SUPPRESS":
        blockers: list[str] = []
        if asset_criticality == "crown_jewel":
            blockers.append("crown-jewel asset — never auto-closed")
        if score > policy.auto_close_max_risk:
            blockers.append(f"risk {score:.0f} exceeds auto-close ceiling "
                            f"{policy.auto_close_max_risk:.0f}")
        if confidence < policy.auto_close_min_confidence:
            blockers.append(f"confidence {confidence:.0%} below "
                            f"{policy.auto_close_min_confidence:.0%}")
        if policy.auto_close_requires_prior_case:
            if not similar_case_outcome:
                blockers.append("no previously ruled case matches this pattern")
            elif not precedent_confirmed_by_human:
                # The agent's own past ruling is not corroboration. Without
                # this the system can bootstrap a mistake into policy: close
                # one case wrongly, and that closure authorises the next.
                blockers.append(
                    "the matching precedent was set by the agent itself and "
                    "never confirmed by an analyst"
                )

        if not blockers:
            reasons.append(
                f"agent suppressed at {confidence:.0%} confidence, risk {score:.0f}, "
                f"matching an analyst-confirmed case ruled '{similar_case_outcome}'"
            )
            return Decision(Band.AUTO_CLOSE, reasons, overrides,
                            requires_approval=False, notify=[])

        overrides.extend(blockers)
        reasons.append("suppression proposed but not permitted automatically")
        return Decision(Band.AUTO_ENRICH, reasons, overrides, True, notify=[])

    # --- default ----------------------------------------------------------
    if confidence < policy.min_confidence_to_act:
        reasons.append(f"confidence {confidence:.0%} is too low to act on in "
                       "either direction; an analyst decides")
    else:
        reasons.append("investigated and enriched; queued for analyst review")
    return Decision(Band.AUTO_ENRICH, reasons, overrides, True, notify=[])


def gate_actions(actions: list[dict[str, Any]], decision: Decision) -> list[dict[str, Any]]:
    """Attach an approval requirement to every proposed action."""
    gated = []
    for action in actions:
        step = action.get("step", "")
        destructive = classify_action(step)
        gated.append({
            **action,
            "destructive": destructive,
            # Even in the most autonomous band, changing production state needs
            # a person. This is the line that does not move.
            "requires_approval": destructive or decision.requires_approval,
            "gate_reason": (
                "changes production state" if destructive
                else f"band={decision.band.value}"
            ),
            "status": "proposed",
        })
    return gated
