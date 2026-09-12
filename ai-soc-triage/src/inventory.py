"""Asset and identity inventory — the business context around a finding.

Detection tells you what happened on a machine. It cannot tell you whether that
machine matters. In an estate of 50,000 assets that distinction is most of
triage: the same PowerShell execution is routine on a developer's laptop and a
crown-jewel incident on a domain controller.

Inventory is normally imported from a CMDB, Active Directory or a cloud asset
API. Where none is configured, criticality is inferred from naming and observed
behaviour and clearly marked `inferred` — a guess an analyst can see and
override, never presented as authoritative.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
INVENTORY_PATH = BASE_DIR / "data" / "inventory.json"

# Criticality drives urgency, so the tiers are deliberately few and meaningful.
TIERS = ["crown_jewel", "high", "standard", "low"]

# Naming conventions that reliably indicate role. Used only when no CMDB is
# available, and always reported as inferred.
ROLE_PATTERNS = [
    (r"\b(dc\d*|domain[-_]?controller|ad\d*)\b", "domain_controller", "crown_jewel"),
    (r"\b(sql|db|oracle|postgres|mysql)\b", "database", "crown_jewel"),
    (r"\b(exch|exchange|mail|smtp)\b", "mail_server", "high"),
    (r"\b(fs|fileserver|share|nas)\b", "file_server", "high"),
    (r"\b(vc|vcenter|esx|hyperv|vmm)\b", "virtualisation", "crown_jewel"),
    (r"\b(bak|backup|veeam)\b", "backup", "crown_jewel"),
    (r"\b(jump|bastion|rdp[-_]?gw)\b", "jump_host", "crown_jewel"),
    (r"\b(web|www|iis|nginx|apache)\b", "web_server", "high"),
    (r"\b(srv|server)\b", "server", "high"),
    (r"\b(lap|laptop|wks|desktop|pc)\b", "workstation", "standard"),
    (r"\b(test|dev|lab|sandbox|tmp)\b", "non_production", "low"),
]

PRIVILEGED_ACCOUNT = re.compile(
    r"(admin|adm[-_]|svc[-_]|service|root|sa$|backup|krbtgt)", re.IGNORECASE
)


@dataclass
class Asset:
    name: str
    kind: str = "host"            # host | account
    role: str = "unknown"
    criticality: str = "standard"
    owner: str = ""
    business_unit: str = ""
    inferred: bool = True
    notes: str = ""
    observed_events: int = 0
    observed_peers: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "role": self.role,
            "criticality": self.criticality,
            "owner": self.owner or "unassigned",
            "business_unit": self.business_unit or "unknown",
            "source": "inferred from telemetry" if self.inferred else "inventory import",
            "notes": self.notes,
            "observed_events": self.observed_events,
        }


class Inventory:
    """Lookup over known assets, with inference as the fallback."""

    def __init__(self, records: dict[str, Asset] | None = None) -> None:
        self.records: dict[str, Asset] = records or {}

    # -- construction ------------------------------------------------------

    @classmethod
    def load(cls, path: Path | None = None) -> "Inventory":
        target = path or INVENTORY_PATH
        if not target.exists():
            return cls()
        try:
            raw = json.loads(target.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return cls()
        records = {
            k.lower(): Asset(**v) for k, v in raw.get("assets", {}).items()
        }
        return cls(records)

    def save(self, path: Path | None = None) -> None:
        target = path or INVENTORY_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(
            {"assets": {k: v.to_dict() | {
                "name": v.name, "kind": v.kind, "role": v.role,
                "criticality": v.criticality, "owner": v.owner,
                "business_unit": v.business_unit, "inferred": v.inferred,
                "notes": v.notes, "observed_events": v.observed_events,
                "observed_peers": v.observed_peers,
            } for k, v in self.records.items()}}, indent=1), encoding="utf-8")

    @classmethod
    def from_telemetry(cls, df) -> "Inventory":
        """Build a provisional inventory from what the logs reveal.

        A real deployment imports this. Inferring it means the system is useful
        on day one instead of blocked on a CMDB project, at the cost of every
        record being a guess — which is why they are labelled as such.
        """
        inv = cls()
        if df is None or df.empty:
            return inv

        hosts = Counter(str(h) for h in df.get("computer", []) if str(h))
        users = Counter(str(u) for u in df.get("user", []) if str(u))

        for host, count in hosts.items():
            role, crit = cls._infer_role(host)
            inv.records[host.lower()] = Asset(
                name=host, kind="host", role=role, criticality=crit,
                inferred=True, observed_events=count,
                notes="criticality inferred from hostname; import a CMDB to correct",
            )

        for user, count in users.items():
            privileged = bool(PRIVILEGED_ACCOUNT.search(user))
            machine = user.endswith("$")
            inv.records[user.lower()] = Asset(
                name=user, kind="account",
                role="machine_account" if machine else
                     ("privileged" if privileged else "user"),
                criticality="high" if privileged and not machine else
                            ("low" if machine else "standard"),
                inferred=True, observed_events=count,
                notes="machine account" if machine else
                      ("name suggests privileged access" if privileged else ""),
            )
        return inv

    @staticmethod
    def _infer_role(name: str) -> tuple[str, str]:
        lowered = name.lower()
        for pattern, role, crit in ROLE_PATTERNS:
            if re.search(pattern, lowered):
                return role, crit
        return "unknown", "standard"

    # -- lookup ------------------------------------------------------------

    def lookup(self, name: str) -> dict[str, Any]:
        if not name:
            return {"found": False, "why": "no name supplied"}
        record = self.records.get(str(name).lower())
        if record is None:
            role, crit = self._infer_role(str(name))
            return {
                "found": False,
                "name": name,
                "role": role,
                "criticality": crit,
                "source": "inferred from name only — not in inventory",
                "caution": "this asset is unknown to the inventory; treat the "
                           "criticality as a guess",
            }
        return {"found": True, **record.to_dict()}

    def criticality_of(self, names: list[str]) -> str:
        """Highest criticality among a set — what an incident inherits."""
        best = "low"
        for name in names:
            tier = self.lookup(name).get("criticality", "standard")
            if TIERS.index(tier) < TIERS.index(best):
                best = tier
        return best

    def crown_jewels(self) -> list[str]:
        return sorted(a.name for a in self.records.values()
                      if a.criticality == "crown_jewel")

    def summary(self) -> dict[str, Any]:
        by_crit = Counter(a.criticality for a in self.records.values())
        by_kind = Counter(a.kind for a in self.records.values())
        return {
            "assets": len(self.records),
            "by_criticality": dict(by_crit),
            "by_kind": dict(by_kind),
            "crown_jewels": self.crown_jewels()[:20],
            "all_inferred": all(a.inferred for a in self.records.values()),
        }
