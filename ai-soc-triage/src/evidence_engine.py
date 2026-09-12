"""Investigation / Evidence Engine.

Agents ask questions; this is what answers them from the underlying telemetry.

Each data domain is a pluggable adapter. Adapters that have a real source
behind them return evidence; adapters that do not report themselves as
NOT CONNECTED rather than returning empty results that read like "nothing
found". The distinction matters: "no Cloud data" and "no Cloud findings" mean
very different things to an analyst deciding whether an investigation is
complete, and conflating them is how a tool quietly loses trust.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

import pandas as pd

# Domains from the SOC reference architecture. Each is either backed by a
# source in this deployment or explicitly declared unconnected.
DOMAINS = [
    "endpoint", "identity", "network", "email",
    "dns", "cloud", "firewall", "saas", "ad",
]


@dataclass
class DomainEvidence:
    domain: str
    connected: bool
    records: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "connected": self.connected,
            "record_count": len(self.records),
            "summary": self.summary,
            "note": self.note,
            "records": self.records[:10],
        }


class DomainAdapter:
    domain = "base"
    source = "none"

    def __init__(self, df: pd.DataFrame | None = None) -> None:
        self.df = df

    def available(self) -> bool:
        return self.df is not None and not self.df.empty

    def query(self, hosts: list[str], users: list[str], window: tuple[str, str]) -> DomainEvidence:
        raise NotImplementedError

    def _scope(self, hosts: list[str], users: list[str]) -> pd.DataFrame:
        """Rows touching any of these hosts or accounts."""
        if self.df is None or self.df.empty:
            return pd.DataFrame()
        mask = pd.Series(False, index=self.df.index)
        if hosts and "computer" in self.df.columns:
            mask |= self.df["computer"].astype(str).isin(hosts)
        if users and "user" in self.df.columns:
            mask |= self.df["user"].astype(str).isin(users)
        return self.df[mask]

    def _disconnected(self, reason: str) -> DomainEvidence:
        return DomainEvidence(
            domain=self.domain, connected=False,
            summary="No data source connected for this domain.", note=reason,
        )


class EndpointAdapter(DomainAdapter):
    domain = "endpoint"
    source = "Sysmon / Windows process telemetry"

    # Sysmon process, network, image-load, file, registry, and Security 4688.
    EVENT_IDS = {"1", "3", "7", "8", "10", "11", "12", "13", "22", "4688"}

    def query(self, hosts, users, window):
        if not self.available():
            return self._disconnected("no endpoint telemetry loaded")
        rows = self._scope(hosts, users)
        if "event_id" in rows.columns:
            rows = rows[rows["event_id"].astype(str).isin(self.EVENT_IDS)]

        procs = Counter(
            str(p) for p in rows.get("process_name", pd.Series(dtype=str)) if str(p) not in ("", "nan")
        )
        records = [
            {
                "timestamp": str(r.get("timestamp", "")),
                "event_id": str(r.get("event_id", "")),
                "host": str(r.get("computer", "")),
                "process": str(r.get("process_name", "")),
                "command_line": str(r.get("command_line", ""))[:200],
            }
            for _, r in rows.head(25).iterrows()
        ]
        top = ", ".join(f"{p} ({n})" for p, n in procs.most_common(4)) or "none"
        return DomainEvidence(
            self.domain, True, records,
            f"{len(rows)} endpoint events on {len(hosts) or 0} host(s). Top processes: {top}.",
        )


class IdentityAdapter(DomainAdapter):
    domain = "identity"
    source = "Windows Security authentication events"

    EVENT_IDS = {"4624", "4625", "4634", "4648", "4672", "4768", "4769", "4776"}

    def query(self, hosts, users, window):
        if not self.available():
            return self._disconnected("no authentication telemetry loaded")
        rows = self._scope(hosts, users)
        if "event_id" in rows.columns:
            rows = rows[rows["event_id"].astype(str).isin(self.EVENT_IDS)]

        by_event = Counter(str(e) for e in rows.get("event_id", pd.Series(dtype=str)))
        failures = by_event.get("4625", 0)
        elevated = by_event.get("4672", 0)
        logon_types = Counter(
            str(t) for t in rows.get("logon_type", pd.Series(dtype=str)) if str(t) not in ("", "nan", "0")
        )
        records = [
            {
                "timestamp": str(r.get("timestamp", "")),
                "event_id": str(r.get("event_id", "")),
                "user": str(r.get("user", "")),
                "logon_type": str(r.get("logon_type", "")),
                "source_ip": str(r.get("source_ip", "")),
            }
            for _, r in rows.head(25).iterrows()
        ]
        parts = [f"{len(rows)} authentication events"]
        if failures:
            parts.append(f"{failures} failed logons")
        if elevated:
            parts.append(f"{elevated} elevated-privilege logons")
        if logon_types:
            parts.append("logon types " + ", ".join(f"{t}x{n}" for t, n in logon_types.most_common(3)))
        return DomainEvidence(self.domain, True, records, "; ".join(parts) + ".")


class NetworkAdapter(DomainAdapter):
    domain = "network"
    source = "Sysmon network connections / share access"

    EVENT_IDS = {"3", "5140", "5145"}

    def query(self, hosts, users, window):
        if not self.available():
            return self._disconnected("no network telemetry loaded")
        rows = self._scope(hosts, users)
        if "event_id" in rows.columns:
            rows = rows[rows["event_id"].astype(str).isin(self.EVENT_IDS)]

        ips = Counter(
            str(i) for i in rows.get("source_ip", pd.Series(dtype=str))
            if str(i) not in ("", "nan", "-", "::1", "127.0.0.1")
        )
        shares = Counter(
            str(s) for s in rows.get("share_name", pd.Series(dtype=str)) if str(s) not in ("", "nan")
        )
        records = [
            {
                "timestamp": str(r.get("timestamp", "")),
                "event_id": str(r.get("event_id", "")),
                "source_ip": str(r.get("source_ip", "")),
                "share": str(r.get("share_name", "")),
                "host": str(r.get("computer", "")),
            }
            for _, r in rows.head(25).iterrows()
        ]
        parts = [f"{len(rows)} network events"]
        if ips:
            parts.append("peers " + ", ".join(f"{i}({n})" for i, n in ips.most_common(3)))
        if shares:
            parts.append("shares " + ", ".join(f"{s}({n})" for s, n in shares.most_common(3)))
        return DomainEvidence(self.domain, True, records, "; ".join(parts) + ".")


class ADAdapter(DomainAdapter):
    domain = "ad"
    source = "Directory object change events"

    EVENT_IDS = {"4720", "4722", "4724", "4728", "4732", "4738", "4756", "5136"}

    def query(self, hosts, users, window):
        if not self.available():
            return self._disconnected("no directory telemetry loaded")
        rows = self._scope(hosts, users)
        if "event_id" in rows.columns:
            rows = rows[rows["event_id"].astype(str).isin(self.EVENT_IDS)]
        if rows.empty:
            return DomainEvidence(self.domain, True, [], "No directory object changes in scope.")
        records = [
            {
                "timestamp": str(r.get("timestamp", "")),
                "event_id": str(r.get("event_id", "")),
                "user": str(r.get("user", "")),
                "target": str(r.get("target_user", "")),
            }
            for _, r in rows.head(25).iterrows()
        ]
        return DomainEvidence(
            self.domain, True, records,
            f"{len(rows)} directory change events — account or group membership modified.",
        )


class UnconnectedAdapter(DomainAdapter):
    """A domain in the architecture with no source wired up in this deployment."""

    def __init__(self, domain: str, reason: str) -> None:
        super().__init__(None)
        self.domain = domain
        self.reason = reason

    def available(self) -> bool:
        return False

    def query(self, hosts, users, window):
        return self._disconnected(self.reason)


class EvidenceEngine:
    """Fans an investigation out across every data domain."""

    def __init__(self, df: pd.DataFrame | None = None) -> None:
        self.adapters: dict[str, DomainAdapter] = {
            "endpoint": EndpointAdapter(df),
            "identity": IdentityAdapter(df),
            "network": NetworkAdapter(df),
            "ad": ADAdapter(df),
            # Declared by the architecture, not wired up here. Named explicitly
            # so an analyst can see the blind spots in their own coverage.
            "email": UnconnectedAdapter("email", "mail gateway connector not configured"),
            "dns": UnconnectedAdapter("dns", "no DNS resolver logs ingested"),
            "cloud": UnconnectedAdapter("cloud", "no cloud audit trail configured"),
            "firewall": UnconnectedAdapter("firewall", "no firewall syslog ingested"),
            "saas": UnconnectedAdapter("saas", "no SaaS audit API configured"),
        }

    def coverage(self) -> dict[str, Any]:
        connected = [d for d, a in self.adapters.items() if a.available()]
        missing = [d for d, a in self.adapters.items() if not a.available()]
        return {
            "connected": sorted(connected),
            "not_connected": sorted(missing),
            "coverage_ratio": round(len(connected) / len(self.adapters), 2),
            "sources": {d: a.source for d, a in self.adapters.items() if a.available()},
        }

    def investigate(self, incident: dict[str, Any]) -> dict[str, DomainEvidence]:
        hosts = incident.get("hosts", [])
        users = incident.get("users", [])
        window = (incident.get("first_seen", ""), incident.get("last_seen", ""))
        return {d: a.query(hosts, users, window) for d, a in self.adapters.items()}

    @staticmethod
    def summarize(evidence: dict[str, DomainEvidence]) -> dict[str, Any]:
        """Compact form for a prompt: findings first, blind spots named."""
        return {
            "domains_with_evidence": {
                d: e.summary for d, e in evidence.items() if e.connected and e.records
            },
            "domains_checked_no_findings": [
                d for d, e in evidence.items() if e.connected and not e.records
            ],
            "domains_not_connected": [d for d, e in evidence.items() if not e.connected],
        }
