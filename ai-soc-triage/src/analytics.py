"""Stages 2b and 3 — statistical detection and UEBA.

These exist because rules alone are a bad gate. Measured on the labelled
corpus, the 10 detection rules fire on only 39 of 249 attack samples: 84% of
known attacks produce no alert at all. If rules were the only path to the AI,
those attacks would be invisible no matter how good the AI is.

Neither stage is trained. There is no labelled benign corpus here, so anything
claiming a fitted model would be fiction. Instead both work from the
distribution of the data itself:

  statistical — how rare is this, against everything else seen
  UEBA        — how unusual is this *for this particular user or host*

Both emit a 0..1 score with a human-readable reason. They never filter; the
funnel ranks on the combined signal, so a low score means "further down the
queue", not "discarded".
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

import pandas as pd

from stream import StreamStats


@dataclass
class Signal:
    """One reason an event drew attention, with its weight."""

    source: str          # "statistical" | "ueba"
    kind: str
    score: float         # 0..1
    reason: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "kind": self.kind,
            "score": round(self.score, 3),
            "reason": self.reason,
            "detail": self.detail,
        }


class RarityModel:
    """Calibrated rarity for one population of keys.

    Absolute frequency is the wrong measure. In this corpus most parent-child
    pairs occur exactly once, so scoring "seen once" as maximally rare flags
    ~80% of the data and the signal carries no information. Rarity has to be
    judged against the *distribution*: being a singleton is only remarkable
    when singletons are themselves unusual.

    So the raw self-information is damped by how common that level of rarity
    is among distinct keys. In a population that is mostly singletons, being a
    singleton scores near zero; in one where repetition is the norm, it scores
    high.
    """

    def __init__(self, counts: Counter) -> None:
        self.counts = counts
        self.total_observations = max(1, sum(counts.values()))
        self.distinct = max(1, len(counts))
        singletons = sum(1 for c in counts.values() if c <= 1)
        self.singleton_share = singletons / self.distinct
        # How much information a singleton actually carries here.
        self.discriminative_power = 1.0 - self.singleton_share

    def score(self, key: str) -> float:
        count = self.counts.get(key, 0)
        if count <= 0:
            return 0.0
        frequency = count / self.total_observations
        raw = min(1.0, max(0.0, -math.log10(frequency) / 4.0))
        if count <= 1:
            # Damp singletons by how ordinary singletons are in this population.
            return round(raw * self.discriminative_power, 4)
        return round(raw, 4)


def _rarity(count: int, total: int) -> float:
    """Uncalibrated fallback, retained for callers without a population."""
    if total <= 0 or count <= 0:
        return 0.0
    return min(1.0, max(0.0, -math.log10(count / total) / 4.0))


# Ubiquitous Windows parent->child relationships. These are boot and servicing
# machinery: rare inside a small capture, utterly normal in reality. Without
# this, self-baselining ranks the operating system starting up above the
# intrusion, because both are equally infrequent in a 4,633-event sample.
BENIGN_LINEAGE = {
    "wininit.exe>services.exe", "wininit.exe>lsass.exe", "wininit.exe>lsm.exe",
    "smss.exe>csrss.exe", "smss.exe>wininit.exe", "smss.exe>winlogon.exe",
    "smss.exe>smss.exe", "smss.exe>autochk.exe", "system>smss.exe",
    "winlogon.exe>userinit.exe", "winlogon.exe>logonui.exe",
    "winlogon.exe>dwm.exe", "userinit.exe>explorer.exe",
    "services.exe>svchost.exe", "services.exe>vboxservice.exe",
    "services.exe>msmpeng.exe", "services.exe>searchindexer.exe",
    "services.exe>spoolsv.exe", "services.exe>vmtoolsd.exe",
    "svchost.exe>runtimebroker.exe", "svchost.exe>taskhostw.exe",
    "svchost.exe>wmiprvse.exe", "svchost.exe>drvinst.exe",
    "svchost.exe>audiodg.exe", "svchost.exe>dllhost.exe",
    "svchost.exe>sihost.exe", "svchost.exe>backgroundtaskhost.exe",
    "runtimebroker.exe>localbridge.exe", "consent.exe>werfault.exe",
    "explorer.exe>runtimebroker.exe", "csrss.exe>conhost.exe",
    "svchost.exe>usoclient.exe", "svchost.exe>mousocoreworker.exe",
    "slui.exe>changepk.exe", "systemsettings.exe>systemsettingsadminflows.exe",
}

# Living-off-the-land binaries: signed, present everywhere, and abused
# precisely because their presence looks unremarkable. Rarity alone
# under-weights them, so they carry a floor.
LOLBIN_HINTS = (
    "rundll32", "regsvr32", "mshta", "certutil", "wmic", "pcalua", "msiexec",
    "cscript", "wscript", "schtasks", "bitsadmin", "installutil", "odbcconf",
    "psexec", "at.exe", "net1.exe",
)

SUSPICIOUS_CMDLINE = (
    "-enc", "-encodedcommand", "frombase64string", "downloadstring",
    "downloadfile", "invoke-expression", "iex ", "-nop", "-noprofile",
    "-windowstyle hidden", "bypass", "hidden", "scrobj.dll", "javascript:",
    "-urlcache",
)

HIGH_RISK_PORTS = {"4444", "1337", "8080", "8443", "3389", "5985", "5986"}


class StatisticalDetector:
    """Rarity and content-based scoring over the whole observed population."""

    def __init__(self, stats: StreamStats) -> None:
        self.stats = stats
        self.process_rarity = RarityModel(stats.process_counts)
        self.lineage_rarity = RarityModel(stats.parent_child_counts)
        self.event_rarity = RarityModel(stats.event_id_counts)

    def auth_calibration(self) -> dict[str, Any]:  # pragma: no cover - reporting
        return {}

    def calibration(self) -> dict[str, Any]:
        """Expose how discriminative each population is, so a weak signal can
        be recognised as weak rather than trusted blindly."""
        return {
            name: {
                "distinct_keys": m.distinct,
                "singleton_share": round(m.singleton_share, 3),
                "discriminative_power": round(m.discriminative_power, 3),
            }
            for name, m in (
                ("process", self.process_rarity),
                ("lineage", self.lineage_rarity),
                ("event_id", self.event_rarity),
            )
        }

    def score_row(self, row: dict[str, Any]) -> list[Signal]:
        signals: list[Signal] = []
        total = max(1, self.stats.events)

        process = str(row.get("process_name", "")).lower()
        parent = str(row.get("parent_process", "")).lower()
        cmdline = str(row.get("command_line", "")).lower()
        port = str(row.get("destination_port", ""))

        # Rare process across the estate.
        if process:
            count = self.stats.process_counts.get(process, 0)
            score = self.process_rarity.score(process)
            if score > 0.35:
                signals.append(Signal(
                    "statistical", "rare_process", score,
                    f"Process {process.rsplit(chr(92), 1)[-1]} seen {count} time(s) "
                    f"in {total:,} events.",
                    {"process": process, "count": count},
                ))

        # Rare parent-child pair. Unusual lineage is one of the strongest
        # single signals on Windows: winword spawning cmd, services spawning
        # powershell. Placeholder parents ("?", "-") carry no lineage
        # information and scoring them manufactures anomalies out of gaps in
        # the telemetry.
        if parent in ("?", "-", "unknown", "n/a"):
            parent = ""
        if parent and process:
            pair = f"{parent.rsplit(chr(92), 1)[-1]}>{process.rsplit(chr(92), 1)[-1]}"
            count = self.stats.parent_child_counts.get(f"{parent}>{process}", 0)
            score = 0.0 if pair in BENIGN_LINEAGE else self.lineage_rarity.score(
                f"{parent}>{process}")
            if score > 0.3:
                signals.append(Signal(
                    "statistical", "rare_lineage", min(0.85, score * 1.2),
                    f"Parent-child {parent.rsplit(chr(92),1)[-1]} -> "
                    f"{process.rsplit(chr(92),1)[-1]} seen {count} time(s).",
                    {"pair": pair, "count": count},
                ))

        # LOLBIN execution.
        if any(h in process for h in LOLBIN_HINTS):
            name = next(h for h in LOLBIN_HINTS if h in process)
            signals.append(Signal(
                "statistical", "lolbin", 0.55,
                f"Living-off-the-land binary {name} executed.",
                {"binary": name},
            ))

        # Suspicious command-line content.
        hits = [t for t in SUSPICIOUS_CMDLINE if t in cmdline]
        if hits:
            signals.append(Signal(
                "statistical", "suspicious_cmdline", min(1.0, 0.4 + 0.2 * len(hits)),
                f"Command line contains {', '.join(h.strip() for h in hits[:3])}.",
                {"indicators": hits},
            ))

        # Very long command lines are a classic obfuscation tell.
        if len(cmdline) > 500:
            signals.append(Signal(
                "statistical", "long_cmdline", 0.4,
                f"Command line is {len(cmdline)} characters.",
                {"length": len(cmdline)},
            ))

        if port in HIGH_RISK_PORTS:
            signals.append(Signal(
                "statistical", "high_risk_port", 0.45,
                f"Connection on port {port}.", {"port": port},
            ))

        # Rare event id.
        eid = str(row.get("event_id", ""))
        if eid:
            count = self.stats.event_id_counts.get(eid, 0)
            score = self.event_rarity.score(eid)
            if score > 0.5:
                signals.append(Signal(
                    "statistical", "rare_event_type", score * 0.8,
                    f"Event ID {eid} seen {count} time(s).",
                    {"event_id": eid, "count": count},
                ))

        return signals


# Principals that are not users and must never be baselined as if they were.
# SYSTEM is present on every host by definition, so "SYSTEM appears on 10 hosts"
# scores as maximally anomalous while being the single most normal fact in a
# Windows estate. Machine accounts (trailing $) have the same problem. Scoring
# these is the classic UEBA false-positive generator.
NON_HUMAN_PRINCIPALS = {
    "system", "nt authority\\system", "local service",
    "nt authority\\local service", "network service",
    "nt authority\\network service", "anonymous logon",
    "nt authority\\anonymous logon", "iusr", "dwm-1", "dwm-2", "umfd-0",
    "umfd-1", "-", "",
}


def is_human_principal(user: str) -> bool:
    name = str(user).strip().lower()
    if name in NON_HUMAN_PRINCIPALS:
        return False
    # Machine accounts: PC01$, DC02$
    if name.endswith("$"):
        return False
    if name.startswith("nt authority") or name.startswith("nt service"):
        return False
    return True


class UEBA:
    """Per-entity baseline deviation.

    The question is not "is this rare overall" but "is this rare *for this
    account*". An admin running psexec is routine; the same command from a
    finance account is not, and only a per-entity baseline separates them.
    """

    # An entity needs some history before deviation means anything; below this
    # every observation looks novel and the signal is noise.
    MIN_BASELINE_EVENTS = 20

    def __init__(self, stats: StreamStats) -> None:
        self.stats = stats
        # How far accounts reach, so breadth is judged against peers rather
        # than a fixed fraction of the estate.
        spreads = sorted(len(h) for h in stats.user_hosts.values()) or [0]
        self.spread_p90 = spreads[int(len(spreads) * 0.9)] if len(spreads) >= 10 else None
        self.spread_median = spreads[len(spreads) // 2]

    def _entity_ready(self, user: str) -> bool:
        return self.stats.user_counts.get(user, 0) >= self.MIN_BASELINE_EVENTS

    def score_row(self, row: dict[str, Any]) -> list[Signal]:
        signals: list[Signal] = []
        user = str(row.get("user", ""))
        host = str(row.get("computer", ""))
        process = str(row.get("process_name", "")).lower()

        if not user or not is_human_principal(user) or not self._entity_ready(user):
            return signals

        user_total = self.stats.user_counts[user]

        # Host this account does not normally touch.
        if host:
            host_count = self.stats.user_hosts[user].get(host, 0)
            if host_count <= max(1, user_total * 0.02):
                signals.append(Signal(
                    "ueba", "unusual_host_for_user",
                    min(1.0, 0.5 + 0.5 * (1 - host_count / max(1, user_total))),
                    f"{user} rarely appears on {host} "
                    f"({host_count} of {user_total} events).",
                    {"user": user, "host": host, "count": host_count},
                ))

        # Process this account does not normally run.
        if process:
            proc_count = self.stats.user_processes[user].get(process, 0)
            if proc_count <= max(1, user_total * 0.01):
                signals.append(Signal(
                    "ueba", "unusual_process_for_user", 0.5,
                    f"{user} rarely runs {process.rsplit(chr(92),1)[-1]} "
                    f"({proc_count} of {user_total} events).",
                    {"user": user, "process": process, "count": proc_count},
                ))

        # Activity outside this account's usual hours.
        hours = self.stats.user_hours.get(user)
        if hours and sum(hours.values()) >= self.MIN_BASELINE_EVENTS:
            ts = pd.to_datetime(row.get("timestamp"), errors="coerce")
            if pd.notna(ts):
                hour = int(ts.hour)
                seen = hours.get(hour, 0)
                if seen == 0:
                    signals.append(Signal(
                        "ueba", "off_hours_for_user", 0.45,
                        f"{user} has no prior activity at {hour:02d}:00.",
                        {"user": user, "hour": hour},
                    ))

        # An account touching an unusually wide slice of the estate is the
        # classic lateral-movement shape. Measured as a fraction of hosts seen,
        # not an absolute count, so it does not fire on every account in a
        # small environment.
        distinct_hosts = len(self.stats.user_hosts.get(user, {}))
        estate = max(1, len(self.stats.host_counts))
        if (self.spread_p90 and distinct_hosts >= 4
                and distinct_hosts > self.spread_p90
                and distinct_hosts > self.spread_median * 2):
            signals.append(Signal(
                "ueba", "wide_host_footprint",
                min(0.75, 0.25 + 0.2 * distinct_hosts / max(1, self.spread_p90)),
                f"{user} appears on {distinct_hosts} of {estate} hosts; the "
                f"typical account reaches {self.spread_median}.",
                {"user": user, "hosts": distinct_hosts, "p90": self.spread_p90},
            ))

        return signals


# No single signal may be treated as certain. Without this, one 1.0 signal
# pins the fused score at 1.0 and every incident above the cap ranks
# identically — which destroys the ordering exactly where it matters most.
MAX_SINGLE_SIGNAL = 0.9


def dedupe(signals: list[Signal]) -> list[Signal]:
    """Collapse repeats of the same finding.

    An incident carries many alerts, and a per-entity signal like "this account
    spans the estate" is true once, not once per alert. Counting it repeatedly
    inflates the fused score with no new evidence.
    """
    best: dict[tuple[str, str, str], Signal] = {}
    for signal in signals:
        key = (signal.source, signal.kind, signal.reason)
        if key not in best or signal.score > best[key].score:
            best[key] = signal
    return sorted(best.values(), key=lambda s: -s.score)


def evidence_weight(signals: list[Signal]) -> float:
    """Accumulated evidence — unbounded, so incidents never tie.

    This is noisy-OR written in log space: sum of -log(1 - s). Two properties
    matter. It keeps accumulating, so six strong signals still outrank three
    (noisy-OR alone converges to 1.0 and every incident scores identically,
    exactly where ordering matters most). And a signal of strength 0
    contributes nothing rather than counting as evidence *against* — these are
    signal strengths, not calibrated probabilities, so 0.5 must mean "moderate
    evidence for", not "no information".
    """
    total = 0.0
    for signal in dedupe(signals):
        strength = max(0.0, min(MAX_SINGLE_SIGNAL, signal.score))
        total += -math.log(1.0 - strength)
    return round(total, 4)


class AuthAnalytics:
    """Behavioural scoring for authentication telemetry.

    Separate from StatisticalDetector because the two operate on disjoint
    fields: that class scores processes, lineage and command lines, none of
    which exist in an auth log. Measured on authentication-only data the
    process scorers produced no signal whatsoever, which is why this exists.

    Everything here is relative to the entity's own history — an administrator
    reaching ten machines is routine, the same behaviour from an account that
    has only ever touched one is not.
    """

    MIN_BASELINE_EVENTS = 15

    def __init__(self, stats: StreamStats) -> None:
        self.stats = stats
        # Precomputed once. Deriving this inside score_row scanned every
        # source->destination pair for every event, which is quadratic and took
        # the funnel from 3s to 17s on only 5,000 events.
        self._source_reach: dict[str, int] = {}
        for pair in stats.source_dest_pairs:
            src, _, dst = pair.partition("->")
            if src and dst:
                self._source_reach[src] = self._source_reach.get(src, 0) + 1

        # Same calibration the process scorers use. "This account has not been
        # on this host before" sounds strong and is worthless in a network
        # where most user-host pairs are new: measured on auth-only data it
        # fired on 100% of events and promoted 4,951 of 5,022 to the AI path.
        # Damped by how ordinary a first-time pairing actually is here.
        self.pair_rarity = RarityModel(stats.user_dest_pairs)

        # Fan-out has to be judged against how far other sources reach, not
        # against a fixed share of the estate. In a densely connected network
        # every machine talks to most others, so "reaches 25% of hosts" fires
        # on everything and the signal is noise. The 90th percentile adapts:
        # in a flat mesh nothing stands out, in a segmented network a pivot
        # does.
        reaches = sorted(self._source_reach.values())
        self.reach_p90 = (
            reaches[int(len(reaches) * 0.9)] if len(reaches) >= 10 else None
        )
        self.reach_median = reaches[len(reaches) // 2] if reaches else 0

    def score_row(self, row: dict[str, Any]) -> list[Signal]:
        signals: list[Signal] = []
        user = str(row.get("user", ""))
        host = str(row.get("computer", ""))
        source = str(row.get("source_ip", ""))
        event_id = str(row.get("event_id", ""))

        if not user or not is_human_principal(user):
            return signals

        seen = (self.stats.user_successes.get(user, 0)
                + self.stats.user_failures.get(user, 0))
        if seen < self.MIN_BASELINE_EVENTS:
            return signals

        # A destination this account has never reached before.
        if host:
            pair = f"{user}->{host}"
            score = self.pair_rarity.score(pair)
            # Only meaningful for an account with an established, narrow
            # footprint: a service account that talks to everything produces a
            # new pair constantly and means nothing by it.
            breadth = len(self.stats.user_hosts.get(user, {}))
            estate = max(1, len(self.stats.host_counts))
            if score > 0.4 and breadth <= max(3, estate * 0.25):
                signals.append(Signal(
                    "ueba", "first_time_user_host", min(0.6, score),
                    f"{user} has not authenticated to {host} before "
                    f"(account normally reaches {breadth} of {estate} hosts).",
                    {"user": user, "host": host,
                     "population_discriminative_power":
                         round(self.pair_rarity.discriminative_power, 2)},
                ))

        # An account failing far more than it usually does.
        failures = self.stats.user_failures.get(user, 0)
        rate = failures / max(1, seen)
        if event_id == "4625" and rate > 0.3 and failures >= 5:
            signals.append(Signal(
                "ueba", "failure_rate_spike", min(0.7, 0.3 + rate),
                f"{user} failed {failures} of {seen} authentications ({rate:.0%}).",
                {"user": user, "failures": failures, "rate": round(rate, 2)},
            ))

        # An authentication mechanism this account does not normally use.
        mechanisms = self.stats.user_auth_types.get(user)
        if mechanisms and len(mechanisms) > 1:
            current = str(row.get("raw_message", "")).split(" ", 1)[0].lower()
            used = mechanisms.get(current, 0)
            if current and used <= max(1, sum(mechanisms.values()) * 0.05):
                signals.append(Signal(
                    "ueba", "unusual_auth_mechanism", 0.45,
                    f"{user} rarely authenticates via {current} "
                    f"({used} of {sum(mechanisms.values())}).",
                    {"user": user, "mechanism": current},
                ))

        # A source machine that talks to an unusual share of the estate.
        if source and self.reach_p90:
            reach = self._source_reach.get(source, 0)
            estate = max(1, len(self.stats.host_counts))
            # Must be an outlier among sources, not merely well connected.
            if reach >= 5 and reach > self.reach_p90 and reach > self.reach_median * 2:
                excess = reach / max(1, self.reach_p90)
                signals.append(Signal(
                    "ueba", "source_fanout", min(0.7, 0.25 + 0.2 * excess),
                    f"{source} reached {reach} hosts; the typical source reaches "
                    f"{self.reach_median} and the 90th percentile is {self.reach_p90}.",
                    {"source": source, "reach": reach, "p90": self.reach_p90},
                ))

        # A logon type this account does not normally produce. Type 9
        # (NewCredentials) and 10 (RemoteInteractive) matter most.
        logon_type = str(row.get("logon_type", ""))
        history = self.stats.user_logon_types.get(user)
        if logon_type and history:
            used = history.get(logon_type, 0)
            if used <= 1 and logon_type in ("9", "10", "3"):
                signals.append(Signal(
                    "ueba", "unusual_logon_type", 0.4,
                    f"{user} rarely uses logon type {logon_type}.",
                    {"user": user, "logon_type": logon_type},
                ))

        return signals


def combine(signals: list[Signal]) -> float:
    """Fused 0..1 suspicion, for display and thresholding.

    The probability corresponding to the accumulated weight, which is exactly
    noisy-OR — so the display value and the ranking key never disagree.
    """
    return round(1.0 - math.exp(-evidence_weight(signals)), 4)
