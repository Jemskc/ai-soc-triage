"""Stage 1 — stream processing.

Reads telemetry in bounded chunks so memory stays flat regardless of volume.
The previous path loaded everything into one DataFrame, which extrapolates to
~15 GB of RAM at 10M events; this holds a chunk at a time and keeps only
accumulated statistics between chunks.

Nothing here judges anything. It normalises, and it maintains the running
counters the analytics stages need so they never require a second pass.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

import pandas as pd

DEFAULT_CHUNK_SIZE = 50_000


@dataclass
class StreamStats:
    """Running counters accumulated in one pass over the stream.

    These are what the rarity and UEBA stages consume. Building them during
    ingestion means the pipeline never re-reads the source.
    """

    events: int = 0
    chunks: int = 0

    process_counts: Counter = field(default_factory=Counter)
    parent_child_counts: Counter = field(default_factory=Counter)
    user_host_counts: Counter = field(default_factory=Counter)
    event_id_counts: Counter = field(default_factory=Counter)
    port_counts: Counter = field(default_factory=Counter)
    host_counts: Counter = field(default_factory=Counter)
    user_counts: Counter = field(default_factory=Counter)

    # Per-entity behaviour, for baseline deviation.
    user_processes: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    user_hosts: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    host_users: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    user_event_ids: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    user_hours: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))

    # Authentication baselines. Process telemetry has none of these, and
    # authentication telemetry has none of the process ones, so both sets are
    # maintained and each scorer uses what exists.
    user_auth_types: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    user_logon_types: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    user_failures: Counter = field(default_factory=Counter)
    user_successes: Counter = field(default_factory=Counter)
    source_dest_pairs: Counter = field(default_factory=Counter)
    user_dest_pairs: Counter = field(default_factory=Counter)
    source_counts: Counter = field(default_factory=Counter)

    def observe(self, df: pd.DataFrame) -> None:
        """Fold one chunk into the running counters."""
        self.events += len(df)
        self.chunks += 1

        def col(name: str) -> pd.Series:
            return df[name].astype(str) if name in df.columns else pd.Series([""] * len(df))

        procs = col("process_name").str.lower()
        parents = col("parent_process").str.lower()
        users = col("user")
        hosts = col("computer")
        eids = col("event_id")
        ports = col("destination_port")

        self.process_counts.update(p for p in procs if p)
        self.parent_child_counts.update(
            f"{pa}>{pr}" for pa, pr in zip(parents, procs) if pa and pr
        )
        self.event_id_counts.update(e for e in eids if e)
        self.port_counts.update(p for p in ports if p and p not in ("0",))
        self.host_counts.update(h for h in hosts if h)
        self.user_counts.update(u for u in users if u)
        self.user_host_counts.update(
            f"{u}@{h}" for u, h in zip(users, hosts) if u and h
        )

        for u, h, p, e in zip(users, hosts, procs, eids):
            if not u:
                continue
            if h:
                self.user_hosts[u][h] += 1
                self.host_users[h][u] += 1
            if p:
                self.user_processes[u][p] += 1
            if e:
                self.user_event_ids[u][e] += 1

        # --- authentication baselines ---
        auth_types = col("raw_message")
        logon_types = col("logon_type")
        eids = col("event_id")
        for u, h, src, eid, lt, msg in zip(users, hosts, col("source_ip"), eids,
                                           logon_types, auth_types):
            if eid == "4625":
                self.user_failures[u] += 1
            elif eid == "4624":
                self.user_successes[u] += 1
            if u and h:
                self.user_dest_pairs[f"{u}->{h}"] += 1
            if src and h:
                self.source_dest_pairs[f"{src}->{h}"] += 1
            if src:
                self.source_counts[src] += 1
            if u and lt:
                self.user_logon_types[u][lt] += 1
            if u and msg:
                # The auth mechanism is the first token of the rendered message.
                self.user_auth_types[u][msg.split(" ", 1)[0].lower()] += 1

        if "timestamp" in df.columns:
            hours = pd.to_datetime(df["timestamp"], errors="coerce", format="mixed").dt.hour
            for u, hr in zip(users, hours):
                if u and pd.notna(hr):
                    self.user_hours[u][int(hr)] += 1

    def summary(self) -> dict[str, Any]:
        return {
            "events": self.events,
            "chunks": self.chunks,
            "distinct_processes": len(self.process_counts),
            "distinct_users": len(self.user_counts),
            "distinct_hosts": len(self.host_counts),
            "distinct_parent_child": len(self.parent_child_counts),
        }


def stream_csv(
    path: Path,
    normalize: Callable[[pd.DataFrame], pd.DataFrame],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    limit: int | None = None,
) -> Iterator[pd.DataFrame]:
    """Yield normalised chunks from a CSV without loading it whole."""
    seen = 0
    for raw in pd.read_csv(path, low_memory=False, chunksize=chunk_size):
        chunk = normalize(raw)
        if limit is not None and seen + len(chunk) > limit:
            chunk = chunk.iloc[: max(0, limit - seen)]
        if chunk.empty:
            break
        seen += len(chunk)
        yield chunk
        if limit is not None and seen >= limit:
            break


def stream_frame(
    df: pd.DataFrame, chunk_size: int = DEFAULT_CHUNK_SIZE
) -> Iterator[pd.DataFrame]:
    """Chunk an in-memory frame, so callers can use one code path for both."""
    for start in range(0, len(df), chunk_size):
        yield df.iloc[start : start + chunk_size]
