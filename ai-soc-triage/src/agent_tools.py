"""Tools an investigating agent can call.

This is the difference between an LLM that fills in a form and one that runs an
investigation. Previously the Evidence Engine gathered a fixed packet, the same
way for every case, and the model wrote a verdict from it. Here the model
decides what it wants to know, asks, reads the answer, and asks again.

Design constraints that shape every tool below:

**Bounded output.** A V100 has no flash-attention kernel, so prompt length costs
memory quadratically and the transcript grows with every observation. Every
tool returns a summary sized for a prompt, never a raw dump. A tool that can
return 10,000 rows will eventually OOM the card mid-investigation.

**Read-only.** Nothing here changes state. Containment is proposed through the
response path and gated on a human. An agent that can isolate a host as a side
effect of investigating is a liability.

**Honest about absence.** A tool over an unconnected data source says so rather
than returning empty, because "no evidence" and "no visibility" are different
findings and an agent that conflates them will clear a case it cannot see.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable

MAX_ROWS_RETURNED = 8


class AskedHuman(Exception):
    """Raised when the agent puts a question to an analyst.

    Control-flow rather than an error: it unwinds the investigation loop so the
    case can be parked with its transcript intact, and resumed when someone
    answers instead of being re-run from scratch.
    """

    def __init__(self, question: str, why: str = "", options=None) -> None:
        super().__init__(question)
        self.question = question
        self.why = why
        self.options = options or []
MAX_OBSERVATION_CHARS = 700


@dataclass
class ToolSpec:
    name: str
    description: str
    args: dict[str, str]
    handler: Callable[..., dict[str, Any]]

    def signature(self) -> str:
        arglist = ", ".join(f"{k}: {v}" for k, v in self.args.items())
        return f"{self.name}({arglist}) — {self.description}"


@dataclass
class ToolCall:
    """One step of an investigation, kept for the audit trail."""

    step: int
    tool: str
    args: dict[str, Any]
    result: dict[str, Any]
    elapsed: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "tool": self.tool,
            "args": self.args,
            "result": self.result,
            "elapsed_seconds": round(self.elapsed, 2),
            "error": self.error,
        }

    def observation(self) -> str:
        """What the model sees back — bounded."""
        if self.error:
            return f"ERROR: {self.error}"
        text = json.dumps(self.result, default=str)
        if len(text) > MAX_OBSERVATION_CHARS:
            text = text[:MAX_OBSERVATION_CHARS] + " …[truncated]"
        return text


def _parse_ts(value: Any) -> datetime | None:
    text = str(value or "").strip().replace("Z", "+00:00")
    if not text:
        return None
    try:
        return datetime.fromisoformat(text).replace(tzinfo=None)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(text[:26], fmt)
            except ValueError:
                continue
    return None


class ToolBox:
    """The tools available for one investigation."""

    def __init__(self, evidence_engine, knowledge_base, df=None,
                 assets=None, case_memory=None, allow_ask_human=None) -> None:
        self.evidence = evidence_engine
        self.kb = knowledge_base
        self.df = df
        self.assets = assets
        self.memory = case_memory
        # The agent decides; it does not hand the decision back.
        #
        # Parking a case as a question to a human is the one move that looks
        # like diligence and behaves like an outage: the incident leaves the
        # queue, nothing is concluded, and the backlog grows while the GPU sits
        # idle. An analyst opening the dashboard wants a verdict they can
        # disagree with, not a question they have to answer before the system
        # will commit to anything. Where the evidence genuinely does not
        # settle it, the honest output is a low-confidence verdict that says
        # what is missing — which is still a decision.
        #
        # Set SOC_ALLOW_ASK_HUMAN=1 to restore the old behaviour.
        if allow_ask_human is None:
            allow_ask_human = os.getenv("SOC_ALLOW_ASK_HUMAN", "").strip() in ("1", "true", "yes")
        self.allow_ask_human = allow_ask_human
        self.calls: list[ToolCall] = []
        self._specs = self._build_specs()

    # -- registry ----------------------------------------------------------

    def _build_specs(self) -> dict[str, ToolSpec]:
        specs = [
            ToolSpec(
                "query_identity",
                "Authentication activity for an account: logon types, failures, "
                "hosts reached. Use to establish whether an account is behaving "
                "as it normally does.",
                {"user": "account name", "hours": "lookback window, default 24"},
                self._query_identity,
            ),
            ToolSpec(
                "query_endpoint",
                "Process and file activity on a host. Use to find what actually "
                "executed after a suspicious logon.",
                {"host": "hostname", "hours": "lookback window, default 24"},
                self._query_endpoint,
            ),
            ToolSpec(
                "query_network",
                "Network and share access involving a host or address. Use to "
                "trace movement between machines.",
                {"entity": "hostname or IP", "hours": "lookback window, default 24"},
                self._query_network,
            ),
            ToolSpec(
                "query_asset",
                "Business context for a host or account: criticality, owner, "
                "business unit. Use before deciding urgency — a domain "
                "controller and a test VM are not the same finding.",
                {"name": "hostname or account"},
                self._query_asset,
            ),
            ToolSpec(
                "check_baseline",
                "How an entity's current behaviour compares with its own history.",
                {"entity": "user or host", "metric": "hosts_reached | failures | processes"},
                self._check_baseline,
            ),
            ToolSpec(
                "search_knowledge",
                "ATT&CK techniques, Windows event semantics, LOLBAS notes and "
                "response playbooks. The only source you may cite.",
                {"query": "what to look up"},
                self._search_knowledge,
            ),
            ToolSpec(
                "timeline",
                "Events involving an entity in time order. Use to establish "
                "sequence — what happened before and after.",
                {"entity": "user or host", "hours": "window, default 6"},
                self._timeline,
            ),
            *([ToolSpec(
                "ask_analyst",
                "Put one question to a human and pause. Use ONLY for a fact the "
                "telemetry cannot contain — whether a change window was "
                "approved, whether a contractor still works here. Never use it "
                "to avoid deciding something the evidence already answers.",
                {"question": "one specific question",
                 "why": "what it would let you conclude",
                 "options": "optional list of likely answers"},
                self._ask_analyst,
            )] if self.allow_ask_human else []),
            # Listed only when it is usable. A tool the agent can see is a tool
            # it will try, and being refused mid-investigation costs a whole
            # model round trip to learn something the catalogue could have said.
            ToolSpec(
                "find_similar_cases",
                "Previously investigated cases resembling this one, with their "
                "outcomes. Use before concluding: this may be a known-benign "
                "pattern already ruled on.",
                {"query": "short description of the activity"},
                self._find_similar_cases,
            ),
        ]
        return {s.name: s for s in specs}

    def catalogue(self) -> str:
        return "\n".join(f"  - {s.signature()}" for s in self._specs.values())

    def names(self) -> list[str]:
        return list(self._specs)

    # -- execution ---------------------------------------------------------

    def run(self, step: int, name: str, args: dict[str, Any]) -> ToolCall:
        import time

        spec = self._specs.get(name)
        if spec is None:
            call = ToolCall(step, name, args, {},
                            error=f"unknown tool '{name}'; available: {', '.join(self._specs)}")
            self.calls.append(call)
            return call

        started = time.time()
        try:
            result = spec.handler(**{k: v for k, v in (args or {}).items()})
            call = ToolCall(step, name, args, result, time.time() - started)
        except AskedHuman:
            # Control flow, not a failure: the loop parks the case with its
            # transcript so answering resumes rather than restarts it.
            raise
        except TypeError as exc:
            call = ToolCall(step, name, args, {}, time.time() - started,
                            error=f"bad arguments: {exc}")
        except Exception as exc:  # noqa: BLE001 — a tool failure is a finding
            call = ToolCall(step, name, args, {}, time.time() - started,
                            error=f"{type(exc).__name__}: {exc}")
        self.calls.append(call)
        return call

    # -- handlers ----------------------------------------------------------

    def _scope(self, hours: Any, **filters: str):
        """Rows matching the filters within the window."""
        if self.df is None or self.df.empty:
            return None
        frame = self.df
        mask = None
        for column, value in filters.items():
            if not value or column not in frame.columns:
                continue
            hit = frame[column].astype(str).str.lower() == str(value).lower()
            mask = hit if mask is None else (mask | hit)
        if mask is None:
            return frame.iloc[0:0]
        return frame[mask]

    def _query_identity(self, user: str = "", hours: Any = 24) -> dict[str, Any]:
        from collections import Counter

        rows = self._scope(hours, user=user, target_user=user)
        if rows is None:
            return {"available": False,
                    "why": "no identity telemetry is connected in this deployment"}
        if rows.empty:
            return {"user": user, "events": 0,
                    "finding": "no authentication activity found for this account"}

        auth_ids = {"4624", "4625", "4768", "4769", "4776", "4672"}
        auth = rows[rows["event_id"].astype(str).isin(auth_ids)] if "event_id" in rows else rows
        hosts = Counter(str(h) for h in auth.get("computer", []) if str(h))
        by_event = Counter(str(e) for e in auth.get("event_id", []))
        logon = Counter(str(t) for t in auth.get("logon_type", []) if str(t))

        return {
            "user": user,
            "events": int(len(auth)),
            "failed_logons": by_event.get("4625", 0),
            "successful_logons": by_event.get("4624", 0),
            "elevated_logons": by_event.get("4672", 0),
            "hosts_reached": len(hosts),
            "top_hosts": [h for h, _ in hosts.most_common(6)],
            "logon_types": dict(logon.most_common(4)),
        }

    def _query_endpoint(self, host: str = "", hours: Any = 24) -> dict[str, Any]:
        from collections import Counter

        rows = self._scope(hours, computer=host)
        if rows is None:
            return {"available": False,
                    "why": "no endpoint telemetry is connected in this deployment"}
        if rows.empty:
            return {"host": host, "events": 0,
                    "finding": "no endpoint activity found for this host"}

        procs = Counter(
            str(p).rsplit("\\", 1)[-1] for p in rows.get("process_name", []) if str(p)
        )
        cmds = [str(c)[:160] for c in rows.get("command_line", []) if str(c)][:5]
        return {
            "host": host,
            "events": int(len(rows)),
            "distinct_processes": len(procs),
            "top_processes": [p for p, _ in procs.most_common(8)],
            "sample_command_lines": cmds,
            "users_seen": sorted({str(u) for u in rows.get("user", []) if str(u)})[:6],
        }

    def _query_network(self, entity: str = "", hours: Any = 24) -> dict[str, Any]:
        from collections import Counter

        rows = self._scope(hours, computer=entity, source_ip=entity)
        if rows is None:
            return {"available": False,
                    "why": "no network telemetry is connected in this deployment"}
        if rows.empty:
            return {"entity": entity, "events": 0, "finding": "no network activity found"}

        peers = Counter(
            str(i) for i in rows.get("source_ip", [])
            if str(i) and str(i) not in ("-", "127.0.0.1", "::1")
        )
        shares = Counter(str(s) for s in rows.get("share_name", []) if str(s))
        return {
            "entity": entity,
            "events": int(len(rows)),
            "distinct_peers": len(peers),
            "top_peers": [p for p, _ in peers.most_common(6)],
            "shares_accessed": [s for s, _ in shares.most_common(5)],
        }

    def _query_asset(self, name: str = "") -> dict[str, Any]:
        if self.assets is None:
            return {"available": False,
                    "why": "no asset inventory is configured; business criticality "
                           "is unknown and urgency cannot account for it"}
        return self.assets.lookup(name)

    def _check_baseline(self, entity: str = "", metric: str = "hosts_reached") -> dict[str, Any]:
        stats = getattr(self.evidence, "stream_stats", None)
        if stats is None:
            return {"available": False,
                    "why": "no behavioural baseline has been accumulated yet"}

        if metric == "hosts_reached":
            reach = len(stats.user_hosts.get(entity, {}))
            spreads = sorted(len(h) for h in stats.user_hosts.values()) or [0]
            typical = spreads[len(spreads) // 2]
            return {"entity": entity, "metric": metric, "observed": reach,
                    "typical_for_population": typical,
                    "assessment": "unusual" if reach > max(2, typical * 2) else "normal"}
        if metric == "failures":
            failures = stats.user_failures.get(entity, 0)
            total = failures + stats.user_successes.get(entity, 0)
            rate = failures / total if total else 0.0
            return {"entity": entity, "metric": metric, "failures": failures,
                    "total_authentications": total, "failure_rate": round(rate, 3),
                    "assessment": "unusual" if rate > 0.3 and failures >= 5 else "normal"}
        if metric == "processes":
            procs = stats.user_processes.get(entity, {})
            return {"entity": entity, "metric": metric,
                    "distinct_processes": len(procs),
                    "top": [p for p, _ in procs.most_common(6)]}
        return {"error": f"unknown metric '{metric}'",
                "valid": ["hosts_reached", "failures", "processes"]}

    def _search_knowledge(self, query: str = "") -> dict[str, Any]:
        if self.kb is None:
            return {"available": False, "why": "knowledge base not loaded"}
        hits = self.kb.search(query, top_k=4)
        if not hits:
            return {"query": query, "results": [],
                    "finding": "nothing relevant retrieved — you may not cite a "
                               "technique for this; use UNKNOWN"}
        return {
            "query": query,
            "results": [
                {"id": h["id"], "title": h.get("title", ""),
                 "text": h.get("text", "")[:450]}
                for h in hits
            ],
        }

    def _timeline(self, entity: str = "", hours: Any = 6) -> dict[str, Any]:
        rows = self._scope(hours, computer=entity, user=entity, source_ip=entity)
        if rows is None or rows.empty:
            return {"entity": entity, "events": 0, "finding": "no events found"}

        ordered = rows.copy()
        if "timestamp" in ordered.columns:
            ordered = ordered.sort_values("timestamp")
        out = []
        for _, r in ordered.head(MAX_ROWS_RETURNED).iterrows():
            out.append({
                "time": str(r.get("timestamp", ""))[:19],
                "event_id": str(r.get("event_id", "")),
                "user": str(r.get("user", "")),
                "host": str(r.get("computer", "")),
                "process": str(r.get("process_name", "")).rsplit("\\", 1)[-1],
            })
        return {"entity": entity, "events": int(len(ordered)),
                "showing": len(out), "sequence": out}

    def _ask_analyst(self, question: str = "", why: str = "",
                     options: Any = None) -> dict[str, Any]:
        if not self.allow_ask_human:
            return {"available": False,
                    "why": "asking a human is disabled for this run; decide on "
                           "the evidence or conclude UNKNOWN"}
        if not str(question).strip():
            return {"error": "a question is required"}
        raise AskedHuman(
            str(question), str(why or ""),
            options if isinstance(options, list) else [],
        )

    def _find_similar_cases(self, query: str = "") -> dict[str, Any]:
        if self.memory is None:
            return {"available": False,
                    "why": "no case history yet; this is the first investigation"}
        return self.memory.search(query)
