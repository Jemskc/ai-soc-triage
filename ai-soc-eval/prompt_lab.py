"""Prompt and RAG bake-off for AI triage, measured on LANL Cyber-1.

Runs every (prompt x retrieval) configuration against the same labelled
incidents and reports the full SOC metric set, so a configuration is chosen on
evidence rather than on which output happened to read well.

WHY LANL AND NOT THE EVTX CORPUS
--------------------------------
evtx_data.csv is 100% malicious. It has no benign incidents, so precision,
specificity and false-positive rate are all undefined on it — any figure quoted
from it is invented. LANL contains a real network's ordinary traffic with 749
labelled red-team events inside it, which makes precision computable for the
first time in this project. That is the whole reason to run here.

THE OVERFITTING PROBLEM, AND WHAT IS DONE ABOUT IT
--------------------------------------------------
Trying N configurations and reporting the best one measures how many were
tried, not how good the winner is. With enough variants something scores well
by luck, and that score does not survive new data.

So incidents are split once, deterministically, by a hash of their id:

    DEV  (70%)  tune here, look as often as you like
    TEST (30%)  locked; --final runs the chosen config against it ONCE

Report the TEST number. The DEV number is a development aid and is not a
result. The split is by incident id rather than at random per run so that it is
identical across every invocation and cannot be reshuffled until it flatters.

WHAT AN INCIDENT'S LABEL MEANS
------------------------------
An incident is malicious if any event that contributed to it is in the
red-team ground truth. The agent sees the incident, never the label.

Usage:
    # one configuration on DEV
    python prompt_lab.py --sample lanl_sample.json --config v1_baseline

    # every configuration on DEV, ranked
    python prompt_lab.py --sample lanl_sample.json --sweep

    # the chosen configuration against the locked TEST split, once
    python prompt_lab.py --sample lanl_sample.json --config v3_auth --final
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import statistics
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

BASE_DIR = Path(__file__).resolve().parent
PROJECT = BASE_DIR.parent / "ai-soc-triage"
sys.path.insert(0, str(PROJECT / "src"))

DEV_FRACTION = 0.70


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@dataclass
class Metrics:
    """The SOC metric set.

    Precision, recall and F1 alone flatter an imbalanced problem, so MCC and
    balanced accuracy are reported alongside — a detector that escalates
    everything gets recall 1.0 and MCC 0.0, and only one of those numbers says
    what actually happened.
    """

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    abstained: int = 0
    abstained_malicious: int = 0

    def _div(self, num: float, den: float) -> float | None:
        return num / den if den else None

    @property
    def precision(self): return self._div(self.tp, self.tp + self.fp)
    @property
    def recall(self): return self._div(self.tp, self.tp + self.fn)
    @property
    def specificity(self): return self._div(self.tn, self.tn + self.fp)
    @property
    def npv(self): return self._div(self.tn, self.tn + self.fn)
    @property
    def fpr(self): return self._div(self.fp, self.fp + self.tn)

    @property
    def f1(self):
        p, r = self.precision, self.recall
        if p is None or r is None or p + r == 0:
            return None
        return 2 * p * r / (p + r)

    @property
    def balanced_accuracy(self):
        r, s = self.recall, self.specificity
        return None if r is None or s is None else (r + s) / 2

    @property
    def mcc(self):
        """Matthews correlation. The honest single number for imbalance:
        unlike F1 it uses all four cells, so escalating everything scores 0."""
        tp, fp, tn, fn = self.tp, self.fp, self.tn, self.fn
        den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
        return ((tp * tn) - (fp * fn)) / den if den else None

    def to_dict(self) -> dict[str, Any]:
        r = lambda v: None if v is None else round(v, 4)  # noqa: E731
        decided = self.tp + self.fp + self.tn + self.fn
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "decided": decided,
            "abstained": self.abstained,
            "abstained_malicious": self.abstained_malicious,
            "precision": r(self.precision), "recall": r(self.recall),
            "f1": r(self.f1), "specificity": r(self.specificity),
            "npv": r(self.npv), "false_positive_rate": r(self.fpr),
            "balanced_accuracy": r(self.balanced_accuracy), "mcc": r(self.mcc),
        }


def brier_and_ece(points: list[tuple[float, int]], bins: int = 5) -> dict[str, Any]:
    """Is stated confidence worth believing?

    An agent whose 0.9 calls are right 50% of the time is miscalibrated, and an
    analyst who learns that stops reading the number at all.
    """
    if not points:
        return {"available": False}
    brier = sum((c - o) ** 2 for c, o in points) / len(points)
    ece, rows = 0.0, []
    for i in range(bins):
        lo, hi = i / bins, (i + 1) / bins
        chunk = [(c, o) for c, o in points if lo <= c < hi or (i == bins - 1 and c == 1.0)]
        if not chunk:
            continue
        stated = sum(c for c, _ in chunk) / len(chunk)
        actual = sum(o for _, o in chunk) / len(chunk)
        ece += (len(chunk) / len(points)) * abs(stated - actual)
        rows.append({"range": f"{lo:.0%}-{hi:.0%}", "n": len(chunk),
                     "stated": round(stated, 3), "actual": round(actual, 3)})
    return {"available": True, "brier": round(brier, 4),
            "ece": round(ece, 4), "bins": rows}


def operational_cost(m: Metrics, incidents_total: int, evaluated: int,
                     days_covered: float) -> dict[str, Any]:
    """What the sample implies for a real day.

    Metrics on a stratified sample do not translate directly: malicious
    incidents are deliberately over-represented so the positive class is large
    enough to measure. Scaling back to the true mix is what turns a score into
    a staffing number.
    """
    if not evaluated or not days_covered:
        return {"available": False}
    scale = incidents_total / evaluated
    fp_per_day = (m.fp * scale) / days_covered
    tp_per_day = (m.tp * scale) / days_covered
    return {
        "available": True,
        "scale_factor": round(scale, 2),
        "escalations_per_day": round(fp_per_day + tp_per_day, 1),
        "false_escalations_per_day": round(fp_per_day, 1),
        "true_escalations_per_day": round(tp_per_day, 2),
        "analyst_hours_per_day_at_8min": round((fp_per_day + tp_per_day) * 8 / 60, 1),
        "note": "8 minutes per escalation is an assumption, not a measurement.",
    }


# ---------------------------------------------------------------------------
# Prompt variants
# ---------------------------------------------------------------------------

SCHEMA = (
    '{"verdict": "ESCALATE or SUPPRESS or UNKNOWN", '
    '"confidence": 0.0-1.0, '
    '"reason": "one sentence citing the specific fields that decided it", '
    '"sources": ["knowledge-base chunk ids you used"]}'
)


def _evidence_block(inc: dict[str, Any]) -> str:
    """Authentication evidence, stated plainly.

    LANL has no process names or command lines — proc.txt anonymises them to
    ids like P16 — so anything phrased around process lineage describes
    evidence that does not exist here.
    """
    fired = ", ".join(
        f"{r.get('rule')} x{r.get('count', 1)}"
        for r in inc.get("rules_fired", [])
    ) or "none"
    lines = [
        f"incident: {inc['incident_id']}",
        f"events: {inc.get('alert_count', 0)}",
        f"source hosts: {', '.join(inc.get('hosts', [])[:6]) or 'none'}",
        f"accounts: {', '.join(inc.get('users', [])[:8]) or 'none'}",
        f"rules fired: {fired}",
        f"first seen: {str(inc.get('first_seen'))[:19]}",
    ]
    facts = inc.get("auth_facts") or {}
    for k, v in facts.items():
        lines.append(f"{k}: {v}")
    return "\n".join(lines)


PROMPTS: dict[str, Any] = {}
# Prompts that ignore the retrieved knowledge. Pairing these with four
# retrievers would run the same prompt four times and report the differences as
# if retrieval had caused them.
PROMPTS_WITHOUT_RAG: set[str] = set()


def prompt(name: str, uses_rag: bool = True):
    def wrap(fn):
        PROMPTS[name] = fn
        if not uses_rag:
            PROMPTS_WITHOUT_RAG.add(name)
        return fn
    return wrap


@prompt("p1_minimal", uses_rag=False)
def _p1(inc, knowledge):
    """No role, no rules, no knowledge. The control arm: everything else has to
    beat answering cold."""
    return (
        "You are a security analyst. Decide whether this is a real attack.",
        f"{_evidence_block(inc)}\n\nReply with JSON only: {SCHEMA}",
    )


@prompt("p2_soc_role", uses_rag=False)
def _p2(inc, knowledge):
    """Role and output contract, still no retrieval — isolates how much the
    role framing alone is worth."""
    return (
        "You are a Tier-1 SOC analyst triaging authentication telemetry. "
        "Decide ESCALATE only when the evidence shows adversary behaviour, "
        "SUPPRESS when it is consistent with ordinary enterprise activity, and "
        "UNKNOWN when the evidence cannot settle it. Reply with JSON only.",
        f"{_evidence_block(inc)}\n\nSchema: {SCHEMA}",
    )


@prompt("p3_auth_grounded")
def _p3(inc, knowledge):
    """Role + retrieved knowledge + explicit base-rate warning.

    The base-rate line matters more here than any other instruction: on this
    network roughly one authentication in 1.5 million is hostile, and a model
    that has not been told so treats every unusual login as an intrusion.
    """
    kb = _format_knowledge(knowledge)
    return (
        "You are a Tier-1 SOC analyst triaging Windows authentication "
        "telemetry from a large enterprise network.\n"
        "Ground rules:\n"
        "- Roughly 1 authentication in 1.5 million on this network is hostile. "
        "Unusual is not the same as malicious; most anomalies are ordinary "
        "operations.\n"
        "- Cite a technique id only if it appears in the knowledge below. "
        "Never from memory.\n"
        "- Quote the specific fields that decided it.\n"
        "- SUPPRESS is a real answer and the common one. Say UNKNOWN only when "
        "the evidence genuinely cannot settle it.\n"
        "- JSON only, no prose.",
        f"KNOWLEDGE\n{kb}\n\nEVIDENCE\n{_evidence_block(inc)}\n\nSchema: {SCHEMA}",
    )


@prompt("p4_auth_graph")
def _p4(inc, knowledge):
    """p3 plus the lateral-movement shape to look for.

    Names what an authentication-graph intrusion looks like — one source
    reaching many destinations, one account appearing on hosts it has no reason
    to touch — because that pattern, not any single event, is the signal in
    this data.
    """
    kb = _format_knowledge(knowledge)
    return (
        "You are a Tier-1 SOC analyst triaging Windows authentication "
        "telemetry from a large enterprise network.\n"
        "What an intrusion looks like in authentication data:\n"
        "- one source host authenticating to many destinations in a short "
        "window (lateral movement)\n"
        "- one account appearing on hosts it has no operational reason to "
        "touch\n"
        "- credential reuse fanning outward from a single foothold\n"
        "- authentication succeeding where the account has no history\n"
        "What ordinary operations look like:\n"
        "- machine accounts ($-suffixed) authenticating constantly\n"
        "- service accounts touching many hosts as their steady baseline\n"
        "- NTLM alongside Kerberos, which is normal on mixed estates and is "
        "not on its own evidence of anything\n"
        "Ground rules:\n"
        "- Roughly 1 authentication in 1.5 million here is hostile. Unusual is "
        "not malicious.\n"
        "- Cite a technique id only if it appears in the knowledge below.\n"
        "- Quote the specific fields that decided it.\n"
        "- JSON only, no prose.",
        f"KNOWLEDGE\n{kb}\n\nEVIDENCE\n{_evidence_block(inc)}\n\nSchema: {SCHEMA}",
    )


@prompt("p5_cost_aware")
def _p5(inc, knowledge):
    """p4 plus what each mistake costs.

    A missed intrusion and a wasted hour are not symmetric, and the model has
    no way to know the exchange rate unless it is told.
    """
    kb = _format_knowledge(knowledge)
    return (
        "You are a Tier-1 SOC analyst triaging Windows authentication "
        "telemetry from a large enterprise network.\n"
        "The cost of each mistake:\n"
        "- Escalating ordinary activity wastes about 8 analyst-minutes. At this "
        "volume, escalating even 1% of incidents buries the team and real "
        "alerts get missed underneath.\n"
        "- Missing a real intrusion lets an adversary spread. Weigh a genuine "
        "lateral-movement signal far above the cost of a wasted hour.\n"
        "- So: escalate on a coherent attack pattern, not on a single odd "
        "event.\n"
        "What an intrusion looks like here: one source reaching many "
        "destinations; one account on hosts it has no reason to touch; "
        "credential reuse fanning out from one foothold.\n"
        "What is ordinary: machine accounts ($-suffixed) authenticating "
        "constantly; service accounts with broad steady reach; NTLM alongside "
        "Kerberos on a mixed estate.\n"
        "Ground rules: cite technique ids only from the knowledge below; quote "
        "the fields that decided it; JSON only.",
        f"KNOWLEDGE\n{kb}\n\nEVIDENCE\n{_evidence_block(inc)}\n\nSchema: {SCHEMA}",
    )


def _format_knowledge(chunks: list[dict[str, Any]]) -> str:
    if not chunks:
        return "(nothing retrieved)"
    out = []
    for c in chunks:
        text = (c.get("text") or "")[:600].replace("\n", " ")
        out.append(f"[{c['id']}] {c.get('title', '')}: {text}")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Retrieval variants
# ---------------------------------------------------------------------------

RETRIEVERS: dict[str, Callable] = {}


def retriever(name: str):
    def wrap(fn):
        RETRIEVERS[name] = fn
        return fn
    return wrap


@retriever("r0_none")
def _r0(kb, inc, top_k=4):
    """Control arm. Whatever retrieval is worth, it has to beat this."""
    return []


@retriever("r1_rule_names")
def _r1(kb, inc, top_k=4):
    """Query with the fired rule names — what the system already does."""
    terms = [r.get("rule", "") for r in inc.get("rules_fired", [])]
    return kb.search_structured(terms=[t for t in terms if t], top_k=top_k) or []


@retriever("r2_auth_terms")
def _r2(kb, inc, top_k=4):
    """Query with authentication concepts rather than rule titles.

    A rule called 'Source Host Fan-Out' retrieves poorly because the corpus
    does not use that phrase; 'lateral movement remote services' does.
    """
    terms = ["lateral movement", "remote services", "valid accounts",
             "credential access"]
    facts = inc.get("auth_facts") or {}
    if facts.get("distinct_destinations", 0) > 5:
        terms.append("one source authenticating to many hosts")
    if facts.get("distinct_accounts", 0) > 3:
        terms.append("credential reuse across accounts")
    if str(facts.get("auth_types", "")).upper().find("NTLM") >= 0:
        terms.append("NTLM authentication pass the hash")
    return kb.search_structured(terms=terms, top_k=top_k) or []


@retriever("r3_hybrid")
def _r3(kb, inc, top_k=4):
    """Rule names and auth concepts fused, deduplicated by chunk id."""
    seen, out = set(), []
    for fn in (_r2, _r1):
        for c in fn(kb, inc, top_k=top_k):
            if c["id"] not in seen:
                seen.add(c["id"])
                out.append(c)
    return out[:top_k]


# ---------------------------------------------------------------------------
# Non-LLM baseline
# ---------------------------------------------------------------------------

def logistic_baseline(incidents: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Logistic regression on the incident features, as a control.

    The published work on this task (Expert Systems with Applications, 2026)
    found a Linear SVM beating every LLM tested on F1 for SOC alert
    classification. An LLM result with no simple baseline beside it cannot be
    read: if plain logistic regression on six numeric features matches the
    model, the model is not earning its 9 seconds and 28GB of GPU.

    Trained on DEV and scored on TEST, the same split the prompts use, so the
    comparison is like for like.
    """
    try:
        from sklearn.linear_model import LogisticRegression
    except ImportError:
        return None

    def features(inc: dict[str, Any]) -> list[float]:
        f = inc.get("auth_facts") or {}
        return [
            float(f.get("distinct_destinations", 0) or 0),
            float(f.get("distinct_accounts", 0) or 0),
            float(f.get("distinct_source_hosts", 0) or 0),
            float(f.get("failed_authentications", 0) or 0),
            float(f.get("machine_accounts", 0) or 0),
            float(f.get("destinations_per_source", 0) or 0),
            float(inc.get("alert_count", 0) or 0),
            float(len(inc.get("rules_fired", []) or [])),
        ]

    dev = [i for i in incidents if i["_split"] == "dev"]
    test = [i for i in incidents if i["_split"] == "test"]
    if not dev or not test:
        return None
    if len({i["_malicious"] for i in dev}) < 2:
        return None

    model = LogisticRegression(max_iter=2000, class_weight="balanced")
    model.fit([features(i) for i in dev], [int(i["_malicious"]) for i in dev])

    out: dict[str, Any] = {}
    for name, rows in (("dev", dev), ("test", test)):
        pred = model.predict([features(i) for i in rows])
        m = Metrics()
        for i, yhat in zip(rows, pred):
            truth = bool(i["_malicious"])
            if yhat and truth: m.tp += 1
            elif yhat: m.fp += 1
            elif truth: m.fn += 1
            else: m.tn += 1
        out[name] = m.to_dict()
    out["features"] = [
        "distinct_destinations", "distinct_accounts", "distinct_source_hosts",
        "failed_authentications", "machine_accounts", "destinations_per_source",
        "alert_count", "rules_fired",
    ]
    out["note"] = (
        "Trained on DEV, scored on TEST. If the LLM does not clearly beat this, "
        "the honest architecture is statistics for classification and the model "
        "for explanation."
    )
    return out


# ---------------------------------------------------------------------------
# Incident preparation
# ---------------------------------------------------------------------------

def auth_facts(inc: dict[str, Any], df) -> dict[str, Any]:
    """Summarise the authentication shape of an incident.

    The agent cannot read thousands of rows, and in this data the shape IS the
    signal: how far one source reached, how many accounts moved with it,
    whether anything failed.

    Column names are taken from lanl_eval._to_event, not guessed. An earlier
    version queried host/dest_host/auth_type/outcome — none of which exist in
    that schema — so every incident arrived at the model with no
    authentication evidence whatsoever, and the whole comparison would have
    been measuring nothing.
    """
    rows = sorted(set(inc.get("member_row_indices") or []))
    if not rows:
        return {}
    present = [r for r in rows if r in df.index]
    if not present:
        return {}
    sub = df.loc[present]
    if sub.empty:
        return {}

    def uniq(col: str) -> list[str]:
        if col not in sub.columns:
            return []
        return [str(v) for v in sub[col].dropna().unique().tolist() if str(v)]

    sources = uniq("source_ip")        # LANL src computer
    dests = uniq("computer")           # LANL dst computer
    accounts = uniq("user")
    targets = uniq("target_user")
    auth_types = uniq("_auth_type")
    orientations = uniq("_orientation")
    logon_types = uniq("logon_type")

    failures = int((sub["event_id"] == "4625").sum()) if "event_id" in sub.columns else 0

    facts: dict[str, Any] = {
        "distinct_source_hosts": len(sources),
        "distinct_destinations": len(dests),
        "distinct_accounts": len(accounts),
        "failed_authentications": failures,
        "successful_authentications": len(sub) - failures,
    }
    if sources: facts["source_hosts"] = ", ".join(sources[:6])
    if dests: facts["destinations_reached"] = ", ".join(dests[:10])
    if accounts: facts["accounts_used"] = ", ".join(accounts[:10])
    if targets: facts["target_accounts"] = ", ".join(targets[:8])
    if auth_types: facts["auth_types"] = ", ".join(auth_types[:6])
    if orientations: facts["orientations"] = ", ".join(orientations[:6])
    if logon_types: facts["logon_types"] = ", ".join(logon_types[:6])
    facts["machine_accounts"] = sum(1 for a in accounts if a.endswith("$"))

    # The fan-out ratio is what separates a foothold spreading from a busy
    # service account: both touch many hosts, but only one does it from a
    # single source with credentials that have no history there.
    if sources and dests:
        facts["destinations_per_source"] = round(len(dests) / len(sources), 1)
    return facts


def split_of(incident_id: str) -> str:
    """Deterministic DEV/TEST assignment.

    Hashed from the id, so the split is identical on every run and cannot be
    reshuffled until it produces a nicer number.
    """
    h = int(hashlib.sha256(incident_id.encode()).hexdigest()[:8], 16)
    return "dev" if (h % 100) < DEV_FRACTION * 100 else "test"


def prepare(sample_path: Path, max_benign: int, seed: int = 1337):
    import pandas as pd
    from funnel import TriageFunnel

    cached = json.loads(sample_path.read_text())
    events, stats = cached["events"], cached["stats"]
    df = pd.DataFrame(events)
    print(f"[+] {len(df):,} events restored from cache", flush=True)

    t0 = time.time()
    funnel = TriageFunnel(ai_budget=10_000)
    outcome = funnel.run(df)
    print(f"[+] funnel: {len(outcome.incidents)} incidents in {time.time()-t0:.0f}s",
          flush=True)

    red_rows = set(df.index[df["_label"] == 1])
    labelled = []
    for inc in outcome.incidents:
        rows = set(inc.get("member_row_indices") or [])
        for a in inc.get("sample_alerts", []):
            if a.get("_row_index") is not None:
                rows.add(a["_row_index"])
        inc["_malicious"] = bool(rows & red_rows)
        inc["_split"] = split_of(inc["incident_id"])
        inc["auth_facts"] = auth_facts(inc, df)
        labelled.append(inc)

    mal = [i for i in labelled if i["_malicious"]]
    ben = [i for i in labelled if not i["_malicious"]]
    print(f"[+] {len(mal)} malicious incidents, {len(ben):,} benign", flush=True)

    # Every malicious incident is kept: the positive class is small and
    # discarding any of it would leave nothing to measure. Benign incidents are
    # subsampled for runtime, and operational_cost() scales back to the true
    # mix so the staffing figure stays honest.
    rng = random.Random(seed)
    rng.shuffle(ben)
    evaluated = mal + ben[:max_benign]
    rng.shuffle(evaluated)
    return evaluated, len(labelled), stats


# ---------------------------------------------------------------------------
# Running one configuration
# ---------------------------------------------------------------------------

@dataclass
class RunResult:
    config: str
    split: str
    metrics: Metrics = field(default_factory=Metrics)
    calibration: dict = field(default_factory=dict)
    parse_failures: int = 0
    calls: int = 0
    citations: int = 0
    ungrounded: int = 0
    latencies: list[float] = field(default_factory=list)
    cases: list[dict] = field(default_factory=list)


def run_config(prompt_name: str, retriever_name: str, incidents: list[dict],
               split: str, backend, kb, top_k: int = 4,
               verbose: bool = False, batch_size: int = 8) -> RunResult:
    import prompts as prompt_mod

    build = PROMPTS[prompt_name]
    retrieve = RETRIEVERS[retriever_name]
    res = RunResult(config=f"{prompt_name}+{retriever_name}", split=split)
    conf_points: list[tuple[float, int]] = []

    subset = [i for i in incidents if i["_split"] == split]

    # Retrieval first, for the whole subset, then one batched generation pass.
    prepared = []
    for inc in subset:
        knowledge = retrieve(kb, inc, top_k) if kb else []
        prepared.append((inc, knowledge, build(inc, knowledge)))

    t0 = time.time()
    if hasattr(backend, "generate_batch"):
        try:
            raws = backend.generate_batch(
                [pr for _, _, pr in prepared], max_tokens=320, batch_size=batch_size)
        except Exception as exc:  # noqa: BLE001
            print(f"    [!] batch failed ({exc}); falling back one at a time",
                  flush=True)
            raws = None
    else:
        raws = None
    if raws is None:
        raws = []
        for _, _, (system, user) in prepared:
            try:
                raws.append(backend.generate_text(
                    system=system, user=user, max_tokens=320))
            except Exception as exc:  # noqa: BLE001
                print(f"    [!] model error: {exc}", flush=True)
                raws.append("")
    per_case = (time.time() - t0) / max(1, len(prepared))

    for n, ((inc, knowledge, _), raw) in enumerate(zip(prepared, raws), 1):
        res.latencies.append(per_case)
        res.calls += 1
        if not raw:
            res.parse_failures += 1
            continue

        try:
            payload = prompt_mod.extract_json(raw)
        except Exception:  # noqa: BLE001
            res.parse_failures += 1
            continue

        call = str(payload.get("verdict", "")).upper()
        truth = bool(inc["_malicious"])

        # Citations are checked against what retrieval actually returned; a
        # technique named from memory is ungrounded however plausible it is.
        retrieved_ids = {c["id"] for c in knowledge}
        cited = [str(x) for x in (payload.get("sources") or [])]
        res.citations += len(cited)
        res.ungrounded += sum(1 for c in cited if c not in retrieved_ids)

        if call == "ESCALATE":
            if truth: res.metrics.tp += 1
            else: res.metrics.fp += 1
        elif call == "SUPPRESS":
            if truth: res.metrics.fn += 1
            else: res.metrics.tn += 1
        else:
            # UNKNOWN is an abstention, not a prediction. Counting it as a
            # SUPPRESS would credit the agent for answers it declined to give.
            res.metrics.abstained += 1
            res.metrics.abstained_malicious += int(truth)
            continue

        try:
            conf = float(payload.get("confidence"))
            correct = int((call == "ESCALATE") == truth)
            conf_points.append((max(0.0, min(1.0, conf)), correct))
        except (TypeError, ValueError):
            pass

        res.cases.append({
            "incident_id": inc["incident_id"], "malicious": truth,
            "verdict": call, "confidence": payload.get("confidence"),
            "reason": str(payload.get("reason", ""))[:200],
            "sources": cited,
        })
        if verbose and n % 10 == 0:
            print(f"    {n}/{len(subset)}", flush=True)

    res.calibration = brier_and_ece(conf_points)
    return res


def summarise(res: RunResult, incidents_total: int, days: float) -> dict[str, Any]:
    m = res.metrics
    evaluated = m.tp + m.fp + m.tn + m.fn + m.abstained
    lat = sorted(res.latencies)
    return {
        "config": res.config,
        "split": res.split,
        "metrics": m.to_dict(),
        "calibration": res.calibration,
        "operational": operational_cost(m, incidents_total, evaluated, days),
        "grounding": {
            "citations": res.citations,
            "ungrounded": res.ungrounded,
            "rate": round(1 - res.ungrounded / res.citations, 4) if res.citations else None,
        },
        "reliability": {
            "calls": res.calls,
            "parse_failures": res.parse_failures,
            "parse_failure_rate": round(res.parse_failures / res.calls, 4) if res.calls else None,
        },
        "latency_seconds": {
            "p50": round(statistics.median(lat), 1) if lat else None,
            "p95": round(lat[int(len(lat) * 0.95)], 1) if len(lat) >= 20 else None,
            "mean": round(statistics.mean(lat), 1) if lat else None,
        },
    }


def print_row(s: dict[str, Any]) -> None:
    m, g = s["metrics"], s["grounding"]
    f = lambda v: "  n/a" if v is None else f"{v:5.3f}"  # noqa: E731
    print(f"  {s['config']:28s} F1 {f(m['f1'])}  P {f(m['precision'])}  "
          f"R {f(m['recall'])}  MCC {f(m['mcc'])}  "
          f"bal {f(m['balanced_accuracy'])}  "
          f"absten {m['abstained']:3d}  ground {f(g['rate'])}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sample", type=Path, default=BASE_DIR / "lanl_sample.json")
    ap.add_argument("--config", help="prompt+retriever, e.g. p3_auth_grounded+r2_auth_terms")
    ap.add_argument("--sweep", action="store_true", help="every combination on DEV")
    ap.add_argument("--final", action="store_true",
                    help="run --config against the locked TEST split, once")
    ap.add_argument("--max-benign", type=int, default=120,
                    help="benign incidents to evaluate (positives are always all kept)")
    ap.add_argument("--top-k", type=int, default=4)
    ap.add_argument("--batch-size", type=int, default=8,
                    help="prompts per batched generation call")
    ap.add_argument("--out", type=Path, default=BASE_DIR / "prompt_lab_results.json")
    ap.add_argument("--list", action="store_true", help="list variants and exit")
    # The funnel costs ~10 minutes on 200k events and is identical every run.
    ap.add_argument("--save-incidents", type=Path,
                    help="cache the labelled incidents after the funnel")
    ap.add_argument("--load-incidents", type=Path,
                    help="reuse cached incidents and skip the funnel")
    ap.add_argument("--dry-run", action="store_true",
                    help="prepare and report label counts, then stop")
    args = ap.parse_args()

    if args.list:
        print("prompts:   " + ", ".join(PROMPTS))
        print("retrievers:" + ", ".join(RETRIEVERS))
        return 0

    if not args.sample.exists():
        print(f"no cached sample at {args.sample}\n"
              f"create one with:\n"
              f"  python lanl_eval.py --auth ../auth.txt.gz --redteam ../redteam.txt.gz "
              f"--no-ai --save-sample {args.sample.name}")
        return 1

    if args.load_incidents and args.load_incidents.exists():
        blob = json.loads(args.load_incidents.read_text())
        incidents = blob["incidents"]
        incidents_total = blob["incidents_total"]
        stats = blob["stats"]
        print(f"[+] reusing cached incidents from {args.load_incidents}", flush=True)
    else:
        incidents, incidents_total, stats = prepare(args.sample, args.max_benign)
        if args.save_incidents:
            args.save_incidents.write_text(json.dumps(
                {"incidents": incidents, "incidents_total": incidents_total,
                 "stats": stats}, default=str))
            print(f"[+] incidents cached -> {args.save_incidents}", flush=True)
    # lanl_eval records the corpus span as span_days.
    days = max(1.0, stats.get("span_days") or 27.85)

    dev = [i for i in incidents if i["_split"] == "dev"]
    test = [i for i in incidents if i["_split"] == "test"]
    print(f"[+] evaluating {len(incidents)} incidents — "
          f"DEV {len(dev)} ({sum(i['_malicious'] for i in dev)} malicious), "
          f"TEST {len(test)} ({sum(i['_malicious'] for i in test)} malicious)",
          flush=True)

    if args.dry_run:
        print("\n[dry run] no model was called.")
        return 0

    from knowledge_base import get_kb
    from llm_backend import get_llm_backend
    backend = get_llm_backend()
    if backend is None:
        print("no LLM backend configured")
        return 1
    kb = get_kb()

    combos: list[tuple[str, str]] = []
    if args.sweep:
        # A prompt that never reads the knowledge block is run once, against
        # the null retriever. Running it four times would produce four
        # near-identical rows and invite reading noise as a retrieval effect.
        combos = [
            (p, r) for p in PROMPTS for r in RETRIEVERS
            if p not in PROMPTS_WITHOUT_RAG or r == "r0_none"
        ]
    elif args.config:
        if "+" in args.config:
            p, r = args.config.split("+", 1)
        else:
            p, r = args.config, "r3_hybrid"
        combos = [(p, r)]
    else:
        ap.error("give --config or --sweep")

    for p, r in combos:
        if p not in PROMPTS: ap.error(f"unknown prompt {p}; have {list(PROMPTS)}")
        if r not in RETRIEVERS: ap.error(f"unknown retriever {r}; have {list(RETRIEVERS)}")

    split = "test" if args.final else "dev"
    if args.final:
        if len(combos) != 1:
            ap.error("--final takes exactly one --config: the point is to touch "
                     "the locked split once, with the configuration DEV chose")
        print("\n*** FINAL RUN AGAINST THE LOCKED TEST SPLIT ***")
        print("This number is the result. A configuration chosen after seeing "
              "it is no longer measured on held-out data.\n")

    results = []
    for p, r in combos:
        print(f"[+] {p} + {r} on {split.upper()} "
              f"({len([i for i in incidents if i['_split'] == split])} incidents)",
              flush=True)
        res = run_config(p, r, incidents, split, backend, kb, args.top_k,
                         batch_size=args.batch_size)
        s = summarise(res, incidents_total, days)
        results.append({**s, "cases": res.cases})
        print_row(s)

    ranked = sorted(
        results,
        key=lambda s: (s["metrics"]["mcc"] if s["metrics"]["mcc"] is not None else -1),
        reverse=True)

    print("\n" + "=" * 78)
    print(f"  RANKED BY MCC — {split.upper()} split")
    print("=" * 78)
    for s in ranked:
        print_row(s)

    base = logistic_baseline(incidents)
    if base:
        b = base[split]
        print()
        print(f"  {'BASELINE logistic regression':28s} F1 "
              f"{'  n/a' if b['f1'] is None else format(b['f1'], '5.3f')}  "
              f"P {'  n/a' if b['precision'] is None else format(b['precision'], '5.3f')}  "
              f"R {'  n/a' if b['recall'] is None else format(b['recall'], '5.3f')}  "
              f"MCC {'  n/a' if b['mcc'] is None else format(b['mcc'], '5.3f')}")
        print("  (no model, no GPU — anything the LLM cannot beat here it has "
              "not earned)")

    best = ranked[0] if ranked else None
    payload = {
        "split": split,
        "dev_fraction": DEV_FRACTION,
        "incidents_evaluated": len(dev if split == "dev" else test),
        "incidents_total": incidents_total,
        "results": results,
        "best_by_mcc": best["config"] if best else None,
        "logistic_baseline": base,
        "caveat": (
            "DEV numbers are a development aid, not a result. Only a --final "
            "run against the TEST split, with a configuration chosen before "
            "seeing it, measures generalisation."
        ),
    }
    args.out.write_text(json.dumps(payload, indent=1, default=str))
    print(f"\n[+] {args.out}")
    if best and split == "dev":
        print(f"[+] best on DEV: {best['config']} — confirm with:\n"
              f"    python prompt_lab.py --config {best['config']} --final")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
