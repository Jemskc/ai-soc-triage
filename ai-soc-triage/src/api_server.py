"""FastAPI server — Qwen3-4B backed chat, log-search, and email-analyze endpoints."""

from __future__ import annotations

import json
import re
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from llm_backend import get_llm_backend
from ai_triage import triage_alert


def _engine_factory():
    """Built lazily: the autopilot only needs it once a case reaches an agent."""
    from ai_engine import AIEngine
    return AIEngine()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the model, then start continuous analysis.

    Both belong here rather than in an @app.on_event("startup") hook: FastAPI
    ignores on_event entirely once a lifespan is supplied, so a hook there
    silently never runs and the server comes up idle.
    """
    print("[+] Pre-loading model into GPU memory...")
    backend = get_llm_backend()
    if backend is not None:
        backend._load()
        print(f"[+] Model ready: {backend.model_label}")

    import autopilot as _ap
    pilot = _ap.get_autopilot(engine_factory=_engine_factory)
    pilot.start(watch_inbox=True)
    print(f"[+] Autopilot running — watching {_ap.INBOX_DIR}", flush=True)

    # Feed the resident telemetry in automatically. The whole point is that
    # analysis happens because logs exist, not because someone pressed a
    # button, so the system must not sit idle waiting to be told to start.
    import threading as _th

    def _seed() -> None:
        try:
            import pipeline as _pl
            df = _pl.load_corpus_dataframe()
            pilot.submit(df, origin="startup-corpus")
            print(f"[+] Auto-ingested {len(df):,} events — analysis started", flush=True)
        except Exception as exc:  # noqa: BLE001 — seeding must never block boot
            print(f"[!] Auto-ingest skipped: {exc}", flush=True)

    _th.Thread(target=_seed, daemon=True).start()

    yield

    pilot.stop()


app = FastAPI(title="SOC Triage AI", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────
# System prompts
# ─────────────────────────────────────────────────────────────

SOC_SYSTEM = (
    "You are an expert SOC analyst and security assistant with 10 years of experience in "
    "incident response, threat hunting, and digital forensics. "
    "Answer questions naturally and conversationally. "
    "You have access to the user's dashboard data — only reference it when the user asks about "
    "their dashboard, alerts, logs, or specific events in their environment. "
    "For greetings, general security questions, or anything not about the dashboard, "
    "respond normally without mentioning the dashboard data at all. "
    "Format lists with bullet points. Keep responses under 400 words unless detail is critical."
)

# The dashboard's tab ids are not the contract ids: the nav is organised around
# what an analyst does, the contracts around what the model produces. Mapped in
# one place so adding a tab means adding one line here, not hunting for
# branches scattered through the UI.
_NAV_TO_CONTRACT = {
    "logs": "logs",
    "alerts": "alerts",
    "ai": "investigations",
    "evidence": "evidence_graph",
    "response": "playbooks",
    "email": "email",
}

# What each tab shows, in the assistant's terms. The analyst_question comes
# from the contract registry so it can never drift from what the tab actually
# renders; this adds only what the screen looks like.
_TAB_SHOWS = {
    "logs": (
        "every raw parsed event, SIEM-style, with search and filters. Each row "
        "expands to all fields plus the original record, and has an 'Explain "
        "this event' button that runs a grounded lookup."
    ),
    "alerts": (
        "correlated incidents ordered by AI urgency, not by time. Each carries "
        "the agent's verdict, the evidence behind it, and the knowledge-base "
        "sources it was grounded in."
    ),
    "ai": (
        "the agent's reasoning trace for one incident: the hypothesis it "
        "started from, every tool call it made, what came back, and how it "
        "reached its verdict."
    ),
    "evidence": (
        "the entity graph for one incident — hosts, accounts, processes, "
        "techniques and the rules that fired — plus entities shared with other "
        "incidents, which is how a campaign becomes visible."
    ),
    "response": (
        "proposed containment and recovery actions, with the human approval "
        "gate. Nothing that changes production state is executed automatically."
    ),
    "email": (
        "phishing assessment: authentication results, indicators with reasons, "
        "and the ATT&CK techniques retrieved to support the verdict."
    ),
    "settings": "configuration, ingestion, detection metrics and the audit trail.",
}


def _tab_briefing(nav_id: str) -> str:
    """Tell the assistant what the analyst is actually looking at."""
    nav_id = (nav_id or "").strip().lower()
    if not nav_id:
        return ""
    shows = _TAB_SHOWS.get(nav_id, "")
    lines = [f"The analyst is currently on the '{nav_id}' tab."]
    if shows:
        lines.append(f"That tab shows {shows}")
    contract_id = _NAV_TO_CONTRACT.get(nav_id)
    if contract_id:
        try:
            from tab_contracts import get_contract
            contract = get_contract(contract_id)
            lines.append(
                f"The question this tab exists to answer: {contract.analyst_question}"
            )
        except Exception:  # noqa: BLE001
            pass
    lines.append(
        "Answer about what is on this screen first — what it shows, how it was "
        "produced, when it ran and why it concluded what it did. Refer to "
        "incidents by their INC- id so the analyst can click through to them, "
        "and name specific hosts, accounts and rules rather than describing "
        "them in general terms. If the screen does not contain the answer, say "
        "so and name the tab that would."
    )
    # This path has no grounding check in code — unlike the verdict and enrich
    # paths, nothing here verifies a citation against what was retrieved. Asked
    # about an incident whose context listed `attack:T1021.002, attack:T1003`
    # as bare ids, the model paired them backwards and told the analyst
    # Mimikatz was T1021.002. Context now carries titles; this states the rule
    # as well, because a chat answer is acted on just like a verdict is.
    lines.append(
        "Only state an ATT&CK technique id that appears verbatim in the "
        "context above, and use the title given there for it — never pair an "
        "id with a technique name from memory. If a rule's technique is not in "
        "the context, name the rule and say the mapping is not shown rather "
        "than supplying an id."
    )
    return "\n".join(lines)


# Per-action token budgets — keeps each endpoint fast and prevents token starvation.
_ACTION_TOKEN_LIMITS: dict[str, int] = {
    # Alert actions
    "explain":       300,
    "investigate":   450,
    "ioc":           350,
    "fix":           400,
    # Log actions
    "log_explain":   350,
    "log_relate":    420,
    "log_iocs":      300,
    "log_mitre":     350,
    # Email actions
    "email_explain": 350,
    "email_iocs":    300,
    "email_headers": 350,
    "email_draft":   280,
    # Free-form chat
    "chat":          650,
}

# ─────────────────────────────────────────────────────────────
# Alert action prompts
# ─────────────────────────────────────────────────────────────

def _build_alert_prompt(action: str, alert: dict[str, Any]) -> str:
    ip   = alert.get("sourceIP") or alert.get("source_ip", "Unknown")
    user = alert.get("user", "Unknown")
    host = alert.get("host") or alert.get("computer", "Unknown")
    rule = alert.get("rule") or alert.get("rule_name", "Unknown")
    sev  = alert.get("severity", "Unknown")
    msg  = alert.get("message") or alert.get("description", "")
    dest = alert.get("destIP") or alert.get("dest_ip", "Unknown")

    if action == "explain":
        return (
            f"Explain this security alert to a SOC analyst. Be clear and actionable.\n\n"
            f"Rule: {rule}\nSeverity: {sev}\nSource IP: {ip}\nUser: {user}\n"
            f"Host: {host}\nMessage: {msg}\n\n"
            "Provide: what happened, why it matters, and the MITRE ATT&CK technique."
        )
    if action == "investigate":
        return (
            f"Provide a step-by-step investigation plan for this alert.\n\n"
            f"Rule: {rule}\nSource IP: {ip}\nUser: {user}\nHost: {host}\nMessage: {msg}\n\n"
            "List 6-8 concrete investigation steps referencing the specific IPs, users, and hosts above."
        )
    if action == "ioc":
        return (
            f"Extract and list all Indicators of Compromise (IOCs) from this alert.\n\n"
            f"Source IP: {ip}\nDest IP: {dest}\nUser: {user}\nHost: {host}\n"
            f"Rule: {rule}\nMessage: {msg}\n\n"
            "Format as a structured IOC list with type, value, and recommended action for each."
        )
    if action == "fix":
        return (
            f"Provide remediation steps for this security alert.\n\n"
            f"Rule: {rule}\nSeverity: {sev}\nSource IP: {ip}\nUser: {user}\n"
            f"Host: {host}\nMessage: {msg}\n\n"
            "Cover: immediate containment, short-term hardening, long-term prevention."
        )
    return ""


# ─────────────────────────────────────────────────────────────
# Log event action prompts
# ─────────────────────────────────────────────────────────────

def _build_log_prompt(action: str, log: dict[str, Any]) -> str:
    rule    = log.get("rule", "Unknown")
    sev     = log.get("severity", "Unknown")
    src_ip  = log.get("sourceIP", "Unknown")
    dest_ip = log.get("destIP", "Unknown")
    user    = log.get("user", "Unknown")
    host    = log.get("host", "Unknown")
    source  = log.get("source", "Unknown")
    msg     = log.get("message", "")
    ts      = log.get("timestamp", "")

    if action == "log_explain":
        return (
            f"Explain this security log event to a SOC analyst.\n\n"
            f"Rule: {rule}\nSeverity: {sev}\nTimestamp: {ts}\nLog Source: {source}\n"
            f"Source IP: {src_ip}\nDest IP: {dest_ip}\nUser: {user}\nHost: {host}\n"
            f"Message: {msg}\n\n"
            "Provide: (1) what exactly happened in plain English, (2) why it is significant, "
            "(3) whether this is likely a true positive or false positive, "
            "(4) MITRE ATT&CK technique ID and name."
        )
    if action == "log_relate":
        return (
            f"Suggest investigation pivots to find events related to this log entry.\n\n"
            f"Rule: {rule}\nSource IP: {src_ip}\nUser: {user}\nHost: {host}\nMessage: {msg}\n\n"
            "List 5-6 specific pivot points and what to look for in each. "
            "Reference the actual IP address, username, and hostname above. "
            "Include: lateral movement checks, persistence checks, and data exfiltration indicators."
        )
    if action == "log_iocs":
        return (
            f"Extract all Indicators of Compromise (IOCs) from this log event.\n\n"
            f"Source IP: {src_ip}\nDest IP: {dest_ip}\nUser: {user}\nHost: {host}\n"
            f"Rule: {rule}\nMessage: {msg}\n\n"
            "For each IOC provide: type, value, severity rating, and recommended action "
            "(block, enrich with threat intel, monitor, or escalate). "
            "Include how to search for this IOC in other log sources."
        )
    if action == "log_mitre":
        return (
            f"Provide detailed MITRE ATT&CK mapping for this log event.\n\n"
            f"Rule: {rule}\nMessage: {msg}\nSource IP: {src_ip}\nUser: {user}\n\n"
            "Include: tactic, technique ID, sub-technique if applicable, "
            "procedure example matching this event, detection opportunities, "
            "and the top 2 relevant ATT&CK mitigations with their IDs."
        )
    return ""


# ─────────────────────────────────────────────────────────────
# Email action prompts
# ─────────────────────────────────────────────────────────────

def _build_email_prompt(action: str, email: dict[str, Any]) -> str:
    subject     = email.get("subject", "(No Subject)")
    from_       = email.get("from", "")
    to          = email.get("to", "")
    date        = email.get("date", "")
    spf         = email.get("spf", "none")
    dkim        = email.get("dkim", "none")
    dmarc       = email.get("dmarc", "none")
    risk_score  = email.get("riskScore", 0)
    risk_label  = email.get("riskLabel", "Unknown")
    origin_ip   = email.get("originIP", "")
    reply_to    = email.get("replyTo", "")
    urls        = email.get("urls", [])
    attachments = email.get("attachments", [])

    def _url_str(u):
        if isinstance(u, dict):
            return f"{u.get('url', '')} [{u.get('risk', 'External')}]"
        return str(u)

    def _att_str(a):
        if isinstance(a, dict):
            return f"{a.get('filename', '')} [{a.get('riskLevel', 'LOW')}]"
        return str(a)

    url_list  = "\n".join(f"  - {_url_str(u)}" for u in urls[:10]) or "  None"
    att_list  = "\n".join(f"  - {_att_str(a)}" for a in attachments) or "  None"

    if action == "email_explain":
        return (
            f"Analyze this email for phishing and social engineering threats.\n\n"
            f"Subject: {subject}\nFrom: {from_}\nTo: {to}\nDate: {date}\n"
            f"SPF: {spf.upper()}\nDKIM: {dkim.upper()}\nDMARC: {dmarc.upper()}\n"
            f"Risk Score: {risk_score}/100 ({risk_label})\nOrigin IP: {origin_ip or 'Unknown'}\n"
            f"Reply-To: {reply_to or 'Same as From'}\n"
            f"URLs ({len(urls)}):\n{url_list}\nAttachments:\n{att_list}\n\n"
            "Provide: (1) threat verdict (Malicious/Suspicious/Benign) with confidence, "
            "(2) the specific attack technique (credential phishing, malware delivery, BEC, etc.), "
            "(3) top 3 risk indicators found, "
            "(4) recommended immediate action."
        )
    if action == "email_iocs":
        return (
            f"Extract all Indicators of Compromise (IOCs) from this suspicious email.\n\n"
            f"Sender: {from_}\nReply-To: {reply_to or 'Same as From'}\n"
            f"Origin IP: {origin_ip or 'Unknown'}\n"
            f"URLs:\n{url_list}\nAttachments:\n{att_list}\n\n"
            "For each IOC: type (IP/domain/URL/email/file), exact value, "
            "threat classification, and recommended action (block at firewall/proxy/email gateway, "
            "submit to VirusTotal, etc.)."
        )
    if action == "email_headers":
        spf_detail  = "sender authorized" if spf == "pass" else ("CRITICAL: unauthorized sender" if spf == "fail" else "no record")
        dkim_detail = "integrity verified" if dkim == "pass" else ("CRITICAL: signature invalid" if dkim == "fail" else "not signed")
        dmarc_detail= "policy compliant" if dmarc == "pass" else ("CRITICAL: policy violated" if dmarc == "fail" else "no policy")
        mismatch    = reply_to and reply_to != from_
        return (
            f"Analyze the email authentication headers and identify spoofing techniques.\n\n"
            f"From: {from_}\nReply-To: {reply_to or 'Same as From'}\n"
            f"SPF: {spf.upper()} — {spf_detail}\n"
            f"DKIM: {dkim.upper()} — {dkim_detail}\n"
            f"DMARC: {dmarc.upper()} — {dmarc_detail}\n"
            f"Origin IP: {origin_ip or 'Unknown'}\n"
            f"Reply-To mismatch: {'YES — replies go to a different domain' if mismatch else 'No'}\n\n"
            "Explain: (1) what each authentication result means in plain terms, "
            "(2) whether this is a spoofed or legitimate email, "
            "(3) the likely spoofing/evasion technique used, "
            "(4) how to confirm the sender's true identity."
        )
    if action == "email_draft":
        findings = []
        if spf   == "fail": findings.append("SPF authentication failed")
        if dkim  == "fail": findings.append("DKIM signature invalid")
        if dmarc == "fail": findings.append("DMARC policy violation")
        if reply_to and reply_to != from_: findings.append("Reply-To domain mismatch")
        bad_urls = [u for u in urls if (isinstance(u, dict) and u.get("risk") != "External") or (isinstance(u, str) and any(p in u for p in ["bit.ly","tinyurl","login","verify"]))]
        if bad_urls: findings.append(f"{len(bad_urls)} suspicious URL(s) detected")
        return (
            f"Draft a professional internal SOC analyst note for this reviewed email.\n\n"
            f"Subject: {subject}\nFrom: {from_}\nDate: {date}\n"
            f"Risk Classification: {risk_label} ({risk_score}/100)\n"
            f"Key Findings: {', '.join(findings) if findings else 'None'}\n\n"
            "Write a structured analyst note under 200 words with sections: "
            "Summary, Key Findings (bullet list), Verdict, Recommended Action. "
            "Use professional SOC language. Include specific sender info and risk factors."
        )
    return ""


# ─────────────────────────────────────────────────────────────
# Request / response models
# ─────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str = ""
    action: str = "chat"
    alert: dict[str, Any] = {}
    log: dict[str, Any] = {}
    email: dict[str, Any] = {}
    history: list[dict[str, Any]] = []
    dashboard_context: str = ""
    # Which dashboard tab the analyst is looking at. The assistant is asked
    # about what is on screen far more often than about the product in the
    # abstract, and without this it cannot tell the Evidence Graph from the
    # Phishing tab.
    active_tab: str = ""


class LogSearchRequest(BaseModel):
    query: str
    logs_sample: list[dict[str, Any]] = []
    match_count: int = 0


class EmailAnalyzeRequest(BaseModel):
    email: dict[str, Any]


class AnalyzeRequest(BaseModel):
    alert: dict[str, Any]


# ─────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    backend = get_llm_backend()
    model = backend.model_label if backend else "none"
    short = model.split("/")[-1] if "/" in model else model
    return {
        "status": "ok",
        "model": model,
        "model_short": short,
        "model_loaded": backend._loaded if backend else False,
    }


def _resolve_chat_request(req: ChatRequest) -> tuple[str, int, list[dict]]:
    """Return (user_message, max_tokens, api_history) from a ChatRequest."""
    action = req.action.lower()

    if action in ("explain", "investigate", "ioc", "fix") and req.alert:
        user_message = _build_alert_prompt(action, req.alert)
    elif action in ("log_explain", "log_relate", "log_iocs", "log_mitre") and req.log:
        user_message = _build_log_prompt(action, req.log)
    elif action in ("email_explain", "email_iocs", "email_headers", "email_draft") and req.email:
        user_message = _build_email_prompt(action, req.email)
    else:
        ctx_prefix = ""
        if req.log:
            ctx_prefix = (
                f"[Log context — Rule: {req.log.get('rule','?')}, "
                f"IP: {req.log.get('sourceIP','?')}, User: {req.log.get('user','?')}, "
                f"Host: {req.log.get('host','?')}, Severity: {req.log.get('severity','?')}]\n\n"
            )
        elif req.email:
            ctx_prefix = (
                f"[Email context — Subject: {req.email.get('subject','?')}, "
                f"From: {req.email.get('from','?')}, "
                f"Risk: {req.email.get('riskLabel','?')} ({req.email.get('riskScore',0)}/100)]\n\n"
            )
        elif req.alert:
            ctx_prefix = (
                f"[Alert context — Rule: {req.alert.get('rule','?')}, "
                f"IP: {req.alert.get('sourceIP','?')}, Severity: {req.alert.get('severity','?')}]\n\n"
            )
        user_message = ctx_prefix + (req.message or "Hello")

    max_tokens = _ACTION_TOKEN_LIMITS.get(action, 650)
    api_history = [
        {"role": h["role"], "content": h["content"]}
        for h in req.history
        if h.get("role") in ("user", "assistant")
    ]

    system = SOC_SYSTEM
    if briefing := _tab_briefing(req.active_tab):
        system += f"\n\n{briefing}"
    if req.dashboard_context:
        system += f"\n\nCurrent dashboard state:\n{req.dashboard_context}"

    return user_message, max_tokens, api_history, system


@app.post("/chat")
def chat(req: ChatRequest):
    backend = get_llm_backend()
    if backend is None:
        return {"response": "No LLM backend configured. Set LOCAL_MODEL_NAME in .env.", "error": True}
    try:
        user_message, max_tokens, api_history, system = _resolve_chat_request(req)
        response = backend.generate_text(
            system=system,
            user=user_message,
            max_tokens=max_tokens,
            history=api_history,
        )
        return {"response": response}
    except Exception as exc:
        return {"response": f"Model error: {exc}", "error": True}


@app.post("/chat-stream")
def chat_stream(req: ChatRequest):
    """Streaming version of /chat — returns SSE tokens as they are generated."""
    backend = get_llm_backend()

    if backend is None:
        def _err():
            yield f"data: {json.dumps('No LLM backend configured.')}\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(_err(), media_type="text/event-stream")

    try:
        user_message, max_tokens, api_history, system = _resolve_chat_request(req)
    except Exception as exc:
        def _err():
            yield f"data: {json.dumps(f'Request error: {exc}')}\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(_err(), media_type="text/event-stream")

    def token_gen():
        try:
            for chunk in backend.generate_stream(system, user_message, max_tokens, api_history):
                if chunk:
                    yield f"data: {json.dumps(chunk)}\n\n"
        except Exception as exc:
            yield f"data: {json.dumps(f'Model error: {exc}')}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(token_gen(), media_type="text/event-stream")


@app.post("/log-search")
def log_search(req: LogSearchRequest):
    """Natural language analysis of a log search result — used by LogsExplorer AI banner."""
    backend = get_llm_backend()
    if backend is None:
        return {"explanation": "AI backend not configured.", "error": True}

    try:
        sample_text = ""
        if req.logs_sample:
            lines = []
            for l in req.logs_sample[:10]:
                lines.append(
                    f"  [{l.get('severity','?')}] {l.get('rule','?')} | "
                    f"IP:{l.get('sourceIP','?')} User:{l.get('user','?')} "
                    f"Host:{l.get('host','?')} | {str(l.get('message',''))[:80]}"
                )
            sample_text = "\n".join(lines)

        prompt = (
            f"A SOC analyst searched for: \"{req.query}\"\n"
            f"The search matched {req.match_count} log events.\n"
            f"Representative samples:\n{sample_text or '  (no samples)'}\n\n"
            "In 2-3 sentences, describe what this data reveals about the security situation. "
            "Highlight patterns, key threat indicators, and the most important finding. "
            "Be direct, specific, and reference actual IPs/users/rules from the samples."
        )

        explanation = backend.generate_text(
            system=SOC_SYSTEM,
            user=prompt,
            max_tokens=150,
        )
        return {"explanation": explanation}

    except Exception as exc:
        return {"explanation": f"Analysis error: {exc}", "error": True}


@app.post("/email-analyze")
def email_analyze(req: EmailAnalyzeRequest):
    """Comprehensive AI threat assessment for the Email Analysis AI tab."""
    backend = get_llm_backend()
    if backend is None:
        return {"analysis": "AI backend not configured.", "error": True}

    try:
        email = req.email
        subject    = email.get("subject", "(No Subject)")
        from_      = email.get("from", "")
        date       = email.get("date", "")
        spf        = email.get("spf", "none")
        dkim       = email.get("dkim", "none")
        dmarc      = email.get("dmarc", "none")
        risk_score = email.get("riskScore", 0)
        risk_label = email.get("riskLabel", "Unknown")
        origin_ip  = email.get("originIP", "")
        reply_to   = email.get("replyTo", "")
        urls       = email.get("urls", [])
        attachments= email.get("attachments", [])
        body_text  = email.get("bodyText", "")

        suspicious_urls = [u for u in urls if isinstance(u, dict) and u.get("risk") != "External"]
        dangerous_att   = [a for a in attachments if isinstance(a, dict) and a.get("riskLevel") in ("CRITICAL", "HIGH")]

        url_lines = "\n".join(
            f"  - {u.get('url','')} [{u.get('risk','')}]" for u in suspicious_urls[:5]
        ) or "  None"
        att_lines = "\n".join(
            f"  - {a.get('filename','')} [{a.get('riskLevel','')}]" for a in dangerous_att
        ) or "  None"

        body_preview = (body_text or "")[:300].replace("\n", " ").strip()

        prompt = (
            f"Perform a comprehensive threat assessment of this email.\n\n"
            f"Subject: {subject}\nFrom: {from_}\nDate: {date}\n"
            f"SPF: {spf.upper()}\nDKIM: {dkim.upper()}\nDMARC: {dmarc.upper()}\n"
            f"Risk Score: {risk_score}/100 ({risk_label})\n"
            f"Origin IP: {origin_ip or 'Unknown'}\n"
            f"Reply-To: {reply_to or 'Same as From'}\n"
            f"Total URLs: {len(urls)} ({len(suspicious_urls)} suspicious)\n"
            f"Suspicious URLs:\n{url_lines}\n"
            f"High-risk Attachments:\n{att_lines}\n"
            f"Body preview: {body_preview or '(empty)'}\n\n"
            "Provide a structured assessment with:\n"
            "1. Verdict: Malicious / Suspicious / Benign (with confidence %)\n"
            "2. Attack technique (e.g. spear-phishing, BEC, malware dropper)\n"
            "3. Top threat indicators (bullet list, max 4)\n"
            "4. Recommended action (1-2 sentences)\n"
            "Keep total response under 280 words."
        )

        analysis = backend.generate_text(
            system=SOC_SYSTEM,
            user=prompt,
            max_tokens=400,
        )
        return {"analysis": analysis}

    except Exception as exc:
        return {"analysis": f"Analysis error: {exc}", "error": True}


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    try:
        result = triage_alert(req.alert)
        return {"analysis": result}
    except Exception as exc:
        return {"analysis": None, "error": str(exc)}


# ─────────────────────────────────────────────────────────────
# Analysis pipeline — the tab-aware AI engine
# ─────────────────────────────────────────────────────────────

import threading
import uuid as _uuid
from pathlib import Path as _Path

import correlator
import pipeline as _pipeline
from knowledge_base import get_kb as _get_kb
from tab_contracts import as_json as _contracts_json

# Background jobs, keyed by id. Single-process and in-memory, which is the right
# scope here: one analyst, one box, one run at a time.
_JOBS: dict[str, _pipeline.JobState] = {}
_JOB_LOCK = threading.Lock()

FEEDBACK_PATH = _Path(__file__).resolve().parent.parent / "output" / "analyst_feedback.json"


class AnalyzeLogsRequest(BaseModel):
    limit_incidents: int | None = None
    use_cache: bool = True
    campaign_tabs: list[str] | None = None
    # How many incidents get the full agent treatment. Declared explicitly:
    # pydantic drops undeclared fields, so a caller passing ai_budget was
    # silently given the default instead.
    ai_budget: int = 40
    use_funnel: bool = True


class FeedbackRequest(BaseModel):
    incident_id: str
    agree: bool
    note: str = ""
    corrected_verdict: str | None = None


def _load_bundle() -> dict[str, Any] | None:
    """The newest usable analysis.

    An in-progress snapshot is preferred only while a run is actually going, so
    a fresh run shows progress without a half-finished bundle displacing the
    last completed one on disk.
    """
    running = any(not j.done and not j.error for j in _JOBS.values())
    candidates = (
        [_pipeline.PARTIAL_ANALYSIS_PATH, _pipeline.ANALYSIS_PATH]
        if running
        else [_pipeline.ANALYSIS_PATH, _pipeline.PARTIAL_ANALYSIS_PATH]
    )
    for path in candidates:
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
    return None


def _run_job(job: _pipeline.JobState, req: AnalyzeLogsRequest) -> None:
    try:
        _pipeline.run_pipeline(
            limit_incidents=req.limit_incidents,
            use_cache=req.use_cache,
            campaign_tabs=tuple(req.campaign_tabs or _pipeline.DEFAULT_CAMPAIGN_TABS),
            ai_budget=req.ai_budget,
            use_funnel=req.use_funnel,
            job=job,
        )
    except Exception as exc:  # noqa: BLE001 — surface the failure to the UI
        job.error = str(exc)
        job.done = True


@app.post("/analyze-logs")
def analyze_logs(req: AnalyzeLogsRequest):
    """Start a background analysis run. Returns immediately with a job id."""
    job_id = _uuid.uuid4().hex[:12]
    job = _pipeline.JobState(job_id=job_id)
    with _JOB_LOCK:
        _JOBS[job_id] = job

    thread = threading.Thread(target=_run_job, args=(job, req), daemon=True)
    thread.start()
    return {"job_id": job_id, "status": job.to_dict()}


@app.get("/analyze-status/{job_id}")
def analyze_status(job_id: str):
    job = _JOBS.get(job_id)
    if job is None:
        return {"error": f"unknown job {job_id}"}
    return job.to_dict()


@app.get("/analysis")
def get_analysis():
    """The bundle every tab renders from."""
    bundle = _load_bundle()
    if bundle is None:
        return {"incidents": [], "verdicts": {}, "campaign": {}, "metrics": None}
    return bundle


@app.get("/incidents")
def get_incidents(verdict: str | None = None, limit: int | None = None):
    bundle = _load_bundle() or {}
    incidents = bundle.get("incidents", [])
    verdicts = bundle.get("verdicts", {})

    enriched = []
    for inc in incidents:
        payload = (verdicts.get(inc["incident_id"]) or {}).get("payload") or {}
        if verdict and str(payload.get("verdict", "")).upper() != verdict.upper():
            continue
        enriched.append({**inc, "ai": payload})

    # Highest AI urgency first — the order an analyst should work them in.
    enriched.sort(key=lambda i: -(i.get("ai", {}).get("urgency_score") or -1))
    return {"incidents": enriched[:limit] if limit else enriched}


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    bundle = _load_bundle() or {}
    for inc in bundle.get("incidents", []):
        if inc["incident_id"] == incident_id:
            record = bundle.get("verdicts", {}).get(incident_id, {})
            return {
                "incident": inc,
                "ai": record.get("payload"),
                "knowledge_used": record.get("knowledge_used", []),
                "ungrounded_techniques": record.get("ungrounded_techniques", []),
            }
    return {"error": f"unknown incident {incident_id}"}


@app.get("/events")
def get_events(
    offset: int = 0,
    limit: int = 1000,
    q: str | None = None,
    severity: str | None = None,
    host: str | None = None,
    user: str | None = None,
    event_id: str | None = None,
):
    """Raw event log, paginated and filterable — the SIEM log view.

    Served from its own file rather than embedded in the analysis bundle: the
    bundle is fetched on every page load, and a full corpus does not belong in
    it. Filtering happens here so the client never has to hold everything.
    """
    path = _pipeline.EVENTS_PATH
    if not path.exists():
        return {"events": [], "total": 0, "offset": 0,
                "error": "no events published yet — run an analysis"}

    rows = json.loads(path.read_text(encoding="utf-8"))

    def keep(row: dict[str, Any]) -> bool:
        if severity and str(row.get("severity", "")).upper() != severity.upper():
            return False
        if host and host.lower() not in str(row.get("host", "")).lower():
            return False
        if user and user.lower() not in str(row.get("user", "")).lower():
            return False
        if event_id and str(row.get("eventId", "")) != str(event_id):
            return False
        if q:
            needle = q.lower()
            haystack = " ".join(str(row.get(k, "")) for k in
                                ("message", "rule", "process", "commandLine",
                                 "host", "user", "sourceIP", "eventId"))
            if needle not in haystack.lower():
                return False
        return True

    filtered = [r for r in rows if keep(r)] if (q or severity or host or user or event_id) else rows
    window = filtered[offset: offset + max(1, min(limit, 5000))]
    return {
        "events": window,
        "total": len(filtered),
        "total_unfiltered": len(rows),
        "offset": offset,
        "limit": limit,
    }


@app.get("/metrics")
def get_metrics():
    bundle = _load_bundle() or {}
    return {
        "metrics": bundle.get("metrics"),
        "counts": bundle.get("counts"),
        "engine_stats": bundle.get("engine_stats"),
        "retrieval_stats": bundle.get("retrieval_stats"),
        "config": bundle.get("config"),
    }


@app.get("/benchmark")
def get_benchmark():
    path = _pipeline.OUTPUT_DIR / "benchmark.json"
    if not path.exists():
        return {"error": "no benchmark yet — run scripts/benchmark.py"}
    return json.loads(path.read_text(encoding="utf-8"))


@app.get("/kb/search")
def kb_search(q: str, top_k: int = 5):
    """Expose retrieval directly, so the UI can show what grounded a verdict."""
    try:
        kb = _get_kb()
    except FileNotFoundError as exc:
        return {"error": str(exc), "results": []}
    return {"query": q, "results": kb.search(q, top_k=top_k)}


@app.get("/tab-contracts")
def tab_contracts():
    """What the AI produces for each tab — the registry, as the UI sees it."""
    return json.loads(_contracts_json())


@app.post("/feedback")
def feedback(req: FeedbackRequest):
    """Record analyst agreement.

    This is the no-fine-tuning improvement path: disagreements become retrieval
    examples that steer future verdicts on similar incidents.
    """
    FEEDBACK_PATH.parent.mkdir(parents=True, exist_ok=True)
    entries = []
    if FEEDBACK_PATH.exists():
        try:
            entries = json.loads(FEEDBACK_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            entries = []

    entries.append(
        {
            "incident_id": req.incident_id,
            "agree": req.agree,
            "note": req.note,
            "corrected_verdict": req.corrected_verdict,
            "recorded_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%S"),
        }
    )
    FEEDBACK_PATH.write_text(json.dumps(entries, indent=1), encoding="utf-8")
    return {"ok": True, "total_feedback": len(entries)}


# ─────────────────────────────────────────────────────────────
# Multi-agent SOC core
# ─────────────────────────────────────────────────────────────

CASES_PATH = _Path(__file__).resolve().parent.parent / "output" / "cases.json"
APPROVALS_PATH = _Path(__file__).resolve().parent.parent / "output" / "approvals.json"


class ApprovalRequest(BaseModel):
    incident_id: str
    action_index: int
    approved: bool
    analyst: str = "analyst"
    note: str = ""


def _load_cases() -> dict[str, Any] | None:
    running = any(not j.done and not j.error for j in _JOBS.values())
    candidates = (
        [_pipeline.PARTIAL_CASES_PATH, CASES_PATH] if running
        else [CASES_PATH, _pipeline.PARTIAL_CASES_PATH]
    )
    for path in candidates:
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
    return None


@app.get("/cases")
def get_cases():
    """The analyst work queue, ordered by fused risk score."""
    data = _load_cases()
    if data is None:
        return {"queue": [], "cases": [], "telemetry_coverage": None}
    return {
        "queue": data.get("queue", []),
        "telemetry_coverage": data.get("telemetry_coverage"),
        "hunt": data.get("hunt"),
        "agent_stats": data.get("agent_stats"),
        "case_count": len(data.get("cases", [])),
    }


@app.get("/cases/{incident_id}")
def get_case(incident_id: str):
    """One full case file: every agent's findings, evidence by domain, risk."""
    data = _load_cases() or {}
    for case in data.get("cases", []):
        if case["incident_id"] == incident_id:
            return case
    return {"error": f"unknown case {incident_id}"}


@app.get("/telemetry-coverage")
def telemetry_coverage():
    """Which data domains have a connector, and which are blind spots."""
    data = _load_cases() or {}
    coverage = data.get("telemetry_coverage")
    if coverage:
        return coverage
    from evidence_engine import EvidenceEngine as _EE
    return _EE().coverage()


@app.get("/agents")
def list_agents():
    """The agents in the core and what each is responsible for."""
    from agents.hunt import HuntAgent as _H
    from agents.intel import IntelAgent as _I
    from agents.response import ResponseAgent as _R
    from agents.triage import TriageAgent as _T
    import risk_engine as _risk

    return {
        "agents": [
            {"name": a.name, "description": a.description}
            for a in (_T, _I, _H, _R)
        ],
        "risk_weights": _risk.WEIGHTS,
        "note": (
            "Agents supply judgement; the Risk Engine fuses it deterministically "
            "so the same case always scores the same."
        ),
    }


@app.post("/approve")
def approve_action(req: ApprovalRequest):
    """Record an analyst decision on a proposed response action.

    Nothing is executed here. This records the human decision, which is the
    gate the Response Agent's destructive steps are held behind.
    """
    APPROVALS_PATH.parent.mkdir(parents=True, exist_ok=True)
    entries = []
    if APPROVALS_PATH.exists():
        try:
            entries = json.loads(APPROVALS_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            entries = []
    entries.append({
        "incident_id": req.incident_id,
        "action_index": req.action_index,
        "approved": req.approved,
        "analyst": req.analyst,
        "note": req.note,
        "decided_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%S"),
    })
    APPROVALS_PATH.write_text(json.dumps(entries, indent=1), encoding="utf-8")
    return {"ok": True, "total_decisions": len(entries)}


# ─────────────────────────────────────────────────────────────
# Autopilot — continuous, event-driven analysis
# ─────────────────────────────────────────────────────────────

# ── serve the dashboard from the API ─────────────────────────────────────────
# One port, not two. The dev server runs the UI on 5173 while the API is on
# 8000, which works locally and fails the moment the dashboard is opened
# through an SSH tunnel or from another machine: the page loads, every API call
# goes to a port nobody forwarded, and the app sits on a loading spinner with
# no error to explain it. Serving the built bundle here makes the UI and its
# API same-origin, so forwarding 8000 is sufficient.
#
# Mounted last so it can never shadow an API route; the catch-all only answers
# paths that matched nothing above.
_UI_DIST = _Path(__file__).resolve().parents[2] / "soc-sentinel" / "dist"


def _mount_dashboard() -> None:
    if not (_UI_DIST / "index.html").exists():
        print(f"[!] no built dashboard at {_UI_DIST} — run `npm run build` in "
              f"soc-sentinel to serve the UI from this port", flush=True)
        return

    from fastapi.responses import FileResponse as _FileResponse
    from fastapi.staticfiles import StaticFiles as _StaticFiles

    app.mount("/assets", _StaticFiles(directory=_UI_DIST / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def _spa(full_path: str):
        # A real file if there is one (favicon, sample data), otherwise
        # index.html so client-side routes survive a page refresh.
        candidate = (_UI_DIST / full_path).resolve()
        if full_path and candidate.is_file() and _UI_DIST in candidate.parents:
            return _FileResponse(candidate)
        return _FileResponse(_UI_DIST / "index.html")

    print(f"[+] dashboard served from {_UI_DIST} — open http://<host>:8000/",
          flush=True)


import autopilot as _autopilot
import scoring as _scoring


@app.get("/autopilot/status")
def autopilot_status():
    ap = _autopilot.get_autopilot()
    return {**ap.state.to_dict(), "inbox": str(_autopilot.INBOX_DIR)}


@app.post("/autopilot/start")
def autopilot_start():
    _autopilot.get_autopilot(engine_factory=_engine_factory).start()
    return {"ok": True}


@app.post("/autopilot/stop")
def autopilot_stop():
    _autopilot.get_autopilot().stop()
    return {"ok": True}


@app.get("/stream")
def stream():
    """Server-sent events: every stage, routing decision and finished case.

    The dashboard subscribes once and updates as work lands, rather than
    polling for a bundle that only changes at the end of a run.
    """
    ap = _autopilot.get_autopilot(engine_factory=_engine_factory)
    sub = ap.bus.subscribe()

    def gen():
        # Replay recent history so a page opened mid-run is not blank.
        for event in ap.bus.history[-30:]:
            yield f"data: {json.dumps(event)}\n\n"
        try:
            while True:
                try:
                    event = sub.q.get(timeout=15)
                    yield f"data: {json.dumps(event)}\n\n"
                except Exception:
                    # Keep the connection alive through quiet periods.
                    yield ": keepalive\n\n"
        finally:
            ap.bus.unsubscribe(sub)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


class IngestRequest(BaseModel):
    """Logs pushed in directly, rather than dropped in the inbox."""
    events: list[dict[str, Any]]
    origin: str = "api"


@app.post("/ingest")
def ingest(req: IngestRequest):
    """Accept logs and return immediately — analysis happens on its own."""
    import pandas as _pd

    if not req.events:
        return {"accepted": 0, "error": "no events supplied"}

    df = _pd.DataFrame(req.events).fillna("")
    for col in _pipeline.STANDARD_COLUMNS:
        if col not in df.columns:
            df[col] = ""
    present = [c for c in _pipeline.MESSAGE_FIELDS if c in df.columns]
    if present:
        df["raw_message"] = df[present].astype(str).agg(" ".join, axis=1).str.strip()

    ap = _autopilot.get_autopilot(engine_factory=_engine_factory)
    ap.submit(df, origin=req.origin)
    return {"accepted": len(df), "queued_batches": ap.inbox.qsize()}


class AnswerRequest(BaseModel):
    answer: str
    analyst: str = "analyst"


@app.get("/questions")
def list_questions(include_answered: bool = False):
    """Questions the agent has put to a human, oldest first.

    A parked case is not a decision. Anything here is blocking an
    investigation that has already done the work it can do alone.
    """
    import questions as _q

    store = _q.get_store()
    store.expire_stale()
    items = (list(store.questions.values()) if include_answered
             else store.waiting())
    return {
        "questions": [x.to_dict() for x in items],
        "stats": store.stats(),
    }


@app.post("/questions/{question_id}/answer")
def answer_question(question_id: str, req: AnswerRequest):
    """Answer, and resume the parked investigation from where it stopped."""
    import questions as _q

    store = _q.get_store()
    answered = store.answer(question_id, req.answer, req.analyst)
    if answered is None:
        return {"ok": False, "error": "unknown or already-answered question"}

    ap = _autopilot.get_autopilot(engine_factory=_engine_factory)
    ap.bus.publish("question.answered",
                   question_id=question_id,
                   incident_id=answered.incident_id,
                   answer=req.answer[:200])
    resumed = ap.resume_answered(answered)
    return {"ok": True, "incident_id": answered.incident_id, "resumed": resumed}


class EnrichRequest(BaseModel):
    payload: dict[str, Any]


def _enrich(tab_id: str, evidence: dict[str, Any],
            keys: dict[str, Any]) -> dict[str, Any]:
    """Shared path so every surface is grounded the same way."""
    try:
        engine = _engine_factory()
    except Exception as exc:  # noqa: BLE001
        return {"error": f"model unavailable: {exc}"}
    result = engine.enrich(tab_id, evidence, keys)
    return result.to_dict()


@app.post("/enrich/email")
def enrich_email(req: EnrichRequest):
    """Phishing assessment through the email contract, with retrieval.

    Replaces a hand-written prompt that had no schema, no retrieval and no
    grounding check — it could name any technique it liked and nothing
    verified it.
    """
    email = req.payload or {}
    evidence = {
        "subject": str(email.get("subject", ""))[:200],
        "from": str(email.get("from", ""))[:120],
        "to": str(email.get("to", ""))[:120],
        "spf": email.get("spf"), "dkim": email.get("dkim"), "dmarc": email.get("dmarc"),
        "reply_to": str(email.get("replyTo", ""))[:120],
        "urls": [str(u)[:120] for u in (email.get("urls") or [])][:8],
        "attachments": [str(a)[:80] for a in (email.get("attachments") or [])][:6],
        "body_excerpt": str(email.get("body", ""))[:900],
    }
    keys = {
        "event_ids": [],
        "processes": [str(a) for a in (email.get("attachments") or [])][:3],
        "terms": ["phishing", "initial access", "user execution",
                  "spearphishing attachment", "spearphishing link"],
    }
    return _enrich("email", evidence, keys)


@app.post("/enrich/event")
def enrich_event(req: EnrichRequest):
    """Explain one log line: what it means, and its benign baseline."""
    event = req.payload or {}
    # Accept both the normalised row the dashboard holds and a raw
    # Windows/Sysmon record, so the endpoint works on whatever the caller has.
    def pick(*names):
        for n in names:
            if (v := event.get(n)) not in (None, ""):
                return v
        return None

    process = pick("process", "Image", "process_name", "ProcessName")
    command_line = str(pick("commandLine", "CommandLine") or "")[:300]
    basename = str(process).rsplit("\\", 1)[-1] if process else ""

    evidence = {
        "event_id": pick("eventId", "event_id", "EventID"),
        "host": pick("host", "Computer", "computer"),
        "user": pick("user", "User"),
        "process": process,
        "command_line": command_line,
        "source_ip": pick("sourceIP", "SourceIp"),
        "raw": {k: str(v)[:120] for k, v in (event.get("_raw") or {}).items()},
    }
    # Retrieve on the basename rather than the full path: the knowledge base
    # indexes `rundll32.exe`, not `C:\Windows\System32\rundll32.exe`.
    keys = {
        "event_ids": [str(evidence["event_id"])] if evidence["event_id"] else [],
        "processes": [basename] if basename else [],
        "terms": correlator.commandline_terms(command_line)
        or ["windows event id meaning and benign baseline"],
    }
    return _enrich("logs", evidence, keys)


@app.post("/enrich/graph")
def enrich_graph(req: EnrichRequest):
    """What the connected entities mean together."""
    inc = req.payload or {}
    evidence = {
        "hosts": inc.get("hosts", [])[:6],
        "users": inc.get("users", [])[:6],
        "processes": [str(p).rsplit("\\", 1)[-1] for p in inc.get("processes", [])][:8],
        "event_ids": inc.get("event_ids", [])[:8],
        "techniques": [t.get("technique") for t in inc.get("techniques_suspected", [])][:4],
        "rules_fired": [r.get("rule") for r in inc.get("rules_fired", [])][:4],
        "shared_entities": inc.get("shared_entities", [])[:6],
    }
    keys = {
        "event_ids": inc.get("event_ids", [])[:4],
        "processes": [str(p).rsplit("\\", 1)[-1] for p in inc.get("processes", [])][:4],
        "terms": [t.get("technique") for t in inc.get("techniques_suspected", [])][:3],
    }
    return _enrich("evidence_graph", evidence, keys)


@app.get("/detection-metrics")
def detection_metrics_endpoint():
    """Per-rule performance. Deterministic — no model involved."""
    import detection_metrics as _dm
    from detector import load_rules as _load_rules

    bundle = _load_bundle() or {}
    incidents = bundle.get("incidents", [])
    if not incidents:
        return {"error": "no analysis yet"}

    alerts = [a for i in incidents for a in i.get("sample_alerts", [])]
    memory = None
    try:
        from case_memory import CaseMemory as _CM
        memory = _CM()
    except Exception:  # noqa: BLE001
        pass

    return _dm.compute(_load_rules(), alerts, incidents,
                       bundle.get("verdicts", {}), case_memory=memory)


class BacktestRequest(BaseModel):
    rule_id: str
    field: str
    pattern: str


@app.post("/detection-backtest")
def detection_backtest(req: BacktestRequest):
    """What a proposed exclusion would have cost, measured against history.

    The check that makes a tuning proposal trustworthy: an exclusion removing
    90% of a rule's noise is only safe if it does not also remove the firings
    that mattered.
    """
    import detection_metrics as _dm
    from detector import load_rules as _load_rules

    bundle = _load_bundle() or {}
    try:
        df = _pipeline.load_corpus_dataframe()
    except Exception as exc:  # noqa: BLE001
        return {"error": f"corpus unavailable: {exc}"}

    df = df.assign(_row_index=df.index)
    return _dm.backtest_exclusion(
        df, _load_rules(), req.rule_id, req.field, req.pattern,
        incidents=bundle.get("incidents", []),
        verdicts=bundle.get("verdicts", {}),
    )


@app.get("/detection-coverage")
def detection_coverage():
    """ATT&CK techniques the collected telemetry could detect but no rule does."""
    import detection_metrics as _dm
    from detector import load_rules as _load_rules
    from knowledge_base import get_kb as _kb

    try:
        df = _pipeline.load_corpus_dataframe()
    except Exception:  # noqa: BLE001
        df = None
    return _dm.coverage_gaps(_load_rules(), _kb(), df)


@app.get("/audit")
def audit(limit: int = 100, q: str | None = None, band: str | None = None):
    """Every AI decision, reconstructable.

    In a regulated environment a verdict nobody can reproduce is worthless.
    This returns the decision, the autonomy band it fell into and why, the risk
    factors that produced the score, and every tool the agent called with what
    came back — for each case, searchable.
    """
    data = _load_cases() or {}
    entries = []

    for case in data.get("cases", []):
        investigation = case.get("investigation") or {}
        risk = case.get("risk") or {}
        autonomy_decision = case.get("autonomy") or {}
        verdict = case.get("payload") or investigation.get("verdict") or {}
        incident = case.get("incident") or {}

        if band and str(autonomy_decision.get("band", "")) != band:
            continue

        record = {
            "incident_id": case.get("incident_id"),
            "decided_at": data.get("generated_at"),
            "verdict": verdict.get("verdict"),
            "confidence": verdict.get("confidence"),
            "risk_score": risk.get("risk_score"),
            "risk_band": risk.get("band"),
            "risk_factors": risk.get("factors", []),
            "risk_caveats": risk.get("caveats", []),
            "autonomy_band": autonomy_decision.get("band"),
            "autonomy_reasons": autonomy_decision.get("reasons", []),
            "autonomy_overrides": autonomy_decision.get("overrides_applied", []),
            "required_approval": autonomy_decision.get("requires_approval"),
            "asset_criticality": case.get("asset_criticality"),
            "hosts": incident.get("hosts", [])[:5],
            "users": incident.get("users", [])[:5],
            # The reconstruction: what was asked, why, and what came back.
            "investigation": {
                "complete": investigation.get("complete"),
                "stopped_reason": investigation.get("stopped_reason"),
                "step_count": investigation.get("step_count"),
                "model_calls": investigation.get("model_calls"),
                "parse_failures": investigation.get("parse_failures"),
                "elapsed_seconds": investigation.get("elapsed_seconds"),
                "steps": investigation.get("steps", []),
            },
            "sources_cited": verdict.get("sources", []),
            "ungrounded_citations": case.get("agents", {}).get("triage", {}).get("ungrounded", []),
        }

        if q:
            needle = q.lower()
            haystack = json.dumps(record, default=str).lower()
            if needle not in haystack:
                continue
        entries.append(record)

    return {
        "entries": entries[:limit],
        "total": len(entries),
        "note": (
            "Each entry reconstructs one AI decision end to end: the tools "
            "called, the reasoning, the evidence returned, the deterministic "
            "risk factors, and the policy band applied."
        ),
    }


@app.get("/audit/{incident_id}")
def audit_one(incident_id: str):
    result = audit(limit=10_000)
    for entry in result["entries"]:
        if entry["incident_id"] == incident_id:
            return entry
    return {"error": f"no audit record for {incident_id}"}


@app.get("/scorecard")
def scorecard():
    """Ground-truth performance per feature, for the tab that owns it."""
    from knowledge_base import get_kb as _kb

    bundle = _load_bundle() or {}
    incidents = bundle.get("incidents", [])
    verdicts = bundle.get("verdicts", {})
    if not incidents:
        return {"error": "no analysis yet"}

    try:
        df = _pipeline.load_corpus_dataframe()
    except Exception as exc:  # noqa: BLE001
        return {"error": f"corpus unavailable: {exc}"}

    tactics = {c["technique_id"]: c.get("tactics", [])
               for c in _kb().chunks if c.get("technique_id")}
    cases = (_load_cases() or {}).get("cases", [])
    return _scoring.score_all(df, incidents, verdicts, tactics, cases=cases)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")


# Registered last: the SPA catch-all must not shadow any API route above.
_mount_dashboard()
