"""FastAPI server — Qwen3-4B backed chat, log-search, and email-analyze endpoints."""

from __future__ import annotations

import json
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Eagerly load Qwen3-4B at startup so the first request is fast."""
    print("[+] Pre-loading Qwen3-4B into GPU memory...")
    backend = get_llm_backend()
    if backend is not None:
        backend._load()
        print(f"[+] Model ready: {backend.model_label}")
    yield


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
    "You are an expert SOC analyst with 10 years of experience in incident response, "
    "threat hunting, and digital forensics. Give concise, actionable answers. "
    "Reference specific IPs, users, and hostnames from the data when relevant. "
    "Format lists with bullet points. Keep responses under 400 words unless detail is critical."
)

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
    return user_message, max_tokens, api_history


@app.post("/chat")
def chat(req: ChatRequest):
    backend = get_llm_backend()
    if backend is None:
        return {"response": "No LLM backend configured. Set LOCAL_MODEL_NAME in .env.", "error": True}
    try:
        user_message, max_tokens, api_history = _resolve_chat_request(req)
        response = backend.generate_text(
            system=SOC_SYSTEM,
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
        user_message, max_tokens, api_history = _resolve_chat_request(req)
    except Exception as exc:
        def _err():
            yield f"data: {json.dumps(f'Request error: {exc}')}\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(_err(), media_type="text/event-stream")

    def token_gen():
        try:
            for chunk in backend.generate_stream(SOC_SYSTEM, user_message, max_tokens, api_history):
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
