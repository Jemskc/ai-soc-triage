"""AI Phishing Triage — Streamlit Dashboard (Phishing-Focused).

Entry point: streamlit run src/phishing_dashboard.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st
import requests

# Add src/ to sys.path so sibling module imports work from any working directory.
SRC_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SRC_DIR))

from threat_intel import enrich_email_threat_intel

BASE_DIR = Path(__file__).resolve().parent.parent
PHISHING_CASES_PATH = BASE_DIR / "output" / "phishing_cases.json"

# ─────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="🎣 Phishing Analysis Center",
    layout="wide",
    page_icon="🎣",
    initial_sidebar_state="expanded",
)


# ─────────────────────────────────────────────────────────────
# GLOBAL CSS - Dark theme optimized for phishing analysis
# ─────────────────────────────────────────────────────────────
def _inject_css() -> None:
    st.markdown(
        """
        <style>
        /* Risk score badges */
        .badge-critical { background:#b91c1c; color:#fff; padding:4px 12px; border-radius:6px; font-weight:700; font-size:0.85rem; }
        .badge-high     { background:#c2410c; color:#fff; padding:4px 12px; border-radius:6px; font-weight:700; font-size:0.85rem; }
        .badge-medium   { background:#b45309; color:#fff; padding:4px 12px; border-radius:6px; font-weight:700; font-size:0.85rem; }
        .badge-low      { background:#15803d; color:#fff; padding:4px 12px; border-radius:6px; font-weight:700; font-size:0.85rem; }
        .badge-safe     { background:#065f46; color:#fff; padding:4px 12px; border-radius:6px; font-weight:700; font-size:0.85rem; }

        /* Email row highlight */
        .email-critical { border-left: 5px solid #b91c1c; padding-left: 12px; background: rgba(185, 28, 28, 0.05); }
        .email-high     { border-left: 5px solid #c2410c; padding-left: 12px; background: rgba(194, 65, 12, 0.05); }
        .email-medium   { border-left: 5px solid #b45309; padding-left: 12px; background: rgba(180, 83, 9, 0.05); }
        .email-low      { border-left: 5px solid #15803d; padding-left: 12px; background: rgba(21, 128, 61, 0.05); }

        /* Threat intel cards */
        .threat-card { 
            background: #1e2936; 
            border-radius: 8px; 
            padding: 16px; 
            margin: 8px 0; 
            border: 1px solid #2d3f50;
        }
        .threat-card-title { font-weight: 700; color: #60a5fa; margin-bottom: 8px; }
        .threat-card-value { font-family: monospace; font-size: 0.9rem; color: #e5e7eb; }
        
        /* IOC highlights */
        .ioc-malicious { background: rgba(185, 28, 28, 0.2); border: 1px solid #b91c1c; padding: 4px 8px; border-radius: 4px; }
        .ioc-suspicious { background: rgba(194, 65, 12, 0.2); border: 1px solid #c2410c; padding: 4px 8px; border-radius: 4px; }
        .ioc-clean { background: rgba(21, 128, 61, 0.2); border: 1px solid #15803d; padding: 4px 8px; border-radius: 4px; }
        </style>
        """,
        unsafe_allow_html=True,
    )


# ─────────────────────────────────────────────────────────────
# SESSION STATE INIT
# ─────────────────────────────────────────────────────────────
def _init_state() -> None:
    defaults = {
        "current_email": None,
        "analysis_results": None,
        "threat_intel_data": None,
        "selected_case_idx": None,
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


# ─────────────────────────────────────────────────────────────
# DATA LOADERS
# ─────────────────────────────────────────────────────────────
def _load_phishing_cases() -> list[dict[str, Any]]:
    if not PHISHING_CASES_PATH.exists() or PHISHING_CASES_PATH.stat().st_size == 0:
        return []
    try:
        content = PHISHING_CASES_PATH.read_text(encoding="utf-8").strip()
        if not content:
            return []
        parsed = json.loads(content)
        return parsed if isinstance(parsed, list) else []
    except Exception as err:
        st.warning(f"Could not read phishing cases: {err}")
        return []


def _save_phishing_case(case: dict[str, Any]) -> None:
    cases = _load_phishing_cases()
    cases.append(case)
    PHISHING_CASES_PATH.parent.mkdir(parents=True, exist_ok=True)
    PHISHING_CASES_PATH.write_text(json.dumps(cases, indent=2), encoding="utf-8")


# ─────────────────────────────────────────────────────────────
# API INTEGRATION
# ─────────────────────────────────────────────────────────────
API_BASE_URL = "http://localhost:8000"

def _analyze_email_api(email_data: dict[str, Any]) -> dict[str, Any]:
    """Call the backend email analysis endpoint."""
    try:
        response = requests.post(
            f"{API_BASE_URL}/email-analyze",
            json={"email": email_data},
            timeout=60
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        return {"error": "Backend server not running. Start with: python src/api_server.py"}
    except Exception as e:
        return {"error": str(e)}


def _get_threat_intel(email_data: dict[str, Any]) -> dict[str, Any]:
    """Enrich email with automated threat intelligence."""
    try:
        return enrich_email_threat_intel(email_data)
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────
def _render_sidebar(cases: list[dict[str, Any]]) -> None:
    with st.sidebar:
        st.markdown("## 🎣 Phishing Analysis Center")
        st.caption("Automated Threat Intelligence Powered")
        st.divider()
        
        st.markdown("#### Quick Stats")
        total = len(cases)
        critical = sum(1 for c in cases if c.get("riskScore", 0) >= 80)
        high = sum(1 for c in cases if 60 <= c.get("riskScore", 0) < 80)
        safe = sum(1 for c in cases if c.get("riskScore", 0) < 40)
        
        st.metric("Total Cases", total)
        c1, c2 = st.columns(2)
        c1.metric("🔴 Critical/High", critical + high)
        c2.metric("🟢 Safe", safe)
        
        st.divider()
        st.markdown("#### Recent Cases")
        if cases:
            for idx, case in enumerate(reversed(cases[-10:])):
                risk = case.get("riskScore", 0)
                risk_color = "🔴" if risk >= 80 else "🟠" if risk >= 60 else "🟡" if risk >= 40 else "🟢"
                subject = case.get("subject", "No Subject")[:30]
                if st.button(f"{risk_color} {subject}", key=f"case_{idx}", use_container_width=True):
                    st.session_state["selected_case_idx"] = len(cases) - 1 - idx
                    st.rerun()
        else:
            st.caption("No cases analyzed yet.")
        
        st.divider()
        if st.button("🗑️ Clear All Cases", use_container_width=True):
            if PHISHING_CASES_PATH.exists():
                PHISHING_CASES_PATH.unlink()
                st.session_state["current_email"] = None
                st.session_state["analysis_results"] = None
                st.rerun()


# ─────────────────────────────────────────────────────────────
# EMAIL PARSER HELPER
# ─────────────────────────────────────────────────────────────
def _parse_raw_email(raw_text: str) -> dict[str, Any]:
    """Simple email parser for raw .eml content."""
    import email
    from email import policy
    
    try:
        msg = email.message_from_string(raw_text, policy=policy.default)
        
        headers = dict(msg.items())
        subject = msg.get("Subject", "")
        from_ = msg.get("From", "")
        to = msg.get("To", "")
        date = msg.get("Date", "")
        
        # Get body
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get("Content-Disposition"))
                if ctype == "text/plain" and "attachment" not in cdispo:
                    try:
                        body = part.get_payload(decode=True).decode(errors="ignore")
                        break
                    except:
                        pass
        else:
            body = msg.get_payload(decode=True) or ""
            if isinstance(body, bytes):
                body = body.decode(errors="ignore")
        
        # Extract URLs (simple regex)
        import re
        urls = list(set(re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', body)))[:20]
        
        # Check authentication headers
        spf = "none"
        dkim = "none"
        dmarc = "none"
        auth_results = headers.get("Authentication-Results", "")
        if "spf=pass" in auth_results.lower():
            spf = "pass"
        elif "spf=fail" in auth_results.lower():
            spf = "fail"
        if "dkim=pass" in auth_results.lower():
            dkim = "pass"
        elif "dkim=fail" in auth_results.lower():
            dkim = "fail"
        if "dmarc=pass" in auth_results.lower():
            dmarc = "pass"
        elif "dmarc=fail" in auth_results.lower():
            dmarc = "fail"
        
        # Extract origin IP from Received headers
        origin_ip = ""
        received_headers = headers.get("Received", "")
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', str(received_headers))
        if ip_match:
            origin_ip = ip_match.group(1)
        
        return {
            "subject": subject,
            "from": from_,
            "to": to,
            "date": date,
            "body": body[:5000],  # Limit body length
            "headers": headers,
            "urls": urls,
            "attachments": [],  # Simplified for now
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "originIP": origin_ip,
            "replyTo": msg.get("Reply-To", ""),
        }
    except Exception as e:
        return {"error": f"Parse failed: {str(e)}"}


# ─────────────────────────────────────────────────────────────
# TAB 1: EMAIL ANALYZER
# ─────────────────────────────────────────────────────────────
def _render_analyzer_tab() -> None:
    st.markdown("### 📧 Email Analysis")
    st.caption("Paste raw email content or upload .eml file for automated phishing detection")
    
    input_method = st.radio("Input Method", ["Paste Raw Email", "Upload .eml File"], horizontal=True)
    
    email_data = None
    
    if input_method == "Paste Raw Email":
        raw_email = st.text_area(
            "Raw Email Content",
            height=300,
            placeholder="Paste the full raw email content here (including all headers)...",
            key="raw_email_input"
        )
        if raw_email.strip():
            if st.button("🔍 Analyze Email", type="primary"):
                with st.spinner("Parsing email..."):
                    email_data = _parse_raw_email(raw_email)
                if "error" in email_data:
                    st.error(email_data["error"])
                    email_data = None
    else:
        uploaded_file = st.file_uploader("Upload .eml file", type=["eml"])
        if uploaded_file:
            raw_email = uploaded_file.read().decode("utf-8", errors="ignore")
            with st.spinner("Parsing email..."):
                email_data = _parse_raw_email(raw_email)
            if "error" in email_data:
                st.error(email_data["error"])
                email_data = None
    
    if email_data:
        st.session_state["current_email"] = email_data
        
        # Display email preview
        with st.expander("📋 Email Preview", expanded=False):
            col1, col2 = st.columns(2)
            col1.markdown(f"**Subject:** {email_data.get('subject', 'N/A')}")
            col1.markdown(f"**From:** {email_data.get('from', 'N/A')}")
            col2.markdown(f"**To:** {email_data.get('to', 'N/A')}")
            col2.markdown(f"**Date:** {email_data.get('date', 'N/A')}")
            st.markdown("**Body Preview:**")
            st.text(email_data.get('body', '')[:1000])
        
        # Run analysis
        st.divider()
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            analyze_btn = st.button("🤖 Run AI Analysis + Threat Intel", type="primary", use_container_width=True)
        
        if analyze_btn or st.session_state.get("analysis_results"):
            with st.spinner("Running AI analysis and querying threat intelligence sources..."):
                # AI Analysis
                ai_result = _analyze_email_api(email_data)
                
                # Threat Intelligence
                ti_result = _get_threat_intel(email_data)
                
                st.session_state["analysis_results"] = {
                    "ai": ai_result,
                    "threat_intel": ti_result,
                    "email": email_data
                }
                
                # Save case
                case_data = {
                    **email_data,
                    "analyzed_at": datetime.now().isoformat(),
                    "ai_analysis": ai_result,
                    "threat_intel": ti_result,
                    "riskScore": ai_result.get("riskScore", ti_result.get("overall_risk_score", 0)),
                }
                _save_phishing_case(case_data)
            
            st.success("Analysis complete!")
            st.rerun()


# ─────────────────────────────────────────────────────────────
# TAB 2: ANALYSIS RESULTS
# ─────────────────────────────────────────────────────────────
def _render_results_tab() -> None:
    results = st.session_state.get("analysis_results")
    
    if not results:
        st.info("No analysis results yet. Go to the Email Analyzer tab to analyze an email.")
        return
    
    email_data = results.get("email", {})
    ai_result = results.get("ai", {})
    ti_result = results.get("threat_intel", {})
    
    # Risk Score Banner
    risk_score = ai_result.get("riskScore", ti_result.get("overall_risk_score", 0))
    risk_label = ai_result.get("riskLabel", ti_result.get("risk_label", "Unknown"))
    
    if risk_score >= 80:
        risk_color = "#b91c1c"
        risk_emoji = "🔴"
    elif risk_score >= 60:
        risk_color = "#c2410c"
        risk_emoji = "🟠"
    elif risk_score >= 40:
        risk_color = "#b45309"
        risk_emoji = "🟡"
    else:
        risk_color = "#15803d"
        risk_emoji = "🟢"
    
    st.markdown(
        f"""
        <div style="background: linear-gradient(135deg, {risk_color}22, {risk_color}11); 
                    border-left: 5px solid {risk_color}; 
                    padding: 20px; 
                    border-radius: 8px; 
                    margin: 20px 0;">
            <h2 style="margin: 0;">{risk_emoji} Risk Score: {risk_score}/100 ({risk_label})</h2>
            <p style="margin: 8px 0 0 0; opacity: 0.8;">{ai_result.get('verdict', ti_result.get('summary', 'Analysis complete'))}</p>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    # Main analysis tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 Overview", 
        "🔬 Headers & Auth", 
        "🌐 URL Analysis", 
        "🛡️ Threat Intel", 
        "🤖 AI Analysis"
    ])
    
    with tab1:
        st.markdown("#### Analysis Overview")
        
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("SPF", email_data.get("spf", "N/A").upper())
        c2.metric("DKIM", email_data.get("dkim", "N/A").upper())
        c3.metric("DMARC", email_data.get("dmarc", "N/A").upper())
        c4.metric("URLs Found", len(email_data.get("urls", [])))
        
        if ai_result.get("keyFindings"):
            st.markdown("**Key Findings:**")
            for finding in ai_result["keyFindings"]:
                st.markdown(f"• {finding}")
        
        if ti_result.get("findings"):
            st.markdown("**Threat Intelligence Findings:**")
            for finding in ti_result["findings"]:
                st.markdown(f"• {finding}")
    
    with tab2:
        st.markdown("#### Email Authentication Analysis")
        
        auth_cols = st.columns(3)
        auth_cols[0].metric("SPF Status", email_data.get("spf", "N/A").upper())
        auth_cols[1].metric("DKIM Status", email_data.get("dkim", "N/A").upper())
        auth_cols[2].metric("DMARC Status", email_data.get("dmarc", "N/A").upper())
        
        reply_to = email_data.get("replyTo", "")
        from_addr = email_data.get("from", "")
        if reply_to and reply_to != from_addr:
            st.warning(f"⚠️ **Reply-To Mismatch Detected**: Replies go to `{reply_to}` instead of `{from_addr}`")
        
        if email_data.get("headers"):
            with st.expander("View All Headers"):
                st.json(email_data["headers"])
    
    with tab3:
        st.markdown("#### URL Analysis")
        
        urls = email_data.get("urls", [])
        if not urls:
            st.info("No URLs found in email.")
        else:
            url_df = pd.DataFrame([
                {"URL": url, "Status": ti_result.get("url_analysis", {}).get(url, {}).get("status", "Not Checked")}
                for url in urls
            ])
            st.dataframe(url_df, use_container_width=True, hide_index=True)
            
            # Show VirusTotal results if available
            if ti_result.get("virustotal_urls"):
                st.markdown("**VirusTotal Results:**")
                for url, vt_data in ti_result["virustotal_urls"].items():
                    malicious = vt_data.get("malicious", 0)
                    if malicious > 0:
                        st.error(f"🚨 `{url[:60]}...` - {malicious} vendors flagged as malicious")
    
    with tab4:
        st.markdown("#### Automated Threat Intelligence")
        
        if ti_result.get("error"):
            st.warning(f"Threat intel error: {ti_result['error']}")
        else:
            # VirusTotal
            if ti_result.get("virustotal_summary"):
                with st.expander("🔍 VirusTotal Results", expanded=True):
                    st.markdown(ti_result["virustotal_summary"])
            
            # Whois
            if ti_result.get("whois_data"):
                with st.expander("📇 Domain Whois Information"):
                    for domain, data in ti_result["whois_data"].items():
                        st.markdown(f"**{domain}**")
                        if data.get("registrar"):
                            st.markdown(f"Registrar: {data['registrar']}")
                        if data.get("creation_date"):
                            st.markdown(f"Created: {data['creation_date']}")
                        if data.get("age_days") is not None:
                            age = data["age_days"]
                            if age < 30:
                                st.warning(f"⚠️ Domain is only {age} days old (high risk)")
                            elif age < 90:
                                st.info(f"Domain is {age} days old (moderate risk)")
            
            # AbuseIPDB
            if ti_result.get("abuseipdb_data"):
                with st.expander("🚫 AbuseIPDB IP Reputation"):
                    for ip, data in ti_result["abuseipdb_data"].items():
                        abuse_score = data.get("abuseConfidenceScore", 0)
                        if abuse_score > 50:
                            st.error(f"🚨 IP `{ip}` - {abuse_score}% abuse confidence")
                        elif abuse_score > 0:
                            st.warning(f"⚠️ IP `{ip}` - {abuse_score}% abuse confidence")
                        else:
                            st.success(f"✅ IP `{ip}` - Clean reputation")
            
            # Shodan
            if ti_result.get("shodan_data"):
                with st.expander("🌐 Shodan IP Intelligence"):
                    for ip, data in ti_result["shodan_data"].items():
                        if data.get("error"):
                            st.caption(f"IP `{ip}`: {data['error']}")
                        else:
                            st.markdown(f"**IP `{ip}`**")
                            if data.get("org"):
                                st.markdown(f"Organization: {data['org']}")
                            if data.get("country_name"):
                                st.markdown(f"Country: {data['country_name']}")
                            if data.get("open_ports"):
                                st.markdown(f"Open Ports: {data['open_ports']}")
    
    with tab5:
        st.markdown("#### AI-Powered Analysis")
        
        if ai_result.get("error"):
            st.warning(f"AI analysis error: {ai_result['error']}")
        else:
            if ai_result.get("threatVerdict"):
                st.markdown(f"**Threat Verdict:** {ai_result['threatVerdict']}")
            
            if ai_result.get("attackTechnique"):
                st.markdown(f"**Attack Technique:** {ai_result['attackTechnique']}")
            
            if ai_result.get("recommendedAction"):
                st.info(f"**Recommended Action:** {ai_result['recommendedAction']}")
            
            if ai_result.get("analystNote"):
                st.markdown("**Analyst Note:**")
                st.markdown(ai_result["analystNote"])


# ─────────────────────────────────────────────────────────────
# TAB 3: CASE HISTORY
# ─────────────────────────────────────────────────────────────
def _render_history_tab(cases: list[dict[str, Any]]) -> None:
    st.markdown("### 📜 Case History")
    
    if not cases:
        st.info("No phishing cases analyzed yet.")
        return
    
    # Filter controls
    col1, col2 = st.columns(2)
    with col1:
        min_risk = st.slider("Minimum Risk Score", 0, 100, 0)
    with col2:
        search_term = st.text_input("Search Subjects", placeholder="Search...")
    
    filtered_cases = [
        c for c in cases 
        if c.get("riskScore", 0) >= min_risk
        and (not search_term or search_term.lower() in c.get("subject", "").lower())
    ]
    
    st.caption(f"Showing {len(filtered_cases)} of {len(cases)} cases")
    
    if filtered_cases:
        # Sort by risk score descending
        filtered_cases.sort(key=lambda x: x.get("riskScore", 0), reverse=True)
        
        for idx, case in enumerate(filtered_cases):
            risk = case.get("riskScore", 0)
            risk_color = "🔴" if risk >= 80 else "🟠" if risk >= 60 else "🟡" if risk >= 40 else "🟢"
            
            with st.expander(f"{risk_color} [{risk}/100] {case.get('subject', 'No Subject')}", expanded=(idx == 0)):
                c1, c2, c3 = st.columns(3)
                c1.markdown(f"**From:** {case.get('from', 'N/A')}")
                c2.markdown(f"**Date:** {case.get('date', 'N/A')[:16] if case.get('date') else 'N/A'}")
                c3.markdown(f"**Analyzed:** {case.get('analyzed_at', 'N/A')[:16] if case.get('analyzed_at') else 'N/A'}")
                
                if case.get("ai_analysis", {}).get("threatVerdict"):
                    st.markdown(f"**Verdict:** {case['ai_analysis']['threatVerdict']}")
                
                if case.get("ai_analysis", {}).get("recommendedAction"):
                    st.info(f"**Action:** {case['ai_analysis']['recommendedAction']}")


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
def main() -> None:
    _inject_css()
    _init_state()
    
    # Load cases
    cases = _load_phishing_cases()
    
    # Sidebar
    _render_sidebar(cases)
    
    # Main tabs
    tab1, tab2, tab3 = st.tabs(["📧 Email Analyzer", "🔬 Analysis Results", "📜 Case History"])
    
    with tab1:
        _render_analyzer_tab()
    
    with tab2:
        _render_results_tab()
    
    with tab3:
        _render_history_tab(cases)


if __name__ == "__main__":
    main()
