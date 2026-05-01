"""AI SOC Triage — Streamlit Dashboard.

Entry point: streamlit run src/dashboard.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st

# Add src/ to sys.path so sibling module imports work from any working directory.
SRC_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SRC_DIR))

from ai_chat import chat as ai_chat_fn, format_history_for_display
from ai_triage import enrich_alerts_with_ai
from detector import run_detection, load_rules
from ingestor import load_all_logs
from search import search_logs
from view_builder import (
    build_view,
    delete_saved_view,
    load_saved_views,
    render_saved_view,
    save_view,
)

BASE_DIR = Path(__file__).resolve().parent.parent
ALERTS_PATH = BASE_DIR / "output" / "alerts.json"

# ─────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI SOC Triage",
    layout="wide",
    page_icon="🔵",
    initial_sidebar_state="expanded",
)


# ─────────────────────────────────────────────────────────────
# GLOBAL CSS
# ─────────────────────────────────────────────────────────────
def _inject_css() -> None:
    st.markdown(
        """
        <style>
        /* Severity badges */
        .badge-critical { background:#b91c1c; color:#fff; padding:2px 8px; border-radius:4px; font-weight:700; font-size:0.75rem; }
        .badge-high     { background:#c2410c; color:#fff; padding:2px 8px; border-radius:4px; font-weight:700; font-size:0.75rem; }
        .badge-medium   { background:#b45309; color:#fff; padding:2px 8px; border-radius:4px; font-weight:700; font-size:0.75rem; }
        .badge-low      { background:#15803d; color:#fff; padding:2px 8px; border-radius:4px; font-weight:700; font-size:0.75rem; }

        /* Alert row highlight */
        .alert-critical { border-left: 4px solid #b91c1c; padding-left: 8px; }
        .alert-high     { border-left: 4px solid #c2410c; padding-left: 8px; }
        .alert-medium   { border-left: 4px solid #b45309; padding-left: 8px; }
        .alert-low      { border-left: 4px solid #15803d; padding-left: 8px; }

        /* Chat message bubbles */
        .chat-user      { background:#1e3a5f; border-radius:12px 12px 4px 12px; padding:10px 14px; margin:6px 0; text-align:right; }
        .chat-assistant { background:#1e2d1e; border-radius:12px 12px 12px 4px; padding:10px 14px; margin:6px 0; text-align:left; }
        .chat-timestamp { font-size:0.65rem; color:#888; margin-top:2px; }

        /* Floating chat button target */
        .element-container:has(#chat-float-anchor) + div button {
            position: fixed !important;
            bottom: 2.2rem !important;
            right: 2.2rem !important;
            z-index: 9999 !important;
            border-radius: 50% !important;
            width: 58px !important;
            height: 58px !important;
            font-size: 1.4rem !important;
            background: linear-gradient(135deg, #1d4ed8, #1e40af) !important;
            color: #fff !important;
            border: none !important;
            box-shadow: 0 4px 20px rgba(0,0,0,0.45) !important;
            padding: 0 !important;
        }

        /* Metric card styling */
        div[data-testid="metric-container"] {
            background: #1e2936;
            border-radius: 8px;
            padding: 12px;
            border: 1px solid #2d3f50;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


# ─────────────────────────────────────────────────────────────
# SESSION STATE INIT
# ─────────────────────────────────────────────────────────────
def _init_state() -> None:
    defaults = {
        "chat_open": False,
        "chat_history": [],
        "chat_input": "",
        "search_results": None,
        "search_explanation": "",
        "last_search_query": "",
        "view_fig": None,
        "view_code": "",
        "view_error": "",
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


# ─────────────────────────────────────────────────────────────
# DATA LOADERS
# ─────────────────────────────────────────────────────────────
@st.cache_data(show_spinner=False)
def _load_logs_cached() -> pd.DataFrame:
    return load_all_logs()


def _load_alerts() -> list[dict[str, Any]]:
    if not ALERTS_PATH.exists() or ALERTS_PATH.stat().st_size == 0:
        return []
    try:
        content = ALERTS_PATH.read_text(encoding="utf-8").strip()
        if not content:
            return []
        parsed = json.loads(content)
        return parsed if isinstance(parsed, list) else []
    except Exception as err:
        st.warning(f"Could not read alerts.json: {err}")
        return []


# ─────────────────────────────────────────────────────────────
# PIPELINE RUNNER
# ─────────────────────────────────────────────────────────────
def _run_pipeline() -> None:
    progress = st.progress(0, text="Loading logs...")
    try:
        st.cache_data.clear()
        df = load_all_logs()
        progress.progress(33, text=f"Loaded {len(df)} events. Running detection rules...")
        alerts = run_detection(df)
        progress.progress(66, text=f"Detected {len(alerts)} alerts. Running AI triage...")
        enrich_alerts_with_ai(alerts, output_path=ALERTS_PATH)
        progress.progress(100, text="Done.")
        st.success(f"Scan complete — {len(alerts)} alert(s) detected and triaged.")
    except Exception as err:
        st.error(f"Pipeline failed: {err}")
    finally:
        progress.empty()


# ─────────────────────────────────────────────────────────────
# SEVERITY HELPERS
# ─────────────────────────────────────────────────────────────
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#b45309",
    "low": "#15803d",
}


def _severity_badge(severity: str) -> str:
    sev = str(severity).lower()
    color = SEVERITY_COLORS.get(sev, "#4b5563")
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-weight:700;font-size:0.75rem;">{sev.upper()}</span>'


def _style_severity(val: Any) -> str:
    color_map = {
        "critical": "background-color:#b91c1c;color:#fff;font-weight:700;",
        "high": "background-color:#c2410c;color:#fff;font-weight:700;",
        "medium": "background-color:#b45309;color:#fff;font-weight:700;",
        "low": "background-color:#15803d;color:#fff;font-weight:700;",
    }
    return color_map.get(str(val).lower(), "")


# ─────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────
def _render_sidebar(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    """Render the sidebar and return current filter settings."""
    with st.sidebar:
        st.markdown("## 🔵 AI SOC Triage")
        st.caption("Powered by Claude AI")
        st.divider()

        if st.button("🔍 Run New Scan", use_container_width=True, type="primary"):
            _run_pipeline()
            st.rerun()

        st.divider()
        st.markdown("#### Filters")

        severities = ["critical", "high", "medium", "low"]
        selected_sev = st.multiselect(
            "Severity",
            options=severities,
            default=severities,
            key="filter_severity",
        )

        mitre_options: list[str] = sorted(
            {str(a.get("mitre_technique", "")) for a in alerts if a.get("mitre_technique")}
        )
        selected_mitre = st.multiselect(
            "MITRE Technique",
            options=mitre_options,
            default=mitre_options,
            key="filter_mitre",
        )

        computer_filter = st.text_input("Computer Name (contains)", key="filter_computer")
        ip_filter = st.text_input("Source IP (contains)", key="filter_ip")

        date_range: tuple | None = None
        if alerts:
            raw_times = [a.get("timestamp", "") for a in alerts if a.get("timestamp")]
            ts_series = pd.to_datetime(raw_times, errors="coerce", utc=True).dropna()
            if not ts_series.empty:
                from datetime import date as date_type
                min_d = ts_series.min().date()
                max_d = ts_series.max().date()
                date_range = st.date_input(
                    "Date Range",
                    value=(min_d, max_d),
                    min_value=min_d,
                    max_value=max_d,
                    key="filter_dates",
                )

        st.divider()
        st.markdown("#### Saved Views")
        saved_views = load_saved_views()
        if saved_views:
            for view in saved_views:
                if st.button(f"📊 {view['name']}", key=f"sv_{view.get('_filename','')}",
                             use_container_width=True):
                    st.session_state["_active_saved_view"] = view
                    st.session_state["active_tab_index"] = 3
        else:
            st.caption("No saved views yet. Use the Custom Views tab.")

    return {
        "severities": selected_sev,
        "mitre": selected_mitre,
        "computer": computer_filter,
        "ip": ip_filter,
        "date_range": date_range,
    }


# ─────────────────────────────────────────────────────────────
# FILTER ALERTS
# ─────────────────────────────────────────────────────────────
def _apply_filters(
    alerts: list[dict[str, Any]],
    filters: dict[str, Any],
) -> list[dict[str, Any]]:
    result = alerts
    if filters.get("severities") is not None:
        sevs = {s.lower() for s in filters["severities"]}
        result = [a for a in result if str(a.get("severity", "")).lower() in sevs]
    if filters.get("mitre"):
        mitres = set(filters["mitre"])
        result = [a for a in result if a.get("mitre_technique", "") in mitres]
    if filters.get("computer"):
        comp_q = filters["computer"].lower()
        result = [a for a in result if comp_q in str(a.get("computer", "")).lower()]
    if filters.get("ip"):
        ip_q = filters["ip"].lower()
        result = [a for a in result if ip_q in str(a.get("source_ip", "")).lower()]
    if filters.get("date_range"):
        dr = filters["date_range"]
        if isinstance(dr, (list, tuple)) and len(dr) == 2:
            start_d, end_d = dr[0], dr[1]
            filtered: list[dict[str, Any]] = []
            for a in result:
                ts = pd.to_datetime(a.get("timestamp", ""), errors="coerce", utc=True)
                if pd.isna(ts):
                    filtered.append(a)
                    continue
                if start_d <= ts.date() <= end_d:
                    filtered.append(a)
            result = filtered
    return result


# ─────────────────────────────────────────────────────────────
# SEARCH BAR
# ─────────────────────────────────────────────────────────────
def _render_search_bar(logs_df: pd.DataFrame, alerts: list[dict[str, Any]]) -> None:
    st.markdown("### 🔎 Log Search")
    col1, col2, col3 = st.columns([6, 2, 1])

    with col1:
        query = st.text_input(
            "Search",
            placeholder="Try: 'failed logins last hour' or 'event_id=4625 AND source_ip=10.0.0.1'",
            key="search_query_input",
            label_visibility="collapsed",
        )
    with col2:
        mode = st.selectbox(
            "Mode",
            options=["Auto", "Syntax", "Natural Language"],
            key="search_mode",
            label_visibility="collapsed",
        )
    with col3:
        search_clicked = st.button("Search", type="primary", use_container_width=True)

    mode_map = {"Auto": "auto", "Syntax": "syntax", "Natural Language": "nl"}

    if search_clicked and query.strip():
        target_df = logs_df if not logs_df.empty else pd.DataFrame()
        with st.spinner("Searching..."):
            results, explanation = search_logs(query, target_df, mode=mode_map[mode])
        st.session_state["search_results"] = results
        st.session_state["search_explanation"] = explanation
        st.session_state["last_search_query"] = query

    if st.session_state.get("search_results") is not None:
        results_df: pd.DataFrame = st.session_state["search_results"]
        explanation = st.session_state.get("search_explanation", "")
        st.caption(f"ℹ️ {explanation}")

        if results_df.empty:
            st.info("No results found.")
        else:
            st.success(f"{len(results_df)} result(s) found.")
            display_cols = [c for c in ["timestamp", "event_id", "computer", "user",
                                        "source_ip", "process_name", "command_line",
                                        "attack_folder"] if c in results_df.columns]
            st.dataframe(results_df[display_cols].head(200), use_container_width=True, hide_index=True)

            if st.button("Clear Search"):
                st.session_state["search_results"] = None
                st.rerun()

    st.divider()


# ─────────────────────────────────────────────────────────────
# TAB 1: DASHBOARD
# ─────────────────────────────────────────────────────────────
def _render_dashboard_tab(filtered_alerts: list[dict[str, Any]]) -> None:
    # Metric cards.
    total = len(filtered_alerts)
    critical = sum(1 for a in filtered_alerts if a.get("severity") == "critical")
    high = sum(1 for a in filtered_alerts if a.get("severity") == "high")
    fp_high = sum(
        1 for a in filtered_alerts
        if isinstance(a.get("ai_analysis"), dict)
        and a["ai_analysis"].get("false_positive_likelihood") == "high"
    )

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Alerts", total)
    m2.metric("Critical", critical)
    m3.metric("High", high)
    m4.metric("Likely False Positives", fp_high)

    if not filtered_alerts:
        st.info("No alerts match the current filters. Run a scan or adjust filters in the sidebar.")
        return

    st.markdown("---")
    st.markdown("#### Alert Table")

    # Build display DataFrame.
    rows: list[dict[str, Any]] = []
    for alert in filtered_alerts:
        ai = alert.get("ai_analysis") or {}
        if not isinstance(ai, dict):
            ai = {}
        sev = str(ai.get("severity_confirmed", alert.get("severity", "low"))).lower()
        urgency = ai.get("urgency_score", "—")
        summary = ai.get("analyst_summary", "No AI analysis.")
        mitre = ai.get("mitre_technique", alert.get("mitre_technique", ""))
        fp = ai.get("false_positive_likelihood", "—")
        rows.append({
            "Time": str(alert.get("timestamp", ""))[:19],
            "Computer": str(alert.get("computer", "")),
            "Rule": str(alert.get("rule_name", "")),
            "Severity": sev,
            "AI Summary": summary[:120] + ("…" if len(summary) > 120 else ""),
            "MITRE": mitre,
            "Score": urgency,
            "FP Risk": fp,
            "_idx": len(rows),
        })

    table_df = pd.DataFrame(rows)
    display_cols = ["Time", "Computer", "Rule", "Severity", "AI Summary", "MITRE", "Score", "FP Risk"]

    try:
        styled = (
            table_df[display_cols]
            .style.applymap(_style_severity, subset=["Severity"])
        )
        st.dataframe(styled, use_container_width=True, hide_index=True)
    except Exception:
        st.dataframe(table_df[display_cols], use_container_width=True, hide_index=True)

    # Expandable detail rows.
    st.markdown("#### Expanded Alert Details")
    for alert in filtered_alerts:
        ai = alert.get("ai_analysis") or {}
        if not isinstance(ai, dict):
            ai = {}
        sev = str(alert.get("severity", "low")).upper()
        label = f"{str(alert.get('timestamp',''))[:19]}  |  {alert.get('rule_name','')}  |  {sev}"
        sev_color = SEVERITY_COLORS.get(sev.lower(), "#4b5563")

        with st.expander(label):
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(f"**Alert ID:** `{alert.get('alert_id','')[:8]}…`")
                st.markdown(f"**Rule:** {alert.get('rule_name','')}")
                st.markdown(f"**Severity:** {_severity_badge(sev)}", unsafe_allow_html=True)
                st.markdown(f"**MITRE:** {ai.get('mitre_technique', alert.get('mitre_technique',''))}")
                st.markdown(f"**Urgency Score:** {ai.get('urgency_score','—')}/10")
                st.markdown(f"**False Positive Risk:** {ai.get('false_positive_likelihood','—')}")
                if ai.get("false_positive_reason"):
                    st.caption(f"Reason: {ai['false_positive_reason']}")
            with c2:
                st.markdown(f"**Computer:** {alert.get('computer','')}")
                st.markdown(f"**User:** {alert.get('user','')}")
                st.markdown(f"**Source IP:** {alert.get('source_ip','')}")
                st.markdown(f"**Process:** {alert.get('process_name','')}")
                st.markdown(f"**Attack Folder:** {alert.get('attack_folder','')}")
                st.markdown(f"**Source File:** {alert.get('source_file','')}")

            if ai.get("analyst_summary"):
                st.markdown("**AI Analysis:**")
                st.info(ai["analyst_summary"])

            if ai.get("recommended_actions"):
                st.markdown("**Recommended Actions:**")
                for action in ai["recommended_actions"]:
                    st.markdown(f"- {action}")

            if ai.get("investigation_steps"):
                st.markdown("**Investigation Steps:**")
                for i, step in enumerate(ai["investigation_steps"], 1):
                    st.markdown(f"{i}. {step}")

            if alert.get("command_line"):
                st.markdown("**Command Line:**")
                st.code(alert["command_line"], language="powershell")

            with st.expander("Raw Event Data"):
                st.json(alert.get("event_data", {}))


# ─────────────────────────────────────────────────────────────
# TAB 2: ANALYTICS
# ─────────────────────────────────────────────────────────────
def _render_analytics_tab(filtered_alerts: list[dict[str, Any]], logs_df: pd.DataFrame) -> None:
    if not filtered_alerts:
        st.info("No alerts to visualise. Run a scan first.")
        return

    alerts_df = pd.DataFrame(filtered_alerts)
    alerts_df["timestamp_dt"] = pd.to_datetime(alerts_df.get("timestamp", pd.Series(dtype="object")), errors="coerce", utc=True)

    col1, col2 = st.columns(2)

    with col1:
        sev_counts = alerts_df["severity"].value_counts().reindex(
            ["critical", "high", "medium", "low"], fill_value=0
        ).reset_index()
        sev_counts.columns = ["Severity", "Count"]
        fig_sev = px.bar(
            sev_counts,
            x="Severity", y="Count",
            color="Severity",
            color_discrete_map={
                "critical": "#b91c1c", "high": "#c2410c",
                "medium": "#b45309", "low": "#15803d",
            },
            title="Alerts by Severity",
        )
        fig_sev.update_layout(showlegend=False)
        st.plotly_chart(fig_sev, use_container_width=True)

    with col2:
        mitre_counts = alerts_df["mitre_technique"].value_counts().head(8).reset_index()
        mitre_counts.columns = ["MITRE Technique", "Count"]
        fig_mitre = px.pie(
            mitre_counts,
            names="MITRE Technique",
            values="Count",
            title="Alerts by MITRE Technique",
        )
        fig_mitre.update_traces(textposition="inside", textinfo="percent+label")
        st.plotly_chart(fig_mitre, use_container_width=True)

    # Timeline: alerts per hour.
    if alerts_df["timestamp_dt"].notna().any():
        timeline_df = alerts_df.dropna(subset=["timestamp_dt"]).copy()
        timeline_df["hour"] = timeline_df["timestamp_dt"].dt.floor("h")
        timeline_counts = timeline_df.groupby(["hour", "severity"]).size().reset_index(name="count")
        fig_time = px.line(
            timeline_counts,
            x="hour", y="count",
            color="severity",
            color_discrete_map={
                "critical": "#b91c1c", "high": "#c2410c",
                "medium": "#b45309", "low": "#15803d",
            },
            title="Alerts Over Time (by Hour)",
            markers=True,
        )
        st.plotly_chart(fig_time, use_container_width=True)

    # Top source IPs.
    ip_data = alerts_df[alerts_df["source_ip"].str.strip().ne("")]
    if not ip_data.empty:
        top_ips = ip_data["source_ip"].value_counts().head(10).reset_index()
        top_ips.columns = ["Source IP", "Alert Count"]
        fig_ips = px.bar(
            top_ips.sort_values("Alert Count"),
            x="Alert Count", y="Source IP",
            orientation="h",
            title="Top 10 Source IPs by Alert Count",
            color="Alert Count",
            color_continuous_scale="Reds",
        )
        st.plotly_chart(fig_ips, use_container_width=True)

    # Heatmap: alerts by hour × day of week.
    if alerts_df["timestamp_dt"].notna().any():
        heatmap_df = alerts_df.dropna(subset=["timestamp_dt"]).copy()
        heatmap_df["hour_of_day"] = heatmap_df["timestamp_dt"].dt.hour
        heatmap_df["day_of_week"] = heatmap_df["timestamp_dt"].dt.day_name()
        day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        heatmap_pivot = (
            heatmap_df.groupby(["day_of_week", "hour_of_day"])
            .size()
            .reset_index(name="count")
        )
        heatmap_pivot["day_of_week"] = pd.Categorical(
            heatmap_pivot["day_of_week"], categories=day_order, ordered=True
        )
        heatmap_pivot = heatmap_pivot.sort_values(["day_of_week", "hour_of_day"])
        fig_heat = px.density_heatmap(
            heatmap_pivot,
            x="hour_of_day",
            y="day_of_week",
            z="count",
            title="Alert Heatmap: Hour of Day × Day of Week",
            color_continuous_scale="Reds",
            labels={"hour_of_day": "Hour of Day", "day_of_week": "Day"},
        )
        st.plotly_chart(fig_heat, use_container_width=True)

    # Attack folder breakdown (from log data).
    if not logs_df.empty and "attack_folder" in logs_df.columns:
        folder_counts = (
            logs_df["attack_folder"]
            .replace("", pd.NA)
            .dropna()
            .value_counts()
            .reset_index()
        )
        folder_counts.columns = ["Attack Category", "Event Count"]
        if not folder_counts.empty:
            fig_folder = px.bar(
                folder_counts,
                x="Attack Category",
                y="Event Count",
                title="Events by MITRE ATT&CK Category",
                color="Event Count",
                color_continuous_scale="Blues",
            )
            st.plotly_chart(fig_folder, use_container_width=True)


# ─────────────────────────────────────────────────────────────
# TAB 3: LOG EXPLORER
# ─────────────────────────────────────────────────────────────
def _render_log_explorer_tab(logs_df: pd.DataFrame) -> None:
    if logs_df.empty:
        st.info("No logs loaded. Place .evtx files in data/raw_logs/ and click 'Run New Scan'.")
        return

    # Stats banner.
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Events", len(logs_df))
    ts_col = pd.to_datetime(logs_df["timestamp"], errors="coerce", utc=True)
    valid_ts = ts_col.dropna()
    if not valid_ts.empty:
        c2.metric("Earliest Event", str(valid_ts.min().date()))
        c3.metric("Latest Event", str(valid_ts.max().date()))

    # Event ID distribution mini-chart.
    if "event_id" in logs_df.columns:
        eid_counts = logs_df["event_id"].value_counts().head(10).reset_index()
        eid_counts.columns = ["Event ID", "Count"]
        fig_eid = px.bar(eid_counts, x="Event ID", y="Count", title="Top 10 Event IDs")
        st.plotly_chart(fig_eid, use_container_width=True)

    # Column selector.
    available_cols = list(logs_df.columns)
    exclude_heavy = ["raw_data", "raw_message"]
    default_cols = [c for c in available_cols if c not in exclude_heavy]
    selected_cols = st.multiselect(
        "Columns to display",
        options=available_cols,
        default=default_cols,
        key="log_explorer_cols",
    )

    # Pagination.
    page_size = 100
    total_pages = max(1, (len(logs_df) + page_size - 1) // page_size)
    page = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1)
    start = (page - 1) * page_size
    end = start + page_size
    page_df = logs_df.iloc[start:end]

    if selected_cols:
        show_cols = [c for c in selected_cols if c in page_df.columns]
        if show_cols:
            st.dataframe(page_df[show_cols], use_container_width=True, hide_index=True)
    st.caption(f"Showing rows {start + 1}–{min(end, len(logs_df))} of {len(logs_df)}")

    # CSV download.
    csv_data = logs_df[[c for c in (selected_cols or default_cols) if c in logs_df.columns]].to_csv(index=False).encode("utf-8")
    st.download_button(
        label="⬇️ Download as CSV",
        data=csv_data,
        file_name="soc_logs_export.csv",
        mime="text/csv",
    )


# ─────────────────────────────────────────────────────────────
# TAB 4: CUSTOM VIEWS
# ─────────────────────────────────────────────────────────────
def _render_custom_views_tab(logs_df: pd.DataFrame, alerts: list[dict[str, Any]]) -> None:
    st.markdown("#### Create New View")

    view_description = st.text_area(
        "Describe the chart you want",
        placeholder="e.g. Show a heatmap of alerts by hour and day of week, coloured by severity",
        key="new_view_description",
        height=80,
    )
    view_name = st.text_input("View name", placeholder="My Custom Chart", key="new_view_name")

    # Choose data source for the view.
    data_source = st.radio(
        "Data source",
        options=["Log Events", "Alerts"],
        horizontal=True,
        key="view_data_source",
    )

    if st.button("✨ Generate View", type="primary"):
        if not view_description.strip():
            st.warning("Enter a description first.")
        elif logs_df.empty and data_source == "Log Events":
            st.warning("No log data loaded — run a scan first.")
        else:
            source_df = logs_df if data_source == "Log Events" else pd.DataFrame(alerts)
            with st.spinner("Generating chart with Claude AI…"):
                fig, result = build_view(view_description, source_df)
            if fig is not None:
                st.session_state["view_fig"] = fig
                st.session_state["view_code"] = result
                st.session_state["view_error"] = ""
                st.success("Chart generated!")
            else:
                st.session_state["view_fig"] = None
                st.session_state["view_error"] = result
                st.error(f"Generation failed: {result}")

    if st.session_state.get("view_fig") is not None:
        st.plotly_chart(st.session_state["view_fig"], use_container_width=True)

        with st.expander("Generated code"):
            st.code(st.session_state.get("view_code", ""), language="python")

        if st.button("💾 Save View") and view_name.strip():
            save_view(
                name=view_name.strip(),
                description=view_description.strip(),
                code=st.session_state.get("view_code", ""),
            )
            st.success(f"View '{view_name}' saved!")
            st.rerun()

    if st.session_state.get("view_error"):
        st.error(st.session_state["view_error"])

    # ── Saved views grid ──
    st.markdown("---")
    st.markdown("#### Saved Views")
    saved_views = load_saved_views()

    if not saved_views:
        st.caption("No views saved yet.")
        return

    # Check if a view was clicked from the sidebar.
    active_view = st.session_state.pop("_active_saved_view", None)

    cols = st.columns(2)
    for idx, view in enumerate(saved_views):
        with cols[idx % 2]:
            with st.container():
                st.markdown(f"**{view.get('name', 'Unnamed')}**")
                st.caption(view.get("description", "")[:100])
                st.caption(f"Created: {view.get('created_at', '')[:10]}")

                source_df_saved = logs_df if not logs_df.empty else pd.DataFrame(alerts)
                show_this = active_view and active_view.get("_filename") == view.get("_filename")

                if st.button("Render", key=f"render_{idx}") or show_this:
                    fig = render_saved_view(view, source_df_saved)
                    if fig:
                        st.plotly_chart(fig, use_container_width=True)
                    else:
                        st.error("Failed to render view.")

                if st.button("🗑️ Delete", key=f"del_{idx}"):
                    if delete_saved_view(view):
                        st.success(f"Deleted '{view.get('name','')}'")
                        st.rerun()


# ─────────────────────────────────────────────────────────────
# FLOATING CHAT BUTTON + PANEL
# ─────────────────────────────────────────────────────────────
def _render_chat_panel(logs_df: pd.DataFrame, alerts: list[dict[str, Any]]) -> None:
    """Render the floating AI chat button and the chat panel when open."""

    # Anchor element — the CSS selector targets the button immediately following this.
    st.markdown('<span id="chat-float-anchor"></span>', unsafe_allow_html=True)
    chat_label = "✕" if st.session_state.get("chat_open") else "💬"
    if st.button(chat_label, key="floating_chat_btn"):
        st.session_state["chat_open"] = not st.session_state.get("chat_open", False)
        st.rerun()

    if not st.session_state.get("chat_open"):
        return

    st.markdown("---")
    st.markdown("### 🤖 Ask AI about your logs")
    st.caption("Claude has access to your current log data and alerts as context.")

    # Chat history display.
    history = st.session_state.get("chat_history", [])
    chat_container = st.container()
    with chat_container:
        for msg in history:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            ts = msg.get("timestamp", "")
            if role == "user":
                st.markdown(
                    f'<div class="chat-user"><b>You:</b> {content}</div>'
                    f'<div class="chat-timestamp" style="text-align:right">{ts}</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f'<div class="chat-assistant"><b>AI:</b> {content}</div>'
                    f'<div class="chat-timestamp">{ts}</div>',
                    unsafe_allow_html=True,
                )

    # Input row.
    inp_col, btn_col, clr_col = st.columns([7, 1, 1])
    with inp_col:
        user_msg = st.text_input(
            "Message",
            key="chat_msg_input",
            placeholder="Ask about your logs, alerts, or threat activity…",
            label_visibility="collapsed",
        )
    with btn_col:
        send = st.button("Send", type="primary", use_container_width=True)
    with clr_col:
        if st.button("Clear", use_container_width=True):
            st.session_state["chat_history"] = []
            st.rerun()

    if send and user_msg.strip():
        with st.spinner("Thinking…"):
            response, updated_history = ai_chat_fn(
                message=user_msg,
                history=history,
                df=logs_df,
                alerts=alerts,
            )
        st.session_state["chat_history"] = updated_history
        st.rerun()


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
def main() -> None:
    _inject_css()
    _init_state()

    # Load data.
    logs_df = _load_logs_cached()
    alerts = _load_alerts()

    # Sidebar filters.
    filters = _render_sidebar(alerts)

    # Apply filters.
    filtered_alerts = _apply_filters(alerts, filters)

    # Search bar (full width, above tabs).
    _render_search_bar(logs_df, alerts)

    # Main tabs.
    tab1, tab2, tab3, tab4 = st.tabs(["📋 Dashboard", "📊 Analytics", "🔬 Log Explorer", "✨ Custom Views"])

    with tab1:
        _render_dashboard_tab(filtered_alerts)

    with tab2:
        _render_analytics_tab(filtered_alerts, logs_df)

    with tab3:
        _render_log_explorer_tab(logs_df)

    with tab4:
        _render_custom_views_tab(logs_df, alerts)

    # Floating chat (renders at bottom of page).
    _render_chat_panel(logs_df, alerts)


if __name__ == "__main__":
    main()
