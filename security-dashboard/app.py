"""
MCP-Sentinel Security Dashboard
Dark-mode Streamlit UI for live audit of intercepted MCP traffic.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import pandas as pd
import requests
import streamlit as st
from streamlit_autorefresh import st_autorefresh

PROXY_BASE_URL = os.getenv("PROXY_BASE_URL", "http://localhost:8080").rstrip("/")
REFRESH_SECONDS = int(os.getenv("DASHBOARD_REFRESH_SECONDS", "5"))

st.set_page_config(
    page_title="MCP-Sentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    :root {
        --bg: #0b1220;
        --panel: #121a2b;
        --border: #1e2a44;
        --text: #e8eefc;
        --muted: #8b9bb8;
        --accent: #3dd6c6;
        --danger: #ff5c7a;
        --ok: #3ecf8e;
    }

    .stApp {
        background: radial-gradient(1200px 600px at 10% -10%, #152238 0%, var(--bg) 55%);
        color: var(--text);
        font-family: 'IBM Plex Sans', sans-serif;
    }

    .block-container { padding-top: 1.5rem; padding-bottom: 2rem; max-width: 1400px; }

    h1, h2, h3 { font-family: 'IBM Plex Sans', sans-serif !important; letter-spacing: -0.02em; }

    .hero-title {
        font-size: 2rem; font-weight: 700; margin: 0;
        background: linear-gradient(90deg, #e8eefc, #3dd6c6);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    }
    .hero-sub { color: var(--muted); margin-top: 0.35rem; margin-bottom: 1.25rem; font-size: 0.95rem; }

    .metric-card {
        background: linear-gradient(180deg, #152238 0%, var(--panel) 100%);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 1.1rem 1.25rem;
        min-height: 110px;
    }
    .metric-label { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.08em; }
    .metric-value { font-size: 2.1rem; font-weight: 700; margin-top: 0.35rem; font-family: 'JetBrains Mono', monospace; }
    .metric-value.ok { color: var(--ok); }
    .metric-value.danger { color: var(--danger); }
    .metric-value.accent { color: var(--accent); }

    div[data-testid="stDataFrame"] { border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
    footer { visibility: hidden; }
    </style>
    """,
    unsafe_allow_html=True,
)


def fetch_json(path: str) -> Any:
    url = f"{PROXY_BASE_URL}{path}"
    response = requests.get(url, timeout=8)
    response.raise_for_status()
    return response.json()


def load_metrics() -> dict[str, Any]:
    return fetch_json("/api/audit/metrics")


def load_logs() -> list[dict[str, Any]]:
    data = fetch_json("/api/audit/logs")
    return data if isinstance(data, list) else []


def format_timestamp(value: Any) -> str:
    if value is None:
        return "—"
    try:
        if isinstance(value, (int, float)):
            dt = datetime.fromtimestamp(value / 1000 if value > 1e12 else value, tz=timezone.utc)
        else:
            text = str(value).replace("Z", "+00:00")
            dt = datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(value)


st_autorefresh(interval=REFRESH_SECONDS * 1000, key="mcp_sentinel_refresh")

st.markdown('<p class="hero-title">MCP-Sentinel</p>', unsafe_allow_html=True)
st.markdown(
    '<p class="hero-sub">Zero-Trust Agent Firewall · Live MCP traffic interception &amp; audit</p>',
    unsafe_allow_html=True,
)

error_message: str | None = None
metrics: dict[str, Any] = {
    "total_requests": 0,
    "threats_blocked": 0,
    "active_mcp_connections": 0,
}
logs: list[dict[str, Any]] = []

try:
    metrics = load_metrics()
    logs = load_logs()
except requests.RequestException as exc:
    error_message = f"Unable to reach mcp-proxy at `{PROXY_BASE_URL}`: {exc}"

if error_message:
    st.error(error_message)
else:
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            f"""
            <div class="metric-card">
              <div class="metric-label">Total Requests</div>
              <div class="metric-value accent">{metrics.get("total_requests", 0)}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f"""
            <div class="metric-card">
              <div class="metric-label">Threats Blocked</div>
              <div class="metric-value danger">{metrics.get("threats_blocked", 0)}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f"""
            <div class="metric-card">
              <div class="metric-label">Active MCP Connections</div>
              <div class="metric-value ok">{metrics.get("active_mcp_connections", 0)}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("### Audit Trail")
    st.caption(f"Auto-refresh every {REFRESH_SECONDS}s · Source: {PROXY_BASE_URL}/api/audit/logs")

    if not logs:
        st.info("No intercepted MCP traffic yet. POST tool calls to `/v1/mcp/execute` to populate the audit trail.")
    else:
        rows = []
        for entry in logs:
            status = str(entry.get("status", "")).upper()
            rows.append(
                {
                    "Timestamp": format_timestamp(entry.get("timestamp")),
                    "Tool Name": entry.get("toolName") or entry.get("tool_name") or "—",
                    "Status": status,
                    "Agent ID": entry.get("agentId") or entry.get("agent_id") or "—",
                    "Session ID": entry.get("sessionId") or entry.get("session_id") or "—",
                    "Reason": entry.get("reason") or "",
                    "Payload": entry.get("payload") or "",
                }
            )

        df = pd.DataFrame(rows)

        filter_col, search_col = st.columns([1, 2])
        with filter_col:
            status_filter = st.selectbox("Status filter", options=["ALL", "ALLOWED", "BLOCKED"], index=0)
        with search_col:
            query = st.text_input("Search tool / payload", placeholder="e.g. bash, read_file, rm -rf")

        view = df.copy()
        if status_filter != "ALL":
            view = view[view["Status"] == status_filter]
        if query:
            q = query.lower()
            mask = (
                view["Tool Name"].astype(str).str.lower().str.contains(q, na=False)
                | view["Payload"].astype(str).str.lower().str.contains(q, na=False)
                | view["Reason"].astype(str).str.lower().str.contains(q, na=False)
            )
            view = view[mask]

        st.dataframe(
            view,
            use_container_width=True,
            height=480,
            hide_index=True,
            column_config={
                "Timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                "Tool Name": st.column_config.TextColumn("Tool Name", width="small"),
                "Status": st.column_config.TextColumn("Status", width="small"),
                "Payload": st.column_config.TextColumn("Payload", width="large"),
                "Reason": st.column_config.TextColumn("Reason", width="medium"),
            },
        )

        blocked = int((df["Status"] == "BLOCKED").sum())
        allowed = int((df["Status"] == "ALLOWED").sum())
        st.caption(f"Showing {len(view)} of {len(df)} events · {allowed} allowed · {blocked} blocked")
