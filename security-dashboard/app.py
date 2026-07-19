"""
MCP-Sentinel Security Dashboard
Dark-mode Streamlit UI for live audit of intercepted MCP traffic.
Surfaces OWASP MCP Top 10 rejection reasons (DNS rebinding, tool poisoning, FGA).
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

KNOWN_REJECTION_REASONS = [
    "DNS Rebinding Blocked",
    "Tool Poisoning Detected",
    "FGA Scope Violation",
    "Path traversal or sensitive path access blocked",
    "Unauthorized shell/bash command blocked",
    "Missing or invalid Bearer token",
]

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
        --warn: #f5c542;
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
    .metric-value.warn { color: var(--warn); }

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


def classify_threat(reason: str) -> str:
    if not reason:
        return "—"
    r = reason.lower()
    if "dns rebinding" in r:
        return "DNS Rebinding"
    if "tool poisoning" in r:
        return "Tool Poisoning"
    if "fga scope" in r:
        return "FGA Violation"
    if "path traversal" in r or "/etc/" in r:
        return "Path Traversal"
    if "shell" in r or "bash" in r or "mcp05" in r or "pipe" in r or "chaining" in r:
        return "Command Injection"
    if "bearer" in r or "unauthorized" in r or "token" in r:
        return "Auth Failure"
    return "Policy Block"


st_autorefresh(interval=REFRESH_SECONDS * 1000, key="mcp_sentinel_refresh")

st.markdown('<p class="hero-title">MCP-Sentinel</p>', unsafe_allow_html=True)
st.markdown(
    '<p class="hero-sub">Zero-Trust Agent Firewall · OWASP MCP Top 10 defenses · Live audit</p>',
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
    c1, c2, c3, c4 = st.columns(4)
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

    rows = []
    for entry in logs:
        status = str(entry.get("status", "")).upper()
        reason = entry.get("reason") or ""
        # Agent ID is stamped from the authenticated Bearer token by the proxy
        agent_id = entry.get("agentId") or entry.get("agent_id") or "—"
        rows.append(
            {
                "Timestamp": format_timestamp(entry.get("timestamp")),
                "Tool Name": entry.get("toolName") or entry.get("tool_name") or "—",
                "Status": status,
                "Agent ID": agent_id,
                "Threat Class": classify_threat(reason) if status == "BLOCKED" else "—",
                "Reason": reason,
                "Session ID": entry.get("sessionId") or entry.get("session_id") or "—",
                "Payload": entry.get("payload") or "",
            }
        )

    with c4:
        fga_count = sum(1 for r in rows if "FGA Scope Violation" in str(r.get("Reason", "")))
        poison_count = sum(1 for r in rows if "Tool Poisoning Detected" in str(r.get("Reason", "")))
        dns_count = sum(1 for r in rows if "DNS Rebinding Blocked" in str(r.get("Reason", "")))
        st.markdown(
            f"""
            <div class="metric-card">
              <div class="metric-label">OWASP MCP Blocks</div>
              <div class="metric-value warn">{fga_count + poison_count + dns_count}</div>
              <div style="color:#8b9bb8;font-size:0.75rem;margin-top:0.35rem;">
                FGA {fga_count} · Poison {poison_count} · DNS {dns_count}
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("### Audit Trail")
    st.caption(
        f"Auto-refresh every {REFRESH_SECONDS}s · Agent ID is resolved from Bearer token (FGA) · "
        f"API: localhost:8080/api/audit/logs"
    )

    if not rows:
        st.info(
            "No intercepted MCP traffic yet. POST authenticated tool calls to `/v1/mcp/execute` "
            "(Authorization: Bearer + trusted Origin/Host) to populate the audit trail."
        )
    else:
        df = pd.DataFrame(rows)

        filter_col, reason_col, search_col = st.columns([1, 1, 2])
        with filter_col:
            status_filter = st.selectbox("Status filter", options=["ALL", "ALLOWED", "BLOCKED"], index=0)
        with reason_col:
            reason_options = ["ALL"] + KNOWN_REJECTION_REASONS + ["Other"]
            reason_filter = st.selectbox("Rejection reason", options=reason_options, index=0)
        with search_col:
            query = st.text_input(
                "Search agent / tool / payload",
                placeholder="e.g. agent-alpha, FGA Scope Violation, ../",
            )

        view = df.copy()
        if status_filter != "ALL":
            view = view[view["Status"] == status_filter]
        if reason_filter != "ALL":
            if reason_filter == "Other":
                view = view[
                    (view["Status"] == "BLOCKED")
                    & (~view["Reason"].isin(KNOWN_REJECTION_REASONS))
                    & (view["Reason"].astype(str).str.len() > 0)
                ]
            else:
                view = view[view["Reason"] == reason_filter]
        if query:
            q = query.lower()
            mask = (
                view["Tool Name"].astype(str).str.lower().str.contains(q, na=False)
                | view["Agent ID"].astype(str).str.lower().str.contains(q, na=False)
                | view["Payload"].astype(str).str.lower().str.contains(q, na=False)
                | view["Reason"].astype(str).str.lower().str.contains(q, na=False)
                | view["Threat Class"].astype(str).str.lower().str.contains(q, na=False)
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
                "Agent ID": st.column_config.TextColumn("Agent ID", width="small"),
                "Threat Class": st.column_config.TextColumn("Threat Class", width="medium"),
                "Reason": st.column_config.TextColumn("Reason", width="medium"),
                "Payload": st.column_config.TextColumn("Payload", width="large"),
            },
        )

        blocked = int((df["Status"] == "BLOCKED").sum())
        allowed = int((df["Status"] == "ALLOWED").sum())
        st.caption(f"Showing {len(view)} of {len(df)} events · {allowed} allowed · {blocked} blocked")
