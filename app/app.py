"""Streamlit application for the improved PQC triage prototype."""

from __future__ import annotations

import io
import base64
import hashlib
import html
import json
import os
import sqlite3
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agents import ALL_AGENTS, AGENT_ICONS
from apecps import ProofEvent, ProofTrace, create_event
from scanner import scan_endpoints, scan_repository


SEVERITY_COLORS = {"high": "#dc2626", "medium": "#d97706", "low": "#059669"}
KIND_COLORS = {
    "premise": "#2563eb",
    "support": "#16a34a",
    "attack": "#dc2626",
    "warrant": "#7c3aed",
    "claim": "#0f766e",
    "validation": "#334155",
}
KIND_ICONS = {
    "premise": "[scan]",
    "support": "[support]",
    "attack": "[attack]",
    "warrant": "[warrant]",
    "claim": "[plan]",
    "validation": "[review]",
}
AI_ROLE_AGENTS = {
    "risk_claim": "AI Risk Analyst",
    "supporting_argument": "AI Evidence Analyst",
    "migration_recommendation": "AI Migration Planner",
    "counterargument": "AI Compatibility Critic",
    "human_review_request": "AI Trust Reviewer",
}


APP_TITLE = "APEC-PS"
APP_TAGLINE = "Argumentation for Trustworthy Agentic AI"
APP_SUBTITLE = "Post-Quantum Cryptography Risk Triage"
LOGO_PATH = ROOT / "assets" / "apec-ps-logo.png"
DB_PATH = ROOT / "apecps_history.db"
PROJECT_AUTHOR = "Sofia Almpani"
PROJECT_AFFILIATION = "School of Applied Mathematical and Physical Sciences, National Technical University of Athens, Greece"
PROJECT_EMAIL = "s.almpani@gmail.com"
PROJECT_DEMO_URL = "https://apec-ps.streamlit.app/"
PROJECT_SOURCE_URL = "https://github.com/salmpani/APEC_PS"
PROJECT_YEAR = "2026"
PROJECT_RIGHTS = "Copyright (c) 2026 Sofia Almpani. All rights reserved unless explicitly licensed otherwise."
PROJECT_USAGE = "Academic demonstration and research prototype. Not certified for production security use."
PROJECT_CITATION = f"Sofia Almpani, APEC-PS: Argumentation for Trustworthy Agentic AI - Post-Quantum Cryptography Risk Triage, 2026. Source code: {PROJECT_SOURCE_URL}. Live demo: {PROJECT_DEMO_URL}"
DEMO_SCENARIOS = {
    "Payment API PQC triage": {
        "path": ROOT / "sample_repo",
        "project_name": "demo-payment-api",
        "summary": "Small repository with payment API configuration, RSA/ECDSA key generation, and certificate evidence.",
        "presentation_angle": "Best for a short end-to-end explanation of finding -> risk -> compatibility challenge -> review.",
    },
    "Partner cloud gateway": {
        "path": ROOT / "sample_upload_repo",
        "project_name": "demo-partner-gateway",
        "summary": "Richer repository with gateway YAML, Terraform TLS policy, Python signing code, JavaScript token signing, and certificate material.",
        "presentation_angle": "Best for showing a more realistic repository with multiple evidence sources.",
    },
    "Internal CA migration": {
        "path": ROOT / "sample_internal_ca",
        "project_name": "demo-internal-ca",
        "summary": "Focused PKI scenario with internal CA configuration, RSA certificates, SHA-1 signing, and long-lived identity data.",
        "presentation_angle": "Best for explaining certificate and signature migration planning.",
    },
}
NAV_SECTIONS = [
    ("OVERVIEW", ["Demo Mode", "Dashboard", "About"], ["One-click scenario", "Executive summary", "Author and rights"]),
    ("INPUT", ["Repository", "Findings"], ["Select source", "Scan findings"]),
    ("REASONING", ["Agents", "Agentic AI", "Argument Graphs", "Debate"], ["Specialist trace", "Central AI coordinator", "Graph inspection", "Argumentation view"]),
    ("OUTPUT", ["Review", "History", "Report"], ["Human decision", "Past scans", "Export evidence"]),
]

st.set_page_config(page_title=f"{APP_TITLE} - {APP_SUBTITLE}", layout="wide")
st.markdown(
    """
    <style>
      :root {
        --apec-navy: #07185f;
        --apec-blue: #0ea5e9;
        --apec-cyan: #38bdf8;
        --apec-magenta: #b516b5;
        --apec-ink: #0f172a;
        --apec-muted: #64748b;
        --apec-panel: #ffffff;
        --apec-line: #d8e0ea;
      }
      .stApp { background: #f8fafc; color: #0f172a; }
      [data-testid="stSidebar"] { background: #eef2f7; }
      .stApp,
      .stApp p,
      .stApp span,
      .stApp label,
      .stApp div,
      [data-testid="stSidebar"],
      [data-testid="stSidebar"] p,
      [data-testid="stSidebar"] span,
      [data-testid="stSidebar"] label,
      [data-testid="stSidebar"] div {
        color: #0f172a;
      }
      .stMarkdown,
      .stMarkdown p,
      .stCaptionContainer,
      .stText,
      [data-testid="stWidgetLabel"],
      [data-testid="stWidgetLabel"] p {
        color: #0f172a !important;
      }
      input,
      textarea,
      div[data-baseweb="select"] > div,
      div[data-baseweb="input"] > div,
      div[data-baseweb="textarea"] > div {
        background: #ffffff !important;
        color: #0f172a !important;
        border-color: #cbd5e1 !important;
      }
      input::placeholder,
      textarea::placeholder {
        color: #64748b !important;
      }
      div[role="listbox"],
      div[role="option"],
      div[data-baseweb="popover"] {
        background: #ffffff !important;
        color: #0f172a !important;
      }
      div[role="option"]:hover {
        background: #e0f2fe !important;
      }
      .block-container { padding-top: 1.25rem; }
      .section-card {
        background: var(--apec-panel);
        border: 1px solid var(--apec-line);
        border-radius: 8px;
        padding: 16px;
        box-shadow: 0 1px 2px rgba(15, 23, 42, 0.05);
        margin: 8px 0 14px 0;
      }
      .metric-card {
        background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
        border: 1px solid var(--apec-line);
        border-top: 4px solid var(--card-accent, var(--apec-blue));
        border-radius: 8px;
        padding: 14px 16px;
        min-height: 112px;
        box-shadow: 0 1px 2px rgba(15, 23, 42, 0.06);
      }
      .metric-card .metric-label {
        color: var(--apec-muted);
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: .04em;
        margin-bottom: 8px;
      }
      .metric-card .metric-value {
        color: var(--apec-ink);
        font-size: 32px;
        line-height: 1;
        font-weight: 800;
        margin-bottom: 8px;
      }
      .metric-card .metric-note {
        color: var(--apec-muted);
        font-size: 13px;
        line-height: 1.25;
      }
      .status-badge {
        display: inline-block;
        border-radius: 999px;
        padding: 3px 9px;
        font-size: 12px;
        font-weight: 700;
        background: #e2e8f0;
        color: #0f172a;
      }
      .decision-step {
        background: #ffffff;
        border: 1px solid #d8e0ea;
        border-left: 4px solid var(--step-accent, #0ea5e9);
        border-radius: 8px;
        padding: 12px 14px;
        min-height: 132px;
        box-shadow: 0 1px 2px rgba(15, 23, 42, 0.05);
      }
      .decision-step h4 {
        margin: 0 0 6px 0;
        color: #07185f;
        font-size: 15px;
      }
      .decision-step p {
        margin: 0;
        color: #334155;
        font-size: 13px;
        line-height: 1.35;
      }
      .conversation-card {
        background: #ffffff;
        border: 1px solid #d8e0ea;
        border-left: 4px solid var(--agent-accent, #0ea5e9);
        border-radius: 8px;
        padding: 12px 14px;
        margin: 8px 0;
      }
      .conversation-meta {
        color: #64748b;
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: .03em;
        margin-bottom: 4px;
      }
      .conversation-claim {
        color: #0f172a;
        font-size: 14px;
        line-height: 1.4;
      }
      .conversation-refs {
        color: #64748b;
        font-size: 12px;
        margin-top: 6px;
      }
      .download-card {
        background: #ffffff;
        border: 1px solid var(--apec-line);
        border-radius: 8px;
        padding: 14px;
        margin-bottom: 10px;
      }
      .download-card h4 {
        margin: 0 0 4px 0;
        color: var(--apec-navy);
      }
      .download-card p {
        margin: 0;
        color: var(--apec-muted) !important;
        font-size: 13px;
      }
      .walkthrough-step {
        background: #ffffff;
        border: 1px solid var(--apec-line);
        border-left: 4px solid var(--apec-blue);
        border-radius: 8px;
        padding: 12px 14px;
        margin-bottom: 10px;
        min-height: 116px;
      }
      .walkthrough-step .step-number {
        color: var(--apec-magenta);
        font-weight: 800;
        font-size: 13px;
        text-transform: uppercase;
        letter-spacing: .04em;
      }
      .walkthrough-step .step-title {
        color: var(--apec-navy);
        font-weight: 800;
        font-size: 17px;
        margin: 4px 0;
      }
      .walkthrough-step .step-text {
        color: var(--apec-muted) !important;
        font-size: 13px;
        line-height: 1.32;
      }
      .preview-card {
        background: #ffffff;
        border: 1px solid var(--apec-line);
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 14px;
        box-shadow: 0 1px 2px rgba(15, 23, 42, 0.05);
      }
      .preview-card h3 {
        margin-top: 0;
        color: var(--apec-navy);
      }
      .source-card {
        background: #ffffff;
        border: 1px solid var(--apec-line);
        border-left: 4px solid var(--apec-blue);
        border-radius: 8px;
        padding: 14px 16px;
        min-height: 120px;
        margin-bottom: 12px;
      }
      .source-card h4 {
        margin: 0 0 6px 0;
        color: var(--apec-navy);
      }
      .source-card p {
        margin: 0;
        color: var(--apec-muted) !important;
        font-size: 13px;
        line-height: 1.35;
      }
      .empty-state {
        background: #ffffff;
        border: 1px dashed #94a3b8;
        border-radius: 8px;
        padding: 22px;
        margin: 12px 0;
      }
      .empty-state h3 {
        margin: 0 0 6px 0;
        color: var(--apec-navy);
      }
      .empty-state p {
        margin: 0;
        color: var(--apec-muted) !important;
      }
      .report-cover {
        background: linear-gradient(180deg, #ffffff 0%, #eff6ff 100%);
        border: 1px solid var(--apec-line);
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 16px;
      }
      .report-cover h2 {
        color: var(--apec-navy);
        margin-top: 0;
      }
      .trace-chip {
        display: inline-block;
        border: 1px solid #cbd5e1;
        background: #f8fafc;
        border-radius: 999px;
        padding: 3px 8px;
        margin: 2px;
        font-size: 12px;
        color: #0f172a !important;
      }
      .nav-section {
        margin-top: 14px;
        padding-top: 10px;
        border-top: 1px solid #cbd5e1;
        color: var(--apec-navy) !important;
        font-size: 12px;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: .06em;
      }
      .nav-hint {
        color: #64748b !important;
        font-size: 12px;
        margin-top: -4px;
        margin-bottom: 2px;
      }
      div[data-testid="stMetric"] {
        background: #ffffff;
        border: 1px solid #d8e0ea;
        border-radius: 8px;
        padding: 12px;
        box-shadow: 0 1px 2px rgba(15, 23, 42, 0.05);
      }
      div[data-testid="stMetric"] label,
      div[data-testid="stMetric"] div {
        color: #0f172a !important;
      }
      .risk-pill {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 999px;
        color: #fff;
        font-size: 12px;
        font-weight: 700;
      }
      .agent-row {
        border: 1px solid #d8e0ea;
        border-radius: 8px;
        padding: 10px 12px;
        background: #ffffff;
        margin-bottom: 8px;
        box-shadow: 0 1px 2px rgba(15, 23, 42, 0.05);
        color: #0f172a;
      }
      .stTabs [data-baseweb="tab-list"] { gap: 8px; }
      .stTabs [data-baseweb="tab"] {
        background: #ffffff;
        border: 1px solid #d8e0ea;
        border-radius: 8px;
        color: #0f172a;
      }
      .stTabs [data-baseweb="tab"] p {
        color: #0f172a !important;
      }
      div[data-testid="stExpander"] {
        background: #ffffff;
        border-color: #d8e0ea;
        color: #0f172a;
      }
      div[data-testid="stExpander"] * {
        color: #0f172a;
      }
      .app-header {
        display: flex;
        align-items: center;
        gap: 24px;
        padding: 18px 0 12px 0;
        margin-bottom: 8px;
      }
      .app-logo {
        width: 156px;
        min-width: 156px;
      }
      .app-logo img {
        width: 156px;
        height: auto;
        display: block;
        object-fit: contain;
      }
      .app-title {
        font-size: 56px;
        line-height: 1;
        font-weight: 800;
        color: #0f172a;
        margin: 0 0 8px 0;
        letter-spacing: 0;
      }
      .app-tagline {
        font-size: 30px;
        line-height: 1.18;
        font-weight: 650;
        color: var(--apec-navy);
        margin: 0 0 8px 0;
        letter-spacing: 0;
      }
      .app-subtitle {
        font-size: 18px;
        color: #475569;
        margin: 0;
      }
      @media (max-width: 720px) {
        .app-header { align-items: flex-start; gap: 14px; }
        .app-logo, .app-logo img { width: 104px; min-width: 104px; }
        .app-title { font-size: 38px; }
        .app-tagline { font-size: 22px; }
      }
    </style>
    """,
    unsafe_allow_html=True,
)


def _severity_html(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#64748b")
    return f"<span class='risk-pill' style='background:{color}'>{severity.upper()}</span>"


def _metric_card(label: str, value: Any, note: str = "", accent: str = "#0ea5e9") -> None:
    st.markdown(
        f"""
        <div class="metric-card" style="--card-accent:{accent}">
          <div class="metric-label">{html.escape(str(label))}</div>
          <div class="metric-value">{html.escape(str(value))}</div>
          <div class="metric-note">{html.escape(str(note))}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _status_badge(status: str) -> str:
    colors = {
        "open": ("#e2e8f0", "#0f172a"),
        "planned": ("#dbeafe", "#1e3a8a"),
        "accepted": ("#fef3c7", "#92400e"),
        "false_positive": ("#dcfce7", "#166534"),
        "fixed": ("#d1fae5", "#065f46"),
        "needs_review": ("#fee2e2", "#991b1b"),
    }
    bg, fg = colors.get(status, ("#e2e8f0", "#0f172a"))
    return f"<span class='status-badge' style='background:{bg};color:{fg}'>{html.escape(status)}</span>"


def _section_card(title: str, body: str = "") -> None:
    st.markdown(
        f"""
        <div class="section-card">
          <h3 style="margin-top:0;color:#07185f;">{html.escape(title)}</h3>
          <p style="margin-bottom:0;color:#64748b;">{html.escape(body)}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _empty_state(title: str, body: str) -> None:
    st.markdown(
        f"""
        <div class="empty-state">
          <h3>{html.escape(title)}</h3>
          <p>{html.escape(body)}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _set_active_nav(section_title: str) -> None:
    page = st.session_state.get(f"nav_radio_{section_title}")
    if not page:
        return
    st.session_state.active_page = page
    for other_title, _, _ in NAV_SECTIONS:
        if other_title != section_title:
            st.session_state[f"nav_radio_{other_title}"] = None


def _logo_data_uri() -> str:
    if not LOGO_PATH.exists():
        return ""
    encoded = base64.b64encode(LOGO_PATH.read_bytes()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _finding_id(finding: Dict[str, Any]) -> str:
    stable = {
        "file": finding.get("file"),
        "line_no": finding.get("line_no"),
        "type": finding.get("type"),
        "algorithm": finding.get("algorithm"),
        "evidence": finding.get("evidence"),
        "endpoint": finding.get("endpoint"),
    }
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def _playbook_for_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    algorithm = str(finding.get("algorithm", "")).upper()
    finding_type = str(finding.get("type", ""))
    common = [
        "Confirm the owning service/team and business criticality.",
        "Create a compatibility test plan before changing production cryptography.",
        "Record the decision as an APEC-PS human review event.",
    ]
    if "TLS" in finding_type or "ENDPOINT" in finding_type.upper() or "ECDHE" in algorithm:
        steps = [
            "Inventory certificate chain, TLS termination point, clients, and dependent integrations.",
            "Enable modern TLS policy and evaluate hybrid/PQC-ready key exchange options where supported.",
            "Run canary rollout with telemetry for handshake failures and client incompatibility.",
            "Rotate affected certificates or TLS profiles after owner approval.",
        ]
    elif "RSA" in algorithm:
        steps = [
            "Identify whether RSA is used for encryption, signing, certificates, or key exchange.",
            "For TLS/certificates, plan certificate rotation and hybrid/PQC readiness testing.",
            "For application signing/encryption, evaluate ML-KEM for key establishment and ML-DSA/SLH-DSA for signatures.",
            "Add regression tests around serialization, key storage, and rollback behavior.",
        ]
    elif "ECDSA" in algorithm or "ECDH" in algorithm or "DSA" in algorithm:
        steps = [
            "Identify protocol, curve, key owner, and consumers of the signature or key agreement.",
            "Assess whether dual-signing, hybrid key exchange, or phased client migration is required.",
            "Prototype PQC-compatible alternatives and measure payload, latency, and compatibility impact.",
            "Schedule staged rollout with explicit fallback and human approval gates.",
        ]
    elif "SHA1" in algorithm:
        steps = [
            "Locate all SHA-1 consumers and determine whether the use is security-sensitive.",
            "Replace with SHA-256/SHA-384 or a protocol-approved stronger hash.",
            "Regenerate affected signatures, certificates, or integrity metadata.",
            "Block new SHA-1 usage in CI once compatibility is verified.",
        ]
    else:
        steps = [
            "Validate the finding with the service owner.",
            "Map the cryptographic use to a PQC migration option.",
            "Define tests, rollout stages, and rollback criteria.",
        ]
    return {
        "summary": f"Remediate {finding.get('algorithm')} in {finding.get('type')} with owner-approved phased migration.",
        "steps": steps + common,
        "priority": finding.get("severity", "medium"),
    }


def _attach_operational_metadata(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    reviews = _load_reviews()
    enriched = []
    for finding in findings:
        item = dict(finding)
        item["finding_id"] = _finding_id(item)
        item["review"] = reviews.get(item["finding_id"], {})
        item["playbook"] = _playbook_for_finding(item)
        enriched.append(item)
    return enriched


def _init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                project_name TEXT NOT NULL,
                source TEXT NOT NULL,
                finding_count INTEGER NOT NULL,
                high_count INTEGER NOT NULL,
                medium_count INTEGER NOT NULL,
                low_count INTEGER NOT NULL,
                findings_json TEXT NOT NULL,
                trace_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reviews (
                finding_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                reviewer TEXT NOT NULL,
                reason TEXT NOT NULL,
                expires_on TEXT,
                updated_at TEXT NOT NULL
            )
            """
        )


def _save_scan(project_name: str, source: str, findings: List[Dict[str, Any]], trace: ProofTrace | None = None) -> int:
    _init_db()
    high = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    low = sum(1 for f in findings if f.get("severity") == "low")
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            INSERT INTO scans (
                created_at, project_name, source, finding_count, high_count,
                medium_count, low_count, findings_json, trace_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                project_name,
                source,
                len(findings),
                high,
                medium,
                low,
                json.dumps(findings, sort_keys=True),
                json.dumps(trace.to_list() if trace else [], sort_keys=True),
            ),
        )
        return int(cursor.lastrowid)


def _list_scans(limit: int = 20) -> List[Dict[str, Any]]:
    _init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, created_at, project_name, source, finding_count, high_count, medium_count, low_count
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def _load_scan(scan_id: int) -> Dict[str, Any] | None:
    _init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        return None
    payload = dict(row)
    payload["findings"] = json.loads(payload.pop("findings_json"))
    payload["trace"] = json.loads(payload.pop("trace_json"))
    return payload


def _trace_from_rows(rows: List[Dict[str, Any]]) -> ProofTrace:
    trace = ProofTrace()
    for row in rows:
        trace.add_event(
            ProofEvent(
                actor=row["actor"],
                kind=row["kind"],
                claim=row["claim"],
                references=row.get("references") or [],
                metadata=row.get("metadata") or {},
                id=row["id"],
            )
        )
    return trace


def _load_reviews() -> Dict[str, Dict[str, Any]]:
    _init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM reviews").fetchall()
    return {row["finding_id"]: dict(row) for row in rows}


def _save_review(finding_id: str, status: str, reviewer: str, reason: str, expires_on: str | None) -> None:
    _init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO reviews (finding_id, status, reviewer, reason, expires_on, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(finding_id) DO UPDATE SET
                status = excluded.status,
                reviewer = excluded.reviewer,
                reason = excluded.reason,
                expires_on = excluded.expires_on,
                updated_at = excluded.updated_at
            """,
            (finding_id, status, reviewer, reason, expires_on, datetime.now(timezone.utc).isoformat()),
        )


def _append_review_event(trace: ProofTrace, finding: Dict[str, Any], review: Dict[str, Any]) -> None:
    trace.add_event(
        create_event(
            actor="HumanReviewAgent",
            kind="validation",
            claim=f"Finding {finding.get('algorithm')} marked {review['status']} by {review['reviewer']}: {review['reason']}",
            references=[],
            finding_id=finding.get("finding_id"),
            status=review["status"],
            reviewer=review["reviewer"],
            expires_on=review.get("expires_on"),
        )
    )


def _run_agent_pipeline(findings: List[Dict[str, Any]], agents: List[Any] | None = None) -> ProofTrace:
    trace = ProofTrace()
    for agent in agents or ALL_AGENTS:
        agent.evaluate(findings, trace)
    return trace


def _severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    return {
        "high": sum(1 for finding in findings if finding.get("severity") == "high"),
        "medium": sum(1 for finding in findings if finding.get("severity") == "medium"),
        "low": sum(1 for finding in findings if finding.get("severity") == "low"),
    }


def _review_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    enriched = _attach_operational_metadata(findings)
    counts: Dict[str, int] = {}
    for finding in enriched:
        status = finding.get("review", {}).get("status", "open")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _render_presentation_walkthrough() -> None:
    st.subheader("Presentation walkthrough")
    steps = [
        ("1", "Load the demo", "Use Demo Mode to run scanner and agents over the bundled sample repository."),
        ("2", "Show risk posture", "Open Dashboard and explain high risks, total score, review state, and top findings."),
        ("3", "Explain evidence", "Open Findings, select one finding, and show evidence, playbook, and the decision brief. Use Review for trace links and human decisions."),
        ("4", "Show argumentation", "Open Debate and Argument Graphs to show support, attack, and validation moves."),
        ("5", "Export securely", "Open Report and export HTML/JSON/SARIF or encrypt the report with ML-KEM + AES-GCM."),
    ]
    cols = st.columns(5)
    for col, (number, title, text) in zip(cols, steps):
        with col:
            st.markdown(
                f"""
                <div class="walkthrough-step">
                  <div class="step-number">Step {html.escape(number)}</div>
                  <div class="step-title">{html.escape(title)}</div>
                  <div class="step-text">{html.escape(text)}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def _render_about_page() -> None:
    st.header("About this project")
    left, right = st.columns([1.2, 1])
    with left:
        _section_card(
            "Project identity",
            "APEC-PS applies argumentation-based proof traces to trustworthy agentic AI for post-quantum cryptography risk triage.",
        )
        st.markdown(
            f"""
            <div class="section-card">
              <h3 style="margin-top:0;color:#07185f;">Author</h3>
              <p><b>Name:</b> {html.escape(PROJECT_AUTHOR)}</p>
              <p><b>Affiliation:</b> {html.escape(PROJECT_AFFILIATION)}</p>
              <p><b>Contact:</b> <a href="mailto:{html.escape(PROJECT_EMAIL)}">{html.escape(PROJECT_EMAIL)}</a></p>
              <p><b>Source code:</b> <a href="{html.escape(PROJECT_SOURCE_URL)}" target="_blank">{html.escape(PROJECT_SOURCE_URL)}</a></p>
              <p><b>Live demo:</b> <a href="{html.escape(PROJECT_DEMO_URL)}" target="_blank">{html.escape(PROJECT_DEMO_URL)}</a></p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            f"""
            <div class="section-card">
              <h3 style="margin-top:0;color:#07185f;">Rights and permitted use</h3>
              <p>{html.escape(PROJECT_RIGHTS)}</p>
              <p>{html.escape(PROJECT_USAGE)}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with right:
        _section_card("Communication", "Use the contact details below for questions, academic discussion, or collaboration requests.")
        st.code(PROJECT_EMAIL, language="text")
        _section_card("Suggested citation", "Use this text when referencing the prototype in slides, reports, or academic material.")
        st.code(PROJECT_CITATION, language="text")


def _finding_trace_events(finding: Dict[str, Any], trace: ProofTrace | None) -> List[ProofEvent]:
    if not trace:
        return []
    finding_file = str(finding.get("file") or "")
    finding_line = finding.get("line_no")
    algorithm = finding.get("algorithm")
    finding_type = finding.get("type")
    seed_ids: Set[str] = set()
    for event in trace.events:
        if event.actor != "CryptoDiscoveryAgent":
            continue
        metadata = event.metadata
        same_algorithm = metadata.get("algorithm") == algorithm
        same_type = metadata.get("type") == finding_type
        same_line = metadata.get("line") == finding_line
        same_file = finding_file and finding_file in event.claim
        if same_algorithm and same_type and (same_line or finding_line is None) and same_file:
            seed_ids.add(event.id)

    if not seed_ids:
        for event in trace.events:
            metadata = event.metadata
            if metadata.get("algorithm") == algorithm and metadata.get("type") == finding_type:
                seed_ids.add(event.id)
                break

    linked_ids = set(seed_ids)
    changed = True
    while changed:
        changed = False
        for event in trace.events:
            if set(event.references or []) & linked_ids and event.id not in linked_ids:
                linked_ids.add(event.id)
                changed = True
    return [event for event in trace.events if event.id in linked_ids]


def _render_finding_trace_links(finding: Dict[str, Any], trace: ProofTrace | None) -> None:
    events = _finding_trace_events(finding, trace)
    st.markdown("**APEC-PS trace links**")
    if not events:
        st.info("Run agents to link this finding to proof events and migration claims.")
        return
    actors = sorted({event.actor for event in events})
    kinds = sorted({event.kind for event in events})
    st.markdown(
        " ".join(_status_badge(actor) for actor in actors).replace("status-badge", "trace-chip"),
        unsafe_allow_html=True,
    )
    c1, c2, c3 = st.columns(3)
    with c1:
        _metric_card("Linked events", len(events), "proof events using this finding", "#0ea5e9")
    with c2:
        _metric_card("Agents", len(actors), "agents involved", "#b516b5")
    with c3:
        _metric_card("Event types", len(kinds), ", ".join(kinds[:3]), "#059669")
    table = pd.DataFrame(
        [
            {
                "id": event.id,
                "actor": event.actor,
                "kind": event.kind,
                "claim": event.claim,
                "references": ", ".join(event.references or []),
            }
            for event in events
        ]
    )
    st.dataframe(table, use_container_width=True, hide_index=True)


def _event_reference_summary(event: Any, events_by_id: Dict[str, Any]) -> str:
    refs = []
    for ref in event.references or []:
        target = events_by_id.get(ref)
        if target:
            refs.append(f"{target.actor} / {target.kind}")
        else:
            refs.append(ref)
    return ", ".join(refs) if refs else "No direct references"


def _conversation_action(event: Any) -> str:
    if event.kind == "premise":
        return "Evidence"
    if event.kind == "support":
        return "Support"
    if event.kind == "attack":
        return "Challenge"
    if event.kind == "warrant":
        return "Warrant"
    if event.kind == "claim":
        return "Plan"
    if event.kind == "validation":
        return "Review"
    return event.kind.title()


def _render_agent_conversation(trace: ProofTrace, events: List[Any] | None = None, compact: bool = False) -> None:
    conversation_events = events or trace.events
    if not conversation_events:
        st.info("No proof events are available for the conversation view.")
        return

    events_by_id = {event.id: event for event in trace.events}
    if not compact:
        st.caption("Readable transcript of how agents move from evidence to challenge, plan, and human review.")
        actors = sorted({event.actor for event in conversation_events})
        selected_actors = st.multiselect(
            "Conversation agents",
            actors,
            default=actors,
            key=f"conversation_agents_{len(conversation_events)}_{conversation_events[0].id}",
        )
        conversation_events = [event for event in conversation_events if event.actor in selected_actors]

    for event in conversation_events:
        icon = event.metadata.get("icon") or AGENT_ICONS.get(event.actor, "bot")
        severity = event.metadata.get("severity")
        severity_html = _severity_html(str(severity)) if severity else _status_badge(event.kind)
        accent = KIND_COLORS.get(event.kind, "#0ea5e9")
        refs = _event_reference_summary(event, events_by_id)
        st.markdown(
            f"""
            <div class="conversation-card" style="--agent-accent:{accent};">
              <div class="conversation-meta">{html.escape(str(icon))} {html.escape(event.actor)} - {html.escape(_conversation_action(event))} {severity_html}</div>
              <div class="conversation-claim">{html.escape(event.claim)}</div>
              <div class="conversation-refs">Connected to: {html.escape(refs)}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def _first_claim(events: List[Any], kind: str, fallback: str) -> str:
    for event in events:
        if event.kind == kind:
            return event.claim
    return fallback


def _render_finding_to_decision(finding: Dict[str, Any], trace: ProofTrace | None) -> None:
    events = _finding_trace_events(finding, trace)
    review = finding.get("review", {})
    playbook = finding.get("playbook", {})
    supports = [event for event in events if event.kind == "support"]
    attacks = [event for event in events if event.kind == "attack"]
    warrants = [event for event in events if event.kind == "warrant"]
    claims = [event for event in events if event.kind == "claim"]
    validations = [event for event in events if event.kind == "validation"]
    decision_status = review.get("status")
    if not decision_status:
        decision_status = validations[-1].metadata.get("status") if validations else ("needs_review" if attacks else "open")
    next_step = review.get("reason") or playbook.get("steps", ["Review finding with the service owner."])[0]
    open_challenge = attacks[-1].claim if attacks and not review.get("status") else "No unresolved challenge has been recorded for the selected finding."

    st.markdown("**Finding-to-decision view**")
    st.caption("A decision brief for one finding: what was detected, why it matters, what challenged the plan, and what action should happen next.")

    st.markdown(
        f"""
        <div class="section-card">
          <div style="display:flex;justify-content:space-between;gap:16px;align-items:flex-start;">
            <div>
              <h3 style="margin:0;color:#07185f;">{html.escape(str(finding.get('algorithm')))} decision brief</h3>
              <p style="margin:5px 0 0 0;color:#475569;">
                {html.escape(str(finding.get('type')))} in {html.escape(str(finding.get('file')))}:{html.escape(str(finding.get('line_no') or '?'))}
              </p>
              <p style="margin:8px 0 0 0;color:#334155;">{html.escape(str(finding.get('description') or finding.get('evidence') or 'No description available.'))}</p>
            </div>
            <div>{_severity_html(str(finding.get('severity', 'low')))} {_status_badge(str(decision_status))}</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    d1, d2, d3, d4, d5 = st.columns(5)
    steps = [
        (
            d1,
            "1. Evidence",
            f"{finding.get('algorithm')} detected in {finding.get('file')}:{finding.get('line_no') or '?'}",
            "#0ea5e9",
        ),
        (
            d2,
            "2. Risk meaning",
            supports[0].claim if supports else "Run agents to convert this scanner finding into a risk argument.",
            "#16a34a",
        ),
        (
            d3,
            "3. Constraint",
            warrants[-1].claim if warrants else "No effort or policy warrant is linked yet.",
            "#d97706",
        ),
        (
            d4,
            "4. Challenge",
            open_challenge,
            "#dc2626",
        ),
        (
            d5,
            "5. Next action",
            next_step,
            "#7c3aed",
        ),
    ]
    for col, title, text, accent in steps:
        with col:
            st.markdown(
                f"""
                <div class="decision-step" style="--step-accent:{accent};">
                  <h4>{html.escape(title)}</h4>
                  <p>{html.escape(str(text))}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        _metric_card("Trace events", len(events), "linked to this finding", "#0ea5e9")
    with m2:
        _metric_card("Supports", len(supports), "risk arguments", "#16a34a")
    with m3:
        _metric_card("Challenges", len(attacks), "explicit attacks", "#dc2626")
    with m4:
        _metric_card("Status", decision_status, "human workflow", "#059669")

    if events:
        rows = [
            {
                "stage": _conversation_action(event),
                "agent": event.actor,
                "kind": event.kind,
                "claim": event.claim,
            }
            for event in events
            if event.kind in {"premise", "support", "attack", "warrant", "claim", "validation"}
        ]
        st.markdown("**Linked reasoning summary**")
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("Run the Agents page after scanning to show the complete finding-to-decision reasoning path.")


def _render_polished_report_preview(findings: List[Dict[str, Any]], trace: ProofTrace | None) -> None:
    enriched = _attach_operational_metadata(findings)
    severity = _severity_counts(enriched)
    reviews = _review_counts(enriched)
    total_score = sum(int(finding.get("risk_score") or 0) for finding in enriched)
    trace_events = len(trace.events) if trace else 0
    st.markdown("<div class='preview-card'><h3>Report Summary</h3></div>", unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        _metric_card("Findings", len(enriched), "included in report", "#0ea5e9")
    with c2:
        _metric_card("High risks", severity["high"], "priority items", "#dc2626")
    with c3:
        _metric_card("Risk score", total_score, "aggregate score", "#b516b5")
    with c4:
        _metric_card("Proof events", trace_events, "APEC-PS trace", "#059669")

    left, right = st.columns([1, 1])
    with left:
        st.markdown("<div class='preview-card'><h3>Top Findings</h3>", unsafe_allow_html=True)
        top = sorted(enriched, key=lambda item: item.get("risk_score", 0), reverse=True)[:5]
        for finding in top:
            st.markdown(
                f"{_severity_html(str(finding.get('severity', 'low')))} "
                f"**{finding.get('algorithm')}** · score `{finding.get('risk_score')}` · "
                f"{finding.get('type')}",
                unsafe_allow_html=True,
            )
            st.caption(str(finding.get("evidence") or finding.get("description") or ""))
        st.markdown("</div>", unsafe_allow_html=True)
    with right:
        st.markdown("<div class='preview-card'><h3>Governance</h3>", unsafe_allow_html=True)
        if reviews:
            for status, count in sorted(reviews.items()):
                st.markdown(f"{_status_badge(status)} `{count}`", unsafe_allow_html=True)
        else:
            st.markdown(f"{_status_badge('open')} `{len(enriched)}`", unsafe_allow_html=True)
        st.markdown("**Export contents**")
        st.write("Findings, remediation playbooks, human review decisions, proof events, and the argument graph when available.")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div class='preview-card'><h3>Remediation Preview</h3>", unsafe_allow_html=True)
    for finding in enriched[:3]:
        st.markdown(f"**{finding.get('algorithm')} / {finding.get('type')}**")
        st.write(finding.get("playbook", {}).get("summary", ""))
    st.markdown("</div>", unsafe_allow_html=True)


def _render_dashboard() -> None:
    st.header("Executive dashboard")
    with st.expander("Guided presentation walkthrough", expanded=False):
        _render_presentation_walkthrough()
    findings = st.session_state.get("findings", [])
    trace: ProofTrace | None = st.session_state.get("proof_trace")
    if not findings:
        _section_card(
            "No active scan",
            "Use Demo Mode for a one-click presentation scenario, or scan a repository from the Findings page.",
        )
        scans = _list_scans(limit=5)
        if scans:
            st.subheader("Recent scans")
            st.dataframe(pd.DataFrame(scans), use_container_width=True, hide_index=True)
        return

    enriched = _attach_operational_metadata(findings)
    severity = _severity_counts(enriched)
    reviews = _review_counts(enriched)
    total_score = sum(int(finding.get("risk_score") or 0) for finding in enriched)
    unresolved_attacks = 0
    if trace:
        attacked_ids = {ref for event in trace.events if event.kind == "attack" for ref in (event.references or [])}
        resolved_ids = {ref for event in trace.events if event.kind == "validation" for ref in (event.references or [])}
        unresolved_attacks = len(attacked_ids - resolved_ids)
    closed = reviews.get("fixed", 0) + reviews.get("false_positive", 0)
    readiness = int((closed / len(enriched)) * 100) if enriched else 0

    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        _metric_card("Findings", len(enriched), "active evidence items", "#0ea5e9")
    with c2:
        _metric_card("High", severity["high"], "priority migration risks", "#dc2626")
    with c3:
        _metric_card("Risk score", total_score, "aggregate triage score", "#b516b5")
    with c4:
        _metric_card("Unresolved", unresolved_attacks, "open argument attacks", "#d97706")
    with c5:
        _metric_card("Readiness", f"{readiness}%", "review closure estimate", "#059669")

    left, right = st.columns([1, 1])
    with left:
        _section_card("Algorithm exposure", "Detected cryptographic primitives and settings grouped by algorithm.")
        algo_df = pd.DataFrame(enriched)
        if "algorithm" in algo_df:
            st.bar_chart(algo_df["algorithm"].value_counts())
        _section_card("Severity distribution", "How the current scan is prioritized.")
        st.bar_chart(pd.Series(severity))
    with right:
        _section_card("Review status", "Human governance state for active findings.")
        st.bar_chart(pd.Series(reviews or {"open": len(enriched)}))
        _section_card("Top risks", "Highest scoring findings for discussion and remediation planning.")
        top = pd.DataFrame(enriched).sort_values("risk_score", ascending=False).head(5)
        st.dataframe(
            top[["severity", "risk_score", "algorithm", "type", "file", "evidence"]],
            use_container_width=True,
            hide_index=True,
        )


def _render_demo_mode() -> None:
    st.header("Demo Mode")
    st.write("Run a complete academic-demo scenario with a selected built-in repository.")
    st.caption("This loads the selected scenario, scans it, runs all deterministic agents, saves a history snapshot, and prepares reports in one click.")
    _render_presentation_walkthrough()

    scenario_name = st.selectbox(
        "Demo scenario",
        list(DEMO_SCENARIOS.keys()),
        help="Choose the presentation story you want to demonstrate.",
    )
    scenario = DEMO_SCENARIOS[scenario_name]
    sample_path = Path(scenario["path"])
    _section_card(str(scenario["summary"]), str(scenario["presentation_angle"]))
    c1, c2, c3 = st.columns(3)
    c1.metric("Demo repository", sample_path.name)
    c2.metric("Agents", len(ALL_AGENTS))
    c3.metric("Output", "Findings + Trace + Reports")
    if st.button("Run selected demo scenario", type="primary"):
        if not sample_path.exists():
            st.error(f"Demo scenario path is missing: {sample_path}")
            return
        with st.spinner("Running demo scan and agent pipeline"):
            findings = scan_repository(str(sample_path), max_workers=4)
            trace = _run_agent_pipeline(findings)
            st.session_state.repo_path = str(sample_path)
            st.session_state.repo_source = f"demo:{scenario_name}"
            st.session_state.findings = findings
            st.session_state.proof_trace = trace
            st.session_state.project_name = str(scenario["project_name"])
            st.session_state.demo_scenario = scenario_name
            scan_id = _save_scan(str(scenario["project_name"]), f"demo:{sample_path}", findings, trace)
            st.session_state.last_scan_id = scan_id
        st.success(f"{scenario_name} ready: {len(findings)} findings and {len(trace.events)} proof events.")

    findings = st.session_state.get("findings", [])
    trace = st.session_state.get("proof_trace")
    if findings and trace:
        st.subheader("Demo pipeline output")
        severity = _severity_counts(findings)
        d1, d2, d3, d4, d5 = st.columns(5)
        with d1:
            _metric_card("Findings", len(findings), "scanner output", "#0ea5e9")
        with d2:
            _metric_card("High risks", severity["high"], "priority issues", "#dc2626")
        with d3:
            _metric_card("Agents", len(ALL_AGENTS), "pipeline executed", "#b516b5")
        with d4:
            _metric_card("Proof events", len(trace.events), "APEC-PS trace", "#059669")
        with d5:
            _metric_card("Reports", "Ready", "export below", "#d97706")

        markdown = _build_markdown_report(findings, trace)
        json_export = _build_json_export(findings, trace)
        sarif_export = _build_sarif_export(findings)
        graph_html = _build_argument_graph_html(trace, layout_mode="Hierarchical", collapse_repeated=True)
        html_report = _build_html_report(findings, trace, graph_html)
        university_markdown = _build_university_markdown_report(findings, trace)
        university_html = _build_university_html_report(findings, trace, graph_html)

        report_tab, decision_tab, secure_tab = st.tabs(
            ["Report downloads", "Finding-to-decision", "PQC secure exchange"]
        )
        with report_tab:
            st.markdown(
                "<div class='download-card'><h4>Academic Report</h4><p>Formal academic-style report for your presentation or submission.</p></div>",
                unsafe_allow_html=True,
            )
            u1, u2, u3 = st.columns(3)
            with u1:
                st.download_button("Download Academic Markdown", university_markdown, file_name="demo_apecps_academic_report.md", mime="text/markdown")
            with u2:
                st.download_button("Download Academic HTML", university_html, file_name="demo_apecps_academic_report.html", mime="text/html")
            with u3:
                university_pdf = _build_pdf_report(
                    university_markdown,
                    findings,
                    trace,
                    university=True,
                )
                if university_pdf:
                    st.download_button("Download Academic PDF", university_pdf, file_name="demo_apecps_academic_report.pdf", mime="application/pdf")
                else:
                    st.info("PDF export is available when reportlab is installed.")
            st.divider()
            r1, r2, r3 = st.columns(3)
            with r1:
                st.download_button("Download Markdown", markdown, file_name="demo_pqc_risk_report.md", mime="text/markdown")
                st.download_button("Download JSON", json_export, file_name="demo_pqc_risk_report.json", mime="application/json")
            with r2:
                st.download_button("Download HTML Report + Graph", html_report, file_name="demo_pqc_risk_report_with_graph.html", mime="text/html")
                st.download_button("Download SARIF", sarif_export, file_name="demo_pqc_risk_report.sarif", mime="application/sarif+json")
            with r3:
                pdf_bytes = _build_pdf_report(
                    markdown,
                    findings,
                    trace,
                )
                if pdf_bytes:
                    st.download_button("Download PDF", pdf_bytes, file_name="demo_pqc_risk_report.pdf", mime="application/pdf")
                if graph_html:
                    st.download_button("Download Standalone Graph HTML", graph_html, file_name="demo_apecps_argument_graph.html", mime="text/html")
            _render_polished_report_preview(findings, trace)
        with decision_tab:
            enriched = _attach_operational_metadata(findings)
            top_finding = sorted(enriched, key=lambda item: item.get("risk_score", 0), reverse=True)[0]
            _render_finding_to_decision(top_finding, trace)
        with secure_tab:
            _render_pqc_report_export(html_report, json_export)


def _render_debate_view(trace: ProofTrace | None) -> None:
    st.header("Agent Debate View")
    if not trace:
        _empty_state("No argumentation trace yet", "Run the agent pipeline first. Demo Mode can create a complete scan, agent debate, graph, and report automatically.")
        return

    events = trace.events
    supports = [event for event in events if event.kind == "support"]
    attacks = [event for event in events if event.kind == "attack"]
    warrants = [event for event in events if event.kind == "warrant"]
    claims = [event for event in events if event.kind == "claim"]
    validations = [event for event in events if event.kind == "validation"]
    attacked_ids = {ref for event in attacks for ref in (event.references or [])}
    validated_ids = {
        ref
        for event in validations
        if not event.metadata.get("ai_generated")
        for ref in (event.references or [])
    }
    unresolved = attacked_ids - validated_ids

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Support arguments", len(supports))
    c2.metric("Attack arguments", len(attacks))
    c3.metric("Warrants", len(warrants))
    c4.metric("Unresolved challenges", len(unresolved))

    left, middle, right = st.columns(3)
    with left:
        st.subheader("Support")
        for event in supports[:12]:
            with st.expander(f"{event.actor} -> {event.metadata.get('severity', '-')}", expanded=False):
                st.write(event.claim)
                st.caption(f"References: {', '.join(event.references or []) or '-'}")
    with middle:
        st.subheader("Attack / Critique")
        for event in attacks[:12]:
            with st.expander(f"{event.actor} -> {event.metadata.get('type', event.kind)}", expanded=False):
                st.write(event.claim)
                st.caption(f"Challenges: {', '.join(event.references or []) or '-'}")
    with right:
        st.subheader("Resolution")
        for event in claims + validations:
            status = event.metadata.get("status", event.kind)
            with st.expander(f"{event.actor} -> {status}", expanded=False):
                st.write(event.claim)
                st.caption(f"References: {', '.join(event.references or []) or '-'}")

    if unresolved:
        st.warning("Some claims or supports are still challenged. Inspect the argument graph for the unresolved red-bordered nodes.")
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "event_id": event_id,
                        "actor": next((event.actor for event in events if event.id == event_id), "-"),
                        "claim": next((event.claim for event in events if event.id == event_id), "-"),
                    }
                    for event_id in unresolved
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )

    st.divider()
    st.subheader("Agent conversation transcript")
    _render_agent_conversation(trace)


def _ai_event_is_grounded(event: Any, events_by_id: Dict[str, Any]) -> bool:
    if event.metadata.get("evidence_grounded") is not None:
        return bool(event.metadata.get("evidence_grounded"))
    if event.metadata.get("evidence_finding_ids"):
        return True
    return any(
        reference in events_by_id and not events_by_id[reference].metadata.get("ai_generated")
        for reference in (event.references or [])
    )


def _ai_trust_score(event: Any, batch_events: List[Any], events_by_id: Dict[str, Any]) -> Tuple[int, int, List[str]]:
    score = 0
    checks = []
    grounded = _ai_event_is_grounded(event, events_by_id)
    if grounded:
        score += 1
    checks.append("evidence-linked" if grounded else "missing evidence link")

    try:
        confidence = float(event.metadata.get("confidence", 0))
    except (TypeError, ValueError):
        confidence = 0.0
    if confidence >= 0.75:
        score += 1
    checks.append("confidence >= 75%" if confidence >= 0.75 else "low confidence")

    has_warrant = event.kind == "warrant" or any(
        reference in events_by_id and events_by_id[reference].kind == "warrant"
        for reference in (event.references or [])
    )
    if has_warrant:
        score += 1
    checks.append("has warrant" if has_warrant else "no warrant link")

    has_counterargument = event.kind == "attack" or any(batch_event.kind == "attack" for batch_event in batch_events)
    if has_counterargument:
        score += 1
    checks.append("counterargument present" if has_counterargument else "no counterargument")

    reviewed = event.metadata.get("review_status") not in {None, "", "pending_review"}
    if reviewed:
        score += 1
    checks.append("human-reviewed" if reviewed else "pending human review")
    return score, 5, checks


def _render_ai_vs_deterministic_comparison(trace: ProofTrace, batch_events: List[Any]) -> None:
    deterministic_events = [event for event in trace.events if not event.metadata.get("ai_generated")]
    if not deterministic_events or not batch_events:
        return

    events_by_kind = {
        "risk": [event for event in deterministic_events if event.actor in {"QuantumRiskAgent", "ThreatIntelligenceAgent"}],
        "constraints": [event for event in deterministic_events if event.actor in {"CompatibilityAgent", "PerformanceCostAgent", "CriticAgent"}],
        "plan": [event for event in deterministic_events if event.actor == "MigrationPlannerAgent"],
        "review": [event for event in deterministic_events if event.actor == "HumanReviewAgent"],
    }
    ai_by_role = {event.metadata.get("argument_role"): event for event in batch_events}
    rows = [
        {
            "Decision area": "Risk interpretation",
            "Deterministic agents": "; ".join(event.claim for event in events_by_kind["risk"][-2:]) or "-",
            "AI agents": ai_by_role.get("risk_claim", ai_by_role.get("supporting_argument")).claim
            if ai_by_role.get("risk_claim") or ai_by_role.get("supporting_argument")
            else "-",
            "Trust signal": "Agreement is stronger when the AI claim links back to deterministic discovery or risk events.",
        },
        {
            "Decision area": "Constraints and critique",
            "Deterministic agents": "; ".join(event.claim for event in events_by_kind["constraints"][-2:]) or "-",
            "AI agents": ai_by_role.get("counterargument").claim if ai_by_role.get("counterargument") else "-",
            "Trust signal": "The workflow is safer when both deterministic and AI agents preserve objections.",
        },
        {
            "Decision area": "Migration plan",
            "Deterministic agents": "; ".join(event.claim for event in events_by_kind["plan"][-1:]) or "-",
            "AI agents": ai_by_role.get("migration_recommendation").claim if ai_by_role.get("migration_recommendation") else "-",
            "Trust signal": "Planner claims should be evidence-linked and remain blocked until review.",
        },
        {
            "Decision area": "Human governance",
            "Deterministic agents": "; ".join(event.claim for event in events_by_kind["review"][-1:]) or "-",
            "AI agents": ai_by_role.get("human_review_request").claim if ai_by_role.get("human_review_request") else "-",
            "Trust signal": "AI may request review, but only a human review event validates the decision.",
        },
    ]
    st.subheader("AI vs deterministic agent comparison")
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def _render_ai_argumentation(trace: ProofTrace, interactive: bool) -> None:
    ai_events = [event for event in trace.events if event.metadata.get("ai_generated")]
    if not ai_events:
        return

    batch_ids = list(dict.fromkeys(event.metadata.get("ai_batch_id") for event in reversed(ai_events)))
    selected_batch = batch_ids[0] if batch_ids else None
    batch_events = [event for event in ai_events if event.metadata.get("ai_batch_id") == selected_batch]
    if not batch_events:
        batch_events = ai_events
    events_by_id = {event.id: event for event in trace.events}

    grounded = [event for event in batch_events if _ai_event_is_grounded(event, events_by_id)]
    agreements = [event for event in batch_events if event.kind in {"support", "claim", "warrant"}]
    disagreements = [event for event in batch_events if event.kind == "attack"]
    reviewed = [event for event in batch_events if event.metadata.get("review_status") != "pending_review"]
    trust_scores = [_ai_trust_score(event, batch_events, events_by_id)[0] for event in batch_events]
    average_trust = round(sum(trust_scores) / len(trust_scores), 1) if trust_scores else 0

    st.subheader("AI agent participation and trust")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("AI argument moves", len(batch_events))
    c2.metric("AI role agents", len({event.actor for event in batch_events}))
    c3.metric("Evidence-grounded", f"{len(grounded)}/{len(batch_events)}")
    c4.metric("Trust score", f"{average_trust}/5")
    c5.metric("Human-reviewed", f"{len(reviewed)}/{len(batch_events)}")

    rows = []
    for event in batch_events:
        linked_actors = sorted(
            {
                events_by_id[reference].actor
                for reference in (event.references or [])
                if reference in events_by_id and not events_by_id[reference].metadata.get("ai_generated")
            }
        )
        trust_score, trust_max, trust_checks = _ai_trust_score(event, batch_events, events_by_id)
        grounded_label = "Evidence-grounded" if _ai_event_is_grounded(event, events_by_id) else "Not evidence-grounded"
        rows.append(
            {
                "AI agent": event.actor,
                "AI role": str(event.metadata.get("argument_role", event.kind)).replace("_", " ").title(),
                "Move": event.kind,
                "Claim": event.claim,
                "Grounding": grounded_label,
                "Trust score": f"{trust_score}/{trust_max}",
                "Trust checklist": "; ".join(trust_checks),
                "Confidence": f"{round(float(event.metadata.get('confidence', 0)) * 100)}%",
                "Linked deterministic agents": ", ".join(linked_actors) or "AI-chain link",
                "Human status": event.metadata.get("review_status", "pending_review"),
                "Provider": event.metadata.get("provider", "-"),
                "Model": event.metadata.get("model", "-"),
            }
        )
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    if grounded and disagreements:
        st.info(
            "Mixed consensus: the AI agrees with grounded risk evidence while preserving a counterargument against unsafe direct migration."
        )
    elif grounded:
        st.success("The AI position is linked to deterministic evidence; no explicit AI counterargument is present.")
    else:
        st.warning("The latest AI batch lacks deterministic evidence links and should not be accepted without revision.")

    provenance = batch_events[0].metadata
    st.caption(
        "AI provenance: "
        f"{provenance.get('provider', '-')} / {provenance.get('model', '-')} / "
        f"{provenance.get('generated_at', '-')} / batch {provenance.get('ai_batch_id', '-')}"
    )

    _render_ai_vs_deterministic_comparison(trace, batch_events)

    if not interactive:
        st.caption("Open Agentic AI to accept, reject, or request revision of individual AI arguments.")
        return

    st.markdown("**Human consensus of AI argument**")
    selected_id = st.selectbox(
        "AI argument to review",
        [event.id for event in batch_events],
        format_func=lambda event_id: (
            f"{events_by_id[event_id].metadata.get('argument_role', events_by_id[event_id].kind).replace('_', ' ').title()}"
            f" - {events_by_id[event_id].claim[:90]}"
        ),
        key="ai_argument_review_event",
    )
    selected = events_by_id[selected_id]
    st.caption(
        f"Provider: {selected.metadata.get('provider', '-')} | Model: {selected.metadata.get('model', '-')} | "
        f"Confidence: {round(float(selected.metadata.get('confidence', 0)) * 100)}% | "
        f"Evidence links: {len(selected.references or [])}"
    )
    reviewer = st.text_input("Reviewer name", key="ai_argument_reviewer")
    comment = st.text_area(
        "Review rationale",
        placeholder="Explain why this AI argument is accepted, rejected, or needs revision.",
        key="ai_argument_review_comment",
    )
    accept_col, reject_col, revise_col = st.columns(3)
    decision = None
    if accept_col.button("Accept argument", type="primary", use_container_width=True):
        decision = "accepted"
    if reject_col.button("Reject argument", use_container_width=True):
        decision = "rejected"
    if revise_col.button("Request revision", use_container_width=True):
        decision = "revision_requested"

    if decision:
        if not reviewer.strip() or not comment.strip():
            st.warning("Add the reviewer name and rationale before recording a decision.")
        else:
            selected.metadata.update(
                {
                    "review_status": decision,
                    "reviewer": reviewer.strip(),
                    "review_comment": comment.strip(),
                    "reviewed_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            action = {
                "accepted": "accepted",
                "rejected": "rejected",
                "revision_requested": "requested revision of",
            }[decision]
            trace.add_event(
                create_event(
                    actor="HumanReviewAgent",
                    kind="validation" if decision == "accepted" else "attack",
                    claim=f"{reviewer.strip()} {action} AI argument {selected.id}: {comment.strip()}",
                    references=[selected.id],
                    status=decision,
                    reviewer=reviewer.strip(),
                    ai_review=True,
                    reviewed_actor=selected.actor,
                    reviewed_model=selected.metadata.get("model"),
                )
            )
            scan_id = _save_scan(
                st.session_state.get("project_name_input") or st.session_state.get("project_name", "default-project"),
                f"ai-review:{selected.id}",
                st.session_state.get("findings", []),
                trace,
            )
            st.session_state.last_scan_id = scan_id
            st.success(f"AI argument marked {decision.replace('_', ' ')} and linked to a HumanReviewAgent event.")
            st.rerun()


def _configured_secret(name: str) -> str:
    env_value = os.environ.get(name, "").strip()
    if env_value:
        return env_value
    try:
        value = st.secrets.get(name, "")
    except Exception:
        value = ""
    return str(value).strip() if value else ""


def _run_openai_compatible_analysis(
    findings: List[Dict[str, Any]],
    trace: ProofTrace | None,
    api_key: str,
    model: str,
    base_url: str | None = None,
) -> str:
    from openai import OpenAI

    prompt = _agentic_prompt_payload(findings, trace)
    client_kwargs: Dict[str, Any] = {"api_key": api_key}
    if base_url:
        client_kwargs["base_url"] = base_url
    client = OpenAI(**client_kwargs)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "system",
                "content": "You are a careful security architecture agent. Return valid JSON only and ground every argument in supplied evidence.",
            },
            {"role": "user", "content": json.dumps(prompt, indent=2)},
        ],
        temperature=0.2,
        response_format={"type": "json_object"},
    )
    return response.choices[0].message.content or ""


def _run_llm_agentic_analysis(findings: List[Dict[str, Any]], trace: ProofTrace | None, api_key: str, model: str) -> str:
    return _run_openai_compatible_analysis(findings, trace, api_key, model)


def _run_groq_agentic_analysis(findings: List[Dict[str, Any]], trace: ProofTrace | None, api_key: str, model: str) -> str:
    return _run_openai_compatible_analysis(
        findings,
        trace,
        api_key,
        model,
        base_url="https://api.groq.com/openai/v1",
    )


def _agentic_prompt_payload(
    findings: List[Dict[str, Any]],
    trace: ProofTrace | None,
    finding_limit: int = 20,
) -> Dict[str, Any]:
    prioritized_findings = sorted(
        _attach_operational_metadata(findings),
        key=lambda finding: finding.get("risk_score", 0),
        reverse=True,
    )[:finding_limit]
    premise_events = [event for event in (trace.events if trace else []) if event.kind == "premise"]
    compact_findings = [
        {
            "evidence_index": index,
            "finding_id": finding.get("finding_id"),
            "algorithm": finding.get("algorithm"),
            "type": finding.get("type"),
            "severity": finding.get("severity"),
            "risk_score": finding.get("risk_score"),
            "evidence": finding.get("evidence"),
            "review": finding.get("review", {}),
            "source_event_ids": [
                event.id
                for event in premise_events
                if event.metadata.get("algorithm") == finding.get("algorithm")
                and event.metadata.get("type") == finding.get("type")
            ][:3],
        }
        for index, finding in enumerate(prioritized_findings)
    ]
    compact_trace = [
        {
            "event_id": event.id,
            "actor": event.actor,
            "kind": event.kind,
            "claim": event.claim,
            "severity": event.metadata.get("severity"),
            "risk_score": event.metadata.get("risk_score"),
        }
        for event in (trace.events if trace else [])[-12:]
    ]
    return {
        "task": "Create five evidence-grounded argument moves for an APEC-PS PQC risk graph.",
        "requirements": [
            "Return JSON only using the exact schema below.",
            "Return exactly one argument for each required role.",
            "Use evidence_index values and event_id values that exist in the supplied data.",
            "Keep every claim below 45 words.",
            "Do not claim that changes were executed.",
        ],
        "required_roles": [
            {"role": "risk_claim", "kind": "claim", "ai_agent": AI_ROLE_AGENTS["risk_claim"]},
            {"role": "supporting_argument", "kind": "support", "ai_agent": AI_ROLE_AGENTS["supporting_argument"]},
            {"role": "migration_recommendation", "kind": "warrant", "ai_agent": AI_ROLE_AGENTS["migration_recommendation"]},
            {"role": "counterargument", "kind": "attack", "ai_agent": AI_ROLE_AGENTS["counterargument"]},
            {"role": "human_review_request", "kind": "validation", "ai_agent": AI_ROLE_AGENTS["human_review_request"]},
        ],
        "schema": {
            "summary": "short decision brief",
            "arguments": [
                {
                    "role": "one required role",
                    "kind": "matching required kind",
                    "claim": "concise grounded statement",
                    "severity": "low, medium, or high",
                    "confidence": "number from 0 to 1",
                    "evidence_indices": ["integer evidence_index"],
                    "reference_event_ids": ["known event_id"],
                }
            ],
        },
        "findings": compact_findings,
        "recent_proof_events": compact_trace,
    }


def _ollama_models(base_url: str, timeout: int = 3) -> List[str]:
    endpoint = base_url.rstrip("/") + "/api/tags"
    try:
        with urllib.request.urlopen(endpoint, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return []
    return [model.get("name", "") for model in data.get("models", []) if model.get("name")]


def _select_ollama_model(installed_models: List[str], preferred: str) -> str:
    if not installed_models:
        return preferred
    if preferred in installed_models:
        return preferred
    fast_variant = f"{preferred}:1b" if ":" not in preferred else ""
    if fast_variant and fast_variant in installed_models:
        return fast_variant
    return next(
        (model for model in installed_models if model.startswith(preferred + ":")),
        installed_models[0],
    )


def _deterministic_quick_analysis(findings: List[Dict[str, Any]], trace: ProofTrace) -> str:
    prioritized = sorted(findings, key=lambda finding: finding.get("risk_score", 0), reverse=True)
    counts = _severity_counts(findings)
    top = prioritized[0] if prioritized else {}
    attacks = [event for event in trace.events if event.kind == "attack"]
    plans = [event.claim for event in trace.find_by_actor("MigrationPlannerAgent")]
    top_location = top.get("file") or top.get("endpoint") or "the scanned source"
    return "\n".join(
        [
            "### Quick agentic assessment",
            f"**Risk posture:** {counts['high']} high, {counts['medium']} medium, and {counts['low']} low-severity findings.",
            (
                f"**Highest priority:** {top.get('algorithm', 'Unknown')} at {top_location} "
                f"(risk score {top.get('risk_score', 0)})."
            ),
            f"**Agent challenge:** {len(attacks)} compatibility or evidence challenge(s) require resolution before migration.",
            f"**Recommended sequence:** {plans[-1] if plans else 'Inventory owners, test a hybrid migration, and require approval before production rollout.'}",
            "**Human decision:** Confirm the system owner, data-retention requirement, compatibility test scope, and migration deadline.",
            "",
            "_Generated by the deterministic coordinator because a local LLM was unavailable._",
        ]
    )


def _deterministic_ai_argument_payload(findings: List[Dict[str, Any]], trace: ProofTrace) -> Dict[str, Any]:
    prioritized = sorted(
        _attach_operational_metadata(findings),
        key=lambda finding: finding.get("risk_score", 0),
        reverse=True,
    )
    top = prioritized[0] if prioritized else {}
    algorithm = top.get("algorithm", "the highest-risk algorithm")
    severity = str(top.get("severity", "medium"))
    score = top.get("risk_score", 0)
    planner_events = trace.find_by_actor("MigrationPlannerAgent")
    plan = (
        planner_events[-1].claim
        if planner_events
        else f"Inventory {algorithm}, test a hybrid PQC migration, stage deployment, and require approval."
    )
    return {
        "summary": f"{algorithm} is the leading PQC migration priority, subject to compatibility testing and human approval.",
        "arguments": [
            {
                "role": "risk_claim",
                "kind": "claim",
                "claim": f"{algorithm} is the highest-priority quantum-risk exposure with risk score {score}.",
                "severity": severity,
                "confidence": 0.9,
                "evidence_indices": [0] if prioritized else [],
                "reference_event_ids": [],
            },
            {
                "role": "supporting_argument",
                "kind": "support",
                "claim": f"Scanner evidence and specialist-agent reasoning support prioritizing {algorithm} for migration planning.",
                "severity": severity,
                "confidence": 0.86,
                "evidence_indices": [0] if prioritized else [],
                "reference_event_ids": [],
            },
            {
                "role": "migration_recommendation",
                "kind": "warrant",
                "claim": plan,
                "severity": severity,
                "confidence": 0.78,
                "evidence_indices": [0] if prioritized else [],
                "reference_event_ids": [event.id for event in planner_events[-1:]],
            },
            {
                "role": "counterargument",
                "kind": "attack",
                "claim": "A direct replacement may create interoperability, certificate, performance, or rollback risk; use a staged hybrid deployment.",
                "severity": "medium",
                "confidence": 0.82,
                "evidence_indices": [0] if prioritized else [],
                "reference_event_ids": [],
            },
            {
                "role": "human_review_request",
                "kind": "validation",
                "claim": "A human reviewer must confirm ownership, evidence sufficiency, compatibility scope, and the migration deadline before execution.",
                "severity": severity,
                "confidence": 0.95,
                "evidence_indices": [0] if prioritized else [],
                "reference_event_ids": [],
            },
        ],
    }


def _parse_ai_argument_payload(raw_response: str, findings: List[Dict[str, Any]], trace: ProofTrace) -> Dict[str, Any]:
    fallback = _deterministic_ai_argument_payload(findings, trace)
    cleaned = raw_response.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[-1]
        cleaned = cleaned.rsplit("```", 1)[0].strip()
    try:
        start = cleaned.index("{")
        end = cleaned.rindex("}") + 1
        parsed = json.loads(cleaned[start:end])
    except (ValueError, json.JSONDecodeError):
        fallback["summary"] = raw_response.strip() or fallback["summary"]
        return fallback

    required = {
        "risk_claim": "claim",
        "supporting_argument": "support",
        "migration_recommendation": "warrant",
        "counterargument": "attack",
        "human_review_request": "validation",
    }
    fallback_by_role = {item["role"]: item for item in fallback["arguments"]}
    supplied_by_role = {
        item.get("role"): item
        for item in parsed.get("arguments", [])
        if isinstance(item, dict) and item.get("role") in required
    }
    normalized = []
    for role, kind in required.items():
        source = supplied_by_role.get(role, fallback_by_role[role])
        try:
            confidence = max(0.0, min(1.0, float(source.get("confidence", fallback_by_role[role]["confidence"]))))
        except (TypeError, ValueError):
            confidence = fallback_by_role[role]["confidence"]
        evidence_indices = [
            int(index)
            for index in source.get("evidence_indices", [])
            if isinstance(index, int) or (isinstance(index, str) and index.isdigit())
        ]
        normalized.append(
            {
                "role": role,
                "kind": kind,
                "claim": str(source.get("claim") or fallback_by_role[role]["claim"])[:700],
                "severity": (
                    source.get("severity")
                    if source.get("severity") in {"low", "medium", "high"}
                    else fallback_by_role[role]["severity"]
                ),
                "confidence": confidence,
                "evidence_indices": evidence_indices,
                "reference_event_ids": [
                    str(event_id) for event_id in source.get("reference_event_ids", []) if event_id
                ],
            }
        )
    return {
        "summary": str(parsed.get("summary") or fallback["summary"])[:1200],
        "arguments": normalized,
    }


def _format_ai_argument_payload(payload: Dict[str, Any]) -> str:
    labels = {
        "risk_claim": "AI Risk Analyst",
        "supporting_argument": "AI Evidence Analyst",
        "migration_recommendation": "AI Migration Planner",
        "counterargument": "AI Compatibility Critic",
        "human_review_request": "AI Trust Reviewer",
    }
    lines = [f"**Decision brief:** {payload.get('summary', '')}"]
    for argument in payload.get("arguments", []):
        label = labels.get(argument.get("role"), str(argument.get("role", "Argument")).replace("_", " ").title())
        confidence = round(float(argument.get("confidence", 0)) * 100)
        lines.append(f"**{label} ({argument.get('kind')} / {confidence}% confidence):** {argument.get('claim', '')}")
    return "\n\n".join(lines)


def _append_structured_ai_events(
    trace: ProofTrace,
    findings: List[Dict[str, Any]],
    payload: Dict[str, Any],
    actor: str,
    provider: str,
    model: str,
) -> List[ProofEvent]:
    prioritized = sorted(
        _attach_operational_metadata(findings),
        key=lambda finding: finding.get("risk_score", 0),
        reverse=True,
    )[:20]
    existing_ids = {event.id for event in trace.events}
    events_by_id = {event.id: event for event in trace.events}
    premise_events = [event for event in trace.events if event.kind == "premise"]
    generated_at = datetime.now(timezone.utc).isoformat()
    batch_seed = f"{generated_at}:{provider}:{model}:{payload.get('summary', '')}"
    batch_id = hashlib.sha256(batch_seed.encode("utf-8")).hexdigest()[:12]
    created: List[ProofEvent] = []
    by_role: Dict[str, ProofEvent] = {}

    for argument in payload.get("arguments", []):
        evidence_indices = [
            index for index in argument.get("evidence_indices", []) if 0 <= index < len(prioritized)
        ]
        evidence_findings = [prioritized[index] for index in evidence_indices]
        evidence_ids = [finding.get("finding_id") for finding in evidence_findings if finding.get("finding_id")]
        references = [
            event_id for event_id in argument.get("reference_event_ids", []) if event_id in existing_ids
        ]
        for finding in evidence_findings:
            references.extend(
                event.id
                for event in premise_events
                if event.metadata.get("algorithm") == finding.get("algorithm")
                and event.metadata.get("type") == finding.get("type")
            )

        role = argument["role"]
        if role == "supporting_argument" and "risk_claim" in by_role:
            references.append(by_role["risk_claim"].id)
        elif role == "migration_recommendation":
            references.extend(
                event.id
                for name in ("risk_claim", "supporting_argument")
                if (event := by_role.get(name)) is not None
            )
        elif role == "counterargument" and "migration_recommendation" in by_role:
            references.append(by_role["migration_recommendation"].id)
        elif role == "human_review_request":
            references.extend(
                event.id
                for name in ("migration_recommendation", "counterargument")
                if (event := by_role.get(name)) is not None
            )

        event_actor = AI_ROLE_AGENTS.get(role, actor)
        unique_references = list(dict.fromkeys(references))[:12]
        evidence_grounded = bool(evidence_ids) or any(
            reference in events_by_id and not events_by_id[reference].metadata.get("ai_generated")
            for reference in unique_references
        )
        event = create_event(
            actor=event_actor,
            kind=argument["kind"],
            claim=argument["claim"],
            references=unique_references,
            severity=argument.get("severity"),
            confidence=argument.get("confidence"),
            argument_role=role,
            ai_role_agent=event_actor,
            coordinator_actor=actor,
            evidence_finding_ids=evidence_ids,
            evidence_grounded=evidence_grounded,
            grounding_status="evidence-grounded" if evidence_grounded else "not evidence-grounded",
            ai_generated=True,
            provenance="llm_generated",
            provider=provider,
            model=model,
            generated_at=generated_at,
            ai_batch_id=batch_id,
            review_status="pending_review",
            status="approval_required" if role == "human_review_request" else "pending_review",
        )
        trace.add_event(event)
        created.append(event)
        by_role[role] = event
        existing_ids.add(event.id)
        events_by_id[event.id] = event

    refreshed_by_id = {event.id: event for event in trace.events}
    for event in created:
        score, maximum, checks = _ai_trust_score(event, created, refreshed_by_id)
        event.metadata["trust_score"] = score
        event.metadata["trust_score_max"] = maximum
        event.metadata["trust_checks"] = checks
    return created


def _run_ollama_agentic_analysis(
    findings: List[Dict[str, Any]],
    trace: ProofTrace | None,
    base_url: str,
    model: str,
    finding_limit: int = 20,
) -> str:
    prompt = (
        "You are a careful security architecture agent. Be precise, auditable, and concise.\n\n"
        + json.dumps(_agentic_prompt_payload(findings, trace, finding_limit=finding_limit), indent=2)
    )
    endpoint = base_url.rstrip("/") + "/api/generate"
    payload = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "keep_alive": "10m",
            "options": {"temperature": 0.2, "num_predict": 520},
        }
    ).encode("utf-8")
    request = urllib.request.Request(endpoint, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", errors="replace")
        except Exception:
            detail = str(exc)
        raise RuntimeError(f"Ollama returned HTTP {exc.code}: {detail[:300]}") from exc
    except urllib.error.URLError as exc:
        if "timed out" in str(exc.reason).lower():
            raise RuntimeError(
                f"Ollama generation timed out for model {model}. Try llama3.2:1b or increase OLLAMA timeout."
            ) from exc
        raise RuntimeError(
            f"Ollama service is unavailable at {base_url}. Start Ollama and verify the URL."
        ) from exc
    except TimeoutError as exc:
        raise RuntimeError(
            f"Ollama generation timed out for model {model}. Try llama3.2:1b."
        ) from exc
    return data.get("response", "")


def _render_agentic_ai_upgrade() -> None:
    st.header("Agentic AI Coordinator")
    st.write(
        "Use this as the central reasoning workflow: specialist agents build the deterministic APEC-PS trace, "
        "then an LLM or deterministic coordinator synthesizes risk, counterarguments, and review actions into linked proof events."
    )
    findings = st.session_state.get("findings", [])
    if not findings:
        st.info("Run Demo Mode or a scan first so the Agentic AI coordinator has evidence to analyze.")
        return

    ollama_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    installed_models = _ollama_models(ollama_url)
    default_model = os.environ.get("OLLAMA_MODEL", "llama3.2")
    selected_model = _select_ollama_model(installed_models, default_model)
    groq_key = _configured_secret("GROQ_API_KEY")
    groq_model = _configured_secret("GROQ_MODEL") or "openai/gpt-oss-20b"
    automatic_provider = "Groq Cloud" if groq_key else "Local Ollama" if installed_models else "Deterministic"
    automatic_model = groq_model if groq_key else selected_model if installed_models else "fallback"
    status_col, scope_col, mode_col = st.columns(3)
    status_col.metric("AI backend", "Ready" if installed_models or groq_key else "Fallback")
    scope_col.metric("Specialist agents", len(ALL_AGENTS))
    mode_col.metric("Coordinator", automatic_provider)
    mode_col.caption(automatic_model)
    if groq_key:
        st.success(f"Hosted coordinator ready: Groq Cloud / {groq_model}")
    elif installed_models:
        st.success(f"Local coordinator ready: {selected_model}")
    else:
        st.warning(
            "No LLM provider is configured. The central workflow will use the deterministic coordinator. "
            "For Streamlit Cloud, add GROQ_API_KEY in app secrets."
        )

    with st.expander("AI role agents and trust controls", expanded=True):
        st.write(
            "The coordinator produces separate AI role-agent arguments. Each role is stored as its own APEC-PS proof event, "
            "so the system can compare AI reasoning with deterministic agents instead of accepting one opaque summary."
        )
        role_rows = [
            {
                "AI role agent": agent_name,
                "APEC-PS move": {
                    "risk_claim": "claim",
                    "supporting_argument": "support",
                    "migration_recommendation": "warrant",
                    "counterargument": "attack",
                    "human_review_request": "validation request",
                }[role],
                "Trust rule": "Must be evidence-linked, confidence-scored, counterargument-aware, and human-reviewed.",
            }
            for role, agent_name in AI_ROLE_AGENTS.items()
        ]
        st.dataframe(pd.DataFrame(role_rows), use_container_width=True, hide_index=True)

    if st.button("Run Agentic AI Analysis", type="primary", use_container_width=True):
        progress = st.progress(0, text="Running specialist agents")
        trace = ProofTrace()
        for index, agent in enumerate(ALL_AGENTS, start=1):
            agent.evaluate(findings, trace)
            progress.progress(index / (len(ALL_AGENTS) + 1), text=f"Completed {agent.name}")

        coordinator = "DeterministicCoordinator"
        provider_name = "Local fallback"
        model_name = "deterministic"
        provider_failure = ""
        try:
            if groq_key:
                progress.progress(len(ALL_AGENTS) / (len(ALL_AGENTS) + 1), text=f"Coordinating with Groq / {groq_model}")
                raw_analysis = _run_groq_agentic_analysis(findings, trace, groq_key, groq_model)
                coordinator = "GroqCoordinatorAgent"
                provider_name = "Groq Cloud"
                model_name = groq_model
            elif installed_models:
                progress.progress(len(ALL_AGENTS) / (len(ALL_AGENTS) + 1), text=f"Coordinating with {selected_model}")
                raw_analysis = _run_ollama_agentic_analysis(
                    findings,
                    trace,
                    ollama_url,
                    selected_model,
                    finding_limit=10,
                )
                coordinator = "OllamaCoordinatorAgent"
                provider_name = "Local Ollama"
                model_name = selected_model
            else:
                raise RuntimeError("No LLM provider is configured")
            if not raw_analysis.strip():
                raise RuntimeError(f"{provider_name} returned an empty response")
        except Exception as exc:
            provider_failure = str(exc)
            raw_analysis = json.dumps(_deterministic_ai_argument_payload(findings, trace))

        argument_payload = _parse_ai_argument_payload(raw_analysis, findings, trace)
        analysis = _format_ai_argument_payload(argument_payload)
        ai_events = _append_structured_ai_events(
            trace,
            findings,
            argument_payload,
            actor=coordinator,
            provider=provider_name,
            model=model_name,
        )
        st.session_state.proof_trace = trace
        st.session_state.llm_agentic_analysis = analysis
        st.session_state.ai_argument_event_ids = [event.id for event in ai_events]
        st.session_state.quick_agentic_coordinator = coordinator
        st.session_state.llm_agentic_source = f"Agentic AI Analysis - {provider_name} - {model_name}"
        scan_id = _save_scan(
            st.session_state.get("project_name_input") or st.session_state.get("project_name", "default-project"),
            f"agentic:{st.session_state.get('repo_path', '')}",
            findings,
            trace,
        )
        st.session_state.last_scan_id = scan_id
        progress.progress(1.0, text="Agentic AI analysis complete")
        st.success(
            f"Completed {len(ALL_AGENTS)} specialist agents with {provider_name}, "
            f"creating {len(ai_events)} linked AI argument nodes."
        )
        if provider_failure:
            st.warning(f"The configured LLM could not complete the request, so the deterministic fallback was used: {provider_failure}")

    with st.expander("Advanced coordinator settings"):
        st.caption("Select a provider or model and append a separate structured coordinator opinion.")
        trace: ProofTrace | None = st.session_state.get("proof_trace")
        openai_key = _configured_secret("OPENAI_API_KEY")
        provider_options = ["Groq Cloud", "Local Ollama", "OpenAI API"]
        default_provider_index = 0
        provider = st.selectbox("LLM provider", provider_options, index=default_provider_index)
        if provider == "OpenAI API":
            api_key_input = st.text_input(
                "OpenAI API key",
                value="",
                type="password",
                help="Leave empty to use OPENAI_API_KEY from Streamlit Secrets or the environment.",
            )
            model = st.text_input("Model", value=_configured_secret("OPENAI_MODEL") or "gpt-4o-mini")
        elif provider == "Groq Cloud":
            api_key_input = st.text_input(
                "Groq API key",
                value="",
                type="password",
                help="Leave empty to use GROQ_API_KEY from Streamlit Secrets or the environment.",
            )
            model = st.text_input("Groq model", value=groq_model)
            if groq_key:
                st.caption("GROQ_API_KEY is configured securely.")
        else:
            api_key_input = ""
            if installed_models:
                model = st.selectbox(
                    "Ollama model",
                    installed_models,
                    index=installed_models.index(selected_model),
                    help="The 1B model is recommended for faster local analysis.",
                )
            else:
                model = st.text_input("Ollama model", value=selected_model)
            advanced_ollama_url = st.text_input("Ollama URL", value=ollama_url)
        append_to_trace = st.checkbox("Append structured AI arguments to proof trace", value=True)
        if st.button("Run Advanced Coordinator"):
            try:
                with st.spinner("Calling Agentic AI coordinator"):
                    if provider == "OpenAI API":
                        key = api_key_input.strip() or openai_key
                        if not key:
                            st.warning("Add an API key or set OPENAI_API_KEY to run the OpenAI-backed agent.")
                            return
                        raw_analysis = _run_llm_agentic_analysis(findings, trace, key, model.strip())
                    elif provider == "Groq Cloud":
                        key = api_key_input.strip() or groq_key
                        if not key:
                            st.warning("Add a Groq API key or configure GROQ_API_KEY in Streamlit Secrets.")
                            return
                        raw_analysis = _run_groq_agentic_analysis(findings, trace, key, model.strip())
                    else:
                        raw_analysis = _run_ollama_agentic_analysis(
                            findings,
                            trace,
                            advanced_ollama_url.strip(),
                            model.strip(),
                        )
                working_trace = trace or ProofTrace()
                argument_payload = _parse_ai_argument_payload(raw_analysis, findings, working_trace)
                analysis = _format_ai_argument_payload(argument_payload)
                st.session_state.llm_agentic_analysis = analysis
                ai_events: List[ProofEvent] = []
                if append_to_trace:
                    trace = working_trace
                    st.session_state.proof_trace = trace
                    ai_events = _append_structured_ai_events(
                        trace,
                        findings,
                        argument_payload,
                        actor="LLMCoordinatorAgent",
                        provider=provider,
                        model=model.strip(),
                    )
                    st.session_state.ai_argument_event_ids = [event.id for event in ai_events]
                    scan_id = _save_scan(
                        st.session_state.get("project_name_input") or st.session_state.get("project_name", "default-project"),
                        f"advanced-agentic:{st.session_state.get('repo_path', '')}",
                        findings,
                        trace,
                    )
                    st.session_state.last_scan_id = scan_id
                st.session_state.llm_agentic_source = f"Advanced Coordinator - {provider} - {model.strip()}"
                suffix = f" as {len(ai_events)} linked argument nodes." if ai_events else "."
                st.success("Coordinator analysis generated and displayed below" + suffix)
            except Exception as exc:
                st.error(f"Coordinator analysis failed: {exc}")

    if st.session_state.get("llm_agentic_analysis"):
        st.subheader("Latest LLM analysis")
        st.caption(st.session_state.get("llm_agentic_source", "Agentic AI coordinator output"))
        st.markdown(st.session_state.llm_agentic_analysis)
        st.caption("Coordinator output is part of the reasoning trace. A human reviewer must still approve remediation decisions.")

    trace = st.session_state.get("proof_trace")
    if trace and any(event.metadata.get("ai_generated") for event in trace.events):
        _render_ai_argumentation(trace, interactive=True)


def _flatten_events(trace: ProofTrace) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for event in trace.events:
        row = event.to_dict()
        metadata = row.pop("metadata", {})
        row.update(metadata)
        row["references"] = ", ".join(row.get("references") or [])
        rows.append(row)
    return rows


def _anonymize_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    file_map: Dict[str, str] = {}
    endpoint_map: Dict[str, str] = {}
    anonymized: List[Dict[str, Any]] = []
    for finding in findings:
        item = dict(finding)
        file_value = item.get("file")
        endpoint_value = item.get("endpoint")
        if file_value:
            key = str(file_value)
            suffix = Path(key).suffix
            file_map.setdefault(key, f"source/file_{len(file_map) + 1}{suffix}")
            item["file"] = file_map[key]
        if endpoint_value:
            key = str(endpoint_value)
            endpoint_map.setdefault(key, f"endpoint-{len(endpoint_map) + 1}.example")
            item["endpoint"] = endpoint_map[key]
        anonymized.append(item)
    return anonymized


def _filter_findings_for_report(findings: List[Dict[str, Any]], severities: Set[str], anonymize_paths: bool) -> List[Dict[str, Any]]:
    filtered = [finding for finding in findings if str(finding.get("severity", "low")) in severities]
    return _anonymize_findings(filtered) if anonymize_paths else filtered


def _subset_trace(trace: ProofTrace | None, event_ids: Set[str]) -> ProofTrace | None:
    if not trace:
        return None
    subset = ProofTrace()
    for event in trace.events:
        if event.id in event_ids:
            subset.add_event(event)
    return subset


def _filter_trace_for_export(
    trace: ProofTrace | None,
    actors: Set[str] | None = None,
    kinds: Set[str] | None = None,
    severities: Set[str] | None = None,
    path_event_id: str | None = None,
    include_context: bool = True,
) -> ProofTrace | None:
    if not trace:
        return None
    events_by_id = {event.id: event for event in trace.events}
    selected_ids: Set[str] = set(events_by_id)
    if path_event_id and path_event_id in events_by_id:
        selected_ids = _connected_path_ids(events_by_id, path_event_id)
    if actors:
        selected_ids &= {event.id for event in trace.events if event.actor in actors}
    if kinds:
        selected_ids &= {event.id for event in trace.events if event.kind in kinds}
    if severities:
        selected_ids &= {
            event.id
            for event in trace.events
            if not event.metadata.get("severity") or str(event.metadata.get("severity")) in severities
        }
    if include_context:
        frontier = list(selected_ids)
        while frontier:
            current = frontier.pop()
            event = events_by_id.get(current)
            if not event:
                continue
            for ref in event.references or []:
                if ref in events_by_id and ref not in selected_ids:
                    selected_ids.add(ref)
                    frontier.append(ref)
    return _subset_trace(trace, selected_ids)


def _report_identity_lines() -> List[str]:
    return [
        f"**Author:** {PROJECT_AUTHOR}",
        f"**Affiliation:** {PROJECT_AFFILIATION}",
        f"**Contact:** {PROJECT_EMAIL}",
        f"**Source code:** {PROJECT_SOURCE_URL}",
        f"**Live demo:** {PROJECT_DEMO_URL}",
    ]


def _build_markdown_report(
    findings: List[Dict[str, Any]],
    trace: ProofTrace | None,
    include_playbooks: bool = True,
    include_proof_events: bool = True,
    include_citation: bool = True,
) -> str:
    findings = _attach_operational_metadata(findings)
    lines = [
        "# APEC-PS PQC Risk Report",
        "",
        "## Findings",
        "",
        "| Severity | Score | Status | Algorithm | Type | Location | Evidence |",
        "| --- | ---: | --- | --- | --- | --- | --- |",
    ]
    for finding in findings:
        location = f"{finding.get('file')}:{finding.get('line_no') or '?'}"
        evidence = str(finding.get("evidence") or "").replace("|", "\\|")
        status = finding.get("review", {}).get("status", "open")
        lines.append(
            f"| {finding.get('severity')} | {finding.get('risk_score')} | {status} | {finding.get('algorithm')} | "
            f"{finding.get('type')} | {location} | {evidence} |"
        )
    if include_playbooks:
        lines.extend(["", "## Remediation Playbooks", ""])
        for finding in findings:
            playbook = finding.get("playbook", {})
            lines.append(f"### {finding.get('algorithm')} - {finding.get('type')} ({finding.get('finding_id')})")
            lines.append("")
            lines.append(str(playbook.get("summary", "")))
            lines.append("")
            for step in playbook.get("steps", []):
                lines.append(f"- {step}")
            lines.append("")
    if trace and include_proof_events:
        lines.extend(["", "## Proof Events", ""])
        for event in trace.events:
            refs = ", ".join(event.references or [])
            lines.append(f"- **{event.actor} / {event.kind}**: {event.claim} (refs: {refs or '-'})")
    if include_citation:
        lines.extend(["", "## Suggested Citation", "", PROJECT_CITATION])
    return "\n".join(lines) + "\n"


def _build_university_markdown_report(
    findings: List[Dict[str, Any]],
    trace: ProofTrace | None,
    include_identity: bool = True,
    include_citation: bool = True,
    include_playbooks: bool = True,
    include_proof_events: bool = True,
) -> str:
    findings = _attach_operational_metadata(findings)
    severity = _severity_counts(findings)
    reviews = _review_counts(findings) or {"open": len(findings)}
    total_score = sum(int(finding.get("risk_score") or 0) for finding in findings)
    generated_at = datetime.now(timezone.utc).isoformat()
    high_priority = sorted(findings, key=lambda item: item.get("risk_score", 0), reverse=True)[:8]
    trace_events = trace.events if trace and include_proof_events else []
    event_counts: Dict[str, int] = {}
    actor_counts: Dict[str, int] = {}
    for event in trace_events:
        event_counts[event.kind] = event_counts.get(event.kind, 0) + 1
        actor_counts[event.actor] = actor_counts.get(event.actor, 0) + 1

    lines = [
        "# APEC-PS",
        "## Argumentation for Trustworthy Agentic AI",
        "### Post-Quantum Cryptography Risk Triage",
        "",
    ]
    if include_identity:
        lines.extend(_report_identity_lines())
        lines.append("")
    lines.extend([
        f"**Generated:** {generated_at}",
        "",
        "## Abstract",
        "",
        "This report documents a post-quantum cryptography risk triage produced by the APEC-PS prototype. "
        "The application combines static cryptographic discovery, operational risk scoring, deterministic "
        "agent reasoning, argumentation-based support and attack events, and human-review evidence into an "
        "auditable migration artefact.",
        "",
        "## Methodology",
        "",
        "1. Repository, ZIP, GitHub, or TLS endpoint evidence is scanned for classical cryptographic exposure.",
        "2. Findings are normalized with severity, confidence, retention, impact, and migration-complexity metadata.",
        "3. Deterministic APEC-PS agents convert findings into premises, support arguments, attacks, warrants, claims, and validations.",
        "4. The argument graph highlights which claims are supported, challenged, or still waiting for human review.",
        "5. Report exports preserve evidence for security review, research discussion, or incident documentation.",
        "",
        "## Executive Summary",
        "",
        f"- Total findings: **{len(findings)}**",
        f"- High severity: **{severity['high']}**",
        f"- Medium severity: **{severity['medium']}**",
        f"- Low severity: **{severity['low']}**",
        f"- Aggregate risk score: **{total_score}**",
        f"- APEC-PS proof events: **{len(trace_events)}**",
        "",
        "## Review Status",
        "",
    ])
    for status, count in sorted(reviews.items()):
        lines.append(f"- {status}: **{count}**")

    lines.extend(
        [
            "",
            "## Priority Findings",
            "",
            "| Priority | Severity | Score | Algorithm | Type | Location | Evidence |",
            "| ---: | --- | ---: | --- | --- | --- | --- |",
        ]
    )
    for index, finding in enumerate(high_priority, start=1):
        location = f"{finding.get('file') or finding.get('endpoint') or 'unknown'}:{finding.get('line_no') or '?'}"
        evidence = str(finding.get("evidence") or finding.get("description") or "").replace("|", "\\|")
        lines.append(
            f"| {index} | {finding.get('severity')} | {finding.get('risk_score')} | "
            f"{finding.get('algorithm')} | {finding.get('type')} | {location} | {evidence} |"
        )

    if include_proof_events:
        lines.extend(["", "## APEC-PS Agent Reasoning", ""])
    if trace_events and include_proof_events:
        lines.append("### Event Distribution")
        lines.append("")
        for kind, count in sorted(event_counts.items()):
            lines.append(f"- {kind}: **{count}**")
        lines.append("")
        lines.append("### Agent Contributions")
        lines.append("")
        for actor, count in sorted(actor_counts.items()):
            lines.append(f"- {actor}: **{count}** proof events")
        lines.append("")
        lines.append("### Representative Proof Events")
        lines.append("")
        for event in trace_events[:20]:
            refs = ", ".join(event.references or [])
            lines.append(f"- **{event.actor} / {event.kind}:** {event.claim} (refs: {refs or '-'})")
    elif include_proof_events:
        lines.append("No proof trace is attached. Run the Agents page to include support, attack, warrant, claim, and validation events.")

    if include_playbooks:
        lines.extend(["", "## Remediation Backlog", ""])
        for finding in high_priority:
            playbook = finding.get("playbook", {})
            lines.append(f"### {finding.get('algorithm')} - {finding.get('type')} ({finding.get('finding_id')})")
            lines.append("")
            lines.append(f"**Priority:** {finding.get('severity')} / score {finding.get('risk_score')}")
            lines.append("")
            lines.append(str(playbook.get("summary", "")))
            lines.append("")
            for step in playbook.get("steps", []):
                lines.append(f"- {step}")
            lines.append("")

    lines.extend(
        [
            "## Limitations",
            "",
            "- The scanner is a research prototype and should not replace certified security testing.",
            "- Findings require validation by the owning engineering/security team.",
            "- LLM coordinator arguments must be evidence-linked and human-reviewed before remediation.",
            "- Public deployments should use sample data and avoid private repositories or internal endpoints.",
        ]
    )
    if include_citation:
        lines.extend(["", "## Suggested Citation", "", PROJECT_CITATION])
    return "\n".join(lines) + "\n"


def _build_pdf_report(
    markdown_text: str,
    findings: List[Dict[str, Any]] | None = None,
    trace: ProofTrace | None = None,
    university: bool = False,
    include_identity: bool = True,
    include_citation: bool = True,
    include_playbooks: bool = True,
    include_proof_events: bool = True,
) -> bytes | None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import Image as RLImage
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except Exception:
        return None

    def short(value: Any, limit: int = 95) -> str:
        text = str(value or "").replace("\n", " ").strip()
        return text if len(text) <= limit else text[: limit - 1] + "..."

    def para(value: Any, style_name: str = "BodyText") -> Any:
        return Paragraph(html.escape(str(value or "")), styles[style_name])

    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
        title="APEC-PS PQC Risk Report",
    )
    styles = getSampleStyleSheet()
    styles["Title"].fontName = "Helvetica-Bold"
    styles["Title"].fontSize = 22
    styles["Heading1"].fontName = "Helvetica-Bold"
    styles["Heading1"].fontSize = 15
    styles["Heading2"].fontName = "Helvetica-Bold"
    styles["Heading2"].fontSize = 12
    styles["BodyText"].fontSize = 8.5
    styles["BodyText"].leading = 11
    story: List[Any] = []

    if LOGO_PATH.exists():
        story.append(RLImage(str(LOGO_PATH), width=1.15 * inch, height=1.15 * inch))
        story.append(Spacer(1, 6))
    story.append(Paragraph("APEC-PS", styles["Title"]))
    story.append(Paragraph("Argumentation for Trustworthy Agentic AI", styles["Heading1"]))
    story.append(Paragraph("Post-Quantum Cryptography Risk Triage", styles["Heading2"]))
    story.append(Spacer(1, 8))
    if include_identity:
        story.append(para(f"Author: {PROJECT_AUTHOR}"))
        story.append(para(f"Affiliation: {PROJECT_AFFILIATION}"))
        story.append(para(f"Contact: {PROJECT_EMAIL}"))
        story.append(para(f"Source code: {PROJECT_SOURCE_URL}"))
        story.append(para(f"Live demo: {PROJECT_DEMO_URL}"))
    story.append(para(f"Generated: {datetime.now(timezone.utc).isoformat()}"))
    story.append(Spacer(1, 12))

    if not findings:
        for raw_line in markdown_text.splitlines():
            cleaned = raw_line.strip().replace("#", "").replace("*", "")
            if cleaned:
                story.append(para(cleaned))
                story.append(Spacer(1, 3))
        document.build(story)
        return buffer.getvalue()

    enriched = _attach_operational_metadata(findings)
    severity = _severity_counts(enriched)
    reviews = _review_counts(enriched) or {"open": len(enriched)}
    total_score = sum(int(finding.get("risk_score") or 0) for finding in enriched)
    trace_events = trace.events if trace and include_proof_events else []

    story.append(Paragraph("Executive Summary", styles["Heading1"]))
    summary_data = [
        [para("Metric", "Heading2"), para("Value", "Heading2")],
        [para("Total findings"), para(len(enriched))],
        [para("High severity"), para(severity["high"])],
        [para("Medium severity"), para(severity["medium"])],
        [para("Low severity"), para(severity["low"])],
        [para("Aggregate risk score"), para(total_score)],
        [para("APEC-PS proof events"), para(len(trace_events))],
    ]
    summary_table = Table(summary_data, colWidths=[2.45 * inch, 4.45 * inch], repeatRows=1)
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 12))

    if university:
        story.append(Paragraph("Methodology", styles["Heading1"]))
        methodology_rows = [
            [para("1"), para("Scan repository, ZIP, GitHub, or TLS endpoint evidence for cryptographic exposure.")],
            [para("2"), para("Normalize findings with severity, confidence, retention, business impact, and migration complexity.")],
            [para("3"), para("Run deterministic APEC-PS agents to produce support, attack, warrant, claim, and validation events.")],
            [para("4"), para("Export the evidence for security review, research discussion, or incident documentation.")],
        ]
        methodology_table = Table(methodology_rows, colWidths=[0.35 * inch, 6.55 * inch])
        methodology_table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(methodology_table)
        story.append(Spacer(1, 12))

    story.append(Paragraph("Priority Findings", styles["Heading1"]))
    top_findings = sorted(enriched, key=lambda item: item.get("risk_score", 0), reverse=True)[:12]
    finding_rows = [[para("#", "Heading2"), para("Severity", "Heading2"), para("Score", "Heading2"), para("Algorithm", "Heading2"), para("Type", "Heading2"), para("Location", "Heading2"), para("Evidence", "Heading2")]]
    for index, finding in enumerate(top_findings, start=1):
        location = f"{finding.get('file') or finding.get('endpoint') or 'unknown'}:{finding.get('line_no') or '?'}"
        finding_rows.append(
            [
                para(index),
                para(finding.get("severity")),
                para(finding.get("risk_score")),
                para(finding.get("algorithm")),
                para(short(finding.get("type"), 34)),
                para(short(location, 60)),
                para(short(finding.get("evidence") or finding.get("description"), 120)),
            ]
        )
    findings_table = Table(
        finding_rows,
        colWidths=[0.28 * inch, 0.62 * inch, 0.42 * inch, 0.72 * inch, 0.92 * inch, 1.45 * inch, 2.49 * inch],
        repeatRows=1,
    )
    findings_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(findings_table)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Review Status", styles["Heading1"]))
    review_rows = [[para("Status", "Heading2"), para("Count", "Heading2")]]
    review_rows.extend([[para(status), para(count)] for status, count in sorted(reviews.items())])
    review_table = Table(review_rows, colWidths=[3.45 * inch, 3.45 * inch], repeatRows=1)
    review_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(review_table)
    story.append(Spacer(1, 12))

    if trace_events and include_proof_events:
        story.append(Paragraph("APEC-PS Agent Reasoning", styles["Heading1"]))
        event_counts: Dict[str, int] = {}
        actor_counts: Dict[str, int] = {}
        for event in trace_events:
            event_counts[event.kind] = event_counts.get(event.kind, 0) + 1
            actor_counts[event.actor] = actor_counts.get(event.actor, 0) + 1
        event_rows = [[para("Event kind", "Heading2"), para("Count", "Heading2")]]
        event_rows.extend([[para(kind), para(count)] for kind, count in sorted(event_counts.items())])
        actor_rows = [[para("Agent", "Heading2"), para("Proof events", "Heading2")]]
        actor_rows.extend([[para(actor), para(count)] for actor, count in sorted(actor_counts.items())])
        reasoning_table = Table(event_rows, colWidths=[3.45 * inch, 3.45 * inch], repeatRows=1)
        reasoning_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        actor_table = Table(actor_rows, colWidths=[4.6 * inch, 2.3 * inch], repeatRows=1)
        actor_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(reasoning_table)
        story.append(Spacer(1, 8))
        story.append(actor_table)
        story.append(Spacer(1, 12))

        proof_rows = [[para("Agent / Kind", "Heading2"), para("Claim", "Heading2"), para("References", "Heading2")]]
        for event in trace_events[:20]:
            proof_rows.append(
                [
                    para(f"{event.actor} / {event.kind}"),
                    para(short(event.claim, 180)),
                    para(short(", ".join(event.references or []) or "-", 90)),
                ]
            )
        proof_table = Table(proof_rows, colWidths=[1.8 * inch, 3.7 * inch, 1.4 * inch], repeatRows=1)
        proof_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(Paragraph("Representative Proof Events", styles["Heading1"]))
        story.append(proof_table)
        story.append(Spacer(1, 12))

    if include_playbooks:
        story.append(Paragraph("Remediation Backlog", styles["Heading1"]))
        backlog_rows = [[para("Finding", "Heading2"), para("Priority", "Heading2"), para("Recommended action", "Heading2")]]
        for finding in top_findings:
            playbook = finding.get("playbook", {})
            backlog_rows.append(
                [
                    para(f"{finding.get('algorithm')} / {finding.get('type')}"),
                    para(f"{finding.get('severity')} / {finding.get('risk_score')}"),
                    para(short(playbook.get("summary"), 180)),
                ]
            )
        backlog_table = Table(backlog_rows, colWidths=[2.2 * inch, 1.2 * inch, 3.5 * inch], repeatRows=1)
        backlog_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(backlog_table)
        story.append(Spacer(1, 12))

    if include_citation:
        story.append(Paragraph("Citation", styles["Heading1"]))
        story.append(para(PROJECT_CITATION))
    document.build(story)
    return buffer.getvalue()


def _build_json_export(findings: List[Dict[str, Any]], trace: ProofTrace | None) -> str:
    payload = {
        "schema": "apec-ps-pqc-report/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": _attach_operational_metadata(findings),
        "proof_trace": trace.to_list() if trace else [],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _sarif_level(severity: str | None) -> str:
    return {"high": "error", "medium": "warning", "low": "note"}.get(str(severity), "note")


def _build_sarif_export(findings: List[Dict[str, Any]]) -> str:
    findings = _attach_operational_metadata(findings)
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for finding in findings:
        rule_id = f"PQC.{finding.get('type', 'finding')}.{finding.get('algorithm', 'unknown')}".replace(" ", "_")
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": str(finding.get("algorithm", "PQC finding")),
                "shortDescription": {"text": str(finding.get("description", "PQC risk finding"))[:200]},
                "help": {"text": str(finding.get("description", "Review this cryptographic finding for PQC migration."))},
                "properties": {
                    "tags": ["security", "cryptography", "post-quantum"],
                    "precision": finding.get("confidence", "medium"),
                },
            },
        )
        uri = str(finding.get("file") or finding.get("endpoint") or "unknown")
        location: Dict[str, Any] = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
        if finding.get("line_no"):
            location["physicalLocation"]["region"] = {"startLine": int(finding["line_no"])}
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(finding.get("severity")),
                "message": {"text": f"{finding.get('algorithm')} risk: {finding.get('description')}"},
                "locations": [location],
                "properties": {
                    "severity": finding.get("severity"),
                    "risk_score": finding.get("risk_score"),
                    "confidence": finding.get("confidence"),
                    "evidence": finding.get("evidence"),
                    "tls_version": finding.get("tls_version"),
                    "cipher": finding.get("cipher"),
                    "endpoint": finding.get("endpoint"),
                    "review": finding.get("review"),
                    "playbook": finding.get("playbook"),
                },
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "APEC-PS PQC Prototype",
                        "informationUri": PROJECT_SOURCE_URL,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True)


def _render_agent_selector() -> List[Any]:
    st.subheader("Agent pipeline")
    st.caption("Choose which reasoning agents should contribute to the APEC-PS trace.")
    agent_names = [agent.name for agent in ALL_AGENTS]
    selected_names = st.multiselect("Enabled agents", agent_names, default=agent_names)
    selected_agents = [agent for agent in ALL_AGENTS if agent.name in selected_names]

    for agent in selected_agents:
        icon = AGENT_ICONS.get(agent.name, "bot")
        st.markdown(
            f"<div class='agent-row'><b>{icon}</b> {agent.name}<br><small>{agent.role}</small></div>",
            unsafe_allow_html=True,
        )
    return selected_agents


def _render_findings(findings: List[Dict[str, Any]]) -> None:
    findings = _attach_operational_metadata(findings)
    severities = sorted({f.get("severity", "low") for f in findings})
    selected = st.multiselect("Severity filter", severities, default=severities)
    min_score = st.slider("Minimum risk score", 0, 12, 0)
    filtered = [f for f in findings if f.get("severity") in selected and f.get("risk_score", 0) >= min_score]

    st.caption(f"Showing {len(filtered)} of {len(findings)} findings")
    if not filtered:
        st.info("No findings match the current filters.")
        return
    df = pd.DataFrame(filtered)
    preferred = [
        "finding_id", "severity", "risk_score", "review_status", "algorithm", "type", "confidence", "file", "line_no",
        "retention_years", "business_impact", "migration_complexity", "evidence", "description",
    ]
    df["review_status"] = df["review"].apply(lambda value: value.get("status", "open") if isinstance(value, dict) else "open")
    st.dataframe(df[[col for col in preferred if col in df.columns]], use_container_width=True, hide_index=True)

    st.subheader("Risk acceptance and remediation")
    selected_finding_id = st.selectbox(
        "Finding",
        [f["finding_id"] for f in filtered],
        format_func=lambda fid: next(
            f"{item['algorithm']} / {item['type']} / {item['severity']} / {fid}"
            for item in filtered
            if item["finding_id"] == fid
        ),
    )
    finding = next(item for item in filtered if item["finding_id"] == selected_finding_id)
    review = finding.get("review", {})
    st.markdown(
        f"""
        <div class="section-card">
          <div style="display:flex;justify-content:space-between;gap:12px;align-items:center;">
            <div>
              <h3 style="margin:0;color:#07185f;">{html.escape(str(finding.get('algorithm')))} remediation case</h3>
              <p style="margin:4px 0 0 0;color:#64748b;">{html.escape(str(finding.get('type')))} · {html.escape(str(finding.get('file')))}:{html.escape(str(finding.get('line_no') or '?'))}</p>
            </div>
            <div>{_severity_html(str(finding.get('severity', 'low')))} {_status_badge(review.get('status', 'open'))}</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("**Finding detail**")
    d1, d2, d3, d4 = st.columns(4)
    with d1:
        _metric_card("Risk score", finding.get("risk_score", "-"), "context-aware score", "#b516b5")
    with d2:
        _metric_card("Confidence", finding.get("confidence", "-"), "detection quality", "#0ea5e9")
    with d3:
        _metric_card("Impact", finding.get("business_impact", "-"), "business context", "#d97706")
    with d4:
        _metric_card("Complexity", finding.get("migration_complexity", "-"), "migration estimate", "#059669")
    st.markdown("**Evidence**")
    st.code(str(finding.get("evidence") or "No evidence string available."))
    st.markdown("**Description**")
    st.write(finding.get("description", ""))


def _render_review_page() -> None:
    st.header("Review")
    findings = st.session_state.get("findings", [])
    if not findings:
        _empty_state("No findings to review", "Run Demo Mode or scan a repository first. Review links findings to APEC-PS trace events and human decisions.")
        return

    enriched = _attach_operational_metadata(findings)
    st.write("Inspect the trace links for a finding and record the human review decision separately from the scanner output.")
    selected_finding_id = st.selectbox(
        "Finding to review",
        [finding["finding_id"] for finding in enriched],
        format_func=lambda fid: next(
            f"{item['algorithm']} / {item['type']} / {item['severity']} / {fid}"
            for item in enriched
            if item["finding_id"] == fid
        ),
        key="review_page_finding",
    )
    finding = next(item for item in enriched if item["finding_id"] == selected_finding_id)
    review = finding.get("review", {})

    st.markdown(
        f"""
        <div class="section-card">
          <div style="display:flex;justify-content:space-between;gap:12px;align-items:center;">
            <div>
              <h3 style="margin:0;color:#07185f;">{html.escape(str(finding.get('algorithm')))} review case</h3>
              <p style="margin:4px 0 0 0;color:#64748b;">{html.escape(str(finding.get('type')))} in {html.escape(str(finding.get('file')))}:{html.escape(str(finding.get('line_no') or '?'))}</p>
            </div>
            <div>{_severity_html(str(finding.get('severity', 'low')))} {_status_badge(review.get('status', 'open'))}</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    decision_tab, trace_tab, playbook_tab, review_tab = st.tabs(
        ["Finding-to-decision", "Trace links", "Remediation playbook", "Human review"]
    )
    with decision_tab:
        _render_finding_to_decision(finding, st.session_state.get("proof_trace"))
    with trace_tab:
        _render_finding_trace_links(finding, st.session_state.get("proof_trace"))
    with playbook_tab:
        playbook = finding.get("playbook", {})
        st.markdown("**Recommended remediation path**")
        st.write(playbook.get("summary", "No remediation playbook is available for this finding."))
        for idx, step in enumerate(playbook.get("steps", []), start=1):
            st.write(f"{idx}. {step}")
        c1, c2, c3 = st.columns(3)
        with c1:
            _metric_card("Priority", playbook.get("priority", finding.get("severity", "-")), "playbook priority", "#dc2626")
        with c2:
            _metric_card("Algorithm", finding.get("algorithm", "-"), "affected primitive", "#0ea5e9")
        with c3:
            _metric_card("Complexity", finding.get("migration_complexity", "-"), "migration estimate", "#7c3aed")
    with review_tab:
        st.markdown("**Human review decision**")
        statuses = ["open", "planned", "accepted", "false_positive", "fixed", "needs_review"]
        current_status = review.get("status", "open")
        status = st.selectbox(
            "Status",
            statuses,
            index=statuses.index(current_status) if current_status in statuses else 0,
            key="review_page_status",
        )
        reviewer = st.text_input("Reviewer", value=review.get("reviewer", ""), key="review_page_reviewer")
        reason = st.text_area("Reason", value=review.get("reason", ""), key="review_page_reason")
        expires_on = st.text_input(
            "Expiry date",
            value=review.get("expires_on") or "",
            placeholder="YYYY-MM-DD, optional",
            key="review_page_expires",
        )
        if st.button("Save review decision", type="primary"):
            if not reviewer.strip() or not reason.strip():
                st.warning("Reviewer and reason are required.")
            else:
                _save_review(finding["finding_id"], status, reviewer.strip(), reason.strip(), expires_on.strip() or None)
                if st.session_state.get("proof_trace"):
                    _append_review_event(
                        st.session_state.proof_trace,
                        finding,
                        {
                            "status": status,
                            "reviewer": reviewer.strip(),
                            "reason": reason.strip(),
                            "expires_on": expires_on.strip() or None,
                        },
                    )
                scan_id = _save_scan(
                    st.session_state.get("project_name_input") or st.session_state.get("project_name", "default-project"),
                    f"review:{finding['finding_id']}",
                    st.session_state.get("findings", findings),
                    st.session_state.get("proof_trace"),
                )
                st.session_state.last_scan_id = scan_id
                st.success("Review decision saved and linked to the current APEC-PS trace.")
                st.rerun()


def _render_argument_graphs_page() -> None:
    st.header("Argument Graphs")
    trace: ProofTrace | None = st.session_state.get("proof_trace")
    if not trace:
        _empty_state("No argument graph yet", "Run Demo Mode, Agents, or Agentic AI first to create an APEC-PS proof trace.")
        return
    st.write("Inspect the APEC-PS proof trace as a graph of evidence, support, attacks, warrants, plans, AI-generated arguments, and human validation.")
    _render_graph(trace)


def _render_trace(trace: ProofTrace) -> None:
    rows = _flatten_events(trace)
    actors = sorted({row["actor"] for row in rows})
    kinds = sorted({row["kind"] for row in rows})
    selected_actors = st.multiselect("Agent filter", actors, default=actors)
    selected_kinds = st.multiselect("Event filter", kinds, default=kinds)
    filtered = [row for row in rows if row["actor"] in selected_actors and row["kind"] in selected_kinds]

    st.dataframe(pd.DataFrame(filtered), use_container_width=True, hide_index=True)
    for row in filtered:
        severity = row.get("severity")
        label = f"{KIND_ICONS.get(row['kind'], '-') } {row['actor']} - {row['kind']}"
        with st.expander(label):
            if severity:
                st.markdown(_severity_html(str(severity)), unsafe_allow_html=True)
            st.write(row["claim"])
            metadata = {k: v for k, v in row.items() if k not in {"id", "actor", "kind", "claim"} and v not in (None, "", [])}
            st.json(metadata)


def _event_option_label(event: Any) -> str:
    severity = event.metadata.get("severity")
    algorithm = event.metadata.get("algorithm")
    bits = [event.actor, event.kind]
    if severity:
        bits.append(str(severity))
    if algorithm:
        bits.append(str(algorithm))
    return f"{event.id} | {' / '.join(bits)} | {event.claim[:80]}"


def _connected_path_ids(events_by_id: Dict[str, Any], selected_id: str) -> Set[str]:
    parents: Dict[str, Set[str]] = {event_id: set(event.references or []) for event_id, event in events_by_id.items()}
    children: Dict[str, Set[str]] = {event_id: set() for event_id in events_by_id}
    for event_id, refs in parents.items():
        for ref in refs:
            if ref in children:
                children[ref].add(event_id)

    path_ids = {selected_id}
    frontier = [selected_id]
    while frontier:
        current = frontier.pop()
        for parent in parents.get(current, set()):
            if parent not in path_ids:
                path_ids.add(parent)
                frontier.append(parent)
    frontier = [selected_id]
    while frontier:
        current = frontier.pop()
        for child in children.get(current, set()):
            if child not in path_ids:
                path_ids.add(child)
                frontier.append(child)
    return path_ids


def _groupable_premise_key(event: Any) -> Tuple[str, str, str] | None:
    if event.kind != "premise":
        return None
    return (
        str(event.metadata.get("algorithm", "unknown")),
        str(event.metadata.get("severity", "unknown")),
        str(event.metadata.get("type", "finding")),
    )


def _build_graph_projection(trace: ProofTrace, collapse_repeated: bool) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]], Dict[str, str]]:
    if not collapse_repeated:
        nodes = [
            {
                "id": event.id,
                "event_ids": [event.id],
                "actor": event.actor,
                "kind": event.kind,
                "claim": event.claim,
                "metadata": event.metadata,
                "count": 1,
                "grouped": False,
            }
            for event in trace.events
        ]
        edges = [
            {"from": ref, "to": event.id, "kind": event.kind}
            for event in trace.events
            for ref in (event.references or [])
        ]
        return nodes, edges, {event.id: event.id for event in trace.events}

    groups: Dict[Tuple[str, str, str], List[Any]] = {}
    id_map: Dict[str, str] = {}
    nodes: List[Dict[str, Any]] = []
    for event in trace.events:
        key = _groupable_premise_key(event)
        if key:
            groups.setdefault(key, []).append(event)
        else:
            nodes.append(
                {
                    "id": event.id,
                    "event_ids": [event.id],
                    "actor": event.actor,
                    "kind": event.kind,
                    "claim": event.claim,
                    "metadata": event.metadata,
                    "count": 1,
                    "grouped": False,
                }
            )
            id_map[event.id] = event.id

    for key, grouped_events in groups.items():
        if len(grouped_events) == 1:
            event = grouped_events[0]
            nodes.append(
                {
                    "id": event.id,
                    "event_ids": [event.id],
                    "actor": event.actor,
                    "kind": event.kind,
                    "claim": event.claim,
                    "metadata": event.metadata,
                    "count": 1,
                    "grouped": False,
                }
            )
            id_map[event.id] = event.id
            continue

        algorithm, severity, finding_type = key
        group_id = f"group:{algorithm}:{severity}:{finding_type}"
        for event in grouped_events:
            id_map[event.id] = group_id
        nodes.append(
            {
                "id": group_id,
                "event_ids": [event.id for event in grouped_events],
                "actor": "CryptoDiscoveryAgent",
                "kind": "premise",
                "claim": f"{len(grouped_events)} grouped {severity} {algorithm} {finding_type} findings",
                "metadata": {
                    "severity": severity,
                    "algorithm": algorithm,
                    "type": finding_type,
                    "risk_score": max(event.metadata.get("risk_score", 0) for event in grouped_events),
                },
                "count": len(grouped_events),
                "grouped": True,
            }
        )

    edge_seen = set()
    edges: List[Dict[str, str]] = []
    for event in trace.events:
        to_id = id_map.get(event.id, event.id)
        for ref in event.references or []:
            from_id = id_map.get(ref, ref)
            if from_id == to_id:
                continue
            key = (from_id, to_id, event.kind)
            if key in edge_seen:
                continue
            edge_seen.add(key)
            edges.append({"from": from_id, "to": to_id, "kind": event.kind})
    return nodes, edges, id_map


def _render_graph_inspector(event: Any, events_by_id: Dict[str, Any]) -> None:
    inbound = [source for source in (event.references or []) if source in events_by_id]
    outbound = [candidate.id for candidate in events_by_id.values() if event.id in (candidate.references or [])]
    st.markdown(_severity_html(str(event.metadata.get("severity", "low"))), unsafe_allow_html=True)
    st.write(event.claim)
    c1, c2, c3 = st.columns(3)
    c1.metric("Inbound refs", len(inbound))
    c2.metric("Outbound refs", len(outbound))
    c3.metric("Risk score", event.metadata.get("risk_score", "-"))
    st.json(
        {
            "id": event.id,
            "actor": event.actor,
            "kind": event.kind,
            "references": event.references or [],
            "metadata": event.metadata,
        }
    )


def _inject_graph_click_inspector(html: str, node_details: Dict[str, Dict[str, Any]]) -> str:
    details_json = json.dumps(node_details).replace("</", "<\\/")
    panel = """
    <div id="node-inspector" style="
      position:absolute; right:14px; top:14px; z-index:10; width:320px;
      max-height:70%; overflow:auto; background:#ffffff; border:1px solid #cbd5e1;
      border-radius:8px; box-shadow:0 8px 24px rgba(15,23,42,.16);
      padding:12px; font-family:Arial,sans-serif; color:#0f172a;">
      <div style="font-weight:700;margin-bottom:4px;">Node details</div>
      <div style="font-size:12px;color:#475569;">Click a graph node to inspect its claim, evidence, and metadata.</div>
    </div>
    <div id="graph-legend" style="
      position:absolute; left:14px; bottom:14px; z-index:10; width:280px;
      background:#ffffff; border:1px solid #cbd5e1; border-radius:8px;
      box-shadow:0 8px 24px rgba(15,23,42,.12); padding:12px;
      font-family:Arial,sans-serif; color:#0f172a; font-size:12px;">
      <div style="font-weight:700;margin-bottom:8px;">Severity and edge legend</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px;">
        <span style="background:#dc2626;color:#fff;border-radius:999px;padding:2px 8px;">high</span>
        <span style="background:#d97706;color:#fff;border-radius:999px;padding:2px 8px;">medium</span>
        <span style="background:#059669;color:#fff;border-radius:999px;padding:2px 8px;">low</span>
      </div>
      <div><span style="color:#16a34a;font-weight:700;">support</span> strengthens a claim</div>
      <div><span style="color:#dc2626;font-weight:700;">attack</span> challenges a claim</div>
      <div><span style="color:#94a3b8;font-weight:700;">other</span> warrant, premise, validation, or plan</div>
      <div style="margin-top:6px;"><span style="border:3px solid #b516b5;padding:1px 6px;font-weight:700;">AI</span> generated node with provenance metadata</div>
      <div style="margin-top:6px;color:#475569;">Thick red node borders mark unresolved challenges.</div>
    </div>
    <script>
      const APEC_NODE_DETAILS = __DETAILS__;
      function escapeHtml(value) {
        return String(value ?? "").replace(/[&<>"']/g, function(ch) {
          return {"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#039;"}[ch];
        });
      }
      function renderNodeInspector(nodeId) {
        const target = document.getElementById("node-inspector");
        const item = APEC_NODE_DETAILS[nodeId];
        if (!target || !item) return;
        const metadata = escapeHtml(JSON.stringify(item.metadata || {}, null, 2));
        target.innerHTML = `
          <div style="font-weight:700;margin-bottom:6px;">${escapeHtml(item.actor)} / ${escapeHtml(item.kind)}</div>
          <div style="font-size:12px;color:#475569;margin-bottom:8px;">${escapeHtml(item.id)}</div>
          <div style="line-height:1.35;margin-bottom:8px;">${escapeHtml(item.claim)}</div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px;">
            <span style="background:#e2e8f0;border-radius:999px;padding:2px 8px;font-size:12px;">severity: ${escapeHtml(item.severity || "-")}</span>
            <span style="background:#e2e8f0;border-radius:999px;padding:2px 8px;font-size:12px;">score: ${escapeHtml(item.risk_score || "-")}</span>
            <span style="background:#e2e8f0;border-radius:999px;padding:2px 8px;font-size:12px;">count: ${escapeHtml(item.count || 1)}</span>
            <span style="background:#f3e8ff;border-radius:999px;padding:2px 8px;font-size:12px;">model: ${escapeHtml((item.metadata || {}).model || "-")}</span>
            <span style="background:#f3e8ff;border-radius:999px;padding:2px 8px;font-size:12px;">confidence: ${escapeHtml((item.metadata || {}).confidence ?? "-")}</span>
            <span style="background:#f3e8ff;border-radius:999px;padding:2px 8px;font-size:12px;">review: ${escapeHtml((item.metadata || {}).review_status || "-")}</span>
          </div>
          <pre style="white-space:pre-wrap;background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:8px;font-size:11px;">${metadata}</pre>
        `;
      }
      network.on("click", function(params) {
        if (params.nodes && params.nodes.length) {
          renderNodeInspector(params.nodes[0]);
        }
      });
    </script>
    """.replace("__DETAILS__", details_json)
    return html.replace("</body>", panel + "</body>")


def _build_argument_graph_html(
    trace: ProofTrace,
    layout_mode: str = "Hierarchical",
    collapse_repeated: bool = True,
    height: int = 760,
) -> str | None:
    try:
        from pyvis.network import Network
    except Exception:
        return None

    projected_nodes, projected_edges, _ = _build_graph_projection(trace, collapse_repeated)
    events_by_id = {event.id: event for event in trace.events}
    attacked_ids = {ref for event in trace.events if event.kind == "attack" for ref in (event.references or [])}
    unresolved_projected_ids = set(attacked_ids)
    projected_by_id = {node["id"]: node for node in projected_nodes}

    net = Network(height=f"{height}px", width="100%", directed=True, bgcolor="#ffffff", font_color="#0f172a")
    if layout_mode == "Hierarchical":
        net.toggle_physics(False)
        net.set_options(
            """
            {
              "layout": {"hierarchical": {"enabled": true, "direction": "LR", "sortMethod": "directed", "levelSeparation": 220, "nodeSpacing": 160}},
              "physics": {"enabled": false},
              "edges": {"smooth": {"type": "cubicBezier", "forceDirection": "horizontal"}}
            }
            """
        )
    elif layout_mode == "Timeline":
        net.toggle_physics(False)
    else:
        net.toggle_physics(True)
        net.set_options("""{"physics": {"stabilization": true}, "edges": {"smooth": true}}""")

    kind_rows = {"premise": 0, "support": 1, "warrant": 2, "attack": 3, "claim": 4, "validation": 5}
    for idx, node in enumerate(projected_nodes):
        metadata = node["metadata"]
        severity = metadata.get("severity")
        kind = node["kind"]
        is_ai = bool(metadata.get("ai_generated"))
        color = SEVERITY_COLORS.get(str(severity), KIND_COLORS.get(kind, "#64748b"))
        is_unresolved = node["id"] in unresolved_projected_ids and kind in {"claim", "support", "warrant"}
        border = "#b91c1c" if is_unresolved else "#b516b5" if is_ai else KIND_COLORS.get(kind, "#64748b")
        title = f"{node['actor']}<br>{kind}<br>{node['claim']}"
        if severity:
            title += f"<br>Severity: {severity}"
        if metadata.get("risk_score") is not None:
            title += f"<br>Risk score: {metadata.get('risk_score')}"
        if node["grouped"]:
            title += f"<br>Grouped events: {node['count']}"
        if is_ai:
            title += (
                f"<br>AI role: {metadata.get('argument_role', '-')}"
                f"<br>Provider: {metadata.get('provider', '-')}"
                f"<br>Model: {metadata.get('model', '-')}"
                f"<br>Confidence: {metadata.get('confidence', '-')}"
                f"<br>Grounding: {metadata.get('grounding_status', '-')}"
                f"<br>Trust score: {metadata.get('trust_score', '-')}/{metadata.get('trust_score_max', '-')}"
                f"<br>Human review: {metadata.get('review_status', 'pending_review')}"
            )
        label = f"AI - {str(metadata.get('argument_role', kind)).replace('_', ' ')}" if is_ai else f"{node['actor']}\n{kind}"
        if node["grouped"]:
            label = f"{node['count']} findings\n{metadata.get('algorithm')}"
        x = idx * 180 if layout_mode == "Timeline" else None
        y = kind_rows.get(kind, 2) * 95 if layout_mode == "Timeline" else None
        net.add_node(
            node["id"],
            label=label,
            title=title,
            color={"background": color, "border": border, "highlight": {"background": "#fef3c7", "border": "#f59e0b"}},
            shape="box",
            margin=8,
            borderWidth=5 if is_unresolved else 4 if is_ai else 1,
            x=x,
            y=y,
            fixed=layout_mode == "Timeline",
        )

    for edge in projected_edges:
        edge_kind = edge["kind"]
        ai_edge = bool(projected_by_id.get(edge["to"], {}).get("metadata", {}).get("ai_generated"))
        edge_color = "#dc2626" if edge_kind == "attack" else "#16a34a" if edge_kind == "support" else "#94a3b8"
        net.add_edge(
            edge["from"],
            edge["to"],
            color=edge_color,
            label=edge_kind,
            title=f"{edge_kind}: {edge['from']} -> {edge['to']}",
            arrows="to",
            dashes=ai_edge,
            width=2 if ai_edge else 1,
            font={"align": "middle", "size": 11, "color": "#334155"},
        )

    node_details = {
        node_id: {
            "id": node_id,
            "event_ids": node["event_ids"],
            "actor": node["actor"],
            "kind": node["kind"],
            "claim": node["claim"],
            "severity": node["metadata"].get("severity"),
            "risk_score": node["metadata"].get("risk_score"),
            "metadata": node["metadata"],
            "count": node["count"],
            "grouped": node["grouped"],
        }
        for node_id, node in projected_by_id.items()
    }
    return _inject_graph_click_inspector(net.generate_html(notebook=False), node_details)


def _build_html_report(
    findings: List[Dict[str, Any]],
    trace: ProofTrace | None,
    graph_html: str | None,
    include_identity: bool = True,
    include_citation: bool = True,
    include_playbooks: bool = True,
    include_proof_events: bool = True,
) -> str:
    enriched = _attach_operational_metadata(findings)
    logo_uri = _logo_data_uri()
    logo_html = f"<img src='{logo_uri}' alt='APEC-PS logo' class='report-logo'>" if logo_uri else ""
    rows = []
    for finding in enriched:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(finding.get('severity', '')))}</td>"
            f"<td>{html.escape(str(finding.get('risk_score', '')))}</td>"
            f"<td>{html.escape(str(finding.get('review', {}).get('status', 'open')))}</td>"
            f"<td>{html.escape(str(finding.get('algorithm', '')))}</td>"
            f"<td>{html.escape(str(finding.get('type', '')))}</td>"
            f"<td>{html.escape(str(finding.get('file', '')))}:{html.escape(str(finding.get('line_no') or '?'))}</td>"
            f"<td>{html.escape(str(finding.get('evidence') or ''))}</td>"
            "</tr>"
        )
    playbooks = []
    if include_playbooks:
        for finding in enriched:
            steps = "".join(f"<li>{html.escape(str(step))}</li>" for step in finding.get("playbook", {}).get("steps", []))
            playbooks.append(
                "<section class='card'>"
                f"<h3>{html.escape(str(finding.get('algorithm')))} - {html.escape(str(finding.get('type')))}</h3>"
                f"<p><b>Finding ID:</b> {html.escape(str(finding.get('finding_id')))}</p>"
                f"<p>{html.escape(str(finding.get('playbook', {}).get('summary', '')))}</p>"
                f"<ol>{steps}</ol>"
                "</section>"
            )
    events = ""
    if trace and include_proof_events:
        events = "".join(
            "<li>"
            f"<b>{html.escape(event.actor)} / {html.escape(event.kind)}</b>: {html.escape(event.claim)}"
            f"<br><small>refs: {html.escape(', '.join(event.references or []) or '-')}</small>"
            "</li>"
            for event in trace.events
        )
    graph_section = graph_html or "<p>Argument graph excluded or unavailable. Enable graph export, install pyvis, and run agents before exporting.</p>"
    identity_section = (
        f"""
      <p><b>Author:</b> {html.escape(PROJECT_AUTHOR)} &middot; <b>Affiliation:</b> {html.escape(PROJECT_AFFILIATION)} &middot; <b>Contact:</b> {html.escape(PROJECT_EMAIL)}</p>
      <p><b>Source code:</b> <a href="{html.escape(PROJECT_SOURCE_URL)}">{html.escape(PROJECT_SOURCE_URL)}</a></p>
      <p><b>Live demo:</b> <a href="{html.escape(PROJECT_DEMO_URL)}">{html.escape(PROJECT_DEMO_URL)}</a></p>
        """
        if include_identity
        else ""
    )
    playbook_section = f"<h2>Remediation Playbooks</h2>{''.join(playbooks)}" if include_playbooks else ""
    proof_section = f"<h2>Proof Events</h2><ul>{events or '<li>No proof events included.</li>'}</ul>" if include_proof_events else ""
    citation_section = f"<p><b>Suggested citation:</b> {html.escape(PROJECT_CITATION)}</p>" if include_citation else ""
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>APEC-PS PQC Risk Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #0f172a; background: #f8fafc; }}
    h1 {{ margin-bottom: 4px; }}
    h2 {{ margin-top: 32px; border-bottom: 1px solid #cbd5e1; padding-bottom: 6px; }}
    table {{ border-collapse: collapse; width: 100%; background: #fff; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 8px; vertical-align: top; font-size: 13px; }}
    th {{ background: #e2e8f0; text-align: left; }}
    .card {{ background: #fff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 14px; margin: 12px 0; }}
    .graph-frame {{ background: #fff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 8px; }}
    .report-header {{ display: flex; align-items: center; gap: 18px; background: #fff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 18px; }}
    .report-logo {{ width: 112px; height: auto; object-fit: contain; }}
  </style>
</head>
<body>
  <section class="report-header">
    {logo_html}
    <div>
      <h1>APEC-PS</h1>
      <p><b>Argumentation for Trustworthy Agentic AI</b></p>
      <p>Post-Quantum Cryptography Risk Triage</p>
      {identity_section}
      <p><small>Generated at {html.escape(datetime.now(timezone.utc).isoformat())}</small></p>
    </div>
  </section>

  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Score</th><th>Status</th><th>Algorithm</th><th>Type</th><th>Location</th><th>Evidence</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>

  <h2>Argument Graph</h2>
  <div class="graph-frame">{graph_section}</div>

  {playbook_section}

  {proof_section}

  <h2>Rights and Contact</h2>
  <p>{html.escape(PROJECT_RIGHTS)}</p>
  <p>{html.escape(PROJECT_USAGE)}</p>
  {citation_section}
</body>
</html>"""


def _build_university_html_report(
    findings: List[Dict[str, Any]],
    trace: ProofTrace | None,
    graph_html: str | None,
    include_identity: bool = True,
    include_citation: bool = True,
    include_playbooks: bool = True,
    include_proof_events: bool = True,
) -> str:
    enriched = _attach_operational_metadata(findings)
    logo_uri = _logo_data_uri()
    logo_html = f"<img src='{logo_uri}' alt='APEC-PS logo' class='cover-logo'>" if logo_uri else ""
    severity = _severity_counts(enriched)
    reviews = _review_counts(enriched) or {"open": len(enriched)}
    total_score = sum(int(finding.get("risk_score") or 0) for finding in enriched)
    trace_events = trace.events if trace and include_proof_events else []
    generated_at = datetime.now(timezone.utc).isoformat()
    top_findings = sorted(enriched, key=lambda item: item.get("risk_score", 0), reverse=True)[:8]
    event_counts: Dict[str, int] = {}
    actor_counts: Dict[str, int] = {}
    for event in trace_events:
        event_counts[event.kind] = event_counts.get(event.kind, 0) + 1
        actor_counts[event.actor] = actor_counts.get(event.actor, 0) + 1

    finding_rows = "".join(
        "<tr>"
        f"<td>{index}</td>"
        f"<td><span class='sev {html.escape(str(finding.get('severity', 'low')))}'>{html.escape(str(finding.get('severity', '')))}</span></td>"
        f"<td>{html.escape(str(finding.get('risk_score', '')))}</td>"
        f"<td>{html.escape(str(finding.get('algorithm', '')))}</td>"
        f"<td>{html.escape(str(finding.get('type', '')))}</td>"
        f"<td>{html.escape(str(finding.get('file') or finding.get('endpoint') or 'unknown'))}:{html.escape(str(finding.get('line_no') or '?'))}</td>"
        f"<td>{html.escape(str(finding.get('evidence') or finding.get('description') or ''))}</td>"
        "</tr>"
        for index, finding in enumerate(top_findings, start=1)
    )
    review_items = "".join(f"<li><b>{html.escape(status)}</b>: {count}</li>" for status, count in sorted(reviews.items()))
    event_items = "".join(f"<li><b>{html.escape(kind)}</b>: {count}</li>" for kind, count in sorted(event_counts.items()))
    actor_items = "".join(f"<li><b>{html.escape(actor)}</b>: {count} events</li>" for actor, count in sorted(actor_counts.items()))
    proof_items = "".join(
        "<li>"
        f"<b>{html.escape(event.actor)} / {html.escape(event.kind)}</b>: {html.escape(event.claim)}"
        f"<br><small>refs: {html.escape(', '.join(event.references or []) or '-')}</small>"
        "</li>"
        for event in trace_events[:30]
    ) if include_proof_events else ""
    backlog = []
    if include_playbooks:
        for finding in top_findings:
            playbook = finding.get("playbook", {})
            steps = "".join(f"<li>{html.escape(str(step))}</li>" for step in playbook.get("steps", [])[:6])
            backlog.append(
                "<section class='card'>"
                f"<h3>{html.escape(str(finding.get('algorithm')))} - {html.escape(str(finding.get('type')))}</h3>"
                f"<p><b>Finding ID:</b> {html.escape(str(finding.get('finding_id')))} &middot; "
                f"<b>Priority:</b> {html.escape(str(finding.get('severity')))} / score {html.escape(str(finding.get('risk_score')))}</p>"
                f"<p>{html.escape(str(playbook.get('summary', '')))}</p>"
                f"<ol>{steps}</ol>"
                "</section>"
            )
    graph_section = graph_html or "<p>Argument graph unavailable. Run agents and install pyvis to include it.</p>"
    identity_section = (
        f"""
        <p><b>Author:</b> {html.escape(PROJECT_AUTHOR)}<br>
        <b>Affiliation:</b> {html.escape(PROJECT_AFFILIATION)}<br>
        <b>Contact:</b> {html.escape(PROJECT_EMAIL)}<br>
        <b>Source code:</b> <a href="{html.escape(PROJECT_SOURCE_URL)}">{html.escape(PROJECT_SOURCE_URL)}</a><br>
        <b>Live demo:</b> <a href="{html.escape(PROJECT_DEMO_URL)}">{html.escape(PROJECT_DEMO_URL)}</a></p>
        """
        if include_identity
        else ""
    )
    backlog_section = f"<section class=\"section\"><h2>Remediation Backlog</h2>{''.join(backlog)}</section>" if include_playbooks else ""
    proof_section = f"<section class=\"section\"><h2>Representative Proof Events</h2><ul>{proof_items or '<li>No proof events available.</li>'}</ul></section>" if include_proof_events else ""
    citation_section = f"<p><b>Suggested citation:</b> {html.escape(PROJECT_CITATION)}</p>" if include_citation else ""
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>APEC-PS Academic Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 0; color: #0f172a; background: #eef2f7; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 28px; }}
    .cover {{ background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 34px; margin-bottom: 20px; }}
    .cover-inner {{ display: flex; gap: 24px; align-items: flex-start; }}
    .cover-logo {{ width: 150px; height: auto; object-fit: contain; }}
    .cover h1 {{ margin: 0; font-size: 44px; color: #07185f; }}
    .cover h2 {{ margin: 8px 0 4px 0; color: #0f172a; font-size: 24px; }}
    .cover p {{ color: #475569; line-height: 1.45; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0; }}
    .metric {{ background: #ffffff; border: 1px solid #cbd5e1; border-top: 4px solid #0ea5e9; border-radius: 8px; padding: 14px; }}
    .metric b {{ display: block; font-size: 28px; color: #07185f; }}
    .section {{ background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; margin: 14px 0; }}
    h2 {{ color: #07185f; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; }}
    table {{ border-collapse: collapse; width: 100%; background: #fff; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 8px; vertical-align: top; font-size: 13px; }}
    th {{ background: #e2e8f0; text-align: left; }}
    .card {{ background: #f8fafc; border: 1px solid #d8e0ea; border-radius: 8px; padding: 14px; margin: 12px 0; }}
    .graph-frame {{ background: #fff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 8px; }}
    .sev {{ border-radius: 999px; padding: 2px 8px; color: #fff; font-weight: 700; font-size: 12px; }}
    .sev.high {{ background: #dc2626; }}
    .sev.medium {{ background: #d97706; }}
    .sev.low {{ background: #059669; }}
    small {{ color: #64748b; }}
  </style>
</head>
<body>
<main>
  <section class="cover">
    <div class="cover-inner">
      {logo_html}
      <div>
        <h1>APEC-PS</h1>
        <h2>Argumentation for Trustworthy Agentic AI</h2>
        <p><b>Post-Quantum Cryptography Risk Triage</b></p>
        {identity_section}
        <p><small>Generated at {html.escape(generated_at)}</small></p>
      </div>
    </div>
  </section>

  <div class="grid">
    <div class="metric">Findings<b>{len(enriched)}</b></div>
    <div class="metric">High severity<b>{severity['high']}</b></div>
    <div class="metric">Risk score<b>{total_score}</b></div>
    <div class="metric">Proof events<b>{len(trace_events)}</b></div>
  </div>

  <section class="section">
    <h2>Abstract</h2>
    <p>This report documents a post-quantum cryptography risk triage generated by APEC-PS. It combines cryptographic discovery, risk scoring, deterministic agent reasoning, argumentation-based proof events, and human-review evidence into an auditable migration artefact.</p>
  </section>

  <section class="section">
    <h2>Methodology</h2>
    <ol>
      <li>Scan repository, ZIP, GitHub, or TLS endpoint evidence for cryptographic exposure.</li>
      <li>Normalize findings with severity, confidence, retention, business impact, and migration complexity.</li>
      <li>Run APEC-PS agents to produce premises, support arguments, attacks, warrants, claims, and validations.</li>
      <li>Inspect the argument graph to identify supported claims and unresolved challenges.</li>
      <li>Export evidence for security review, research discussion, or incident documentation.</li>
    </ol>
  </section>

  <section class="section">
    <h2>Priority Findings</h2>
    <table>
      <thead><tr><th>#</th><th>Severity</th><th>Score</th><th>Algorithm</th><th>Type</th><th>Location</th><th>Evidence</th></tr></thead>
      <tbody>{finding_rows}</tbody>
    </table>
  </section>

  <section class="section">
    <h2>Governance And Agent Reasoning</h2>
    <h3>Review status</h3>
    <ul>{review_items}</ul>
    <h3>Event distribution</h3>
    <ul>{event_items or '<li>No proof trace attached.</li>'}</ul>
    <h3>Agent contributions</h3>
    <ul>{actor_items or '<li>No agent contributions attached.</li>'}</ul>
  </section>

  <section class="section">
    <h2>Argument Graph</h2>
    <div class="graph-frame">{graph_section}</div>
  </section>

  {backlog_section}

  {proof_section}

  <section class="section">
    <h2>Limitations And Citation</h2>
    <p>{html.escape(PROJECT_USAGE)}</p>
    <p>{html.escape(PROJECT_RIGHTS)}</p>
    {citation_section}
  </section>
</main>
</body>
</html>"""


def _load_ml_kem_768():
    try:
        from pqcrypto.kem import ml_kem_768

        return ml_kem_768
    except Exception as exc:
        raise RuntimeError("PQC export requires the `pqcrypto` package with ML-KEM-768 support.") from exc


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


def _derive_report_key(shared_secret: bytes, associated_data: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"APEC-PS PQC report export|" + associated_data,
    ).derive(shared_secret)


def _generate_pqc_recipient_keypair() -> Dict[str, str]:
    kem = _load_ml_kem_768()
    public_key, secret_key = kem.generate_keypair()
    return {
        "algorithm": "ML-KEM-768",
        "public_key": _b64encode(public_key),
        "secret_key": _b64encode(secret_key),
        "public_key_fingerprint": hashlib.sha256(public_key).hexdigest()[:24],
    }


def _encrypt_report_with_ml_kem(plaintext: bytes, public_key_b64: str, plaintext_format: str) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    kem = _load_ml_kem_768()
    public_key = _b64decode(public_key_b64.strip())
    kem_ciphertext, shared_secret = kem.encrypt(public_key)
    associated_data = json.dumps(
        {
            "schema": "apec-ps-pqc-encrypted-report/v1",
            "kem": "ML-KEM-768",
            "kdf": "HKDF-SHA256",
            "cipher": "AES-256-GCM",
            "plaintext_format": plaintext_format,
        },
        sort_keys=True,
    ).encode("utf-8")
    aes_key = _derive_report_key(shared_secret, associated_data)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, associated_data)
    package = {
        "schema": "apec-ps-pqc-encrypted-report/v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "kem": "ML-KEM-768",
        "kdf": "HKDF-SHA256",
        "cipher": "AES-256-GCM",
        "public_key_fingerprint": hashlib.sha256(public_key).hexdigest()[:24],
        "plaintext_format": plaintext_format,
        "associated_data": _b64encode(associated_data),
        "kem_ciphertext": _b64encode(kem_ciphertext),
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
    }
    return json.dumps(package, indent=2, sort_keys=True)


def _decrypt_report_with_ml_kem(package_json: str, secret_key_b64: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    kem = _load_ml_kem_768()
    package = json.loads(package_json)
    shared_secret = kem.decrypt(_b64decode(secret_key_b64.strip()), _b64decode(package["kem_ciphertext"]))
    associated_data = _b64decode(package["associated_data"])
    aes_key = _derive_report_key(shared_secret, associated_data)
    return AESGCM(aes_key).decrypt(_b64decode(package["nonce"]), _b64decode(package["ciphertext"]), associated_data)


def _render_pqc_report_export(html_report: str, json_export: str) -> None:
    st.subheader("PQC-Protected Report Export")
    st.write("Encrypt the generated report for a recipient using ML-KEM-768 to establish key material and AES-256-GCM for the report payload.")
    st.caption("For a real workflow, the recipient generates the key pair and shares only the public key. The private key should not be uploaded or shared.")

    try:
        _load_ml_kem_768()
    except Exception as exc:
        st.warning(str(exc))
        st.code("python -m pip install pqcrypto", language="powershell")
        return

    if st.button("Generate demo ML-KEM recipient keypair"):
        st.session_state.pqc_recipient_keypair = _generate_pqc_recipient_keypair()

    keypair = st.session_state.get("pqc_recipient_keypair")
    if keypair:
        c1, c2 = st.columns(2)
        c1.metric("KEM", keypair["algorithm"])
        c2.metric("Public key fingerprint", keypair["public_key_fingerprint"])
        st.download_button(
            "Download recipient public key",
            keypair["public_key"],
            file_name="apecps_ml_kem_768_public_key.b64",
            mime="text/plain",
        )
        st.download_button(
            "Download demo recipient private key",
            keypair["secret_key"],
            file_name="apecps_ml_kem_768_private_key_KEEP_SECRET.b64",
            mime="text/plain",
        )

    public_key = st.text_area(
        "Recipient ML-KEM-768 public key",
        value=keypair["public_key"] if keypair else "",
        height=120,
        help="Paste a base64 ML-KEM-768 public key. For demos, generate one above.",
    )
    report_format = st.selectbox("Plaintext report to encrypt", ["HTML report", "JSON report"])
    plaintext = html_report.encode("utf-8") if report_format == "HTML report" else json_export.encode("utf-8")
    plaintext_format = "text/html" if report_format == "HTML report" else "application/json"
    if st.button("Encrypt report with ML-KEM + AES-256-GCM", type="primary"):
        if not public_key.strip():
            st.warning("Generate or paste a recipient public key first.")
        else:
            try:
                encrypted = _encrypt_report_with_ml_kem(plaintext, public_key, plaintext_format)
                st.session_state.pqc_encrypted_report = encrypted
                st.success("Report encrypted with ML-KEM-768 + HKDF-SHA256 + AES-256-GCM.")
            except Exception as exc:
                st.error(f"PQC encryption failed: {exc}")

    if st.session_state.get("pqc_encrypted_report"):
        st.download_button(
            "Download PQC-encrypted report package",
            st.session_state.pqc_encrypted_report,
            file_name="apecps_pqc_encrypted_report.json",
            mime="application/json",
        )

    with st.expander("Decrypt package locally for verification"):
        st.caption("Use this for secure exchange: upload or paste a package sent by someone else, then provide your ML-KEM private key.")
        package_upload = st.file_uploader("Upload encrypted report package", type=["json"], key="pqc_package_upload")
        key_upload = st.file_uploader("Upload recipient private key", type=["b64", "txt", "key"], key="pqc_private_key_upload")
        uploaded_package_text = package_upload.getvalue().decode("utf-8") if package_upload else ""
        uploaded_key_text = key_upload.getvalue().decode("utf-8") if key_upload else ""
        package_json = st.text_area(
            "Encrypted package JSON",
            value=uploaded_package_text or st.session_state.get("pqc_encrypted_report", ""),
            height=140,
        )
        secret_key = st.text_area(
            "Recipient private key",
            value=uploaded_key_text or (keypair["secret_key"] if keypair else ""),
            height=120,
        )
        if st.button("Decrypt received package"):
            if not package_json.strip() or not secret_key.strip():
                st.warning("Package JSON and private key are required.")
            else:
                try:
                    decrypted = _decrypt_report_with_ml_kem(package_json, secret_key)
                    package = json.loads(package_json)
                    plaintext_format = package.get("plaintext_format", "application/octet-stream")
                    extension = ".html" if plaintext_format == "text/html" else ".json" if plaintext_format == "application/json" else ".bin"
                    mime = plaintext_format if plaintext_format in {"text/html", "application/json", "text/plain"} else "application/octet-stream"
                    st.session_state.pqc_decrypted_report = decrypted
                    st.session_state.pqc_decrypted_format = plaintext_format
                    st.success("Decryption succeeded.")
                    st.download_button(
                        "Download decrypted report",
                        decrypted,
                        file_name=f"decrypted_apecps_report{extension}",
                        mime=mime,
                    )
                    if plaintext_format == "text/html":
                        components.html(decrypted.decode("utf-8", errors="replace"), height=420, scrolling=True)
                    elif plaintext_format == "application/json":
                        st.json(json.loads(decrypted.decode("utf-8")))
                    else:
                        st.code(decrypted.decode("utf-8", errors="replace")[:5000])
                except Exception as exc:
                    st.error(f"Decryption failed: {exc}")


def _render_graph(trace: ProofTrace) -> None:
    try:
        from pyvis.network import Network
        import streamlit.components.v1 as components
    except Exception:
        st.warning("Install pyvis to view the interactive argument graph.")
        return

    events_by_id = {event.id: event for event in trace.events}
    attacked_ids = {ref for event in trace.events if event.kind == "attack" for ref in (event.references or [])}
    graph_cols = st.columns([2, 1, 1])
    with graph_cols[0]:
        query = st.text_input(
            "Search nodes",
            placeholder="Actor, claim, severity, algorithm...",
            help="Filters the graph to matching nodes plus their direct references and dependents.",
        ).strip().lower()
    with graph_cols[1]:
        height = st.slider("Graph height", 360, 900, 560, step=40)
    with graph_cols[2]:
        physics = st.toggle("Physics layout", value=True)

    control_cols = st.columns([1, 1, 2])
    with control_cols[0]:
        layout_mode = st.selectbox("Layout", ["Hierarchical", "Force-directed", "Timeline"])
    with control_cols[1]:
        collapse_repeated = st.toggle("Group repeated findings", value=True)
    with control_cols[2]:
        selected_event_id = st.selectbox(
            "Inspect / highlight path",
            [""] + [event.id for event in trace.events],
            format_func=lambda value: "Select a node" if not value else _event_option_label(events_by_id[value]),
        )

    path_ids = _connected_path_ids(events_by_id, selected_event_id) if selected_event_id else set()
    if selected_event_id:
        with st.expander("Selected node details", expanded=True):
            _render_graph_inspector(events_by_id[selected_event_id], events_by_id)

    st.markdown(
        """
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin:6px 0 12px 0;">
          <b>Severity:</b>
          <span class="risk-pill" style="background:#dc2626">HIGH</span>
          <span class="risk-pill" style="background:#d97706">MEDIUM</span>
          <span class="risk-pill" style="background:#059669">LOW</span>
          <b style="margin-left:10px;">Node kind border:</b>
          <span style="border-left:18px solid #2563eb;padding-left:6px;">premise</span>
          <span style="border-left:18px solid #16a34a;padding-left:6px;">support</span>
          <span style="border-left:18px solid #dc2626;padding-left:6px;">attack/unresolved</span>
          <span style="border-left:18px solid #7c3aed;padding-left:6px;">warrant</span>
          <span style="border-left:18px solid #0f766e;padding-left:6px;">claim</span>
          <b style="margin-left:10px;">Edges:</b>
          <span style="border-left:18px solid #16a34a;padding-left:6px;">support</span>
          <span style="border-left:18px solid #dc2626;padding-left:6px;">attack</span>
          <span style="border-left:18px solid #94a3b8;padding-left:6px;">other</span>
          <span style="border:3px solid #b516b5;padding:1px 6px;margin-left:10px;">AI + provenance</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    projected_nodes, projected_edges, id_map = _build_graph_projection(trace, collapse_repeated)
    projected_by_id = {node["id"]: node for node in projected_nodes}
    visible_ids = set(events_by_id)
    if query:
        matches = set()
        for event in trace.events:
            haystack = " ".join(
                [
                    event.id,
                    event.actor,
                    event.kind,
                    event.claim,
                    str(event.metadata.get("severity", "")),
                    str(event.metadata.get("algorithm", "")),
                    str(event.metadata.get("risk_score", "")),
                    str(event.metadata.get("argument_role", "")),
                    str(event.metadata.get("provider", "")),
                    str(event.metadata.get("model", "")),
                    str(event.metadata.get("review_status", "")),
                ]
            ).lower()
            if query in haystack:
                matches.add(event.id)
                matches.update(event.references or [])
        for event in trace.events:
            if set(event.references or []) & matches:
                matches.add(event.id)
        visible_ids = {id_map.get(event_id, event_id) for event_id in matches}
        st.caption(f"Graph search matched {len(visible_ids)} connected nodes.")
    else:
        visible_ids = set(projected_by_id)

    projected_path_ids = {id_map.get(event_id, event_id) for event_id in path_ids}
    unresolved_projected_ids = {id_map.get(event_id, event_id) for event_id in attacked_ids}

    net = Network(height=f"{height}px", width="100%", directed=True, bgcolor="#ffffff", font_color="#0f172a")
    net.toggle_physics(physics and layout_mode == "Force-directed")
    if layout_mode == "Hierarchical":
        net.set_options(
            """
            {
              "layout": {"hierarchical": {"enabled": true, "direction": "LR", "sortMethod": "directed", "levelSeparation": 220, "nodeSpacing": 160}},
              "physics": {"enabled": false},
              "edges": {"smooth": {"type": "cubicBezier", "forceDirection": "horizontal"}}
            }
            """
        )
    elif layout_mode == "Timeline":
        net.toggle_physics(False)
    else:
        net.set_options("""{"physics": {"stabilization": true}, "edges": {"smooth": true}}""")

    kind_rows = {"premise": 0, "support": 1, "warrant": 2, "attack": 3, "claim": 4, "validation": 5}
    for idx, node in enumerate(projected_nodes):
        node_id = node["id"]
        if node_id not in visible_ids:
            continue
        metadata = node["metadata"]
        severity = metadata.get("severity")
        kind = node["kind"]
        is_ai = bool(metadata.get("ai_generated"))
        color = SEVERITY_COLORS.get(str(severity), KIND_COLORS.get(kind, "#64748b"))
        is_unresolved = node_id in unresolved_projected_ids and kind in {"claim", "support", "warrant"}
        is_path = not projected_path_ids or node_id in projected_path_ids
        border = "#b91c1c" if is_unresolved else "#b516b5" if is_ai else KIND_COLORS.get(kind, "#64748b")
        title = f"{node['actor']}<br>{kind}<br>{node['claim']}"
        if severity:
            title += f"<br>Severity: {severity}"
        risk_score = metadata.get("risk_score")
        if risk_score is not None:
            title += f"<br>Risk score: {risk_score}"
        if node["grouped"]:
            title += f"<br>Grouped events: {node['count']}"
        if is_unresolved:
            title += "<br>Unresolved attack present"
        if is_ai:
            title += (
                f"<br>AI role: {metadata.get('argument_role', '-')}"
                f"<br>Provider: {metadata.get('provider', '-')}"
                f"<br>Model: {metadata.get('model', '-')}"
                f"<br>Confidence: {metadata.get('confidence', '-')}"
                f"<br>Grounding: {metadata.get('grounding_status', '-')}"
                f"<br>Trust score: {metadata.get('trust_score', '-')}/{metadata.get('trust_score_max', '-')}"
                f"<br>Human review: {metadata.get('review_status', 'pending_review')}"
            )

        label = f"AI - {str(metadata.get('argument_role', kind)).replace('_', ' ')}" if is_ai else f"{node['actor']}\n{kind}"
        if node["grouped"]:
            label = f"{node['count']} findings\n{metadata.get('algorithm')}"
        x = idx * 180 if layout_mode == "Timeline" else None
        y = kind_rows.get(kind, 2) * 95 if layout_mode == "Timeline" else None
        net.add_node(
            node_id,
            label=label,
            title=title,
            color={
                "background": color if is_path else "#e5e7eb",
                "border": border,
                "highlight": {"background": "#fef3c7", "border": "#f59e0b"},
            },
            shape="box",
            margin=8,
            borderWidth=5 if is_unresolved else 4 if is_ai else 3 if node_id in projected_path_ids else 1,
            opacity=1.0 if is_path else 0.35,
            x=x,
            y=y,
            fixed=layout_mode == "Timeline",
        )
    node_details = {
        node["id"]: {
            "id": node["id"],
            "event_ids": node["event_ids"],
            "actor": node["actor"],
            "kind": node["kind"],
            "claim": node["claim"],
            "severity": node["metadata"].get("severity"),
            "risk_score": node["metadata"].get("risk_score"),
            "metadata": node["metadata"],
            "count": node["count"],
            "grouped": node["grouped"],
        }
        for node in projected_nodes
        if node["id"] in visible_ids
    }
    for edge in projected_edges:
        if edge["to"] not in visible_ids or edge["from"] not in visible_ids:
            continue
        edge_kind = edge["kind"]
        edge_in_path = not projected_path_ids or (edge["from"] in projected_path_ids and edge["to"] in projected_path_ids)
        ai_edge = bool(projected_by_id.get(edge["to"], {}).get("metadata", {}).get("ai_generated"))
        edge_color = "#dc2626" if edge_kind == "attack" else "#16a34a" if edge_kind == "support" else "#94a3b8"
        net.add_edge(
            edge["from"],
            edge["to"],
            color=edge_color if edge_in_path else "#cbd5e1",
            label=edge_kind,
            title=f"{edge_kind}: {edge['from']} -> {edge['to']}",
            arrows="to",
            width=3 if edge_in_path and projected_path_ids else 2 if ai_edge else 1,
            dashes=ai_edge or not edge_in_path,
            font={"align": "middle", "size": 11, "color": "#334155"},
        )
    if not visible_ids:
        st.info("No graph nodes match the search.")
        return
    html = _inject_graph_click_inspector(net.generate_html(notebook=False), node_details)
    components.html(html, height=height + 40)


def _safe_extract_zip(archive_path: Path, destination: Path) -> Path:
    extracted = destination / "extracted"
    extracted.mkdir(parents=True, exist_ok=True)
    root = extracted.resolve()
    with zipfile.ZipFile(archive_path, "r") as zf:
        for member in zf.infolist():
            member_path = Path(member.filename)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ValueError(f"Unsafe archive path: {member.filename}")
            target = (extracted / member.filename).resolve()
            target.relative_to(root)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as source, target.open("wb") as sink:
                    sink.write(source.read())
    top_level = [item for item in extracted.iterdir() if item.name != "__MACOSX"]
    if len(top_level) == 1 and top_level[0].is_dir():
        return top_level[0]
    return extracted


def _extract_uploaded_repo(uploaded_file: Any) -> str:
    tmpdir = Path(tempfile.mkdtemp(prefix="pqc_repo_"))
    archive_path = tmpdir / uploaded_file.name
    archive_path.write_bytes(uploaded_file.getbuffer())
    return str(_safe_extract_zip(archive_path, tmpdir))


def _parse_github_url(url: str) -> Tuple[str, str, str | None]:
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        raise ValueError("Use a public GitHub repository URL such as https://github.com/owner/repo.")
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        raise ValueError("GitHub URL must include owner and repository name.")
    owner = parts[0]
    repo = parts[1].removesuffix(".git")
    branch = None
    if len(parts) >= 4 and parts[2] == "tree":
        branch = "/".join(parts[3:])
    return owner, repo, branch


def _github_default_branch(owner: str, repo: str) -> str:
    api_url = f"https://api.github.com/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}"
    request = urllib.request.Request(api_url, headers={"User-Agent": "APEC-PS-PQC-Triage"})
    with urllib.request.urlopen(request, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return str(payload.get("default_branch") or "main")


def _download_github_repo(url: str) -> Tuple[str, str]:
    owner, repo, branch = _parse_github_url(url)
    candidates = []
    if branch:
        candidates.append(branch)
    else:
        try:
            candidates.append(_github_default_branch(owner, repo))
        except Exception:
            candidates.extend(["main", "master"])
    candidates.extend(candidate for candidate in ["main", "master"] if candidate not in candidates)

    last_error: Exception | None = None
    tmpdir = Path(tempfile.mkdtemp(prefix="pqc_github_"))
    for candidate in candidates:
        archive_url = (
            "https://codeload.github.com/"
            f"{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/zip/refs/heads/{urllib.parse.quote(candidate, safe='')}"
        )
        archive_path = tmpdir / f"{repo}-{candidate.replace('/', '-')}.zip"
        request = urllib.request.Request(archive_url, headers={"User-Agent": "APEC-PS-PQC-Triage"})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                archive_path.write_bytes(response.read())
            extracted = _safe_extract_zip(archive_path, tmpdir)
            return str(extracted), f"github:{owner}/{repo}@{candidate}"
        except Exception as exc:
            last_error = exc
    raise RuntimeError(f"Could not download GitHub repository: {last_error}")


def main() -> None:
    logo_uri = _logo_data_uri()
    logo_html = f"<div class='app-logo'><img src='{logo_uri}' alt='APEC-PS logo'></div>" if logo_uri else ""
    st.markdown(
        f"""
        <div class="app-header">
          {logo_html}
          <div>
            <div class="app-title">{APP_TITLE}</div>
            <div class="app-tagline">{APP_TAGLINE}</div>
            <div class="app-subtitle">{APP_SUBTITLE}</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.sidebar:
        st.markdown("### Workflow")
        if "active_page" not in st.session_state:
            st.session_state.active_page = "Demo Mode"
        for section_title, pages, captions in NAV_SECTIONS:
            st.markdown(f"<div class='nav-section'>{section_title}</div>", unsafe_allow_html=True)
            key = f"nav_radio_{section_title}"
            if st.session_state.active_page in pages:
                st.session_state[key] = st.session_state.active_page
            else:
                st.session_state[key] = None
            index = pages.index(st.session_state.active_page) if st.session_state.active_page in pages else None
            st.radio(
                section_title,
                pages,
                captions=captions,
                index=index,
                key=key,
                label_visibility="collapsed",
                on_change=_set_active_nav,
                args=(section_title,),
            )
        step = st.session_state.active_page
        st.text_input("Project name", value=st.session_state.get("project_name", "default-project"), key="project_name_input")

    if step == "Dashboard":
        _render_dashboard()

    elif step == "Demo Mode":
        _render_demo_mode()

    elif step == "About":
        _render_about_page()

    elif step == "Repository":
        st.header("Repository")
        st.write("Choose the evidence source that APEC-PS should scan for post-quantum cryptography migration risks.")
        local_tab, zip_tab, github_tab = st.tabs(["Local path", "ZIP upload", "GitHub URL"])
        repo_path = st.session_state.get("repo_path", str(ROOT / "sample_repo"))
        source_label = st.session_state.get("repo_source", f"repository:{repo_path}")
        with local_tab:
            st.markdown(
                "<div class='source-card'><h4>Local repository</h4><p>Use a directory that exists on the same machine running Streamlit. This is best for development and private experiments.</p></div>",
                unsafe_allow_html=True,
            )
            repo_path = st.text_input(
                "Path accessible to this app",
                value=repo_path,
                help="Use a local directory. ZIP upload and GitHub download are extracted to temporary directories.",
            )
            if st.button("Use local path"):
                st.session_state.repo_path = repo_path
                st.session_state.repo_source = f"repository:{repo_path}"
                st.success("Local path selected.")
        with zip_tab:
            st.markdown(
                "<div class='source-card'><h4>ZIP archive</h4><p>Upload a small demo repository or project archive. The app extracts it into a temporary folder before scanning.</p></div>",
                unsafe_allow_html=True,
            )
            uploaded = st.file_uploader("Upload ZIP archive", type=["zip"])
            if uploaded:
                try:
                    repo_path = _extract_uploaded_repo(uploaded)
                    source_label = f"zip:{uploaded.name}"
                    st.session_state.repo_path = repo_path
                    st.session_state.repo_source = source_label
                    st.success(f"Extracted archive to {repo_path}")
                except Exception as exc:
                    st.error(f"Could not extract ZIP archive: {exc}")
        with github_tab:
            st.markdown(
                "<div class='source-card'><h4>Public GitHub repository</h4><p>Paste a public repository URL. APEC-PS downloads the default branch ZIP and scans the extracted source tree.</p></div>",
                unsafe_allow_html=True,
            )
            github_url = st.text_input(
                "GitHub repository URL",
                value=st.session_state.get("github_repo_url", PROJECT_SOURCE_URL),
                placeholder="https://github.com/owner/repo",
            )
            if st.button("Download GitHub repository", type="primary"):
                try:
                    with st.spinner("Downloading public GitHub repository"):
                        repo_path, source_label = _download_github_repo(github_url)
                    st.session_state.github_repo_url = github_url
                    st.session_state.repo_path = repo_path
                    st.session_state.repo_source = source_label
                    st.success(f"Downloaded {source_label} to {repo_path}")
                except Exception as exc:
                    st.error(f"GitHub download failed: {exc}")
        repo_path = st.session_state.get("repo_path", repo_path)
        source_label = st.session_state.get("repo_source", source_label)
        st.session_state.repo_path = repo_path
        exists = Path(repo_path).exists()
        c1, c2 = st.columns([1, 2])
        c1.metric("Source status", "Ready" if exists else "Missing")
        c2.metric("Source", source_label)
        if exists:
            st.code(repo_path)
        else:
            _empty_state("No valid repository selected", "Select a local path, upload a ZIP archive, or download a public GitHub repository before scanning.")

    elif step == "Findings":
        st.header("Scan and review findings")
        repo_path = st.session_state.get("repo_path", str(ROOT / "sample_repo"))
        workers = st.slider("Parallel scanner workers", 1, 16, 6)
        if st.button("Run scanner", type="primary"):
            with st.spinner("Scanning repository with static analysis and heuristics"):
                st.session_state.findings = scan_repository(repo_path, max_workers=workers)
                scan_id = _save_scan(
                    st.session_state.get("project_name_input") or Path(repo_path).name,
                    st.session_state.get("repo_source") or f"repository:{repo_path}",
                    st.session_state.findings,
                    st.session_state.get("proof_trace"),
                )
                st.session_state.last_scan_id = scan_id
            st.success(f"Found {len(st.session_state.findings)} potential issues")

        with st.expander("Live TLS endpoint scan"):
            st.caption("Enter one endpoint per line. Formats: example.com, example.com:8443, https://example.com.")
            endpoints_text = st.text_area("Endpoints", placeholder="example.com\napi.example.com:443")
            endpoint_timeout = st.slider("Endpoint timeout seconds", 1, 15, 5)
            endpoint_workers = st.slider("Endpoint scanner workers", 1, 12, 4)
            append_results = st.checkbox("Append endpoint findings to repository findings", value=True)
            if st.button("Scan endpoints"):
                endpoints = [line.strip() for line in endpoints_text.splitlines() if line.strip()]
                if not endpoints:
                    st.warning("Enter at least one endpoint.")
                else:
                    with st.spinner("Scanning live TLS endpoints"):
                        endpoint_findings = scan_endpoints(endpoints, timeout=float(endpoint_timeout), max_workers=endpoint_workers)
                    if append_results:
                        st.session_state.findings = st.session_state.get("findings", []) + endpoint_findings
                    else:
                        st.session_state.findings = endpoint_findings
                    scan_id = _save_scan(
                        st.session_state.get("project_name_input") or st.session_state.get("project_name", "default-project"),
                        "endpoints:" + ",".join(endpoints),
                        st.session_state.findings,
                        st.session_state.get("proof_trace"),
                    )
                    st.session_state.last_scan_id = scan_id
                    st.success(f"Endpoint scan produced {len(endpoint_findings)} findings")

        findings = st.session_state.get("findings", [])
        if findings:
            high = sum(1 for f in findings if f.get("severity") == "high")
            medium = sum(1 for f in findings if f.get("severity") == "medium")
            low = sum(1 for f in findings if f.get("severity") == "low")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Findings", len(findings))
            c2.metric("High", high)
            c3.metric("Medium", medium)
            c4.metric("Low", low)
            _render_findings(findings)
        else:
            _empty_state("No findings yet", "Run the repository scanner, scan live TLS endpoints, or use Demo Mode to create a complete example with findings and agent reasoning.")

    elif step == "Review":
        _render_review_page()

    elif step == "Agents":
        st.header("Multi-agent reasoning")
        findings = st.session_state.get("findings", [])
        if not findings:
            _empty_state("Agents need scanner evidence", "Run a scan first so the Discovery, Risk, Compliance, Planning, Critic, and Human Review agents have findings to reason over.")
            return
        selected_agents = _render_agent_selector()
        if not selected_agents:
            st.warning("Select at least one agent.")
            return
        if st.button("Run agents", type="primary"):
            trace = ProofTrace()
            progress = st.progress(0)
            for idx, agent in enumerate(selected_agents, start=1):
                agent.evaluate(findings, trace)
                progress.progress(idx / len(selected_agents), text=f"Executed {agent.name}")
            st.session_state.proof_trace = trace
            scan_id = _save_scan(
                st.session_state.get("project_name_input") or st.session_state.get("project_name", "default-project"),
                f"agent-trace:{st.session_state.get('repo_path', '')}",
                findings,
                trace,
            )
            st.session_state.last_scan_id = scan_id
            st.success(f"Generated {len(trace.events)} proof events")

        trace = st.session_state.get("proof_trace")
        if trace:
            _render_trace(trace)
        else:
            _empty_state("No proof trace yet", "Select the agents you want and click Run agents to create the APEC-PS support, attack, warrant, claim, and validation events.")

    elif step == "Debate":
        _render_debate_view(st.session_state.get("proof_trace"))

    elif step == "Agentic AI":
        _render_agentic_ai_upgrade()

    elif step == "Argument Graphs":
        _render_argument_graphs_page()

    elif step == "History":
        st.header("Persistent scan history")
        scans = _list_scans(limit=50)
        if not scans:
            st.info("No saved scans yet. Run a repository or endpoint scan first.")
            return
        st.dataframe(pd.DataFrame(scans), use_container_width=True, hide_index=True)
        selected_scan_id = st.selectbox(
            "Load scan",
            [scan["id"] for scan in scans],
            format_func=lambda scan_id: next(
                f"#{scan['id']} - {scan['project_name']} - {scan['created_at']} - {scan['finding_count']} findings"
                for scan in scans
                if scan["id"] == scan_id
            ),
        )
        if st.button("Load selected scan into workspace"):
            payload = _load_scan(int(selected_scan_id))
            if payload:
                st.session_state.findings = payload["findings"]
                st.session_state.proof_trace = _trace_from_rows(payload["trace"]) if payload["trace"] else None
                st.session_state.project_name = payload["project_name"]
                st.session_state.last_scan_id = payload["id"]
                st.success(f"Loaded scan #{payload['id']}")
                st.rerun()

    elif step == "Report":
        st.header("Export report")
        findings = st.session_state.get("findings", [])
        trace = st.session_state.get("proof_trace")
        if not findings:
            _empty_state("Report not ready", "Run a scan first, then optionally run the agents. Reports become much stronger when findings and the APEC-PS proof trace are both available.")
            return
        all_severities = ["high", "medium", "low"]
        with st.expander("Report customization", expanded=True):
            c1, c2, c3 = st.columns(3)
            with c1:
                selected_severities = set(st.multiselect("Include severities", all_severities, default=all_severities))
                anonymize_paths = st.checkbox("Anonymize file paths/endpoints", value=False)
            with c2:
                include_graph = st.checkbox("Include argument graph", value=True)
                include_proof_events = st.checkbox("Include proof events", value=True)
                include_playbooks = st.checkbox("Include remediation backlog", value=True)
            with c3:
                include_identity = st.checkbox("Include author/contact details", value=True)
                include_citation = st.checkbox("Include citation", value=True)
                st.caption("These options affect Markdown, HTML, PDF, JSON, and PQC-protected exports generated below.")
        if not selected_severities:
            st.warning("Select at least one severity to export.")
            return
        report_findings = _filter_findings_for_report(findings, selected_severities, anonymize_paths)
        if not report_findings:
            st.warning("The current report filters exclude all findings. Adjust the severity selection to export a report.")
            return
        report_trace = _filter_trace_for_export(trace, severities=selected_severities) if include_proof_events else None
        json_export = _build_json_export(report_findings, report_trace)
        sarif_export = _build_sarif_export(report_findings)
        graph_html = _build_argument_graph_html(report_trace, layout_mode="Hierarchical", collapse_repeated=True) if include_graph and report_trace else None
        markdown = _build_markdown_report(
            report_findings,
            report_trace,
            include_playbooks=include_playbooks,
            include_proof_events=include_proof_events,
            include_citation=include_citation,
        )
        html_report = _build_html_report(
            report_findings,
            report_trace,
            graph_html,
            include_identity=include_identity,
            include_citation=include_citation,
            include_playbooks=include_playbooks,
            include_proof_events=include_proof_events,
        )
        university_markdown = _build_university_markdown_report(
            report_findings,
            report_trace,
            include_identity=include_identity,
            include_citation=include_citation,
            include_playbooks=include_playbooks,
            include_proof_events=include_proof_events,
        )
        university_html = _build_university_html_report(
            report_findings,
            report_trace,
            graph_html,
            include_identity=include_identity,
            include_citation=include_citation,
            include_playbooks=include_playbooks,
            include_proof_events=include_proof_events,
        )
        standard_tab, tooling_tab, pqc_tab, preview_tab = st.tabs(
            ["Standard reports", "Security tooling", "PQC-protected export", "Preview"]
        )
        with standard_tab:
            st.markdown(
                """
                <div class="report-cover">
                  <h2>Academic report package</h2>
                  <p>Formal report export with cover details, methodology, executive summary, APEC-PS agent reasoning, argument graph, remediation backlog, limitations, and citation.</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown("<div class='download-card'><h4>Academic Markdown</h4><p>Structured academic report for editing or submission.</p></div>", unsafe_allow_html=True)
                st.download_button("Download Academic Markdown", university_markdown, file_name="apecps_academic_report.md", mime="text/markdown")
            with c2:
                st.markdown("<div class='download-card'><h4>Academic HTML</h4><p>Polished standalone report with graph and formal sections.</p></div>", unsafe_allow_html=True)
                st.download_button("Download Academic HTML", university_html, file_name="apecps_academic_report.html", mime="text/html")
            with c3:
                st.markdown("<div class='download-card'><h4>Academic PDF</h4><p>Printable version of the academic report.</p></div>", unsafe_allow_html=True)
                university_pdf = _build_pdf_report(university_markdown, findings, trace, university=True)
                if university_pdf:
                    st.download_button("Download Academic PDF", university_pdf, file_name="apecps_academic_report.pdf", mime="application/pdf")
                else:
                    st.info("PDF export is available when reportlab is installed.")
            st.divider()
            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown("<div class='download-card'><h4>Markdown</h4><p>Readable report for docs and review.</p></div>", unsafe_allow_html=True)
                st.download_button("Download Markdown", markdown, file_name="pqc_risk_report.md", mime="text/markdown")
            with c2:
                st.markdown("<div class='download-card'><h4>HTML + Graph</h4><p>Complete report with interactive argument graph.</p></div>", unsafe_allow_html=True)
                st.download_button("Download HTML Report + Graph", html_report, file_name="pqc_risk_report_with_graph.html", mime="text/html")
            with c3:
                st.markdown("<div class='download-card'><h4>PDF</h4><p>Printable summary for presentation or archive.</p></div>", unsafe_allow_html=True)
                pdf_bytes = _build_pdf_report(markdown, findings, trace)
                if pdf_bytes:
                    st.download_button("Download PDF", pdf_bytes, file_name="pqc_risk_report.pdf", mime="application/pdf")
                else:
                    st.info("PDF export is available when reportlab is installed.")
            if graph_html:
                st.markdown("<div class='download-card'><h4>Standalone Graph</h4><p>Interactive APEC-PS argument graph as a separate HTML file.</p></div>", unsafe_allow_html=True)
                st.download_button("Download Standalone Graph HTML", graph_html, file_name="apecps_argument_graph.html", mime="text/html")
            else:
                st.info("Run agents to include the argument graph in HTML exports.")
            if trace:
                with st.expander("Advanced graph export", expanded=False):
                    st.caption("Create a focused graph export for a subset of agents, event types, severities, or one selected reasoning path.")
                    actors = sorted({event.actor for event in trace.events})
                    kinds = sorted({event.kind for event in trace.events})
                    g1, g2, g3 = st.columns(3)
                    with g1:
                        graph_layout = st.selectbox("Graph layout", ["Hierarchical", "Force-directed", "Timeline"], key="report_graph_layout")
                        graph_collapse = st.checkbox("Group repeated finding nodes", value=True, key="report_graph_collapse")
                    with g2:
                        graph_actors = set(st.multiselect("Graph agents", actors, default=actors, key="report_graph_actors"))
                        graph_kinds = set(st.multiselect("Graph event types", kinds, default=kinds, key="report_graph_kinds"))
                    with g3:
                        graph_severities = set(st.multiselect("Graph severities", all_severities, default=list(selected_severities), key="report_graph_severities"))
                        path_options = ["Full filtered graph"] + [event.id for event in trace.events]
                        path_event_id = st.selectbox(
                            "Selected path only",
                            path_options,
                            format_func=lambda value: "Full filtered graph" if value == "Full filtered graph" else _event_option_label(next(event for event in trace.events if event.id == value)),
                            key="report_graph_path",
                        )
                    if graph_actors and graph_kinds and graph_severities:
                        focused_trace = _filter_trace_for_export(
                            trace,
                            actors=graph_actors,
                            kinds=graph_kinds,
                            severities=graph_severities,
                            path_event_id=None if path_event_id == "Full filtered graph" else str(path_event_id),
                        )
                        focused_graph_html = _build_argument_graph_html(focused_trace, layout_mode=graph_layout, collapse_repeated=graph_collapse) if focused_trace else None
                        if focused_graph_html:
                            st.download_button(
                                "Download Filtered Graph HTML",
                                focused_graph_html,
                                file_name="apecps_filtered_argument_graph.html",
                                mime="text/html",
                            )
                            st.caption(f"Filtered graph contains {len(focused_trace.events)} proof events.")
                        else:
                            st.info("No graph events match the selected filters.")
                    else:
                        st.warning("Select at least one agent, event type, and severity for graph export.")
        with tooling_tab:
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("<div class='download-card'><h4>JSON</h4><p>Structured findings, reviews, playbooks, and proof trace.</p></div>", unsafe_allow_html=True)
                st.download_button("Download JSON", json_export, file_name="pqc_risk_report.json", mime="application/json")
            with c2:
                st.markdown("<div class='download-card'><h4>SARIF</h4><p>Security tooling format for code scanning integrations.</p></div>", unsafe_allow_html=True)
                st.download_button("Download SARIF", sarif_export, file_name="pqc_risk_report.sarif", mime="application/sarif+json")
        with pqc_tab:
            _render_pqc_report_export(html_report, json_export)
        with preview_tab:
            _render_polished_report_preview(report_findings, report_trace)
            with st.expander("Raw Markdown report"):
                st.markdown(markdown)


if __name__ == "__main__":
    main()
