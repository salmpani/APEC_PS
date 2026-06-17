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
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple

import pandas as pd
import streamlit as st

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


APP_TITLE = "APEC-PS"
APP_TAGLINE = "Argumentation for Trustworthy Agentic AI"
APP_SUBTITLE = "Post-Quantum Cryptography Risk Triage"
LOGO_PATH = ROOT / "assets" / "apec-ps-logo.png"
DB_PATH = ROOT / "apecps_history.db"

st.set_page_config(page_title=f"{APP_TITLE} - {APP_SUBTITLE}", layout="wide")
st.markdown(
    """
    <style>
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
        color: #1e3a8a;
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


def _render_dashboard() -> None:
    st.header("Executive dashboard")
    findings = st.session_state.get("findings", [])
    trace: ProofTrace | None = st.session_state.get("proof_trace")
    if not findings:
        st.info("No active scan yet. Use Demo Mode or run a repository scan to populate the dashboard.")
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
    c1.metric("Findings", len(enriched))
    c2.metric("High", severity["high"])
    c3.metric("Risk score", total_score)
    c4.metric("Unresolved attacks", unresolved_attacks)
    c5.metric("Readiness", f"{readiness}%")

    left, right = st.columns([1, 1])
    with left:
        st.subheader("Algorithm exposure")
        algo_df = pd.DataFrame(enriched)
        if "algorithm" in algo_df:
            st.bar_chart(algo_df["algorithm"].value_counts())
        st.subheader("Severity")
        st.bar_chart(pd.Series(severity))
    with right:
        st.subheader("Review status")
        st.bar_chart(pd.Series(reviews or {"open": len(enriched)}))
        st.subheader("Top risks")
        top = pd.DataFrame(enriched).sort_values("risk_score", ascending=False).head(5)
        st.dataframe(
            top[["severity", "risk_score", "algorithm", "type", "file", "evidence"]],
            use_container_width=True,
            hide_index=True,
        )


def _render_demo_mode() -> None:
    st.header("Demo Mode")
    st.write("Run a complete university-demo scenario with the bundled sample repository.")
    st.caption("This loads the sample repo, scans it, runs all deterministic agents, saves a history snapshot, and prepares the dashboard, debate view, graph, and reports.")
    sample_path = ROOT / "sample_repo"
    c1, c2, c3 = st.columns(3)
    c1.metric("Demo repository", "sample_repo")
    c2.metric("Agents", len(ALL_AGENTS))
    c3.metric("Output", "Findings + Trace")
    if st.button("Load Demo Scenario", type="primary"):
        with st.spinner("Running demo scan and agent pipeline"):
            findings = scan_repository(str(sample_path), max_workers=4)
            trace = _run_agent_pipeline(findings)
            st.session_state.repo_path = str(sample_path)
            st.session_state.findings = findings
            st.session_state.proof_trace = trace
            st.session_state.project_name = "university-demo"
            scan_id = _save_scan("university-demo", f"demo:{sample_path}", findings, trace)
            st.session_state.last_scan_id = scan_id
        st.success(f"Demo scenario ready: {len(findings)} findings and {len(trace.events)} proof events.")
    if st.session_state.get("findings"):
        _render_dashboard()


def _render_debate_view(trace: ProofTrace | None) -> None:
    st.header("Agent Debate View")
    if not trace:
        st.info("Run the agent pipeline first. Demo Mode can create a complete trace automatically.")
        return

    events = trace.events
    supports = [event for event in events if event.kind == "support"]
    attacks = [event for event in events if event.kind == "attack"]
    warrants = [event for event in events if event.kind == "warrant"]
    claims = [event for event in events if event.kind == "claim"]
    validations = [event for event in events if event.kind == "validation"]
    attacked_ids = {ref for event in attacks for ref in (event.references or [])}
    validated_ids = {ref for event in validations for ref in (event.references or [])}
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


def _run_llm_agentic_analysis(findings: List[Dict[str, Any]], trace: ProofTrace | None, api_key: str, model: str) -> str:
    from openai import OpenAI

    compact_findings = [
        {
            "algorithm": finding.get("algorithm"),
            "type": finding.get("type"),
            "severity": finding.get("severity"),
            "risk_score": finding.get("risk_score"),
            "evidence": finding.get("evidence"),
            "review": finding.get("review", {}),
        }
        for finding in _attach_operational_metadata(findings)[:20]
    ]
    compact_trace = [
        {
            "actor": event.actor,
            "kind": event.kind,
            "claim": event.claim,
            "metadata": event.metadata,
        }
        for event in (trace.events if trace else [])[-20:]
    ]
    prompt = {
        "task": "Act as an LLM-backed agentic advisor for a PQC risk triage tool. Produce a concise, actionable analysis.",
        "requirements": [
            "Summarize the highest-priority risk.",
            "Challenge any unrealistic migration assumptions.",
            "Recommend next human decision points.",
            "Suggest one remediation sequence.",
            "Do not claim that changes were executed.",
        ],
        "findings": compact_findings,
        "recent_proof_events": compact_trace,
    }
    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a careful security architecture agent. Be precise, auditable, and concise."},
            {"role": "user", "content": json.dumps(prompt, indent=2)},
        ],
        temperature=0.2,
    )
    return response.choices[0].message.content or ""


def _agentic_prompt_payload(findings: List[Dict[str, Any]], trace: ProofTrace | None) -> Dict[str, Any]:
    compact_findings = [
        {
            "algorithm": finding.get("algorithm"),
            "type": finding.get("type"),
            "severity": finding.get("severity"),
            "risk_score": finding.get("risk_score"),
            "evidence": finding.get("evidence"),
            "review": finding.get("review", {}),
        }
        for finding in _attach_operational_metadata(findings)[:20]
    ]
    compact_trace = [
        {
            "actor": event.actor,
            "kind": event.kind,
            "claim": event.claim,
            "metadata": event.metadata,
        }
        for event in (trace.events if trace else [])[-20:]
    ]
    return {
        "task": "Act as an LLM-backed agentic advisor for a PQC risk triage tool. Produce a concise, actionable analysis.",
        "requirements": [
            "Summarize the highest-priority risk.",
            "Challenge any unrealistic migration assumptions.",
            "Recommend next human decision points.",
            "Suggest one remediation sequence.",
            "Do not claim that changes were executed.",
        ],
        "findings": compact_findings,
        "recent_proof_events": compact_trace,
    }


def _run_ollama_agentic_analysis(findings: List[Dict[str, Any]], trace: ProofTrace | None, base_url: str, model: str) -> str:
    prompt = (
        "You are a careful security architecture agent. Be precise, auditable, and concise.\n\n"
        + json.dumps(_agentic_prompt_payload(findings, trace), indent=2)
    )
    endpoint = base_url.rstrip("/") + "/api/generate"
    payload = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode("utf-8")
    request = urllib.request.Request(endpoint, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach Ollama at {endpoint}. Start Ollama and pull the selected model first.") from exc
    return data.get("response", "")


def _render_agentic_ai_upgrade() -> None:
    st.header("Real Agentic AI Upgrade")
    st.write("This optional layer calls an LLM as an advisor agent and can append its analysis to the APEC-PS proof trace.")
    findings = st.session_state.get("findings", [])
    trace: ProofTrace | None = st.session_state.get("proof_trace")
    if not findings:
        st.info("Run Demo Mode or a scan first so the LLM agent has evidence to analyze.")
        return

    env_key = os.environ.get("OPENAI_API_KEY", "")
    provider = st.selectbox("LLM provider", ["OpenAI API", "Local Ollama"])
    if provider == "OpenAI API":
        api_key = st.text_input("OpenAI API key", value="", type="password", help="Leave empty to use OPENAI_API_KEY from the environment.")
        model = st.text_input("Model", value=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"))
    else:
        st.info("Local Ollama does not require OpenAI billing. Install Ollama, run `ollama pull llama3.2`, and keep Ollama running locally.")
        api_key = ""
        model = st.text_input("Ollama model", value=os.environ.get("OLLAMA_MODEL", "llama3.2"))
        ollama_url = st.text_input("Ollama URL", value=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"))
    append_to_trace = st.checkbox("Append LLM advisor output as proof event", value=True)
    if st.button("Run LLM Advisor Agent", type="primary"):
        try:
            with st.spinner("Calling LLM advisor agent"):
                if provider == "OpenAI API":
                    key = api_key.strip() or env_key
                    if not key:
                        st.warning("Add an API key or set OPENAI_API_KEY to run the OpenAI-backed agent.")
                        return
                    analysis = _run_llm_agentic_analysis(findings, trace, key, model.strip())
                else:
                    analysis = _run_ollama_agentic_analysis(findings, trace, ollama_url.strip(), model.strip())
            st.session_state.llm_agentic_analysis = analysis
            if append_to_trace:
                if not trace:
                    trace = ProofTrace()
                    st.session_state.proof_trace = trace
                trace.add_event(
                    create_event(
                        actor="LLMAdvisorAgent",
                        kind="warrant",
                        claim=analysis,
                        references=[event.id for event in trace.events[-5:]],
                        model=model.strip(),
                        provider=provider,
                        status="llm_generated_requires_human_review",
                    )
                )
            st.success("LLM advisor analysis generated.")
        except Exception as exc:
            st.error(f"LLM advisor failed: {exc}")

    if st.session_state.get("llm_agentic_analysis"):
        st.subheader("LLM Advisor Output")
        st.write(st.session_state.llm_agentic_analysis)


def _flatten_events(trace: ProofTrace) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for event in trace.events:
        row = event.to_dict()
        metadata = row.pop("metadata", {})
        row.update(metadata)
        row["references"] = ", ".join(row.get("references") or [])
        rows.append(row)
    return rows


def _build_markdown_report(findings: List[Dict[str, Any]], trace: ProofTrace | None) -> str:
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
    if trace:
        lines.extend(["", "## Proof Events", ""])
        for event in trace.events:
            refs = ", ".join(event.references or [])
            lines.append(f"- **{event.actor} / {event.kind}**: {event.claim} (refs: {refs or '-'})")
    return "\n".join(lines) + "\n"


def _build_pdf_report(markdown_text: str) -> bytes | None:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except Exception:
        return None

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 48
    pdf.setFont("Helvetica", 10)
    for raw_line in markdown_text.splitlines():
        line = raw_line.replace("#", "").replace("*", "")
        while len(line) > 105:
            pdf.drawString(40, y, line[:105])
            line = line[105:]
            y -= 14
            if y < 48:
                pdf.showPage()
                pdf.setFont("Helvetica", 10)
                y = height - 48
        pdf.drawString(40, y, line)
        y -= 14
        if y < 48:
            pdf.showPage()
            pdf.setFont("Helvetica", 10)
            y = height - 48
    pdf.save()
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
                        "informationUri": "https://github.com/",
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
    playbook = finding["playbook"]
    review = finding.get("review", {})
    left, right = st.columns([1, 1])
    with left:
        st.markdown("**Remediation playbook**")
        st.write(playbook["summary"])
        for idx, step in enumerate(playbook["steps"], start=1):
            st.write(f"{idx}. {step}")
    with right:
        st.markdown("**Human review decision**")
        status = st.selectbox(
            "Status",
            ["open", "planned", "accepted", "false_positive", "fixed", "needs_review"],
            index=["open", "planned", "accepted", "false_positive", "fixed", "needs_review"].index(review.get("status", "open"))
            if review.get("status", "open") in ["open", "planned", "accepted", "false_positive", "fixed", "needs_review"]
            else 0,
        )
        reviewer = st.text_input("Reviewer", value=review.get("reviewer", ""))
        reason = st.text_area("Reason", value=review.get("reason", ""))
        expires_on = st.text_input("Expiry date", value=review.get("expires_on") or "", placeholder="YYYY-MM-DD, optional")
        if st.button("Save review decision"):
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
                st.success("Review decision saved.")
                st.rerun()


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
        color = SEVERITY_COLORS.get(str(severity), KIND_COLORS.get(kind, "#64748b"))
        is_unresolved = node["id"] in unresolved_projected_ids and kind in {"claim", "support", "warrant"}
        border = "#b91c1c" if is_unresolved else KIND_COLORS.get(kind, "#64748b")
        title = f"{node['actor']}<br>{kind}<br>{node['claim']}"
        if severity:
            title += f"<br>Severity: {severity}"
        if metadata.get("risk_score") is not None:
            title += f"<br>Risk score: {metadata.get('risk_score')}"
        if node["grouped"]:
            title += f"<br>Grouped events: {node['count']}"
        label = f"{node['actor']}\n{kind}"
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
            borderWidth=5 if is_unresolved else 1,
            x=x,
            y=y,
            fixed=layout_mode == "Timeline",
        )

    for edge in projected_edges:
        edge_kind = edge["kind"]
        edge_color = "#dc2626" if edge_kind == "attack" else "#16a34a" if edge_kind == "support" else "#94a3b8"
        net.add_edge(
            edge["from"],
            edge["to"],
            color=edge_color,
            label=edge_kind,
            title=f"{edge_kind}: {edge['from']} -> {edge['to']}",
            arrows="to",
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


def _build_html_report(findings: List[Dict[str, Any]], trace: ProofTrace | None, graph_html: str | None) -> str:
    enriched = _attach_operational_metadata(findings)
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
    if trace:
        events = "".join(
            "<li>"
            f"<b>{html.escape(event.actor)} / {html.escape(event.kind)}</b>: {html.escape(event.claim)}"
            f"<br><small>refs: {html.escape(', '.join(event.references or []) or '-')}</small>"
            "</li>"
            for event in trace.events
        )
    graph_section = graph_html or "<p>Argument graph unavailable. Install pyvis and run agents before exporting.</p>"
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
  </style>
</head>
<body>
  <h1>APEC-PS</h1>
  <p><b>Argumentation for Trustworthy Agentic AI</b></p>
  <p>Post-Quantum Cryptography Risk Triage</p>
  <p><small>Generated at {html.escape(datetime.now(timezone.utc).isoformat())}</small></p>

  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Score</th><th>Status</th><th>Algorithm</th><th>Type</th><th>Location</th><th>Evidence</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>

  <h2>Argument Graph</h2>
  <div class="graph-frame">{graph_section}</div>

  <h2>Remediation Playbooks</h2>
  {''.join(playbooks)}

  <h2>Proof Events</h2>
  <ul>{events}</ul>
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
        package_json = st.text_area("Encrypted package JSON", value=st.session_state.get("pqc_encrypted_report", ""), height=140)
        secret_key = st.text_area("Recipient private key", value=keypair["secret_key"] if keypair else "", height=120)
        if st.button("Decrypt package"):
            if not package_json.strip() or not secret_key.strip():
                st.warning("Package JSON and private key are required.")
            else:
                try:
                    decrypted = _decrypt_report_with_ml_kem(package_json, secret_key)
                    st.success("Decryption succeeded.")
                    st.download_button("Download decrypted report", decrypted, file_name="decrypted_apecps_report.html", mime="text/html")
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
        color = SEVERITY_COLORS.get(str(severity), KIND_COLORS.get(kind, "#64748b"))
        is_unresolved = node_id in unresolved_projected_ids and kind in {"claim", "support", "warrant"}
        is_path = not projected_path_ids or node_id in projected_path_ids
        border = "#b91c1c" if is_unresolved else KIND_COLORS.get(kind, "#64748b")
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

        label = f"{node['actor']}\n{kind}"
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
            borderWidth=5 if is_unresolved else 3 if node_id in projected_path_ids else 1,
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
        edge_color = "#dc2626" if edge_kind == "attack" else "#16a34a" if edge_kind == "support" else "#94a3b8"
        net.add_edge(
            edge["from"],
            edge["to"],
            color=edge_color if edge_in_path else "#cbd5e1",
            label=edge_kind,
            title=f"{edge_kind}: {edge['from']} -> {edge['to']}",
            arrows="to",
            width=3 if edge_in_path and projected_path_ids else 1,
            dashes=not edge_in_path,
            font={"align": "middle", "size": 11, "color": "#334155"},
        )
    if not visible_ids:
        st.info("No graph nodes match the search.")
        return
    html = _inject_graph_click_inspector(net.generate_html(notebook=False), node_details)
    components.html(html, height=height + 40)


def _extract_uploaded_repo(uploaded_file: Any) -> str:
    tmpdir = Path(tempfile.mkdtemp(prefix="pqc_repo_"))
    archive_path = tmpdir / uploaded_file.name
    archive_path.write_bytes(uploaded_file.getbuffer())
    with zipfile.ZipFile(archive_path, "r") as zf:
        zf.extractall(tmpdir / "extracted")
    return str(tmpdir / "extracted")


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
        step = st.radio(
            "Workflow",
            ["Dashboard", "Demo Mode", "Repository", "Findings", "Agents", "Debate", "Agentic AI", "History", "Report"],
            captions=[
                "Executive summary",
                "One-click scenario",
                "Select source",
                "Scan and review",
                "Reason over trace",
                "Argumentation view",
                "Optional LLM advisor",
                "Past scans",
                "Export evidence",
            ],
        )
        st.text_input("Project name", value=st.session_state.get("project_name", "default-project"), key="project_name_input")

    if step == "Dashboard":
        _render_dashboard()

    elif step == "Demo Mode":
        _render_demo_mode()

    elif step == "Repository":
        st.header("Repository")
        repo_path = st.text_input(
            "Path accessible to this app",
            value=st.session_state.get("repo_path", str(ROOT / "sample_repo")),
            help="Use a local directory. ZIP upload is extracted to a temporary directory.",
        )
        uploaded = st.file_uploader("Upload ZIP archive", type=["zip"])
        if uploaded:
            repo_path = _extract_uploaded_repo(uploaded)
            st.success(f"Extracted archive to {repo_path}")
        st.session_state.repo_path = repo_path
        exists = Path(repo_path).exists()
        st.metric("Selected path", repo_path, delta="ready" if exists else "missing")
        if exists:
            st.code(repo_path)
        else:
            st.error("The selected path does not exist.")

    elif step == "Findings":
        st.header("Scan and review findings")
        repo_path = st.session_state.get("repo_path", str(ROOT / "sample_repo"))
        workers = st.slider("Parallel scanner workers", 1, 16, 6)
        if st.button("Run scanner", type="primary"):
            with st.spinner("Scanning repository with static analysis and heuristics"):
                st.session_state.findings = scan_repository(repo_path, max_workers=workers)
                scan_id = _save_scan(
                    st.session_state.get("project_name_input") or Path(repo_path).name,
                    f"repository:{repo_path}",
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
            st.info("No findings yet. Run the scanner.")

    elif step == "Agents":
        st.header("Multi-agent reasoning")
        findings = st.session_state.get("findings", [])
        if not findings:
            st.error("Run the scanner before launching agents.")
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
            tab_table, tab_graph = st.tabs(["Proof events", "Argument graph"])
            with tab_table:
                _render_trace(trace)
            with tab_graph:
                _render_graph(trace)

    elif step == "Debate":
        _render_debate_view(st.session_state.get("proof_trace"))

    elif step == "Agentic AI":
        _render_agentic_ai_upgrade()

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
            st.warning("Run a scan first so the report has findings.")
            return
        markdown = _build_markdown_report(findings, trace)
        json_export = _build_json_export(findings, trace)
        sarif_export = _build_sarif_export(findings)
        graph_html = _build_argument_graph_html(trace, layout_mode="Hierarchical", collapse_repeated=True) if trace else None
        html_report = _build_html_report(findings, trace, graph_html)
        st.download_button("Download Markdown", markdown, file_name="pqc_risk_report.md", mime="text/markdown")
        st.download_button("Download HTML Report + Graph", html_report, file_name="pqc_risk_report_with_graph.html", mime="text/html")
        if graph_html:
            st.download_button("Download Standalone Graph HTML", graph_html, file_name="apecps_argument_graph.html", mime="text/html")
        else:
            st.info("Run agents to include the argument graph in HTML exports.")
        st.download_button("Download JSON", json_export, file_name="pqc_risk_report.json", mime="application/json")
        st.download_button("Download SARIF", sarif_export, file_name="pqc_risk_report.sarif", mime="application/sarif+json")
        pdf_bytes = _build_pdf_report(markdown)
        if pdf_bytes:
            st.download_button("Download PDF", pdf_bytes, file_name="pqc_risk_report.pdf", mime="application/pdf")
        else:
            st.info("PDF export is available when reportlab is installed.")
        _render_pqc_report_export(html_report, json_export)
        st.subheader("Preview")
        st.markdown(markdown)


if __name__ == "__main__":
    main()
