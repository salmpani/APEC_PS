# APEC-PS

**Argumentation for Trustworthy Agentic AI**  
**Post-Quantum Cryptography Risk Triage**

APEC-PS is a Streamlit research prototype for discovering post-quantum
cryptography (PQC) migration risks and explaining them through an auditable
multi-agent argumentation trace.

Source code: <https://github.com/salmpani/APEC_PS>

Live demo: <https://apec-ps.streamlit.app/>

The application scans source code, configuration files, certificates, selected
binary artifacts, and live TLS endpoints. It then runs a deterministic
multi-agent reasoning pipeline that creates APEC-PS proof events: premises,
supporting arguments, attacks, warrants, migration claims, and human-review
validations.

This project is designed for university demonstrations, research discussion,
and security-workflow prototyping. It is not a production security scanner.

## Key Features

- **Demo Mode** for one-click university presentations, including optional
  Agentic AI quick run, argument-graph preview, and human review.
- **Grouped sidebar workflow** with Quick View, Input, Reasoning, and Output
  sections for clearer research demonstrations.
- **Academic and operational report exports** with distinct research-facing
  and security-facing content.
- **Guided presentation walkthrough** for a clear live-demo narrative.
- **Executive Dashboard** after Crypto Findings, with risk score, severity counts, top risks, review
  status, and unresolved argumentation challenges.
- **Repository and ZIP scanning** for source code, configs, certificates, and
  infrastructure files.
- **Public GitHub repository scanning** by downloading the default branch ZIP
  from a GitHub URL.
- **Live TLS endpoint scanning** for certificate public keys, certificate
  signatures, TLS versions, and cipher indicators.
- **Context-aware risk scoring** using severity, confidence, retention years,
  business impact, and migration complexity.
- **Agentic reasoning pipeline** with selectable specialist agents, a central
  AI coordinator, AI role-agents, debate rounds, critique, and human consensus.
- **Agent Debate View** focused on the proof-event conversation and APEC-PS
  support/attack/resolution lists.
- **Reviewer explanation views** for `Why?`, `Why not?`, and `What changed?`
  questions over the selected proof event.
- **Human review action panel** in Agent & Human Reasoning for requesting evidence,
  challenging reasoning, or accepting/deferring a proof event.
- **Interactive argument graph** with layouts, search, path highlighting,
  grouping, legends, and unresolved attack markers.
- **Trace Quality panel** that checks identifier uniqueness, reference
  integrity, chronology, attack typing, warrant coverage, evidence links, and
  human consensus over AI arguments.
- **Formal APEC-PS view** that renders selected proof events using
  `e = <communicate <Phi, c>, w>` notation and temporal predicates such as
  `Happens`, `Initiates`, `ActiveAt`, `Clipped`, `Terminates`, and `Valid`.
- **Simplified graph semantics** with three main node categories:
  support event, attack/unresolved event, and validation event. Finer APEC-PS
  types such as `support_observation`, `support_elaborate`,
  `support_strategy`, `attack_undermine`, `attack_undercut`,
  `attack_rebut`, and `validation_accept` are stored as metadata.
- **Readable proof-event identifiers** such as `PE1`, `PE2`, and `PE3` in the
  graph, proof-event trace, JSON export, and temporal predicates.
- **Final Human Decision workflow** with reviewer decision first, finding-to-decision view, trace links, remediation
  playbook, reviewer, reason, status, and expiry.
- **Persistent scan history** using local SQLite.
- **Report exports** in Markdown, PDF, JSON, SARIF, HTML, and standalone graph
  HTML.
- **Styled report preview** before export.
- **Report customization** for severity scope, anonymized paths/endpoints,
  author/contact inclusion, citation inclusion, proof events, remediation
  backlog, and argument graph inclusion.
- **Finding-to-decision trace links** showing which agents and proof events
  used a selected finding and how it moved toward a decision.
- **Advanced graph export** with layout selection, agent filters, event-type
  filters, severity filters, selected-path export, and embedded legend.
- **PQC-protected report export** using ML-KEM-768, HKDF-SHA256, and
  AES-256-GCM.
- **LLM-backed Agentic AI coordinator** using Groq Cloud, local Ollama, OpenAI
  API, or a deterministic fallback depending on the deployment environment.

## Project Structure

```text
improved_apec_ps_pqc_prototype/
|-- app/
|   `-- app.py
|-- assets/
|   `-- apec-ps-logo.png
|-- sample_repo/
|-- sample_upload_repo/
|-- agents.py
|-- apecps.py
|-- scanner.py
|-- cli_demo.py
|-- requirements.txt
|-- README.md
|-- CHANGELOG.md
`-- .streamlit/
    `-- config.toml
```

Important generated/local files:

```text
apecps_history.db       local scan history database
sample_upload_repo.zip  optional sample ZIP for upload testing
.venv/                  local virtual environment, do not upload
__pycache__/            Python cache, do not upload
```

## Installation

Use Python 3.10+.

```bash
pip install -r requirements.txt
```

Run the Streamlit app:

```bash
streamlit run app/app.py
```

Or, on Windows:

```powershell
python -m streamlit run app/app.py --server.port 8501
```

Open:

```text
http://localhost:8501
```

## Quick University Demo

The fastest presentation flow uses the grouped sidebar workflow:

1. Open the app.
2. Go to **Demo Mode**.
3. Select whether to include **Agentic AI quick run** and **Show argument
   graph after run**.
4. Click **Run selected demo scenario**.
5. In Demo Mode, present the tabs in this order:
   **Argument graph**, **Final human decision**, **Finding-to-decision**,
   **Reports**, and **PQC secure exchange**.
6. Go to **Crypto Findings** to show the scanner evidence.
7. Go to **Dashboard** to show the executive overview after the findings.
8. Go to **Agent & Human Reasoning** to show selected specialist agents, the deterministic
   proof-event trace, and human proof-event actions.
9. Go to **Final Human Decision** to record a decision, inspect finding-to-decision,
   trace links, and remediation playbook.
10. Go to **Reports** to export the academic report, operational report,
    security tooling formats, or PQC-protected package.

The sidebar is organized into **Quick View**, **Input**, **Reasoning**, and
**Output** categories so audiences can see where each part of the prototype
belongs.

Demo Mode automatically:

- loads `sample_repo`
- runs the repository scanner
- runs all deterministic agents
- optionally adds Agentic AI coordinator and role-agent proof events
- creates the APEC-PS proof trace
- saves a scan-history snapshot
- prepares the dashboard, graph, review view, reports, and PQC secure exchange

### Short Presentation Script

Use this script for a 5-7 minute live demo:

1. **Problem framing**: "The prototype demonstrates how Agentic AI can support
   PQC migration triage while preserving an auditable APEC-PS reasoning trace."
2. **Run demo**: "Demo Mode loads a sample repository, scans cryptographic
   evidence, runs specialist agents, and optionally adds AI coordinator
   arguments."
3. **Trace quality**: "Before using the output, the app checks whether proof
   events have unique IDs, valid references, typed attacks, warrants, evidence
   links, and human-review status."
4. **Argument graph**: "The graph shows three main event types: support,
   attack, and validation. Details such as premises, warrants, and claims are
   preserved in node metadata."
5. **Formal APEC-PS view**: "For the paper, each event can also be rendered as
   `PEi = <communicate <Phi, c>, w>` with temporal predicates such as
   `Happens(PEi, ti)` and `Valid(PEi, f, ti)`."
6. **Review and reports**: "The Final Human Decision menu records the final governance
   decision, and the Reports menu exports either academic or operational
   evidence packages."

## How To Use Each Page

### Dashboard

The Dashboard gives a high-level summary of the active scan.

Fields:

- **Findings**: total findings currently loaded.
- **High**: high severity findings.
- **Risk score**: sum of all finding risk scores.
- **Unresolved attacks**: argumentation challenges that have not been resolved
  by validation events.
- **Readiness**: rough percentage based on findings marked fixed or false
  positive.

Charts:

- **Algorithm exposure**: which algorithms or crypto settings appear most.
- **Severity**: low/medium/high distribution.
- **Review status**: open, planned, accepted, fixed, etc.
- **Top risks**: highest-scoring findings.

Use this page when presenting the overall result to a non-technical audience.

### Demo Mode

Runs a complete bundled scenario with one button.

Options:

- **Agentic AI quick run**: adds deterministic AI coordinator output and
  role-agent proof events for a fast presentation without requiring an API key.
- **Show argument graph after run**: renders the APEC-PS graph directly inside
  Demo Mode after the scan and agents complete.

Button:

- **Run selected demo scenario**: scans `sample_repo`, runs agents, saves history, and
  prepares all app views.

Demo output tabs:

- **Argument graph**
- **Final human decision**
- **Finding-to-decision**
- **Reports**
- **PQC secure exchange**

Use this for a reliable live presentation.

### Evidence Sources

Selects the evidence source to scan. This page keeps input collection separate
from the results table.

Tabs:

- **Repository**: select a local directory path scanned by the app.
- **ZIP upload**: upload a zipped project/repository.
- **GitHub URL**: download and scan a public GitHub repository.
- **Live TLS**: scan deployed HTTPS/TLS endpoints as runtime evidence.

Supported GitHub examples:

```text
https://github.com/owner/repo
https://github.com/owner/repo/tree/main
https://github.com/owner/repo/tree/feature-branch
```

For public GitHub repositories, the app downloads a ZIP archive of the selected
or default branch into a temporary folder, then scans the extracted source tree.

Recommended ZIP content:

- source code: `.py`, `.js`, `.ts`, `.java`, `.go`, `.rb`, `.c`, `.cpp`, `.cs`
- configs: `.yaml`, `.yml`, `.json`, `.ini`, `.cfg`, `.tf`, `.hcl`
- certificates: `.pem`, `.crt`, `.cer`
- manifests: `requirements.txt`, `package.json`, `pom.xml`, `go.mod`

Do not upload real secrets, private keys, or proprietary repositories in a
public demo.

#### Live TLS Endpoint Scan

Use this tab to scan deployed HTTPS/TLS endpoints.

Examples:

```text
example.com
api.example.com:443
https://payments.example.com
```

Fields:

- **Endpoints**: one endpoint per line.
- **Endpoint timeout seconds**: connection timeout.
- **Endpoint scanner workers**: concurrent endpoint scans.
- **Append endpoint findings**: add endpoint results to existing findings
  instead of replacing them.

The endpoint scanner checks TLS version, cipher, certificate public key, and
certificate signature algorithm.

### Crypto Findings

Presents normalized scanner output from the selected evidence source. Human
review, trace links, finding-to-decision explanation, and remediation playbooks
are handled in the separate **Final Human Decision** page so the scanner output stays
clean.

Controls:

- **Severity filter**: filters visible findings.
- **Minimum risk score**: hides lower-priority findings.

Findings table:

- **finding_id**: stable ID used for review/history tracking.
- **severity**: low, medium, or high.
- **risk_score**: numeric priority score.
- **review_status**: current human-review decision.
- **algorithm**: detected algorithm or crypto setting.
- **type**: detection category.
- **confidence**: confidence in the finding.
- **file**: file or endpoint where the finding was detected.
- **line_no**: line number if available.
- **retention_years**: detected/inferred retention period.
- **business_impact**: inferred impact.
- **migration_complexity**: estimated complexity.
- **evidence**: code/config/certificate evidence.
- **description**: risk explanation.

### Final Human Decision

The Final Human Decision page is the first page in the Output menu. It connects raw scanner
findings to APEC-PS reasoning and human decision-making.

Tabs:

- **Final human decision**: records the human disposition for the selected finding.
- **Finding-to-decision**: summarizes how the selected finding moves from
  evidence to risk interpretation, challenge, migration plan, and decision
  state.
- **Trace links**: shows which proof events reference the finding and which
  downstream agents used those events.
- **Remediation playbook**: lists concrete mitigation steps, owner guidance,
  evidence to collect, and review notes.

Statuses:

- **open**: no decision yet.
- **planned**: remediation is planned.
- **accepted**: risk is accepted temporarily.
- **false_positive**: finding is invalid.
- **fixed**: issue has been remediated.
- **needs_review**: more analysis is needed.

Fields:

- **Reviewer**: person/team making the decision.
- **Reason**: justification.
- **Expiry date**: optional date for accepted risks.

Saving a review decision stores it in SQLite and, if a proof trace exists,
adds a HumanReview proof event.

### Agent & Human Reasoning

Runs selectable deterministic specialist agents over the current findings.
This page is used to build the auditable baseline trace before, or alongside,
the Agentic AI coordinator.

Tabs:

- **Agent pipeline**: select deterministic agents, run the proof-event
  pipeline, and inspect the proof-event table.
- **Human review actions in proof-events**: add reviewer-generated proof events
  such as evidence requests, reasoning challenges, acceptances, and deferrals.

Agents:

- **CryptoDiscoveryAgent**: turns scanner findings into premises.
- **QuantumRiskAgent**: maps classical crypto to quantum risk.
- **ThreatIntelligenceAgent**: adds harvest-now-decrypt-later context.
- **ComplianceAgent**: supports migration from a policy perspective.
- **CompatibilityAgent**: attacks unsafe or disruptive migration assumptions.
- **PerformanceCostAgent**: estimates migration effort.
- **MigrationPlannerAgent**: proposes migration actions.
- **CriticAgent**: challenges unsupported plans.
- **HumanReviewAgent**: marks the generated plan as requiring human approval
  or review.

The specialist agents can be selected for a run. A smaller set is often easier
to present than a large one. The recommended core set is:

- **CryptoDiscoveryAgent**
- **QuantumRiskAgent**
- **CompatibilityAgent**
- **MigrationPlannerAgent**
- **HumanReviewAgent**

The output is a proof-event table with readable event IDs such as `PE1`,
`PE2`, and `PE3`. Each event has one main category and a more precise APEC-PS
type.

Main event categories:

- **support**: an event that contributes evidence, elaboration, warrant,
  strategy, solution, or claim support.
- **attack**: an event that challenges a premise, warrant, claim, or plan.
- **request**: a reviewer-generated request for more evidence before accepting
  an event.
- **revision**: a revised claim or plan after an objection or new evidence.
- **validation**: an event that records human review, acceptance, rejection,
  deferral, or risk acceptance.

Examples of detailed event types:

- `support_observation`
- `support_elaborate`
- `support_warrant`
- `support_strategy`
- `support_solution`
- `support_claim`
- `attack_undermine`
- `attack_undercut`
- `attack_rebut`
- `request_evidence`
- `revision_plan`
- `validation_accept`
- `validation_defer`

Premises, warrants, claims, source kind, confidence, provenance, and evidence
links are stored as event metadata. This keeps the graph simple while still
preserving the formal APEC-PS details in JSON, reports, and selected-node
details.

The page also includes the **Human review action** panel. It creates
reviewer-generated proof events for requesting evidence, challenging reasoning,
or accepting/deferring an event. Challenge target maps directly to APEC-PS
attack types: premise -> undermine, warrant -> undercut, and claim -> rebut.

### Argument Graphs

The Argument Graphs page visualizes the APEC-PS proof trace. It is separate
from Agent & Human Reasoning so the user can first generate a trace, then inspect it as a graph.

After the graph, the page shows **Trace Quality**, which summarizes structural integrity:
unique IDs, reference resolution, attack typing, warrant coverage, evidence
links, unresolved challenges, and human consensus over AI-generated arguments.

Argument graph controls:

- **Search nodes**: search actor, claim, severity, algorithm, review status,
  provider, or model.
- **Layout**: hierarchical, force-directed, or timeline. Hover help explains
  what each layout is for.
- **Physics layout**: lets the graph move dynamically when enabled; when
  disabled, the graph is more static and presentation-friendly.
- **Group repeated findings**: collapses repeated low-level discovery events
  with the same algorithm, severity, and finding type.
- **Inspect / highlight path (fluent)**: highlights a selected proof event,
  its referenced ancestors, and its dependent descendants.

Graph conventions:

- node fill color shows severity or AI-generated provenance
- node border color shows the main event category: support, attack, or
  validation
- red thick border shows unresolved attack or unresolved challenge
- edge color and line style show argumentation moves
- hover and selected-node details show premises, warrants, claims, references,
  event type, provider/model, confidence, and review status

Argumentation moves:

- **Evidence link**: connects scanner evidence to a proof event.
- **Warrant link**: connects a reason or rule to the event it justifies.
- **Claim link**: connects a proposed decision or plan to its supporting
  events.
- **Support relation**: shows that one event strengthens another.
- **Attack relation**: shows rebutting, undercutting, or undermining.
- **Validation link**: connects human or review events to the claim or plan
  being decided.

Additional views:

- **Formal APEC-PS view**: renders proof events as
  `PEi = <communicate <Phi, c>, w>` and displays temporal predicates.
- **Temporal predicates**: shows the computed operational state for each
  event, including `Happens`, `Initiates`, `ActiveAt`, `Clipped`,
  `Terminates`, and `Valid`.
### Agent Debate

Explains the APEC-PS contribution as argument lists rather than a flat event
log. The main view is organized into:

- **Support**: premises, warrants, claims, and supporting arguments.
- **Attack / Critique**: rebutting, undercutting, and undermining moves.
- **Resolution**: validation, review, requests, revisions, and dispositions.

The round-based view and agent conversation transcript remain available as
optional expanders.

Use this page to explain why the system is not just a scanner. It creates an
argumentation structure around the security findings and shows how agents move
from evidence to disagreement, revision, and governance.

The page also includes the three reviewer-oriented explanation questions:

- **Why?** shows the selected recommendation with supporting warrants,
  evidence, and referenced scanner findings.
- **Why not?** shows attacks against the selected event or its supporting path.
- **What changed?** shows the movement from initial proposal, to objection, to
  revised proposal, to human decision.

### Agentic AI

The **Agentic AI** page makes the AI coordinator central to the prototype. It
does not replace the deterministic specialist agents; it coordinates over
their proof trace and adds higher-level AI role-agent arguments that remain
evidence-linked and human-reviewable.

After a scan, open **Agentic AI** and click **Run Agentic AI Analysis**. The
app:

1. runs the selected deterministic specialist agents if a proof trace does not
   already exist;
2. selects the best available AI coordinator provider;
3. sends the highest-risk findings and compact proof trace to the coordinator;
4. creates structured AI role-agent proof events, such as risk analyst,
   migration strategist, compatibility critic, and trust reviewer; and
5. saves the completed trace in scan history.

The AI coordinator can create multiple AI role-agents in one coordinated run.
These are represented as proof events with main categories `support`,
`attack`, or `validation`, and detailed types such as `support_claim`,
`support_elaborate`, `support_warrant`, `attack_undercut`, and
`validation_accept`. Premises, warrants, claims, provider/model provenance,
confidence, grounding status, referenced proof events, and linked finding IDs
are stored as metadata.

The **Human consensus of AI argument** panel in **Agentic AI** is the review
control for AI-generated proof events. It shows evidence-grounded AI moves,
agreement and challenge counts, linked deterministic agents, provider/model
provenance, confidence, grounding status, trace-completeness cues, and human review state. A reviewer
can accept, reject, or request revision of each AI argument. The decision
becomes a linked `HumanReviewAgent` proof event and is retained in history,
JSON, graph exports, and reports. AI-generated review requests never count as
human approval.

Trace-completeness cues are interface indicators only. They are not
probabilities of correctness and should not be interpreted as validated
measures of generalized trustworthiness.

The public Streamlit deployment is expected to use **Groq Cloud** as the
default hosted AI coordinator when `GROQ_API_KEY` is configured. A local
developer run can use local Ollama, Groq, OpenAI, or the deterministic
fallback. Automatic provider order is:

```text
Local app:       Ollama -> Groq -> deterministic fallback
Streamlit Cloud: Groq -> deterministic fallback
```

The advanced panel retains manual provider and model controls:

- **Local Ollama**: runs locally without API billing.
- **Groq Cloud**: hosted inference suitable for Streamlit Community Cloud.
- **OpenAI API**: requires an API key and available quota.

Groq setup for Streamlit Community Cloud:

1. Create a Groq API key.
2. Open the deployed app settings.
3. Open **Secrets** and add:

```toml
GROQ_API_KEY = "your_groq_api_key"
GROQ_MODEL = "openai/gpt-oss-20b"
```

Do not add these values to GitHub. After saving the secrets, reboot the
Streamlit app. The Agentic AI page should show
`Hosted coordinator ready: Groq Cloud`.

OpenAI setup:

```powershell
$env:OPENAI_API_KEY="your_api_key_here"
python -m streamlit run app/app.py
```

Local Ollama setup:

```bash
ollama pull llama3.2
```

Keep Ollama running at `http://localhost:11434`; the app selects
`llama3.2:latest` automatically when it is installed. A first request can take
longer while the model loads into memory. Later requests remain warm for ten
minutes.

Important: Agentic AI is central to the research prototype, but trust is not
delegated blindly to the model. The deterministic specialist trace remains the
auditable baseline, while AI-generated arguments must stay evidence-grounded,
typed, reference-valid, and subject to human consensus.

### History

Loads previous scan snapshots from `apecps_history.db`.

Columns:

- **id**: scan ID.
- **created_at**: timestamp.
- **project_name**: project label.
- **source**: repository, endpoint, demo, agent trace, or review source.
- **finding_count**: total findings.
- **high_count**, **medium_count**, **low_count**: severity distribution.

Use **Load selected scan into workspace** to restore previous findings and
proof trace.

### Reports

Exports results through separate report types. The two main reports have
different audiences:

- **Academic report**: explains the research method. It emphasizes APEC-PS,
  Agentic AI workflow, proof-event interpretation, trust controls, limitations,
  and citation.
- **Operational report**: supports security action. It emphasizes findings,
  severity, review state, remediation playbooks, proof-event evidence, and the
  argument graph.

Report tabs:

- **Academic report**: academic Markdown, HTML, and PDF.
- **Operational report**: operational Markdown, HTML + Graph, PDF, standalone
  graph HTML, and advanced graph export.
- **Security tooling**: JSON and SARIF.
- **PQC-protected export**: encrypted HTML or JSON report package.
- **Preview**: styled report preview plus raw Markdown.

Available downloads:

- **Academic Markdown / HTML / PDF**: formal academic-style report with cover
  details, abstract, methodology, APEC-PS and Agentic AI explanation,
  governance/trust controls, argument graph, limitations, and citation.
- **Operational Markdown / HTML + Graph / PDF**: security-facing triage report
  with findings, remediation playbooks, human review state, proof-event ledger,
  and optional graph.
- **Standalone Graph HTML**: graph only.
- **JSON**: structured findings, reviews, playbooks, proof trace, temporal
  predicates, `PE1`-style event IDs, event types, premises, warrants, claims,
  metadata, and references.
- **SARIF**: security-tooling format for code scanning.

The **Preview** tab provides a styled report preview with summary metrics, top
findings, governance status, and remediation previews. The raw Markdown report
is still available inside an expander.

#### Report Customization

Before exporting, use **Report customization** to choose:

- severities to include
- whether to anonymize file paths and endpoints
- whether to include the argument graph
- whether to include proof events
- whether to include the remediation backlog
- whether to include author/contact details
- whether to include the suggested citation

These options affect the report exports and PQC-protected report package.

#### Advanced Graph Export

Inside **Report > Operational report**, open **Advanced graph export** to
create a focused argument graph. You can filter by:

- layout: hierarchical, force-directed, or timeline
- agent
- proof-event type, such as `support_observation`, `attack_undermine`, or
  `validation_accept`
- severity
- selected reasoning path

The exported graph includes a built-in legend for severity, event types, and
argumentation moves.

#### PQC-Protected Report Export

The report page can encrypt HTML or JSON reports using:

```text
ML-KEM-768 + HKDF-SHA256 + AES-256-GCM
```

Flow:

1. Recipient generates an ML-KEM-768 key pair.
2. Recipient shares only the public key.
3. App encapsulates a shared secret to that public key.
4. App derives an AES-256 key with HKDF-SHA256.
5. App encrypts the report with AES-256-GCM.
6. Recipient decrypts using the private key.

Buttons:

- **Generate demo ML-KEM recipient keypair**: creates demo public/private key
  pair.
- **Download recipient public key**: public key for encryption.
- **Download demo recipient private key**: keep secret; needed for decryption.
- **Encrypt report with ML-KEM + AES-256-GCM**: creates encrypted package.
- **Download PQC-encrypted report package**: encrypted JSON package.
- **Decrypt package**: local verification.

## CLI Demo

```bash
python cli_demo.py --path sample_repo
```

## Sample ZIP Upload

The project includes an optional sample ZIP:

```text
sample_upload_repo.zip
```

Upload it through **Evidence Sources > ZIP upload** to test a different
scenario from `sample_repo`.

## Deploy On Streamlit Community Cloud

1. Create a GitHub repository.
2. Upload these files/folders:

```text
app/
assets/
sample_repo/
sample_upload_repo/
.streamlit/
agents.py
apecps.py
scanner.py
cli_demo.py
README.md
requirements.txt
CHANGELOG.md
__init__.py
.gitignore
```

3. Do not upload:

```text
.venv/
__pycache__/
apecps_history.db
*.pyc
```

4. In Streamlit Community Cloud, set:

```text
Main file path: app/app.py
```

5. Deploy.

For public demos, use only sample data. Disable or avoid live scanning of
private/internal endpoints.

## Real Agents Or Illustration?

The current default agents are **real deterministic software agents**, not
fully autonomous LLM agents.

They are real in the sense that each agent has:

- a role
- input data
- decision logic
- proof-event output
- interaction through a shared APEC-PS trace

They are not fully autonomous by default because they do not independently
search, call tools, or modify code. The **Agentic AI** page adds a central
LLM-backed coordinator that can create multiple AI role-agent proof events.
The coordinator strengthens the agentic perspective, while the deterministic
trace remains the auditable baseline for trust and reproducibility.

In the graph and JSON export, AI role-agents are treated as normal APEC-PS
proof events. They use the same main categories: `support`, `attack`, and
`validation`. Their detailed role, such as risk analyst, migration strategist,
compatibility critic, or trust reviewer, is stored as metadata together with
provider/model provenance and human consensus state.

## Security Notes

- Do not upload private keys or real secrets.
- Do not scan internal endpoints from a public deployment.
- Treat generated remediation plans as recommendations requiring human review.
- PQC-protected exports protect report confidentiality, but key management is
  still the user's responsibility.
- This is a research prototype, not a certified security product.

## Author, Rights, And Contact

Author:

```text
Sofia Almpani
```

Affiliation:

```text
School of Applied Mathematical and Physical Sciences, National Technical University of Athens, Greece
```

Contact:

```text
s.almpani@gmail.com
```

Live demo:

```text
https://apec-ps.streamlit.app/
```

Source code:

```text
https://github.com/salmpani/APEC_PS
```

Rights:

```text
Copyright (c) 2026 Sofia Almpani. All rights reserved unless explicitly licensed otherwise.
```

Permitted use:

```text
Academic demonstration and research prototype. Not certified for production security use.
```

Suggested citation:

```text
Sofia Almpani, APEC-PS: Argumentation for Trustworthy Agentic AI - Post-Quantum Cryptography Risk Triage, 2026. Source code: https://github.com/salmpani/APEC_PS. Live demo: https://apec-ps.streamlit.app/
```

Use the GitHub URL for source-code citation and version tracking, and keep the
Streamlit URL as the live demo link.

## Troubleshooting

### `No module named openai`

Install dependencies:

```bash
pip install -r requirements.txt
```

### OpenAI quota error

Use local Ollama or configure billing/quota in the OpenAI platform account.

### PDF export unavailable

Install ReportLab:

```bash
pip install reportlab
```

### PQC export unavailable

Install pqcrypto:

```bash
pip install pqcrypto
```

### Streamlit does not show recent changes

Restart the app:

```powershell
python -m streamlit run app/app.py --server.port 8501
```

## Suggested Presentation Story

1. Quantum computing threatens RSA/ECDSA/ECDH.
2. The scanner discovers vulnerable crypto assets.
3. Specialist agents produce an auditable baseline proof trace.
4. The Agentic AI coordinator creates higher-level AI role-agent arguments.
5. The argument graph shows `PE1`, `PE2`, and later proof events as support,
   attack, and validation nodes.
6. Review records finding-to-decision trace links, remediation playbook, and
   human consensus.
7. Academic and operational reports export the same evidence for different
   audiences.
8. The final report itself can be protected with PQC.
