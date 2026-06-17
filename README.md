# APEC-PS

**Argumentation for Trustworthy Agentic AI**  
**Post-Quantum Cryptography Risk Triage**

APEC-PS is a Streamlit research prototype for discovering post-quantum
cryptography (PQC) migration risks and explaining them through an auditable
multi-agent argumentation trace.

The application scans source code, configuration files, certificates, selected
binary artifacts, and live TLS endpoints. It then runs a deterministic
multi-agent reasoning pipeline that creates APEC-PS proof events: premises,
supporting arguments, attacks, warrants, migration claims, and human-review
validations.

This project is designed for university demonstrations, research discussion,
and security-workflow prototyping. It is not a production security scanner.

## Key Features

- **Demo Mode** for one-click university presentations.
- **Guided presentation walkthrough** for a clear live-demo narrative.
- **Executive Dashboard** with risk score, severity counts, top risks, review
  status, and unresolved argumentation challenges.
- **Repository and ZIP scanning** for source code, configs, certificates, and
  infrastructure files.
- **Live TLS endpoint scanning** for certificate public keys, certificate
  signatures, TLS versions, and cipher indicators.
- **Context-aware risk scoring** using severity, confidence, retention years,
  business impact, and migration complexity.
- **Agentic reasoning pipeline** with deterministic agents for discovery, risk,
  compliance, compatibility, cost, planning, critique, and human review.
- **Agent Debate View** to explain the APEC-PS research contribution.
- **Interactive argument graph** with layouts, search, path highlighting,
  grouping, legends, and unresolved attack markers.
- **Risk acceptance workflow** with reviewer, reason, status, and expiry.
- **Persistent scan history** using local SQLite.
- **Report exports** in Markdown, PDF, JSON, SARIF, HTML, and standalone graph
  HTML.
- **Styled report preview** before export.
- **Finding-to-agent trace links** showing which agents and proof events used a
  selected finding.
- **PQC-protected report export** using ML-KEM-768, HKDF-SHA256, and
  AES-256-GCM.
- **Optional LLM advisor agent** using either OpenAI API or local Ollama.

## Project Structure

```text
improved_apec_ps_pqc_prototype/
├── app/
│   └── app.py
├── assets/
│   └── apec-ps-logo.png
├── sample_repo/
├── sample_upload_repo/
├── agents.py
├── apecps.py
├── scanner.py
├── cli_demo.py
├── requirements.txt
├── README.md
├── CHANGELOG.md
└── .streamlit/
    └── config.toml
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

The fastest presentation flow is:

1. Open the app.
2. Go to **Demo Mode**.
3. Click **Load Demo Scenario**.
4. Go to **Dashboard** to show the executive overview.
5. Use the guided walkthrough panel as your presentation script.
6. Go to **Findings** and open **Trace links** for a selected finding.
7. Go to **Debate** to explain APEC-PS support/attack reasoning.
8. Go to **Agents > Argument graph** to show the visual proof trace.
9. Go to **Report** to preview/export the report or encrypt it with PQC.

Demo Mode automatically:

- loads `sample_repo`
- runs the repository scanner
- runs all deterministic agents
- creates the APEC-PS proof trace
- saves a scan-history snapshot
- prepares the dashboard, debate view, graph, and reports

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

Button:

- **Load Demo Scenario**: scans `sample_repo`, runs agents, saves history, and
  prepares all app views.

Use this for a reliable live presentation.

### Repository

Selects the source to scan.

Fields:

- **Path accessible to this app**: local directory path scanned by the app.
- **Upload ZIP archive**: upload a zipped project/repository.

Recommended ZIP content:

- source code: `.py`, `.js`, `.ts`, `.java`, `.go`, `.rb`, `.c`, `.cpp`, `.cs`
- configs: `.yaml`, `.yml`, `.json`, `.ini`, `.cfg`, `.tf`, `.hcl`
- certificates: `.pem`, `.crt`, `.cer`
- manifests: `requirements.txt`, `package.json`, `pom.xml`, `go.mod`

Do not upload real secrets, private keys, or proprietary repositories in a
public demo.

### Findings

Runs scans and supports human review.

Controls:

- **Parallel scanner workers**: number of scanning threads.
- **Run scanner**: scans the selected repository.
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

#### Live TLS Endpoint Scan

Use this to scan deployed HTTPS/TLS endpoints.

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
- **Append endpoint findings**: add endpoint results to repository findings
  instead of replacing them.

The endpoint scanner checks TLS version, cipher, certificate public key, and
certificate signature algorithm.

#### Risk Acceptance And Remediation

For each finding, the app provides a remediation playbook and review form.

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

### Agents

Runs deterministic software agents over the current findings.

Agents:

- **CryptoDiscoveryAgent**: turns scanner findings into premises.
- **QuantumRiskAgent**: maps classical crypto to quantum risk.
- **ThreatIntelligenceAgent**: adds harvest-now-decrypt-later context.
- **ComplianceAgent**: supports migration from a policy perspective.
- **CompatibilityAgent**: attacks unsafe or disruptive migration assumptions.
- **PerformanceCostAgent**: estimates migration effort.
- **MigrationPlannerAgent**: proposes migration actions.
- **CriticAgent**: challenges unsupported plans.
- **HumanReviewAgent**: requires human approval or review.

Tabs:

- **Proof events**: table and expandable event details.
- **Argument graph**: visual proof trace.

Argument graph controls:

- **Search nodes**: search actor, claim, severity, algorithm, or score.
- **Layout**: hierarchical, force-directed, or timeline.
- **Group repeated findings**: collapses similar premise nodes.
- **Inspect / highlight path**: highlights upstream/downstream reasoning.

Graph conventions:

- node fill color shows severity
- node border color shows event kind
- red thick border shows unresolved challenge
- edge labels show support, attack, warrant, validation, etc.

### Finding-To-Agent Trace Links

Inside **Findings**, select a finding and open the **Trace links** tab. This
shows which APEC-PS proof events were created from the selected finding and
which agents used it downstream. It connects scanner evidence to risk claims,
critiques, migration plans, and validations.

### Debate

Explains the research contribution of APEC-PS.

It separates:

- support arguments
- attack/critique arguments
- warrants
- migration claims
- validation events
- unresolved challenges

Use this page to explain why the system is not just a scanner: it creates an
argumentation structure around the security findings.

### Agentic AI

Optional LLM-backed advisor agent.

Provider options:

- **OpenAI API**: requires an API key and available quota.
- **Local Ollama**: runs locally without OpenAI billing.

OpenAI setup:

```powershell
$env:OPENAI_API_KEY="your_api_key_here"
python -m streamlit run app/app.py
```

Local Ollama setup:

```bash
ollama pull llama3.2
```

Then choose:

```text
Provider: Local Ollama
Ollama URL: http://localhost:11434
Model: llama3.2
```

The LLM advisor can append its output as an APEC-PS proof event from
`LLMAdvisorAgent`.

Important: the deterministic agents are the reliable baseline. The LLM advisor
is optional and should be treated as human-reviewed analysis.

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

### Report

Exports results.

Available downloads:

- **Markdown**: readable report.
- **HTML Report + Graph**: full report with embedded interactive argument graph.
- **Standalone Graph HTML**: graph only.
- **JSON**: structured findings, reviews, playbooks, and proof trace.
- **SARIF**: security-tooling format for code scanning.
- **PDF**: PDF report.

The **Preview** tab provides a styled report preview with summary metrics, top
findings, governance status, and remediation previews. The raw Markdown report
is still available inside an expander.

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

Upload it through **Repository > Upload ZIP archive** to test a different
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
search, call tools, or modify code. The optional **Agentic AI** page adds an
LLM-backed advisor, but the deterministic trace remains the auditable baseline.

## Security Notes

- Do not upload private keys or real secrets.
- Do not scan internal endpoints from a public deployment.
- Treat generated remediation plans as recommendations requiring human review.
- PQC-protected exports protect report confidentiality, but key management is
  still the user's responsibility.
- This is a research prototype, not a certified security product.

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
3. Deterministic agents produce explainable APEC-PS proof events.
4. Debate view shows support and attack arguments.
5. Human review records accountability.
6. Reports can be exported for security workflows.
7. The final report itself can be protected with PQC.
