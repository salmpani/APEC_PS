# Improved APEC-PS PQC Prototype

This repository contains a research prototype for post-quantum cryptography
(PQC) risk triage and multi-agent reasoning using an APEC-PS style proof trace.

The app scans source code, configuration, certificates, and selected binary
artifacts for quantum-vulnerable cryptography. It then runs a deterministic
agent team that turns findings into premises, supports and attacks claims,
estimates migration effort, and creates a human-review checkpoint before any
remediation plan is considered executable.

## What is included

- Static crypto discovery with Python AST analysis plus heuristics for common
  JavaScript, Java, Go, Ruby, config, manifest, and infrastructure files.
- Certificate inspection with `cryptography` when available, plus PEM text
  fallback and small-binary signature scanning for DER/JKS/JAR/shared-library
  style artifacts.
- Context-aware scoring with severity, confidence, retention years, business
  impact, and migration complexity.
- Parallel repository scanning for larger codebases.
- Multi-agent APEC-PS reasoning with discovery, quantum risk, threat
  intelligence, compliance, compatibility, performance/cost, migration
  planning, critic, and human-review agents.
- Streamlit UI with dark styling, filters, collapsible proof-event inspection,
  color-coded argument graph, and Markdown/PDF/JSON/SARIF report export.
- Live TLS endpoint scanning for certificate public keys, certificate
  signatures, negotiated TLS versions, and cipher-suite indicators.

## Run the app

```bash
pip install -r requirements.txt
streamlit run app/app.py
```

The default UI path points to `sample_repo`, so you can scan immediately.
Use the `Findings` page to scan local repositories and optional live TLS
endpoints such as `example.com` or `api.example.com:8443`.

## Deploy for a university demo

The simplest public demo path is Streamlit Community Cloud:

1. Create a GitHub repository.
2. Upload this project, including `app/`, `assets/`, `sample_repo/`,
   `agents.py`, `apecps.py`, `scanner.py`, `requirements.txt`, and
   `.streamlit/config.toml`.
3. In Streamlit Community Cloud, choose the repository.
4. Set the main file path to:

```text
app/app.py
```

5. Deploy.

For public demos, use sample repositories only. Avoid uploading secrets,
private keys, proprietary source code, or scanning private/internal endpoints.

## Run the CLI demo

```bash
python cli_demo.py --path sample_repo
```

## Notes

This is a prototype, not a production security scanner. Use the results as
triage evidence that should be reviewed by security and application owners.
