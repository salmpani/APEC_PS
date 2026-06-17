# Changelog

## 0.2 (2026‑06‑16)

This is an **experimental** release that refines the PQC risk triage
prototype.  Major changes:

- **Expanded scanning**:
  - Added certificate parsing for PEM/CRT files to extract key type and
    signature algorithm.
  - Added detection of vulnerable cryptographic algorithms in
    dependency manifests (`requirements.txt`, `package.json`), YAML/JSON
    configuration files and infrastructure‑as‑code (`*.tf`, `k8s*.yml`).
  - Added detection of outdated TLS settings such as TLS 1.0/1.1 and weak
    key exchange or signature schemes.

- **Improved agents**:
  - Agents are now implemented as Python classes with an `evaluate` method
    that consumes findings and writes `ProofEvent` records.
  - Added a `ComplianceAgent` for policy and standards alignment.
  - The `CriticAgent` now classifies attacks as rebut, undercut or
    undermine and can ask other agents to revise their recommendations.

- **Better UI**:
  - Streamlit interface now guides the user through scanning and
    reasoning steps.
  - Added table views for findings and proof events and a simple graph
    visualisation of argument relations.
  - Added export of JSON report and markdown summary.

## 0.1 (2026‑06‑15)

Initial release of the PQC risk triage prototype with basic scanning,
agent definitions and a simple Streamlit UI.