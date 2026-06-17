"""Agent definitions for the improved PQC prototype.

Agents consume scanner findings and append proof events to an APEC-PS trace.
They remain deterministic for reproducibility, but their outputs are richer:
each event carries severity, risk score, evidence, and references that make the
argument graph useful for inspection.
"""

from collections import Counter
from typing import Any, Dict, List

from apecps import ProofTrace, create_event


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}
AGENT_ICONS = {
    "CryptoDiscoveryAgent": "search",
    "QuantumRiskAgent": "activity",
    "ThreatIntelligenceAgent": "radar",
    "ComplianceAgent": "scale",
    "CompatibilityAgent": "plug",
    "PerformanceCostAgent": "gauge",
    "MigrationPlannerAgent": "map",
    "CriticAgent": "alert-triangle",
    "HumanReviewAgent": "user-check",
}


class Agent:
    """Base class for all agents."""

    name: str = "Agent"
    role: str = "Generic reasoning agent"

    def evaluate(self, findings: List[Dict[str, Any]], trace: ProofTrace) -> None:
        raise NotImplementedError


class CryptoDiscoveryAgent(Agent):
    name = "CryptoDiscoveryAgent"
    role = "Turns scanner findings into premises."

    def evaluate(self, findings: List[Dict[str, Any]], trace: ProofTrace) -> None:
        for finding in findings:
            location = f"{finding['file']}:{finding.get('line_no') or '?'}"
            claim = f"Found {finding['algorithm']} risk at {location}"
            trace.add_event(
                create_event(
                    actor=self.name,
                    kind="premise",
                    claim=claim,
                    severity=finding.get("severity"),
                    type=finding.get("type"),
                    line=finding.get("line_no"),
                    algorithm=finding.get("algorithm"),
                    risk_score=finding.get("risk_score", 0),
                    confidence=finding.get("confidence"),
                    evidence=finding.get("evidence"),
                    icon=AGENT_ICONS[self.name],
                )
            )


class QuantumRiskAgent(Agent):
    name = "QuantumRiskAgent"
    role = "Maps classical cryptography findings to quantum threat exposure."

    def evaluate(self, findings: List[Dict[str, Any]], trace: ProofTrace) -> None:
        for pe in trace.find_by_actor("CryptoDiscoveryAgent"):
            algorithm = pe.metadata.get("algorithm")
            risk_score = pe.metadata.get("risk_score", 0)
            severity = pe.metadata.get("severity")
            if algorithm in {"RSA", "RSA-2048", "ECDSA", "ECDH", "DSA"}:
                claim = f"{algorithm} depends on factoring or discrete-log assumptions and is exposed to cryptographically relevant quantum computers"
            elif algorithm == "SHA1":
                claim = "SHA-1 also carries classical collision risk, increasing migration urgency"
            else:
                claim = f"{algorithm} should be reviewed for quantum-era cryptographic exposure"
            trace.add_event(
                create_event(
                    actor=self.name,
                    kind="support",
                    claim=claim,
                    references=[pe.id],
                    severity=severity,
                    risk_score=risk_score,
                    icon=AGENT_ICONS[self.name],
                )
            )


class ThreatIntelligenceAgent(Agent):
    name = "ThreatIntelligenceAgent"
    role = "Adds external threat context without live network dependencies."

    def evaluate(self, findings: List[Dict[str, Any]], trace: ProofTrace) -> None:
        high_retention = [f for f in findings if (f.get("retention_years") or 0) >= 10]
        asymmetric = [f for f in findings if f.get("algorithm") in {"RSA", "RSA-2048", "ECDSA", "ECDH", "DSA"}]
        if high_retention and asymmetric:
            claim = "Harvest-now-decrypt-later exposure is plausible because long-retention data is protected by non-PQC asymmetric cryptography"
            refs = [event.id for event in trace.find_by_actor("CryptoDiscoveryAgent")[:5]]
            trace.add_event(
                create_event(
                    actor=self.name,
                    kind="support",
                    claim=claim,
                    references=refs,
                    severity="high",
                    risk_score=max(f.get("risk_score", 0) for f in high_retention),
                    icon=AGENT_ICONS[self.name],
                )
            )


class ComplianceAgent(Agent):
    name = "ComplianceAgent"
    role = "Checks findings against PQC and crypto hygiene policy."

    def evaluate(self, findings: List[Dict[str, Any]], trace: ProofTrace) -> None:
        for pe in trace.find_by_actor("CryptoDiscoveryAgent"):
            severity = pe.metadata.get("severity")
            algorithm = pe.metadata.get("algorithm")
            if severity == "high":
                claim = f"{algorithm} should be prioritized for migration planning under current PQC readiness guidance"
                trace.add_event(
                    create_event(
                        actor=self.name,
                        kind="support",
                        claim=claim,
                        references=[pe.id],
                        severity=severity,
                        risk_score=pe.metadata.get("risk_score", 0),
                        icon=AGENT_ICONS[self.name],
                    )
                )


class CompatibilityAgent(Agent):
    name = "CompatibilityAgent"
    role = "Challenges risky migrations that could disrupt clients."

    def evaluate(self, findings: List[Dict[str, Any]], trace: ProofTrace) -> None:
        for pe in list(trace.events):
            if pe.actor in {"QuantumRiskAgent", "ComplianceAgent"} and pe.metadata.get("severity") in {"medium", "high"}:
                claim = "Direct replacement may break clients or certificates; hybrid and staged rollout should be required"
                trace.add_event(
                    create_event(
                        actor=self.name,
                        kind="attack",
                        claim=claim,
                        references=[pe.id],
                        type="undercut",
                        severity="medium",
                        icon=AGENT_ICONS[self.name],
                    )
                )


class PerformanceCostAgent(Agent):
    name = "PerformanceCostAgent"
    role = "Estimates migration effort and operational cost."

    def evaluate(self, findings: List[Dict[str, Any]], trace: ProofTrace) -> None:
        if not findings:
            return
        complexity_counts = Counter(f.get("migration_complexity", "medium") for f in findings)
        high_risk = [f for f in findings if f.get("severity") == "high"]
        effort = "high" if complexity_counts["high"] or len(high_risk) >= 3 else "medium"
        claim = f"Estimated migration effort is {effort}; {len(high_risk)} high-priority findings need sequencing and test coverage"
        refs = [event.id for event in trace.find_by_actor("CryptoDiscoveryAgent")[:6]]
        trace.add_event(
            create_event(
                actor=self.name,
                kind="warrant",
                claim=claim,
                references=refs,
                severity="medium" if effort == "medium" else "high",
                effort=effort,
                icon=AGENT_ICONS[self.name],
            )
        )


class MigrationPlannerAgent(Agent):
    name = "MigrationPlannerAgent"
    role = "Produces a migration plan from supported risks and constraints."

    def evaluate(self, findings: List[Dict[str, Any]], trace: ProofTrace) -> None:
        if not findings:
            return
        highest = max(findings, key=lambda f: f.get("risk_score", 0))
        algorithm = highest.get("algorithm")
        severity = highest.get("severity")
        risk_score = highest.get("risk_score", 0)
        if severity == "high":
            plan = f"Prioritize {algorithm}: inventory owners, add hybrid/PQC option, stage rollout, and require human approval before production change"
        elif severity == "medium":
            plan = f"Plan controlled migration for {algorithm} with compatibility tests and fallback"
        else:
            plan = f"Monitor {algorithm} and record PQC replacement options"
        refs = [event.id for event in trace.events if event.kind in {"support", "warrant"}][-6:]
        trace.add_event(
            create_event(
                actor=self.name,
                kind="claim",
                claim=plan,
                references=refs,
                severity=severity,
                risk_score=risk_score,
                icon=AGENT_ICONS[self.name],
            )
        )


class CriticAgent(Agent):
    name = "CriticAgent"
    role = "Looks for missing evidence and unresolved migration risk."

    def evaluate(self, findings: List[Dict[str, Any]], trace: ProofTrace) -> None:
        for pe in trace.find_by_actor("MigrationPlannerAgent"):
            has_support = bool(pe.references)
            compatibility_attacks = [ev for ev in trace.events if ev.kind == "attack" and set(ev.references or []) & set(pe.references or [])]
            if not has_support:
                claim = "Migration plan lacks supporting evidence"
            elif compatibility_attacks:
                claim = "Migration plan must explicitly resolve compatibility attacks before execution"
            else:
                continue
            trace.add_event(
                create_event(
                    actor=self.name,
                    kind="attack",
                    claim=claim,
                    references=[pe.id],
                    type="rebut",
                    severity="medium",
                    icon=AGENT_ICONS[self.name],
                )
            )


class HumanReviewAgent(Agent):
    name = "HumanReviewAgent"
    role = "Requires human confirmation before remediation."

    def evaluate(self, findings: List[Dict[str, Any]], trace: ProofTrace) -> None:
        for pe in trace.find_by_actor("MigrationPlannerAgent"):
            unresolved_attacks = [ev for ev in trace.events if ev.references and pe.id in ev.references and ev.kind == "attack"]
            if unresolved_attacks:
                claim = "Human review required: plan is challenged and needs owner sign-off"
                status = "needs_review"
            else:
                claim = "Human review checkpoint created: approve before executing remediation"
                status = "approval_required"
            trace.add_event(
                create_event(
                    actor=self.name,
                    kind="validation",
                    claim=claim,
                    references=[pe.id],
                    status=status,
                    icon=AGENT_ICONS[self.name],
                )
            )


ALL_AGENTS: List[Agent] = [
    CryptoDiscoveryAgent(),
    QuantumRiskAgent(),
    ThreatIntelligenceAgent(),
    ComplianceAgent(),
    CompatibilityAgent(),
    PerformanceCostAgent(),
    MigrationPlannerAgent(),
    CriticAgent(),
    HumanReviewAgent(),
]
