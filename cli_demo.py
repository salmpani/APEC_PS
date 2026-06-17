"""CLI demo for the improved PQC triage prototype."""

import argparse
from pathlib import Path

from agents import ALL_AGENTS
from apecps import ProofTrace
from scanner import scan_repository


def run_demo(path: Path) -> None:
    findings = scan_repository(str(path))
    trace = ProofTrace()
    for agent in ALL_AGENTS:
        agent.evaluate(findings, trace)

    print("Findings:")
    for finding in findings:
        line = finding.get("line_no") or "?"
        score = finding.get("risk_score", "-")
        print(f"- {finding['file']}:{line} -> {finding['algorithm']} ({finding['severity']}, score={score})")

    print("\nProof Events:")
    for event in trace.events:
        refs = ", ".join(event.references) if event.references else "-"
        print(f"[{event.id}] {event.actor} {event.kind} -> {event.claim} (refs: {refs})")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run PQC triage CLI demo")
    parser.add_argument("--path", type=str, required=True, help="Path to project directory")
    args = parser.parse_args()
    path = Path(args.path)
    if not path.exists() or not path.is_dir():
        raise SystemExit(f"Path {path} does not exist or is not a directory")
    run_demo(path)


if __name__ == "__main__":
    main()
