"""Minimal APEC-PS representation for the prototype.

Actors contribute argumentation-based proof events that collectively explain
why a claim is supported, attacked, warranted, or awaiting validation.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class ProofEvent:
    """Representation of a proof event in APEC-PS."""

    actor: str
    kind: str
    claim: str
    references: Optional[List[str]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "actor": self.actor,
            "kind": self.kind,
            "claim": self.claim,
            "references": self.references or [],
            "metadata": self.metadata,
        }


class ProofTrace:
    """Simple container for proof events."""

    def __init__(self) -> None:
        self.events: List[ProofEvent] = []

    def add_event(self, event: ProofEvent) -> None:
        self.events.append(event)

    def find_by_actor(self, actor: str) -> List[ProofEvent]:
        return [event for event in self.events if event.actor == actor]

    def to_list(self) -> List[Dict[str, Any]]:
        return [event.to_dict() for event in self.events]


def create_event(actor: str, kind: str, claim: str, references: Optional[List[str]] = None, **metadata: Any) -> ProofEvent:
    """Create and return a proof event."""
    return ProofEvent(
        actor=actor,
        kind=kind,
        claim=claim,
        references=references,
        metadata=metadata or {},
    )
