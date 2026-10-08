"""Plain data containers shared by every module (replaces untyped JS objects)."""
from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class Asset:
    id: str
    type: str = "Unknown"
    threat_level: str = "Unknown"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Relationship:
    source: str
    target: str
    type: str          # OWNS | RESOLVES_TO | LOCAL_ADJACENCY

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IngestResult:
    nodes_seen: int = 0
    nodes_added: int = 0
    edges_added: int = 0
