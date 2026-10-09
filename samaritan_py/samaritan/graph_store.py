"""In-memory property graph with JSON persistence (replaces Neo4j + Cypher).

Cypher                                   ->  Python
MERGE (n:Asset {id}) ON CREATE SET ...   ->  AssetGraph.merge_asset
MATCH (a),(b) MERGE (a)-[:TYPE]->(b)     ->  AssetGraph.merge_relationship
MATCH (n)-[r]->(m) RETURN n,r,m          ->  AssetGraph.to_dict / to_frames
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Tuple

import networkx as nx
import pandas as pd

from .models import Asset, IngestResult, Relationship


class AssetGraph:
    def __init__(self) -> None:
        # MultiDiGraph + edge key = relationship type, so the same type between
        # the same two nodes is stored once (exactly what Cypher MERGE guarantees).
        self.g = nx.MultiDiGraph()

    # ---- writes -------------------------------------------------------
    def merge_asset(self, a: Asset) -> bool:
        """Create the node if missing; never overwrite an existing one (ON CREATE SET)."""
        if a.id in self.g:
            return False
        self.g.add_node(a.id, type=a.type, threat_level=a.threat_level)
        return True

    def merge_relationship(self, r: Relationship) -> bool:
        """Needs both endpoints to exist (like MATCH ... MATCH ... MERGE)."""
        if r.source not in self.g or r.target not in self.g:
            return False
        if self.g.has_edge(r.source, r.target, key=r.type):
            return False
        self.g.add_edge(r.source, r.target, key=r.type, type=r.type)
        return True

    def ingest(self, entities: Iterable[Asset], relationships: Iterable[Relationship]) -> IngestResult:
        res = IngestResult()
        for e in entities:
            res.nodes_seen += 1
            res.nodes_added += self.merge_asset(e)
        for r in relationships:
            res.edges_added += self.merge_relationship(r)
        return res

    def add_local_devices(self, gateway_id: str, devices: Iterable[Asset]) -> IngestResult:
        gw = Asset(gateway_id, "Control Gateway", "Normal")
        devices = list(devices)
        rels = [Relationship(gateway_id, d.id, "LOCAL_ADJACENCY") for d in devices]
        return self.ingest([gw, *devices], rels)

    def merge(self, other: "AssetGraph") -> IngestResult:
        """Copy every asset and relationship of `other` into this graph (idempotent)."""
        ents = [Asset(n, d.get("type", "Unknown"), d.get("threat_level", "Unknown"))
                for n, d in other.g.nodes(data=True)]
        rels = [Relationship(u, v, k) for u, v, k in other.g.edges(keys=True)]
        return self.ingest(ents, rels)

    def clear(self) -> None:
        self.g.clear()

    # ---- reads --------------------------------------------------------
    def to_dict(self) -> dict:
        """Same {nodes, links} shape the old /api/v1/network endpoint returned."""
        nodes = [{"id": n, "name": n, "type": d.get("type", "Unknown"),
                  "threat_level": d.get("threat_level", "Unknown")}
                 for n, d in self.g.nodes(data=True)]
        links = [{"source": u, "target": v, "type": k} for u, v, k in self.g.edges(keys=True)]
        return {"nodes": nodes, "links": links}

    def to_frames(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        d = self.to_dict()
        nodes = pd.DataFrame(d["nodes"], columns=["id", "name", "type", "threat_level"])
        edges = pd.DataFrame(d["links"], columns=["source", "target", "type"])
        return nodes, edges

    def __len__(self) -> int:
        return self.g.number_of_nodes()

    # ---- persistence --------------------------------------------------
    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "AssetGraph":
        graph = cls()
        path = Path(path)
        if not path.exists():
            return graph
        data = json.loads(path.read_text(encoding="utf-8"))
        for n in data.get("nodes", []):
            graph.merge_asset(Asset(n["id"], n.get("type", "Unknown"), n.get("threat_level", "Unknown")))
        for l in data.get("links", []):
            graph.merge_relationship(Relationship(l["source"], l["target"], l["type"]))
        return graph
