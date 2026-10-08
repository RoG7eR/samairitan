"""Graph analytics with NumPy / pandas / SciPy / NetworkX.

This is the 'scientific computing' layer the original JS project did not have.
"""
from __future__ import annotations

import networkx as nx
import numpy as np
import pandas as pd
from scipy import sparse


def _undirected(G: nx.MultiDiGraph) -> nx.Graph:
    return nx.Graph(G.to_undirected())


def adjacency_matrix(G: nx.MultiDiGraph) -> tuple[np.ndarray, list]:
    """Dense directed adjacency matrix A (A[i, j] = 1 if i -> j) plus the node order."""
    order = list(G.nodes)
    A = nx.to_numpy_array(nx.DiGraph(G), nodelist=order, weight=None)
    return A, order


def node_metrics(G: nx.MultiDiGraph) -> pd.DataFrame:
    """One row per asset with structural importance scores."""
    if G.number_of_nodes() == 0:
        return pd.DataFrame(columns=["id", "type", "threat_level", "in_degree", "out_degree",
                                     "degree", "degree_centrality", "betweenness", "pagerank",
                                     "component"])
    U = _undirected(G)
    A, order = adjacency_matrix(G)
    in_deg, out_deg = A.sum(axis=0), A.sum(axis=1)

    comp_of = {n: i for i, comp in enumerate(sorted(nx.connected_components(U), key=len, reverse=True))
               for n in comp}
    pr = nx.pagerank(nx.DiGraph(G)) if G.number_of_edges() else {n: 1 / len(order) for n in order}
    bt = nx.betweenness_centrality(U)
    dc = nx.degree_centrality(U)

    df = pd.DataFrame({
        "id": order,
        "type": [G.nodes[n].get("type", "Unknown") for n in order],
        "threat_level": [G.nodes[n].get("threat_level", "Unknown") for n in order],
        "in_degree": in_deg.astype(int),
        "out_degree": out_deg.astype(int),
        "degree": [U.degree(n) for n in order],
        "degree_centrality": [dc[n] for n in order],
        "betweenness": [bt[n] for n in order],
        "pagerank": [pr[n] for n in order],
        "component": [comp_of[n] for n in order],
    })
    return df.sort_values(["pagerank", "degree"], ascending=False).reset_index(drop=True)


def summary(G: nx.MultiDiGraph) -> dict:
    """Headline numbers for the whole graph."""
    n, m = G.number_of_nodes(), G.number_of_edges()
    if n == 0:
        return {"nodes": 0, "edges": 0}
    U = _undirected(G)
    degrees = np.array([d for _, d in U.degree()])
    comps = list(nx.connected_components(U))
    return {
        "nodes": n,
        "edges": m,
        "density": float(nx.density(U)),
        "components": len(comps),
        "largest_component": max(len(c) for c in comps),
        "mean_degree": float(degrees.mean()),
        "median_degree": float(np.median(degrees)),
        "max_degree": int(degrees.max()),
        "degree_std": float(degrees.std()),
        "elevated_assets": int(sum(d.get("threat_level") == "Elevated" for _, d in G.nodes(data=True))),
    }


def degree_distribution(G: nx.MultiDiGraph) -> pd.DataFrame:
    """How many nodes have degree k (counts via np.bincount)."""
    degs = np.array([d for _, d in _undirected(G).degree()], dtype=int)
    if degs.size == 0:
        return pd.DataFrame(columns=["degree", "count", "fraction"])
    counts = np.bincount(degs)
    k = np.nonzero(counts)[0]
    return pd.DataFrame({"degree": k, "count": counts[k], "fraction": counts[k] / degs.size})


def classification_table(G: nx.MultiDiGraph) -> pd.DataFrame:
    """Asset type x threat level contingency table."""
    nodes = pd.DataFrame([{"type": d.get("type", "Unknown"), "threat_level": d.get("threat_level", "Unknown")}
                          for _, d in G.nodes(data=True)])
    if nodes.empty:
        return nodes
    return pd.crosstab(nodes["type"], nodes["threat_level"], margins=True, margins_name="Total")


def shared_infrastructure(G: nx.MultiDiGraph) -> pd.DataFrame:
    """IPs that several hostnames resolve to (shared hosting / CDN / single points of failure)."""
    rows = [(v, u) for u, v, k in G.edges(keys=True) if k == "RESOLVES_TO"]
    if not rows:
        return pd.DataFrame(columns=["ip", "hostnames", "host_count"])
    df = pd.DataFrame(rows, columns=["ip", "host"])
    out = df.groupby("ip")["host"].agg(hostnames=lambda s: sorted(s), host_count="count").reset_index()
    return out.sort_values("host_count", ascending=False).reset_index(drop=True)


def blast_radius(G: nx.MultiDiGraph, node: str) -> pd.DataFrame:
    """Hop distance from `node` to every reachable asset (BFS over the undirected graph)."""
    if node not in G:
        raise KeyError(node)
    dist = nx.single_source_shortest_path_length(_undirected(G), node)
    return (pd.DataFrame({"id": list(dist), "hops": list(dist.values())})
            .sort_values(["hops", "id"]).reset_index(drop=True))


def laplacian_spectrum(G: nx.MultiDiGraph) -> np.ndarray:
    """Eigenvalues of the graph Laplacian (sparse -> dense eigvalsh).

    The number of (near-)zero eigenvalues equals the number of connected components;
    the smallest non-zero one (algebraic connectivity) measures how well-knit a component is.
    """
    U = _undirected(G)
    if U.number_of_nodes() == 0:
        return np.array([])
    L = sparse.csgraph.laplacian(nx.to_scipy_sparse_array(U, weight=None, format="csr").astype(float))
    return np.linalg.eigvalsh(L.toarray())
