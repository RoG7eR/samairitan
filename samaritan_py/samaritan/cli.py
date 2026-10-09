"""Command-line front-end (replaces the Express routes and the React command bar)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

from . import analytics
from .graph_store import AssetGraph
from .local_scanner import GATEWAY_ID, scan_local_network
from .osint import conduct_reconnaissance
from .parser import parse_intelligence_log
from .sample_data import build_demo_graph

DEFAULT_DB = "data/graph.json"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="samaritan", description="Samaritan Asset Index (Python edition). "
                                "Use only against assets you are authorised to assess.")
    p.add_argument("--db", default=DEFAULT_DB, help=f"graph file (default {DEFAULT_DB})")
    sub = p.add_subparsers(dest="cmd")   # no sub-command -> open the GUI
    sub.add_parser("gui", help="open the desktop GUI (default when no command is given)")

    s = sub.add_parser("sweep", help="OSINT sweep: crt.sh subdomains + DNS resolution")
    s.add_argument("target"); s.add_argument("--limit", type=int, default=10,
                                              help="max subdomains to resolve (default 10)")
    sub.add_parser("local-sweep", help="proximity scan from the OS ARP cache")
    i = sub.add_parser("ingest", help="parse one raw log line into the graph")
    i.add_argument("line")
    sub.add_parser("demo", help="load the offline demo dataset")
    sub.add_parser("reset", help="delete all stored assets")

    sub.add_parser("stats", help="graph summary + top assets + shared infrastructure")
    e = sub.add_parser("export", help="write nodes.csv / edges.csv / metrics.csv")
    e.add_argument("--out", default="export")

    v = sub.add_parser("show", help="draw the interactive network map")
    v.add_argument("--save", help="save PNG instead of opening a window")
    v.add_argument("--focus", help="start with this asset focused")
    v.add_argument("--no-infra", action="store_true", help="hide IP infrastructure")
    v.add_argument("--no-domains", action="store_true", help="hide domains/subdomains")
    v.add_argument("--critical-only", action="store_true", help="elevated threats only")
    return p


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    if args.cmd in (None, "gui"):
        from .gui import run          # imported lazily so the CLI works without a display
        run(args.db)
        return 0
    graph = AssetGraph.load(args.db)

    if args.cmd == "sweep":
        ents, rels = conduct_reconnaissance(args.target.lower(), limit=args.limit)
        if not ents:
            print("SWEEP FAILED: no intelligence extracted."); return 1
        r = graph.ingest(ents, rels)
        print(f"SWEEP COMPLETE. {r.nodes_added} new assets ({r.nodes_seen} seen), {r.edges_added} new links.")
    elif args.cmd == "local-sweep":
        try:
            devices = scan_local_network()
        except RuntimeError as exc:
            print(f"PROXIMITY SCAN FAILED: {exc}"); return 1
        r = graph.add_local_devices(GATEWAY_ID, devices)
        print(f"PROXIMITY SCAN COMPLETE. Mapped {len(devices)} neighbouring assets.")
    elif args.cmd == "ingest":
        r = graph.ingest(*parse_intelligence_log(args.line))
        print(f"Ingested: {r.nodes_added} nodes, {r.edges_added} links.")
    elif args.cmd == "demo":
        graph = build_demo_graph(); print(f"Demo graph loaded: {len(graph)} assets.")
    elif args.cmd == "reset":
        graph.clear(); print("Graph cleared.")
    elif args.cmd == "stats":
        _print_stats(graph); return 0
    elif args.cmd == "export":
        _export(graph, Path(args.out)); return 0
    elif args.cmd == "show":
        return _show(graph, args)

    graph.save(args.db)
    return 0


def _print_stats(graph: AssetGraph) -> None:
    if len(graph) == 0:
        print("Graph is empty. Try: python main.py demo"); return
    pd.set_option("display.width", 140); pd.set_option("display.max_columns", 20)
    print("== SUMMARY ==")
    for k, v in analytics.summary(graph.g).items():
        print(f"{k:<20}{v:.3f}" if isinstance(v, float) else f"{k:<20}{v}")
    print("\n== ASSET CLASSIFICATION =="); print(analytics.classification_table(graph.g))
    print("\n== TOP 10 ASSETS (PageRank) ==")
    print(analytics.node_metrics(graph.g).head(10).round(4).to_string(index=False))
    shared = analytics.shared_infrastructure(graph.g)
    if not shared.empty:
        print("\n== SHARED INFRASTRUCTURE =="); print(shared.to_string(index=False))
    print("\n== DEGREE DISTRIBUTION =="); print(analytics.degree_distribution(graph.g).round(3).to_string(index=False))


def _export(graph: AssetGraph, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    nodes, edges = graph.to_frames()
    nodes.to_csv(out / "nodes.csv", index=False)
    edges.to_csv(out / "edges.csv", index=False)
    analytics.node_metrics(graph.g).to_csv(out / "metrics.csv", index=False)
    print(f"Wrote nodes.csv, edges.csv, metrics.csv to {out}/")


def _show(graph: AssetGraph, args) -> int:
    import matplotlib
    if args.save:
        matplotlib.use("Agg")
    from .visualizer import NetworkMap
    if len(graph) == 0:
        print("Graph is empty. Try: python main.py demo"); return 1
    nm = NetworkMap(graph.g, focus=args.focus, filters={
        "show_infrastructure": not args.no_infra, "show_domains": not args.no_domains,
        "critical_only": args.critical_only})
    if args.save:
        nm.save(args.save); print(f"Saved {args.save}")
    else:
        nm.show()
    return 0


if __name__ == "__main__":
    sys.exit(main())
