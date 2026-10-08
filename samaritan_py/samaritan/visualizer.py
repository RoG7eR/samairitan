"""Interactive Matplotlib network map (replaces React + D3 force simulation).

* Layout:        Fruchterman-Reingold force-directed physics (nx.spring_layout, NumPy-based)
* Focus mode:    click a node -> 1st-degree neighbours stay bright, the rest dims; click again to clear
* Over-Watch:    check-boxes drop/restore asset classes without touching the stored graph
* Asset profile: side panel updates for the selected node
"""
from __future__ import annotations

from typing import Optional

import matplotlib
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
from matplotlib.collections import LineCollection
from matplotlib.widgets import CheckButtons

BG, PANEL = "#0b0c10", "#1f2833"
CYAN, RED, GREY = "#66fcf1", "#ff4a4a", "#c5c6c7"
DOMAIN_TYPES = {"Domain", "Subdomain", "Primary Target"}

DEFAULT_FILTERS = {"show_infrastructure": True, "show_domains": True, "critical_only": False}


def apply_filters(G: nx.MultiDiGraph, filters: dict) -> nx.MultiDiGraph:
    """Same rules as the old React useMemo: filter nodes, keep edges whose ends both survive."""
    def keep(_, d) -> bool:
        if filters.get("critical_only") and d.get("threat_level") != "Elevated":
            return False
        if not filters.get("show_infrastructure", True) and d.get("type") == "Infrastructure":
            return False
        if not filters.get("show_domains", True) and d.get("type") in DOMAIN_TYPES:
            return False
        return True
    return G.subgraph([n for n, d in G.nodes(data=True) if keep(n, d)]).copy()


class NetworkMap:
    def __init__(self, G: nx.MultiDiGraph, filters: Optional[dict] = None,
                 focus: Optional[str] = None, seed: int = 42) -> None:
        self.G = G
        self.filters = {**DEFAULT_FILTERS, **(filters or {})}
        self.focus = focus
        self.selected: Optional[str] = focus
        self.seed = seed
        self.pos: dict = {}
        self.view = apply_filters(G, self.filters)

        self.fig = plt.figure(figsize=(14, 7.5), facecolor=BG)
        self.ax = self.fig.add_axes([0.02, 0.04, 0.68, 0.86], facecolor=BG)
        self.info = self.fig.add_axes([0.72, 0.40, 0.26, 0.50], facecolor=PANEL)
        self.chk_ax = self.fig.add_axes([0.72, 0.04, 0.26, 0.28], facecolor=PANEL)
        self.fig.text(0.02, 0.94, "SAMARITAN ASSET INDEX", color=CYAN, fontsize=18,
                      fontweight="bold", family="monospace")
        self._build_filter_widget()
        self._relayout()
        self.draw()
        self.fig.canvas.mpl_connect("button_press_event", self._on_click)

    # ---- layout / state ------------------------------------------------
    def _relayout(self) -> None:
        """Force-directed layout per connected component, packed on a grid.

        Running one spring simulation over the whole graph lets disconnected pieces
        repel each other to infinity, so each component is laid out on its own and
        the results are tiled.
        """
        if self.view.number_of_nodes() == 0:
            self.pos = {}
            return
        U = nx.Graph(self.view)
        comps = sorted(nx.connected_components(U), key=len, reverse=True)
        layouts = []
        for comp in comps:
            n = len(comp)
            if n == 1:
                layouts.append(({next(iter(comp)): np.zeros(2)}, 0.4))
                continue
            radius = 0.45 * np.sqrt(n) + 0.3
            p = nx.spring_layout(U.subgraph(comp), k=1.5 / np.sqrt(n), iterations=300,
                                 seed=self.seed, scale=radius)
            layouts.append((p, radius))
        cell = 2 * max(r for _, r in layouts) + 0.8
        cols = int(np.ceil(np.sqrt(len(layouts))))
        self.pos = {}
        for i, (p, _) in enumerate(layouts):
            off = np.array([(i % cols) * cell, -(i // cols) * cell])
            for node, xy in p.items():
                self.pos[node] = np.asarray(xy) + off

    def _build_filter_widget(self) -> None:
        self.labels = ["INFRASTRUCTURE (IPs)", "DOMAINS", "ELEVATED THREATS ONLY"]
        self.keys = ["show_infrastructure", "show_domains", "critical_only"]
        self.check = CheckButtons(self.chk_ax, self.labels, [self.filters[k] for k in self.keys])
        for lab in self.check.labels:
            lab.set_color(GREY); lab.set_family("monospace"); lab.set_fontsize(9)
        self.chk_ax.set_title("OVER-WATCH FILTERS", color="#f0ad4e", fontsize=10, family="monospace")
        try:   # matplotlib >= 3.7 styling API
            self.check.set_frame_props({"edgecolor": CYAN, "facecolor": GREY, "s": 90})
        except AttributeError:
            pass
        self.check.on_clicked(self._on_filter)

    def _on_filter(self, label: str) -> None:
        key = self.keys[self.labels.index(label)]
        self.filters[key] = not self.filters[key]
        self.view = apply_filters(self.G, self.filters)
        if self.focus not in self.view:
            self.focus = self.selected = None
        self._relayout()
        self.draw()

    def _on_click(self, event) -> None:
        if event.inaxes is not self.ax or not self.pos or event.xdata is None:
            return
        ids = list(self.pos)
        pts = np.array([self.pos[n] for n in ids])
        d = np.hypot(pts[:, 0] - event.xdata, pts[:, 1] - event.ydata)
        i = int(d.argmin())
        span = max(np.ptp(pts[:, 0]), np.ptp(pts[:, 1]), 1e-9)
        if d[i] < 0.04 * span:                              # clicked a node
            self.selected = ids[i]
            self.focus = None if self.focus == ids[i] else ids[i]
        else:                                               # clicked background -> clear focus
            self.focus = None
        self.draw()

    # ---- rendering -----------------------------------------------------
    def _near(self, node: str) -> set:
        return {node, *self.view.predecessors(node), *self.view.successors(node)}

    def draw(self) -> None:
        ax, V = self.ax, self.view
        ax.clear(); ax.set_facecolor(BG); ax.axis("off")
        if V.number_of_nodes() == 0:
            ax.text(0.5, 0.5, "NO ASSETS VISIBLE", color=GREY, ha="center", family="monospace",
                    transform=ax.transAxes)
            self._draw_info(); self.fig.canvas.draw_idle(); return

        near = self._near(self.focus) if self.focus else None
        ids = list(V.nodes)

        # edges (one line per connected pair)
        pairs = list({tuple(sorted((u, v))) for u, v in V.edges()})
        segs = [(self.pos[u], self.pos[v]) for u, v in pairs]
        hot = [self.focus is None or self.focus in (u, v) for u, v in pairs]
        base = matplotlib.colors.to_rgb(CYAN)
        rgba = [(*base, 0.6 if self.focus is None else (1.0 if h else 0.05)) for h in hot]
        widths = [2 if self.focus is None else (3 if h else 1) for h in hot]
        ax.add_collection(LineCollection(segs, colors=rgba, linewidths=widths, zorder=1))

        # nodes
        xy = np.array([self.pos[n] for n in ids])
        elevated = np.array([V.nodes[n].get("threat_level") == "Elevated" for n in ids])
        alpha = np.array([1.0 if near is None or n in near else 0.1 for n in ids])
        colors = np.array([matplotlib.colors.to_rgba(RED if e else CYAN, a) for e, a in zip(elevated, alpha)])
        ax.scatter(xy[:, 0], xy[:, 1], s=np.where(elevated, 330, 170), c=colors,
                   edgecolors="white", linewidths=1.2, zorder=2)
        for n, (x, y), a in zip(ids, xy, alpha):
            ax.text(x, y, "  " + n, color=GREY, fontsize=7, alpha=max(a * 0.8, 0.05),
                    va="center", family="monospace", zorder=3)
        ax.set_aspect("equal", adjustable="datalim")
        ax.margins(0.12)
        self._draw_info()
        self.fig.canvas.draw_idle()

    def _draw_info(self) -> None:
        a = self.info
        a.clear(); a.set_facecolor(PANEL); a.set_xticks([]); a.set_yticks([])
        a.set_title("ASSET PROFILE", color="#f0ad4e", fontsize=10, family="monospace")
        n = self.selected
        if n and n in self.G:
            d = self.G.nodes[n]
            threat = d.get("threat_level", "Unknown")
            lines = [(n, CYAN, 11), (f"Classification: {d.get('type', 'Unknown')}", GREY, 9),
                     (f"Threat priority: {threat}", RED if threat == "Elevated" else "#5cb85c", 9),
                     (f"Connections: {self.G.degree(n)}", GREY, 9),
                     ("STATUS: ACTIVE", GREY, 8)]
            for i, (t, c, s) in enumerate(lines):
                a.text(0.05, 0.9 - i * 0.14, t, color=c, fontsize=s, family="monospace",
                       transform=a.transAxes, wrap=True)
        else:
            a.text(0.5, 0.5, "STANDBY.\nAWAITING ASSET SELECTION.", color=GREY, ha="center",
                   va="center", fontsize=9, family="monospace", transform=a.transAxes)

    # ---- output --------------------------------------------------------
    def save(self, path: str) -> None:
        self.fig.savefig(path, dpi=150, facecolor=BG)

    def show(self) -> None:
        plt.show()
