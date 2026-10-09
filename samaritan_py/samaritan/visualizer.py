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


def layout_components(view: nx.MultiDiGraph, seed: int = 42, aspect: float = 1.6) -> dict:
    """Force-directed layout per connected component, tiled on a grid.

    One global spring simulation would repel disconnected pieces to infinity,
    so every component is laid out on its own and the results are packed in a grid whose
    shape follows the canvas aspect ratio (width / height).
    """
    if view.number_of_nodes() == 0:
        return {}
    U = nx.Graph(view)
    comps = sorted(nx.connected_components(U), key=len, reverse=True)
    layouts = []
    for comp in comps:
        n = len(comp)
        if n == 1:
            layouts.append(({next(iter(comp)): np.zeros(2)}, 0.4))
            continue
        radius = 0.6 * np.sqrt(n) + 0.3
        p = nx.spring_layout(U.subgraph(comp), k=1.5 / np.sqrt(n), iterations=300,
                             seed=seed, scale=radius)
        layouts.append((p, radius))
    # shelf packing: components keep their own size, rows wrap at a width that matches the canvas shape
    gap = 0.6
    total = sum((2 * r + gap) ** 2 for _, r in layouts)
    row_w = max(np.sqrt(total * aspect), 2 * layouts[0][1] + gap)
    pos, x, y, row_h = {}, 0.0, 0.0, 0.0
    for p, r in layouts:
        w = 2 * r + gap
        if x > 0 and x + w > row_w:
            x, y, row_h = 0.0, y - row_h, 0.0
        off = np.array([x + w / 2, y - w / 2])
        for node, xy in p.items():
            pos[node] = np.asarray(xy) + off
        x += w; row_h = max(row_h, w)
    return pos


def render_graph(ax, V: nx.MultiDiGraph, pos: dict, focus=None, label_size: int = 7,
                 empty_message: str = "NO ASSETS VISIBLE") -> None:
    """Draw nodes, edges and labels on `ax` (shared by the CLI map and the GUI)."""
    ax.clear(); ax.set_facecolor(BG); ax.axis("off")
    if V.number_of_nodes() == 0:
        ax.text(0.5, 0.5, empty_message, color=GREY, ha="center", va="center",
                family="monospace", fontsize=11, transform=ax.transAxes, linespacing=1.8)
        return
    focus = focus if focus in V else None
    near = {focus, *V.predecessors(focus), *V.successors(focus)} if focus else None
    ids = list(V.nodes)

    pairs = list({tuple(sorted((u, v))) for u, v in V.edges()})
    segs = [(pos[u], pos[v]) for u, v in pairs]
    hot = [focus is None or focus in (u, v) for u, v in pairs]
    base = matplotlib.colors.to_rgb(CYAN)
    rgba = [(*base, 0.6 if focus is None else (1.0 if h else 0.05)) for h in hot]
    widths = [2 if focus is None else (3 if h else 1) for h in hot]
    if segs:
        ax.add_collection(LineCollection(segs, colors=rgba, linewidths=widths, zorder=1))

    xy = np.array([pos[n] for n in ids])
    elevated = np.array([V.nodes[n].get("threat_level") == "Elevated" for n in ids])
    alpha = np.array([1.0 if near is None or n in near else 0.1 for n in ids])
    colors = [matplotlib.colors.to_rgba(RED if e else CYAN, a) for e, a in zip(elevated, alpha)]
    ax.scatter(xy[:, 0], xy[:, 1], s=np.where(elevated, 330, 170), c=colors,
               edgecolors="white", linewidths=1.2, zorder=2)
    for n, (x, y), a in zip(ids, xy, alpha):
        ax.text(x, y, "  " + n, color=GREY, fontsize=label_size, alpha=max(a * 0.8, 0.05),
                va="center", family="monospace", zorder=3)
    ax.set_aspect("equal", adjustable="datalim")
    ax.margins(0.12)


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
        self.pos = layout_components(self.view, self.seed)

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
    def draw(self) -> None:
        render_graph(self.ax, self.view, self.pos, self.focus)
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
