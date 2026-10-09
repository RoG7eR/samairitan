"""Desktop GUI for the Samaritan Asset Index (Tkinter + Matplotlib, standard library only).

Layout
------
* Left sidebar : target / URL input, scans, Over-Watch filters, focus picker, data tools
* Centre tabs  : "Network Map" (click, hover, scroll-zoom, drag-pan) and "Analytics"
* Bottom       : activity log + progress bar

Network operations run in a worker thread so the window never freezes; results are
handed back to the Tk main loop through a queue.
"""
from __future__ import annotations

import json
import queue
import warnings
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont
from typing import Callable, Optional

import numpy as np
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from . import analytics
from .cli import DEFAULT_DB
from .cli import _export as export_csv
from .graph_store import AssetGraph
from .local_scanner import GATEWAY_ID, scan_local_network
from .osint import conduct_reconnaissance, fetch_ct_records
from .parser import parse_intelligence_log
from .sample_data import build_demo_graph
from .utils import normalize_target
from .visualizer import BG, CYAN, GREY, PANEL, RED, apply_filters, layout_components, render_graph

warnings.filterwarnings("ignore", message="Ignoring fixed .* limits")   # harmless while zooming/panning

INPUT, BORDER, AMBER, GREEN = "#0f141a", "#2d3b4a", "#f0ad4e", "#5cb85c"
BTN, BTN_HOVER = "#2b3a4a", "#3a5069"
HEADERS = {"id": "ASSET", "type": "TYPE", "threat_level": "THREAT", "degree": "DEG", "betweenness": "BETWEEN.",
           "pagerank": "PAGERANK", "component": "CLUSTER", "ip": "IP", "host_count": "HOSTS", "hostnames": "HOST NAMES"}
HINT = "Click a node to focus  ·  click empty space to clear  ·  scroll to zoom  ·  drag to pan"
EMPTY_MSG = ("NO ASSETS YET\n\nEnter a domain or URL on the left and press  RUN OSINT SWEEP,\n"
             "or press  LOAD DEMO DATA  to explore a sample network.")


# --------------------------------------------------------------------------- theme
def _pick(root: tk.Misc, candidates, fallback: str) -> str:
    families = set(tkfont.families(root))
    return next((f for f in candidates if f in families), fallback)


def apply_theme(root: tk.Tk) -> tuple[str, str]:
    ui = _pick(root, ("Segoe UI", "SF Pro Text", "Helvetica Neue", "Ubuntu", "DejaVu Sans"), "TkDefaultFont")
    mono = _pick(root, ("Cascadia Mono", "Consolas", "Menlo", "DejaVu Sans Mono", "Courier New"), "TkFixedFont")
    root.configure(bg=BG)
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=BG, foreground=GREY, fieldbackground=INPUT, bordercolor=BORDER,
                lightcolor=PANEL, darkcolor=PANEL, troughcolor=BG, font=(ui, 10),
                focuscolor=BG, insertcolor="white")
    s.configure("TFrame", background=BG)
    s.configure("Card.TFrame", background=PANEL)
    s.configure("TLabel", background=BG, foreground=GREY)
    s.configure("Card.TLabel", background=PANEL, foreground=GREY)
    s.configure("Title.TLabel", background=BG, foreground=CYAN, font=(mono, 17, "bold"))
    s.configure("Sub.TLabel", background=BG, foreground="#7d8590", font=(ui, 9))
    s.configure("Chip.TLabel", background=PANEL, foreground=CYAN, font=(mono, 10, "bold"), padding=(12, 5))
    s.configure("H.TLabel", background=PANEL, foreground=AMBER, font=(mono, 9, "bold"))
    s.configure("Hint.TLabel", background=PANEL, foreground="#7d8590", font=(ui, 8))
    s.configure("Val.TLabel", background=PANEL, foreground="white", font=(ui, 10))
    s.configure("Name.TLabel", background=PANEL, foreground=CYAN, font=(mono, 12, "bold"))
    s.configure("Tile.TLabel", background=PANEL, foreground=CYAN, font=(mono, 16, "bold"))
    s.configure("TileCap.TLabel", background=PANEL, foreground="#7d8590", font=(ui, 8))

    s.configure("TButton", background=BTN, foreground="white", padding=(10, 7), borderwidth=0, relief="flat")
    s.map("TButton", background=[("disabled", "#1c242d"), ("active", BTN_HOVER)],
          foreground=[("disabled", "#5b6570")])
    s.configure("Accent.TButton", background=CYAN, foreground="#0b0c10", font=(ui, 10, "bold"))
    s.map("Accent.TButton", background=[("disabled", "#2a5a58"), ("active", "#9ffff7")],
          foreground=[("disabled", "#0b0c10")])
    s.configure("Danger.TButton", background="#5a1f24", foreground="#ffb3b3")
    s.map("Danger.TButton", background=[("disabled", "#2b1517"), ("active", "#7a2a30")])
    s.configure("Mini.TButton", padding=(8, 3))

    s.configure("TCheckbutton", background=PANEL, foreground=GREY, indicatorbackground=INPUT,
                indicatorforeground=CYAN, padding=3)
    s.map("TCheckbutton", background=[("active", PANEL)], indicatorbackground=[("selected", INPUT)])
    s.configure("TEntry", fieldbackground=INPUT, foreground="white", padding=6, bordercolor=BORDER)
    s.configure("TCombobox", fieldbackground=INPUT, background=BTN, foreground="white",
                arrowcolor=CYAN, padding=5, bordercolor=BORDER)
    s.map("TCombobox", fieldbackground=[("readonly", INPUT)], foreground=[("readonly", "white")],
          background=[("active", BTN_HOVER)])
    s.configure("TSpinbox", fieldbackground=INPUT, foreground="white", arrowcolor=CYAN, padding=4)
    root.option_add("*TCombobox*Listbox.background", INPUT)
    root.option_add("*TCombobox*Listbox.foreground", "white")
    root.option_add("*TCombobox*Listbox.selectBackground", "#1f6f78")
    root.option_add("*TCombobox*Listbox.font", (ui, 10))

    s.configure("Treeview", background=INPUT, fieldbackground=INPUT, foreground=GREY, rowheight=24,
                borderwidth=0, font=(ui, 9))
    s.configure("Treeview.Heading", background=PANEL, foreground=AMBER, font=(mono, 9, "bold"),
                relief="flat", padding=(6, 5))
    s.map("Treeview", background=[("selected", "#1f6f78")], foreground=[("selected", "white")])
    s.map("Treeview.Heading", background=[("active", BTN)])

    s.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 0, 0, 0))
    s.configure("TNotebook.Tab", background=PANEL, foreground="#7d8590", padding=(18, 8),
                font=(mono, 10, "bold"), borderwidth=0)
    s.map("TNotebook.Tab", background=[("selected", BG), ("active", BTN)],
          foreground=[("selected", CYAN)])
    s.configure("Horizontal.TProgressbar", troughcolor=PANEL, background=CYAN, thickness=6, borderwidth=0)
    for sb in ("TScrollbar", "Vertical.TScrollbar"):
        s.configure(sb, background=BTN, troughcolor=INPUT, arrowcolor=GREY, bordercolor=INPUT,
                    lightcolor=BTN, darkcolor=BTN, borderwidth=0, arrowsize=12, relief="flat")
        s.map(sb, background=[("active", BTN_HOVER), ("pressed", CYAN)])
    s.configure("TPanedwindow", background=BG)
    return ui, mono


# --------------------------------------------------------------------------- app
class App(tk.Tk):
    def __init__(self, db_path: str = DEFAULT_DB) -> None:
        super().__init__()
        self.title("Samaritan Asset Index")
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{min(1420, sw - 60)}x{min(880, sh - 90)}+30+20")
        self.minsize(1100, 680)
        self.ui_font, self.mono_font = apply_theme(self)

        self.db = Path(db_path)
        self.graph = AssetGraph.load(self.db)
        self.history_file = self.db.with_name("history.json")
        self.history = self._load_history()

        self.focus: Optional[str] = None
        self.selected: Optional[str] = None
        self.view = self.graph.g
        self.pos: dict = {}
        self.pos_ids: list = []
        self.pos_arr = np.zeros((0, 2))
        self.q: "queue.Queue" = queue.Queue()
        self.busy = False
        self._press = None
        self._dragged = False
        self.analytics_dirty = True

        self.target_var = tk.StringVar()
        self.limit_var = tk.IntVar(value=10)
        self.preview_var = tk.StringVar(value="")
        self.focus_var = tk.StringVar()
        self.chip_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.hover_var = tk.StringVar(value=HINT)
        self.filter_vars = {"show_infrastructure": tk.BooleanVar(value=True),
                            "show_domains": tk.BooleanVar(value=True),
                            "critical_only": tk.BooleanVar(value=False)}

        self._build_header()
        self._build_sidebar()
        self._build_main()
        self._build_statusbar()
        self.target_var.trace_add("write", self._on_target_change)
        for v in self.filter_vars.values():
            v.trace_add("write", lambda *_: self.refresh())

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.bind("<Control-r>", lambda e: self.on_sweep())
        self._on_target_change()
        self.refresh()
        self.log("[+] Samaritan Asset Index ready. Use only against assets you are authorised to assess.")
        if len(self.graph):
            self.log(f"[~] Loaded {len(self.graph)} assets from {self.db}")
        self.after(100, self._poll)

    # ------------------------------------------------------------------ building
    def _build_header(self) -> None:
        h = ttk.Frame(self, padding=(18, 12, 18, 8))
        h.grid(row=0, column=0, columnspan=2, sticky="ew")
        left = ttk.Frame(h); left.pack(side="left")
        ttk.Label(left, text="SAMARITAN ASSET INDEX", style="Title.TLabel").pack(anchor="w")
        ttk.Label(left, text="Passive reconnaissance & asset-graph analytics  ·  Python for Scientific Computing",
                  style="Sub.TLabel").pack(anchor="w")
        ttk.Label(h, textvariable=self.chip_var, style="Chip.TLabel").pack(side="right")

    def _card(self, parent, title: str) -> ttk.Frame:
        card = ttk.Frame(parent, style="Card.TFrame", padding=(12, 9, 12, 11))
        card.pack(fill="x", pady=(0, 9))
        ttk.Label(card, text=title, style="H.TLabel").pack(anchor="w", pady=(0, 6))
        return card

    def _build_sidebar(self) -> None:
        side = ttk.Frame(self, padding=(14, 0, 6, 8), width=300)
        side.grid(row=1, column=0, sticky="ns"); side.grid_propagate(False)
        self.actions: list[ttk.Button] = []

        c = self._card(side, "TARGET  (DOMAIN OR URL)")
        self.target_combo = ttk.Combobox(c, textvariable=self.target_var, values=self.history)
        self.target_combo.pack(fill="x")
        self.target_combo.bind("<Return>", lambda e: self.on_sweep())
        ttk.Label(c, textvariable=self.preview_var, style="Hint.TLabel", wraplength=250).pack(anchor="w", pady=(4, 6))
        row = ttk.Frame(c, style="Card.TFrame"); row.pack(fill="x", pady=(0, 8))
        ttk.Label(row, text="Max sub-domains to resolve", style="Card.TLabel").pack(side="left")
        ttk.Spinbox(row, from_=1, to=100, width=5, textvariable=self.limit_var).pack(side="right")
        b = ttk.Button(c, text="▶  RUN OSINT SWEEP", style="Accent.TButton", command=self.on_sweep)
        b.pack(fill="x"); self.actions.append(b)

        c = self._card(side, "QUICK ACTIONS")
        for text, cmd in (("Local Network Scan (ARP)", self.on_local_scan),
                          ("Ingest Log Line…", self.on_ingest),
                          ("Load Demo Data", self.on_demo)):
            b = ttk.Button(c, text=text, command=cmd); b.pack(fill="x", pady=2); self.actions.append(b)

        c = self._card(side, "OVER-WATCH FILTERS")
        for key, text in (("show_infrastructure", "Infrastructure (IPs)"), ("show_domains", "Domains"),
                          ("critical_only", "Elevated threats only")):
            ttk.Checkbutton(c, text=text, variable=self.filter_vars[key]).pack(anchor="w")

        c = self._card(side, "DATA")
        ttk.Button(c, text="Export CSV…", command=self.on_export).pack(fill="x", pady=2)
        ttk.Button(c, text="Save Map Image…", command=self.on_save_image).pack(fill="x", pady=2)
        b = ttk.Button(c, text="Reset Graph", style="Danger.TButton", command=self.on_reset)
        b.pack(fill="x", pady=(8, 0)); self.actions.append(b)

    def _build_main(self) -> None:
        main = ttk.Frame(self, padding=(6, 0, 14, 8))
        main.grid(row=1, column=1, sticky="nsew")
        main.rowconfigure(0, weight=1); main.columnconfigure(0, weight=1)
        self.nb = ttk.Notebook(main)
        self.nb.grid(row=0, column=0, sticky="nsew")
        self.nb.bind("<<NotebookTabChanged>>", self._on_tab)

        # ---- map tab
        tab = ttk.Frame(self.nb); self.nb.add(tab, text="NETWORK MAP")
        tab.columnconfigure(0, weight=1); tab.rowconfigure(1, weight=1)
        bar = ttk.Frame(tab, padding=(0, 8, 0, 6)); bar.grid(row=0, column=0, columnspan=2, sticky="ew")
        for text, cmd in (("＋", lambda: self._zoom(0.8)), ("－", lambda: self._zoom(1.25)),
                          ("Fit view", lambda: self.draw_map(fit=True))):
            ttk.Button(bar, text=text, style="Mini.TButton", command=cmd).pack(side="left", padx=(0, 5))
        ttk.Button(bar, text="Clear focus", style="Mini.TButton", command=self.clear_focus).pack(side="right")
        self.focus_combo = ttk.Combobox(bar, textvariable=self.focus_var, state="readonly", width=30)
        self.focus_combo.pack(side="right", padx=(0, 6))
        self.focus_combo.bind("<<ComboboxSelected>>", self._on_focus_pick)
        ttk.Label(bar, text="Focus asset:", style="Sub.TLabel").pack(side="right", padx=(0, 6))

        self.fig = Figure(figsize=(8, 6), facecolor=BG)
        self.ax = self.fig.add_axes([0.01, 0.01, 0.98, 0.98])
        self.canvas = FigureCanvasTkAgg(self.fig, master=tab)
        self.canvas.get_tk_widget().configure(bg=BG, highlightthickness=0)
        self.canvas.get_tk_widget().grid(row=1, column=0, sticky="nsew")
        for ev, fn in (("button_press_event", self._on_press), ("motion_notify_event", self._on_motion),
                       ("button_release_event", self._on_release), ("scroll_event", self._on_scroll)):
            self.canvas.mpl_connect(ev, fn)

        prof = ttk.Frame(tab, style="Card.TFrame", padding=12, width=250)
        prof.grid(row=1, column=1, sticky="ns", padx=(10, 0)); prof.grid_propagate(False)
        ttk.Label(prof, text="ASSET PROFILE", style="H.TLabel").pack(anchor="w", pady=(0, 8))
        self.p_empty = ttk.Label(prof, text="STANDBY\n\nClick an asset on the map\nto inspect it.",
                                 style="Hint.TLabel", justify="center")
        self.p_body = ttk.Frame(prof, style="Card.TFrame")
        self.p_name = ttk.Label(self.p_body, text="", style="Name.TLabel", wraplength=225, justify="left")
        self.p_name.pack(anchor="w")
        self.p_rows = {}
        for key in ("Classification", "Threat priority", "Connections"):
            r = ttk.Frame(self.p_body, style="Card.TFrame"); r.pack(fill="x", pady=2)
            ttk.Label(r, text=key, style="Hint.TLabel").pack(anchor="w")
            self.p_rows[key] = ttk.Label(r, text="", style="Val.TLabel", wraplength=225)
            self.p_rows[key].pack(anchor="w")
        ttk.Label(self.p_body, text="RELATIONSHIPS  (double-click to jump)", style="H.TLabel").pack(anchor="w", pady=(12, 4))
        lf = ttk.Frame(self.p_body, style="Card.TFrame"); lf.pack(fill="both", expand=True)
        self.p_list = tk.Listbox(lf, bg=INPUT, fg=GREY, bd=0, highlightthickness=0, activestyle="none",
                                 selectbackground="#1f6f78", font=(self.mono_font, 8))
        sb = ttk.Scrollbar(lf, command=self.p_list.yview); self.p_list.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y"); self.p_list.pack(side="left", fill="both", expand=True)
        self.p_list.bind("<Double-Button-1>", self._on_neighbour_dbl)
        self.p_empty.pack(pady=40)

        # ---- analytics tab
        an = ttk.Frame(self.nb, padding=(0, 10, 0, 0)); self.nb.add(an, text="ANALYTICS")
        an.columnconfigure(0, weight=1); an.rowconfigure(1, weight=1)
        tiles = ttk.Frame(an); tiles.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        self.tiles = {}
        for i, (key, cap) in enumerate((("nodes", "ASSETS"), ("edges", "LINKS"), ("components", "CLUSTERS"),
                                        ("largest_component", "LARGEST CLUSTER"), ("density", "DENSITY"),
                                        ("mean_degree", "MEAN DEGREE"), ("max_degree", "MAX DEGREE"),
                                        ("elevated_assets", "ELEVATED"))):
            t = ttk.Frame(tiles, style="Card.TFrame", padding=(12, 8)); t.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 6, 0))
            tiles.columnconfigure(i, weight=1)
            v = ttk.Label(t, text="–", style="Tile.TLabel"); v.pack(anchor="w")
            ttk.Label(t, text=cap, style="TileCap.TLabel").pack(anchor="w")
            self.tiles[key] = v
        pw = ttk.PanedWindow(an, orient="horizontal"); pw.grid(row=1, column=0, sticky="nsew")
        left = ttk.Frame(pw, style="Card.TFrame", padding=10); pw.add(left, weight=3)
        ttk.Label(left, text="ASSET RANKING  (click a header to sort · double-click to open on map)", style="H.TLabel").pack(anchor="w", pady=(0, 6))
        cols = ("id", "type", "threat_level", "degree", "betweenness", "pagerank", "component")
        self.m_tree = self._make_tree(left, cols, (190, 125, 75, 50, 85, 85, 65), self._on_tree_dbl)
        right = ttk.Frame(pw, style="Card.TFrame", padding=10); pw.add(right, weight=2)
        ttk.Label(right, text="SHARED INFRASTRUCTURE", style="H.TLabel").pack(anchor="w", pady=(0, 6))
        self.s_tree = self._make_tree(right, ("ip", "host_count", "hostnames"), (105, 50, 220), None, height=5)
        ttk.Label(right, text="DEGREE DISTRIBUTION", style="H.TLabel").pack(anchor="w", pady=(10, 4))
        self.dfig = Figure(figsize=(4, 2.4), facecolor=PANEL)
        self.dax = self.dfig.add_subplot(111)
        self.dcanvas = FigureCanvasTkAgg(self.dfig, master=right)
        self.dcanvas.get_tk_widget().configure(bg=PANEL, highlightthickness=0)
        self.dcanvas.get_tk_widget().pack(fill="both", expand=True)

        # ---- console
        con = ttk.Frame(main, style="Card.TFrame", padding=(10, 6, 10, 8)); con.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        top = ttk.Frame(con, style="Card.TFrame"); top.pack(fill="x")
        ttk.Label(top, text="ACTIVITY LOG", style="H.TLabel").pack(side="left")
        ttk.Button(top, text="Clear", style="Mini.TButton", command=lambda: self._console(clear=True)).pack(side="right")
        wrap = ttk.Frame(con, style="Card.TFrame"); wrap.pack(fill="x", pady=(5, 0))
        self.console = tk.Text(wrap, height=6, bg=INPUT, fg=GREY, bd=0, highlightthickness=0, wrap="word",
                               font=(self.mono_font, 9), state="disabled", padx=8, pady=6)
        sb = ttk.Scrollbar(wrap, command=self.console.yview); self.console.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y"); self.console.pack(side="left", fill="x", expand=True)
        for tag, color in (("ok", CYAN), ("err", RED), ("warn", AMBER), ("dim", "#7d8590"), ("time", "#4b5563")):
            self.console.tag_configure(tag, foreground=color)

        self.columnconfigure(1, weight=1); self.rowconfigure(1, weight=1)

    def _make_tree(self, parent, cols, widths, dbl, height=None) -> ttk.Treeview:
        frame = ttk.Frame(parent, style="Card.TFrame"); frame.pack(fill="both", expand=(height is None))
        tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="browse", **({"height": height} if height else {}))
        sb = ttk.Scrollbar(frame, command=tree.yview); tree.configure(yscrollcommand=sb.set)
        for c, w in zip(cols, widths):
            tree.heading(c, text=HEADERS.get(c, c.upper()), command=lambda c=c, t=tree: self._sort_tree(t, c, False))
            tree.column(c, width=w, anchor="w" if c in ("id", "type", "ip", "hostnames") else "center", stretch=True)
        sb.pack(side="right", fill="y"); tree.pack(side="left", fill="both", expand=True)
        if dbl:
            tree.bind("<Double-Button-1>", dbl)
        return tree

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self, padding=(18, 4, 18, 8)); bar.grid(row=2, column=0, columnspan=2, sticky="ew")
        ttk.Label(bar, textvariable=self.status_var, style="Sub.TLabel").pack(side="left")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=160)
        self._progress_shown = False
        ttk.Label(bar, textvariable=self.hover_var, style="Sub.TLabel").pack(side="right", padx=18)

    # ------------------------------------------------------------------ logging / history
    def log(self, msg: str) -> None:
        tag = {"[+]": "ok", "[-]": "err", "[!]": "warn", "[~]": "dim"}.get(msg.strip()[:3], None)
        self.console.configure(state="normal")
        self.console.insert("end", time.strftime("%H:%M:%S  "), "time")
        self.console.insert("end", msg + "\n", tag or ())
        self.console.see("end"); self.console.configure(state="disabled")

    def _console(self, clear: bool = False) -> None:
        if clear:
            self.console.configure(state="normal"); self.console.delete("1.0", "end"); self.console.configure(state="disabled")

    def _load_history(self) -> list:
        try:
            return json.loads(self.history_file.read_text(encoding="utf-8"))[:15]
        except (OSError, ValueError):
            return []

    def _remember(self, target: str) -> None:
        self.history = [target] + [h for h in self.history if h != target]
        self.history = self.history[:15]
        self.target_combo["values"] = self.history
        try:
            self.history_file.parent.mkdir(parents=True, exist_ok=True)
            self.history_file.write_text(json.dumps(self.history), encoding="utf-8")
        except OSError:
            pass

    def _save(self) -> None:
        try:
            self.graph.save(self.db)
        except OSError as exc:
            self.log(f"[!] Could not save graph: {exc}")

    # ------------------------------------------------------------------ background tasks
    def run_task(self, label: str, work: Callable, done: Callable) -> None:
        if self.busy:
            return
        self._set_busy(True, label)

        def target() -> None:
            try:
                res = work()
            except Exception as exc:               # report any failure to the UI thread
                self.q.put(("error", exc, done)); return
            self.q.put(("done", res, done))
        threading.Thread(target=target, daemon=True).start()

    def _set_busy(self, busy: bool, label: str = "Ready") -> None:
        self.busy = busy
        self.status_var.set(label if busy else "Ready")
        for b in self.actions:
            b.state(["disabled"] if busy else ["!disabled"])
        if busy and not self._progress_shown:
            self.progress.pack(side="right"); self.progress.start(12); self._progress_shown = True
        elif not busy and self._progress_shown:
            self.progress.stop(); self.progress.pack_forget(); self._progress_shown = False

    def _poll(self) -> None:
        try:
            while True:
                kind, *rest = self.q.get_nowait()
                if kind == "log":
                    self.log(rest[0])
                elif kind == "done":
                    res, done = rest; self._set_busy(False)
                    try:
                        done(res)
                    except Exception as exc:
                        self.log(f"[-] Internal error: {exc}")
                elif kind == "error":
                    exc, _ = rest; self._set_busy(False)
                    self.log(f"[-] Task failed: {exc}")
                    messagebox.showerror("Task failed", str(exc), parent=self)
        except queue.Empty:
            pass
        self.after(100, self._poll)

    # ------------------------------------------------------------------ actions
    def _on_target_change(self, *_) -> None:
        text = self.target_var.get().strip()
        if not text:
            self.preview_var.set("e.g. example.com or https://example.com/page"); return
        try:
            self.preview_var.set("✔ Will sweep:  " + normalize_target(text))
        except ValueError as exc:
            self.preview_var.set("✖ " + str(exc))

    def on_sweep(self) -> None:
        if self.busy:
            return
        try:
            target = normalize_target(self.target_var.get())
        except ValueError as exc:
            messagebox.showwarning("Invalid target", str(exc), parent=self); return
        try:
            limit = max(1, min(100, int(self.limit_var.get())))
        except (tk.TclError, ValueError):
            limit = 10
        self.log(f"[+] Queued OSINT sweep for {target} (limit {limit})")
        put = lambda m: self.q.put(("log", m))

        def work():
            return conduct_reconnaissance(target, limit=limit, log=put,
                                          fetcher=lambda t: fetch_ct_records(t, log=put))

        def done(result):
            ents, rels = result
            if not ents:
                self.log("[-] Sweep returned no data (CT services unavailable or no certificates found).")
                messagebox.showwarning("Sweep failed", "No intelligence was extracted.\nThe CT services may be "
                                       "unavailable, or the domain has no public certificates. Try again later.", parent=self)
                return
            r = self.graph.ingest(ents, rels); self._remember(target); self._save()
            self.log(f"[+] Sweep complete: {r.nodes_added} new assets ({r.nodes_seen} seen), {r.edges_added} new links.")
            self.refresh()
        self.run_task(f"Sweeping {target} …", work, done)

    def on_local_scan(self) -> None:
        def done(devices):
            r = self.graph.add_local_devices(GATEWAY_ID, devices); self._save()
            self.log(f"[+] Proximity scan complete: {len(devices)} neighbouring assets ({r.nodes_added} new).")
            self.refresh()
        self.log("[~] Reading local ARP cache …")
        self.run_task("Scanning local network …", scan_local_network, done)

    def on_demo(self) -> None:
        r = self.graph.merge(build_demo_graph()); self._save()
        self.log(f"[+] Demo data loaded: {r.nodes_added} new assets, {r.edges_added} new links.")
        self.refresh()

    def on_ingest(self) -> None:
        text = self._ask_text("Ingest log line", "Paste one line of intelligence text. It must contain a domain "
                              "and an IP address.", "Asset discovered: admin.example.com resolving to IP 192.0.2.5")
        if not text:
            return
        ents, rels = parse_intelligence_log(text)
        if not ents:
            messagebox.showinfo("Nothing found", "No domain + IP pair could be extracted from that line.", parent=self); return
        r = self.graph.ingest(ents, rels); self._save()
        self.log(f"[+] Ingested {r.nodes_added} new assets and {r.edges_added} link(s) from log line.")
        self.refresh()

    def on_reset(self) -> None:
        n = len(self.graph)
        if n == 0:
            messagebox.showinfo("Reset", "The graph is already empty.", parent=self); return
        if not messagebox.askyesno("Reset graph", f"Delete all {n} assets and their relationships?\n"
                                   "This cannot be undone.", icon="warning", default="no", parent=self):
            return
        self.graph.clear(); self.focus = self.selected = None; self._save()
        self.log(f"[!] Graph reset ({n} assets removed).")
        self.refresh()

    def on_export(self) -> None:
        if len(self.graph) == 0:
            messagebox.showinfo("Export", "Nothing to export yet.", parent=self); return
        folder = filedialog.askdirectory(title="Choose export folder", parent=self)
        if folder:
            export_csv(self.graph, Path(folder))
            self.log(f"[+] Exported nodes.csv, edges.csv and metrics.csv to {folder}")

    def on_save_image(self) -> None:
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".png", initialfile="network_map.png",
                                            filetypes=[("PNG image", "*.png"), ("PDF", "*.pdf"), ("SVG", "*.svg")])
        if path:
            self.fig.savefig(path, dpi=200, facecolor=BG)
            self.log(f"[+] Map saved to {path}")

    def _ask_text(self, title: str, prompt: str, example: str = "") -> Optional[str]:
        win = tk.Toplevel(self); win.title(title); win.configure(bg=PANEL); win.transient(self); win.resizable(False, False)
        box = ttk.Frame(win, style="Card.TFrame", padding=18); box.pack()
        ttk.Label(box, text=prompt, style="Card.TLabel", wraplength=480, justify="left").pack(anchor="w", pady=(0, 8))
        var = tk.StringVar(); ent = ttk.Entry(box, textvariable=var, width=70); ent.pack(fill="x")
        if example:
            ttk.Label(box, text="Example:  " + example, style="Hint.TLabel", wraplength=480).pack(anchor="w", pady=(5, 12))
        out = {"v": None}

        def ok(_=None):
            out["v"] = var.get().strip(); win.destroy()
        row = ttk.Frame(box, style="Card.TFrame"); row.pack(fill="x")
        ttk.Button(row, text="Ingest", style="Accent.TButton", command=ok).pack(side="right")
        ttk.Button(row, text="Cancel", command=win.destroy).pack(side="right", padx=8)
        win.bind("<Return>", ok); win.bind("<Escape>", lambda e: win.destroy())
        win.update_idletasks()
        x = self.winfo_rootx() + (self.winfo_width() - win.winfo_width()) // 2
        y = self.winfo_rooty() + (self.winfo_height() - win.winfo_height()) // 3
        win.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        win.grab_set(); ent.focus_set(); self.wait_window(win)
        return out["v"]

    # ------------------------------------------------------------------ refresh / drawing
    def refresh(self, fit: bool = True) -> None:
        self.view = apply_filters(self.graph.g, {k: v.get() for k, v in self.filter_vars.items()})
        if self.focus not in self.view:
            self.focus = None
        if self.selected not in self.graph.g:
            self.selected = None
        w, h = self.canvas.get_tk_widget().winfo_width(), self.canvas.get_tk_widget().winfo_height()
        self.pos = layout_components(self.view, aspect=(w / h) if w > 50 and h > 50 else 1.8)
        self.pos_ids = list(self.pos)
        self.pos_arr = np.array([self.pos[n] for n in self.pos_ids]) if self.pos_ids else np.zeros((0, 2))
        self.focus_combo["values"] = sorted(self.view.nodes)
        self.focus_var.set(self.focus or "")
        self.draw_map(fit=fit)
        self._show_profile(self.selected)
        s = analytics.summary(self.graph.g)
        clusters = s.get("components", 0)
        self.chip_var.set(f"●  {s['nodes']} assets   ·   {s['edges']} links   ·   {clusters} cluster{'s' if clusters != 1 else ''}")
        self.analytics_dirty = True
        if self.nb.index(self.nb.select()) == 1:
            self.update_analytics()

    def draw_map(self, fit: bool = True) -> None:
        lims = None if fit else (self.ax.get_xlim(), self.ax.get_ylim())
        render_graph(self.ax, self.view, self.pos, self.focus, label_size=8,
                     empty_message=EMPTY_MSG if len(self.graph) == 0 else "NO ASSETS MATCH THE ACTIVE FILTERS")
        if lims and self.pos:
            self.ax.set_xlim(*lims[0]); self.ax.set_ylim(*lims[1])
        self.canvas.draw_idle()

    def _show_profile(self, node: Optional[str]) -> None:
        self.p_list.delete(0, "end")
        if not node or node not in self.graph.g:
            self.p_body.pack_forget(); self.p_empty.pack(pady=40); return
        self.p_empty.pack_forget(); self.p_body.pack(fill="both", expand=True)
        g = self.graph.g; d = g.nodes[node]; threat = d.get("threat_level", "Unknown")
        self.p_name.configure(text=node)
        self.p_rows["Classification"].configure(text=d.get("type", "Unknown"))
        self.p_rows["Threat priority"].configure(text=threat, foreground=RED if threat == "Elevated" else GREEN if threat == "Normal" else "white")
        self.p_rows["Connections"].configure(text=str(g.degree(node)))
        for u, v, k in g.out_edges(node, keys=True):
            self.p_list.insert("end", f"→ {v}   [{k}]")
        for u, v, k in g.in_edges(node, keys=True):
            self.p_list.insert("end", f"← {u}   [{k}]")

    def _on_neighbour_dbl(self, _=None) -> None:
        sel = self.p_list.curselection()
        if sel:
            parts = self.p_list.get(sel[0]).split()
            if len(parts) >= 2:
                self.select_node(parts[1], toggle=False)

    # ------------------------------------------------------------------ selection / interaction
    def select_node(self, node: Optional[str], toggle: bool = True) -> None:
        if node is None:
            self.focus = self.selected = None
        else:
            self.selected = node
            self.focus = None if (toggle and self.focus == node) else (node if node in self.view else None)
        self.focus_var.set(self.focus or "")
        self._show_profile(self.selected); self.draw_map(fit=False)

    def clear_focus(self) -> None:
        self.select_node(None)

    def _on_focus_pick(self, _=None) -> None:
        node = self.focus_var.get()
        if node:
            self.select_node(node, toggle=False)

    def _nearest(self, event, radius: float = 16):
        if len(self.pos_ids) == 0 or event.x is None:
            return None
        pts = self.ax.transData.transform(self.pos_arr)
        d = np.hypot(pts[:, 0] - event.x, pts[:, 1] - event.y); i = int(d.argmin())
        return self.pos_ids[i] if d[i] <= radius else None

    def _on_press(self, e) -> None:
        if e.inaxes is self.ax and e.button == 1:
            self._press = (e.x, e.y, e.xdata, e.ydata); self._dragged = False

    def _on_motion(self, e) -> None:
        if self._press and e.inaxes is self.ax and e.xdata is not None:
            if self._dragged or np.hypot(e.x - self._press[0], e.y - self._press[1]) > 4:
                self._dragged = True
                dx, dy = e.xdata - self._press[2], e.ydata - self._press[3]
                x0, x1 = self.ax.get_xlim(); y0, y1 = self.ax.get_ylim()
                self.ax.set_xlim(x0 - dx, x1 - dx); self.ax.set_ylim(y0 - dy, y1 - dy)
                self.canvas.draw_idle()
            return
        node = self._nearest(e) if e.inaxes is self.ax else None
        if node:
            d = self.graph.g.nodes[node]
            self.hover_var.set(f"{node}  |  {d.get('type', '?')}  |  threat: {d.get('threat_level', '?')}  |  links: {self.graph.g.degree(node)}")
            self.canvas.get_tk_widget().configure(cursor="hand2")
        else:
            self.hover_var.set(HINT); self.canvas.get_tk_widget().configure(cursor="")

    def _on_release(self, e) -> None:
        if self._press and not self._dragged and e.button == 1:
            node = self._nearest(e)
            self.select_node(node) if node else self.select_node(None)
        self._press = None

    def _on_scroll(self, e) -> None:
        if e.inaxes is self.ax and e.xdata is not None:
            self._zoom(0.85 if e.step > 0 else 1 / 0.85, e.xdata, e.ydata)

    def _zoom(self, scale: float, cx: Optional[float] = None, cy: Optional[float] = None) -> None:
        if not self.pos:
            return
        x0, x1 = self.ax.get_xlim(); y0, y1 = self.ax.get_ylim()
        cx = (x0 + x1) / 2 if cx is None else cx; cy = (y0 + y1) / 2 if cy is None else cy
        self.ax.set_xlim(cx + (x0 - cx) * scale, cx + (x1 - cx) * scale)
        self.ax.set_ylim(cy + (y0 - cy) * scale, cy + (y1 - cy) * scale)
        self.canvas.draw_idle()

    # ------------------------------------------------------------------ analytics tab
    def _on_tab(self, _=None) -> None:
        if self.nb.index(self.nb.select()) == 1 and self.analytics_dirty:
            self.update_analytics()

    def update_analytics(self) -> None:
        g = self.graph.g
        s = analytics.summary(g)
        fmt = {"density": "{:.3f}", "mean_degree": "{:.2f}"}
        for key, lab in self.tiles.items():
            lab.configure(text=fmt.get(key, "{}").format(s[key]) if key in s else "0")
        for t in (self.m_tree, self.s_tree):
            t.delete(*t.get_children())
        if len(self.graph):
            for r in analytics.node_metrics(g).itertuples():
                self.m_tree.insert("", "end", values=(r.id, r.type, r.threat_level, r.degree,
                                                      f"{r.betweenness:.4f}", f"{r.pagerank:.4f}", r.component))
            for r in analytics.shared_infrastructure(g).itertuples():
                if r.host_count > 1:
                    self.s_tree.insert("", "end", values=(r.ip, r.host_count, ", ".join(r.hostnames)))
        ax = self.dax; ax.clear(); ax.set_facecolor(PANEL)
        dd = analytics.degree_distribution(g)
        if not dd.empty:
            ax.bar(dd.degree, dd["count"], color=CYAN, width=0.7)
            ax.set_xticks(dd.degree)
        ax.set_xlabel("degree k", color=GREY, fontsize=8); ax.set_ylabel("nodes", color=GREY, fontsize=8)
        ax.tick_params(colors=GREY, labelsize=8)
        for sp in ax.spines.values():
            sp.set_color(BORDER)
        self.dfig.tight_layout(); self.dcanvas.draw_idle()
        self.analytics_dirty = False

    def _sort_tree(self, tree: ttk.Treeview, col: str, reverse: bool) -> None:
        def key(item):
            try:
                return (0, float(item[0]))
            except ValueError:
                return (1, item[0].lower())
        items = sorted(((tree.set(i, col), i) for i in tree.get_children("")), key=key, reverse=reverse)
        for idx, (_, i) in enumerate(items):
            tree.move(i, "", idx)
        tree.heading(col, command=lambda: self._sort_tree(tree, col, not reverse))

    def _on_tree_dbl(self, _=None) -> None:
        sel = self.m_tree.selection()
        if sel:
            node = self.m_tree.item(sel[0], "values")[0]
            self.nb.select(0); self.update_idletasks()
            if node not in self.view:               # hidden by a filter -> show everything
                for k, v in self.filter_vars.items():
                    v.set(k != "critical_only")
            self.select_node(node, toggle=False)

    def _on_close(self) -> None:
        self._save(); self.destroy()


def run(db_path: str = DEFAULT_DB) -> None:
    App(db_path).mainloop()
