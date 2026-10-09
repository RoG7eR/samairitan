import os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import matplotlib
matplotlib.use("Agg")
import requests

from samaritan import analytics
from samaritan.graph_store import AssetGraph
from samaritan.local_scanner import parse_arp_output
from samaritan.models import Asset, Relationship
from samaritan.osint import conduct_reconnaissance, extract_subdomains
from samaritan.parser import parse_intelligence_log
from samaritan.sample_data import build_demo_graph
from samaritan.visualizer import NetworkMap, apply_filters

ARP_LINUX = """? (192.168.1.1) at aa:bb:cc:dd:ee:01 [ether] on eth0
? (192.168.1.255) at ff:ff:ff:ff:ff:ff [ether] on eth0
gateway (192.168.1.7) at aa:bb:cc:dd:ee:02 [ether] on eth0"""
ARP_WIN = """Interface: 192.168.1.5 --- 0x7
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-01     dynamic
  224.0.0.22            01-00-5e-00-00-16     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static"""


class ParserTests(unittest.TestCase):
    def test_log_line(self):
        e, r = parse_intelligence_log("Asset discovered: admin-portal.target.com resolving to IP 192.168.1.50")
        self.assertEqual([x.id for x in e], ["admin-portal.target.com", "192.168.1.50"])
        self.assertEqual(r, [Relationship("admin-portal.target.com", "192.168.1.50", "RESOLVES_TO")])

    def test_no_match(self):
        self.assertEqual(parse_intelligence_log("nothing here"), ([], []))


class OsintTests(unittest.TestCase):
    RECORDS = [{"name_value": "WWW.Example.org\n*.example.org"}, {"name_value": "api.example.org"},
               {"name_value": "www.example.org"}]

    def test_extract(self):
        self.assertEqual(extract_subdomains(self.RECORDS), ["www.example.org", "api.example.org"])

    def test_sweep_with_mocks(self):
        def resolver(h):
            if h.startswith("api"): raise OSError("nx")
            return "203.0.113.1"
        e, r = conduct_reconnaissance("example.org", fetcher=lambda t: self.RECORDS,
                                      resolver=resolver, log=lambda _: None)
        ids = {a.id for a in e}
        self.assertEqual(ids, {"example.org", "www.example.org", "api.example.org", "203.0.113.1"})
        self.assertIn(Relationship("www.example.org", "203.0.113.1", "RESOLVES_TO"), r)
        self.assertEqual(sum(x.type == "OWNS" for x in r), 2)

    def test_failure_returns_empty(self):
        def boom(_): raise requests.ConnectionError("down")
        self.assertEqual(conduct_reconnaissance("x.org", fetcher=boom, log=lambda _: None), ([], []))

    def test_limit(self):
        recs = [{"name_value": f"h{i}.example.org"} for i in range(30)]
        e, _ = conduct_reconnaissance("example.org", limit=5, fetcher=lambda t: recs,
                                      resolver=lambda h: "192.0.2.1", log=lambda _: None)
        self.assertEqual(sum(a.type == "Subdomain" for a in e), 5)


class FetchFallbackTests(unittest.TestCase):
    class R:
        def __init__(self, code, data=None):
            self.status_code, self._d, self.url = code, data, "u"
        def raise_for_status(self):
            if self.status_code >= 400: raise requests.HTTPError("bad", response=self)
        def json(self): return self._d

    def test_retry_then_success(self):
        from unittest import mock
        from samaritan import osint
        seq = [self.R(502), self.R(200, [{"name_value": "a.example.org"}])]
        with mock.patch.object(osint.requests, "get", side_effect=seq), mock.patch.object(osint.time, "sleep"):
            self.assertEqual(osint.fetch_crtsh("example.org", log=lambda _: None)[0]["name_value"], "a.example.org")

    def test_fallback_to_certspotter(self):
        from unittest import mock
        from samaritan import osint
        def fake_get(url, **kw):
            if "crt.sh" in url: return self.R(502)
            return self.R(200, [{"dns_names": ["x.example.org", "y.example.org"]}])
        with mock.patch.object(osint.requests, "get", side_effect=fake_get), mock.patch.object(osint.time, "sleep"):
            recs = osint.fetch_ct_records("example.org", log=lambda _: None)
        self.assertEqual(osint.extract_subdomains(recs), ["x.example.org", "y.example.org"])


class ArpTests(unittest.TestCase):
    def test_linux(self):
        self.assertEqual([d.id for d in parse_arp_output(ARP_LINUX)], ["192.168.1.1", "192.168.1.7"])

    def test_windows(self):
        self.assertEqual([d.id for d in parse_arp_output(ARP_WIN)], ["192.168.1.5", "192.168.1.1"])


class GraphTests(unittest.TestCase):
    def test_merge_is_idempotent_and_on_create_only(self):
        g = AssetGraph()
        self.assertTrue(g.merge_asset(Asset("a", "Domain", "Elevated")))
        self.assertFalse(g.merge_asset(Asset("a", "Other", "Normal")))
        self.assertEqual(g.g.nodes["a"]["type"], "Domain")
        g.merge_asset(Asset("b"))
        self.assertTrue(g.merge_relationship(Relationship("a", "b", "OWNS")))
        self.assertFalse(g.merge_relationship(Relationship("a", "b", "OWNS")))
        self.assertFalse(g.merge_relationship(Relationship("a", "zzz", "OWNS")))   # MATCH fails -> no edge
        self.assertEqual(g.g.number_of_edges(), 1)

    def test_roundtrip(self):
        g = build_demo_graph()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "g.json"); g.save(p); h = AssetGraph.load(p)
        self.assertEqual(set(g.g.nodes), set(h.g.nodes))
        self.assertEqual(g.g.number_of_edges(), h.g.number_of_edges())


class AnalyticsTests(unittest.TestCase):
    def setUp(self): self.g = build_demo_graph().g

    def test_summary(self):
        s = analytics.summary(self.g)
        self.assertEqual(s["nodes"], len(self.g)); self.assertEqual(s["components"], 3)

    def test_metrics_columns_and_hub(self):
        m = analytics.node_metrics(self.g)
        self.assertEqual(len(m), len(self.g))
        self.assertIn(m.iloc[0]["id"], set(self.g.nodes))
        self.assertAlmostEqual(m["pagerank"].sum(), 1.0, places=6)

    def test_shared_infra(self):
        s = analytics.shared_infrastructure(self.g)
        self.assertEqual(s.iloc[0]["ip"], "203.0.113.10"); self.assertEqual(s.iloc[0]["host_count"], 3)

    def test_laplacian_zero_eigs_equal_components(self):
        w = analytics.laplacian_spectrum(self.g)
        self.assertEqual(int((w < 1e-9).sum()), analytics.summary(self.g)["components"])

    def test_blast_radius(self):
        b = analytics.blast_radius(self.g, "example.org")
        self.assertEqual(b.loc[b.id == "203.0.113.10", "hops"].iloc[0], 2)

    def test_degree_distribution_sums_to_one(self):
        self.assertAlmostEqual(analytics.degree_distribution(self.g)["fraction"].sum(), 1.0)

    def test_empty_graph(self):
        e = AssetGraph().g
        self.assertEqual(analytics.summary(e)["nodes"], 0); self.assertTrue(analytics.node_metrics(e).empty)


class VisualTests(unittest.TestCase):
    def test_filters(self):
        g = build_demo_graph().g
        self.assertTrue(all(d["type"] != "Infrastructure" for _, d in
                            apply_filters(g, {"show_infrastructure": False}).nodes(data=True)))
        crit = apply_filters(g, {"critical_only": True})
        self.assertTrue(all(d["threat_level"] == "Elevated" for _, d in crit.nodes(data=True)))

    def test_render_and_focus(self):
        nm = NetworkMap(build_demo_graph().g, focus="example.org")
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.png"); nm.save(p); self.assertGreater(os.path.getsize(p), 10_000)


class UtilsTests(unittest.TestCase):
    def test_normalize_urls(self):
        from samaritan.utils import normalize_target as n
        self.assertEqual(n("https://www.Example.com:8443/a/b?q=1#x"), "example.com")
        self.assertEqual(n("  Example.COM. "), "example.com")
        self.assertEqual(n("sub.domain.co.uk/path"), "sub.domain.co.uk")
        self.assertEqual(n("http://user:pw@test-corp.io/"), "test-corp.io")

    def test_normalize_rejects(self):
        from samaritan.utils import normalize_target as n
        for bad in ("", "   ", "not a domain", "localhost", "192.168.1.1", "http://", "a..b.com", "-bad-.com"):
            with self.assertRaises(ValueError, msg=bad):
                n(bad)


class MergeTests(unittest.TestCase):
    def test_merge_is_idempotent(self):
        a = AssetGraph(); a.merge_asset(Asset("keep", "Domain", "Elevated"))
        b = build_demo_graph()
        r1 = a.merge(b); r2 = a.merge(b)
        self.assertEqual(r1.nodes_added, len(b)); self.assertEqual(r2.nodes_added, 0)
        self.assertEqual(r2.edges_added, 0); self.assertIn("keep", a.g)


@unittest.skipUnless(os.environ.get("SAMARITAN_GUI_TEST"), "set SAMARITAN_GUI_TEST=1 (needs a display)")
class GuiSmokeTests(unittest.TestCase):
    def test_gui_flow(self):
        from unittest import mock
        from tkinter import messagebox
        from samaritan import gui
        with tempfile.TemporaryDirectory() as d:
            app = gui.App(os.path.join(d, "g.json"))
            try:
                app.on_demo(); app.update()
                self.assertEqual(len(app.graph), 21)
                app.select_node("203.0.113.10"); self.assertEqual(app.focus, "203.0.113.10")
                app.select_node("203.0.113.10"); self.assertIsNone(app.focus)          # toggle off
                app.filter_vars["show_infrastructure"].set(False); app.update()
                self.assertTrue(all(app.graph.g.nodes[n]["type"] != "Infrastructure" for n in app.view))
                app.filter_vars["show_infrastructure"].set(True)
                app.nb.select(1); app.update(); self.assertEqual(len(app.m_tree.get_children()), 21)
                with mock.patch.object(messagebox, "askyesno", return_value=False):
                    app.on_reset()
                self.assertEqual(len(app.graph), 21)                                     # cancelled
                with mock.patch.object(messagebox, "askyesno", return_value=True):
                    app.on_reset()
                self.assertEqual(len(app.graph), 0)
            finally:
                app.destroy()


if __name__ == "__main__":
    unittest.main()
