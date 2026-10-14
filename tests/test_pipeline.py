"""Tests for parsing, active-check helpers, nmap multi-host, dedup, and the
graph correlation (per-hypothesis priority end to end)."""
import base64
import unittest

import main
from analyzer import analyze, _dedup_prefixes
from dir_bruteforce import _parse_ferox_line
from fingerprinter import (_looks_serialized, _classify_cors, _stack_detected,
                           _candidate_schemes, _build_url, CORS_PROBE_ORIGIN)
from graph_builder import build_graph
from nmap_parser import parse_nmap_xml


class TestParsePorts(unittest.TestCase):
    def test_list_and_range(self):
        self.assertEqual(main._parse_ports("80,443,8000-8002"), [80, 443, 8000, 8001, 8002])

    def test_invalid_exits(self):
        with self.assertRaises(SystemExit):
            main._parse_ports("8o")

    def test_reversed_range_skipped(self):
        self.assertEqual(main._parse_ports("100-1"), [])


class TestFeroxParse(unittest.TestCase):
    def test_response_kept(self):
        e = _parse_ferox_line('{"type":"response","status":200,"url":"http://x/a","path":"/a","content_length":5}')
        self.assertEqual(e["path"], "/a")

    def test_non_found_status_dropped(self):
        self.assertIsNone(_parse_ferox_line('{"type":"response","status":404,"path":"/a"}'))

    def test_statistics_dropped(self):
        self.assertIsNone(_parse_ferox_line('{"type":"statistics","status":0}'))


class TestSerializedDetection(unittest.TestCase):
    def test_php_raw(self):
        self.assertEqual(_looks_serialized('O:4:"User":1:{s:4:"role";s:4:"user";}'), "PHP")

    def test_java_b64(self):
        self.assertEqual(_looks_serialized(base64.b64encode(b"\xac\xed\x00\x05x").decode()), "Java")

    def test_java_prefix(self):
        self.assertEqual(_looks_serialized("rO0ABXNyABU"), "Java")

    def test_pickle_b64(self):
        self.assertEqual(_looks_serialized(base64.b64encode(b"\x80\x04\x95abc").decode()), "Python pickle")

    def test_random_not_flagged(self):
        self.assertIsNone(_looks_serialized(base64.b64encode(b"just a normal session id 123456").decode()))


class TestCorsClassify(unittest.TestCase):
    def test_reflected_with_creds(self):
        c = _classify_cors({"access-control-allow-origin": CORS_PROBE_ORIGIN,
                            "access-control-allow-credentials": "true"})
        self.assertTrue(c["reflects_origin"] and c["credentials"])

    def test_null(self):
        self.assertTrue(_classify_cors({"access-control-allow-origin": "null"})["null_origin"])

    def test_absent(self):
        self.assertIsNone(_classify_cors({}))


class TestStackDetected(unittest.TestCase):
    def test_generic_server_not_detected(self):
        self.assertFalse(_stack_detected({"server": "nginx/1.24.0"}, []))

    def test_framework_header_detected(self):
        self.assertTrue(_stack_detected({"x-powered-by": "Express"}, []))

    def test_framework_cookie_detected(self):
        self.assertTrue(_stack_detected({}, ["PHPSESSID"]))


class TestScheme(unittest.TestCase):
    def test_hint_wins(self):
        self.assertEqual(_candidate_schemes(8080, "https"), ["https"])

    def test_default_by_port_with_fallback(self):
        self.assertEqual(_candidate_schemes(443, None), ["https", "http"])
        self.assertEqual(_candidate_schemes(8080, None), ["http", "https"])

    def test_build_url_scheme(self):
        self.assertEqual(_build_url("h", 8080, scheme="https"), "https://h:8080/")
        self.assertTrue(_build_url("h", 443).startswith("https://"))


class TestHeaderParse(unittest.TestCase):
    def test_header_and_cookie(self):
        h = main._parse_headers(["Authorization: Bearer x", "X-Env: dev"], "s=1; t=2")
        self.assertEqual(h["Authorization"], "Bearer x")
        self.assertEqual(h["X-Env"], "dev")
        self.assertEqual(h["Cookie"], "s=1; t=2")

    def test_malformed_header_skipped(self):
        self.assertEqual(main._parse_headers(["no-colon-here"], None), {})


class TestTargetValidation(unittest.TestCase):
    def test_valid_targets(self):
        for t in ("target.thm", "10.0.0.1", "app.example.com", "host-1_test"):
            self.assertEqual(main._target_arg(t), t)

    def test_rejects_argument_injection_and_paths(self):
        import argparse
        for bad in ("-oX/tmp/x", "--script=evil", "a b", "../etc", "a/b", "a;b", "", "  "):
            with self.assertRaises(argparse.ArgumentTypeError):
                main._target_arg(bad)


class TestSafeName(unittest.TestCase):
    def test_keeps_hostnames(self):
        self.assertEqual(main._safe_name("target.thm"), "target.thm")
        self.assertEqual(main._safe_name("10.0.0.1"), "10.0.0.1")

    def test_no_path_traversal(self):
        for t in ("..", "../etc", "/etc/passwd", "...."):
            n = main._safe_name(t)
            self.assertNotIn("/", n)
            self.assertFalse(n.startswith("."))


class TestSitemapGuard(unittest.TestCase):
    def test_rejects_dtd_entities(self):
        from passive import _locs_from_sitemap
        payload = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "AAAA">]>'
                   '<urlset><url><loc>http://x/&a;</loc></url></urlset>')
        self.assertEqual(_locs_from_sitemap(payload), [])

    def test_parses_clean_sitemap(self):
        from passive import _locs_from_sitemap
        payload = ('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                   '<url><loc>http://x/a</loc></url></urlset>')
        self.assertEqual(_locs_from_sitemap(payload), ["http://x/a"])


class TestNmapMultiHost(unittest.TestCase):
    XML = """<?xml version="1.0"?><nmaprun>
      <host><address addr="10.0.0.1"/><ports>
        <port portid="80"><state state="open"/><service name="http"/></port></ports></host>
      <host><address addr="10.0.0.2"/><ports>
        <port portid="5432"><state state="open"/><service name="postgresql"/></port></ports></host>
    </nmaprun>"""

    def test_hosts_preserved(self):
        import tempfile, os
        fd, p = tempfile.mkstemp(suffix=".xml")
        os.write(fd, self.XML.encode()); os.close(fd)
        try:
            d = parse_nmap_xml(p)
        finally:
            os.unlink(p)
        self.assertEqual(len(d["hosts"]), 2)
        self.assertEqual(d["address"], "10.0.0.1")          # flat = first host
        self.assertEqual([x["port"] for x in d["ports"]], [80])  # not blended
        self.assertEqual([x["port"] for x in d["hosts"][1]["ports"]], [5432])


class TestDedup(unittest.TestCase):
    def test_prefix_dropped(self):
        out = _dedup_prefixes(["unserialize", "unserialize (PHPGGC)", "SQLi"])
        self.assertNotIn("unserialize", out)
        self.assertIn("unserialize (PHPGGC)", out)
        self.assertIn("SQLi", out)


class TestAnalyzeFindings(unittest.TestCase):
    def _fp(self, **over):
        fp = {"headers": {}, "cookies": [], "cookie_flags": [], "secure_scheme": False,
              "waf": None, "cors": None, "deserialization": [], "interesting_paths": [],
              "security_headers_missing": [], "error": None}
        fp.update(over)
        return fp

    def test_cors_high(self):
        a = analyze(self._fp(cors={"reflects_origin": True, "credentials": True,
                                   "null_origin": False, "wildcard": False}))
        self.assertTrue(any("CORS" in v for v in a["vulns_by_priority"]["HIGH"]))

    def test_deser_high(self):
        a = analyze(self._fp(deserialization=[{"type": "Java", "where": "cookie X"}]))
        self.assertTrue(any("deserialization" in v for v in a["vulns_by_priority"]["HIGH"]))


class TestGraphPerHypPriority(unittest.TestCase):
    def test_hyp_nodes_keep_own_priority(self):
        dirs = [{"target": "http://h:80", "found": [{"path": "/.git/config", "status": 200}]}]
        g = build_graph("h", dirs=dirs)
        prios = {n["label"]: n.get("priority") for n in g["nodes"] if n["type"] == "vuln"}
        # Git disclosure is CRITICAL, Configuration disclosure is HIGH — not all CRITICAL.
        self.assertIn("CRITICAL", prios.values())
        self.assertIn("HIGH", prios.values())


if __name__ == "__main__":
    unittest.main()
