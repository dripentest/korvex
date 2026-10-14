"""Core matching-engine tests: parsing, keyword collisions, per-hypothesis
priority, id-segment heuristics, params, and stack refinement."""
import unittest

from signatures import match_path, match_params, refine_hypotheses, _has_id_segment


class TestMatchPath(unittest.TestCase):
    def test_basic_keyword(self):
        m = match_path("/login")
        self.assertIsNotNone(m)
        self.assertEqual(m["priority"], "HIGH")

    def test_no_match_returns_none(self):
        self.assertIsNone(match_path("/totally-benign-xyz"))

    def test_parsing_edge_cases(self):
        # case, trailing slash, fragment, double slash, query, unicode
        for p in ("/ADMIN/Config", "/admin/", "/admin#x", "//admin", "/café/login"):
            self.assertIsNotNone(match_path(p), p)
        # query is parsed off the path
        self.assertIsNotNone(match_path("/admin?debug=1"))

    def test_collision_guard_compose(self):
        # 'compose' must not fire inside 'composer.json' / 'docker-compose.yml'
        for p in ("/composer.json", "/composer.lock", "/docker-compose.yml"):
            m = match_path(p)
            hyps = m["hypotheses"] if m else []
            self.assertFalse(any("template injection" in h.lower() for h in hyps), p)
        # but a real compose endpoint still does
        self.assertTrue(any("template injection" in h.lower()
                            for h in match_path("/compose")["hypotheses"]))

    def test_collision_guard_feed_atom(self):
        self.assertFalse(any("XXE" in h for h in (match_path("/feedback") or {"hypotheses": []})["hypotheses"]))

    def test_per_hypothesis_priority(self):
        # /.git/config: config hyps are HIGH, git hyp is CRITICAL — distinct.
        m = match_path("/.git/config")
        self.assertIn("hyp_priorities", m)
        self.assertEqual(len(m["hyp_priorities"]), len(m["hypotheses"]))
        self.assertIn("CRITICAL", m["hyp_priorities"])
        self.assertIn("HIGH", m["hyp_priorities"])

    def test_id_segment_year_excluded(self):
        self.assertFalse(_has_id_segment("/report/2024"))
        self.assertFalse(_has_id_segment("/news/1999"))

    def test_id_segment_real_ids(self):
        self.assertTrue(_has_id_segment("/user/1337"))
        self.assertTrue(_has_id_segment("/x/0000000000000000abcd"))  # 20 hex
        self.assertTrue(_has_id_segment("/a/550e8400-e29b-41d4-a716-446655440000"))

    def test_id_segment_short_hex_slug_not_id(self):
        self.assertFalse(_has_id_segment("/post/deadbeefcafe"))  # 12 hex < 16


class TestMatchParams(unittest.TestCase):
    def test_ssrf_param(self):
        hits = match_params("img_url=http://x")
        self.assertTrue(any("SSRF" in h for h, _ in hits))

    def test_oauth_param(self):
        hits = match_params("response_type=token")
        self.assertTrue(any("OAuth" in h for h, _ in hits))

    def test_array_param_normalised(self):
        self.assertTrue(match_params("q[]=1"))


class TestRefine(unittest.TestCase):
    def test_refine_python_jinja(self):
        hyps = ["Server-side template injection (RCE)"]
        out, prios = refine_hypotheses(hyps, ["HIGH"], "python")
        self.assertIn("Jinja2", out[0])
        self.assertEqual(prios, ["HIGH"])

    def test_refine_preserves_alignment(self):
        hyps = ["Server-side template injection (RCE)", "Stored XSS"]
        out, prios = refine_hypotheses(hyps, ["HIGH", "LOW"], "php")
        self.assertEqual(len(out), len(prios))
        self.assertIn("Twig", out[0])

    def test_no_kind_is_noop(self):
        hyps, prios = ["a"], ["LOW"]
        self.assertEqual(refine_hypotheses(hyps, prios, None), (["a"], ["LOW"]))


if __name__ == "__main__":
    unittest.main()
