import json
import os
import tempfile
import unittest

from modules.scoring import Finding, calculate_score, verdict_for
from modules.reporting import save_report, render_report, _safe_name


def f(check="c", cat="network", trig=True, w=0.5, conf=1.0):
    return Finding(check, cat, trig, w, f"reason for {check}", conf)


class ScoringTests(unittest.TestCase):
    def test_no_findings_is_zero(self):
        r = calculate_score([])
        self.assertEqual(r.likelihood_pct, 0.0)
        self.assertEqual(r.contributions, [])

    def test_untriggered_findings_do_not_count(self):
        r = calculate_score([f(trig=False, w=1.0)])
        self.assertEqual(r.likelihood_pct, 0.0)
        self.assertEqual(r.checks_run, 1)

    def test_single_finding(self):
        r = calculate_score([f(w=0.6)])
        self.assertEqual(r.likelihood_pct, 60.0)

    def test_noisy_or_combines_and_never_exceeds_100(self):
        r = calculate_score([f("a", w=0.5), f("b", w=0.5)])
        self.assertEqual(r.likelihood_pct, 75.0)
        many = calculate_score([f(str(i), w=0.9) for i in range(20)])
        self.assertLessEqual(many.likelihood_pct, 100.0)

    def test_confidence_reduces_strength(self):
        r = calculate_score([f(w=0.8, conf=0.5)])
        self.assertEqual(r.likelihood_pct, 40.0)

    def test_out_of_range_values_are_clamped(self):
        r = calculate_score([f(w=5.0, conf=-2.0)])
        self.assertEqual(r.likelihood_pct, 0.0)

    def test_bad_category_rejected(self):
        with self.assertRaises(ValueError):
            Finding("x", "wifi", True, 0.5, "bad")

    def test_contributions_sorted_strongest_first(self):
        r = calculate_score([f("weak", w=0.1), f("strong", w=0.9)])
        self.assertEqual(r.contributions[0]["check"], "strong")

    def test_category_split(self):
        r = calculate_score([f("n", "network", w=0.5), f("h", "host", w=0.2)])
        self.assertEqual(r.category_pct["network"], 50.0)
        self.assertEqual(r.category_pct["host"], 20.0)

    def test_verdict_bands(self):
        self.assertIn("UNLIKELY", verdict_for(0))
        self.assertIn("POSSIBLY", verdict_for(25))
        self.assertIn("LIKELY a", verdict_for(50))
        self.assertIn("VERY LIKELY", verdict_for(100))


class ReportingTests(unittest.TestCase):
    def test_save_report_writes_labelled_json_and_txt(self):
        findings = [f(w=0.7)]
        result = calculate_score(findings)
        with tempfile.TemporaryDirectory() as tmp:
            jpath, tpath = save_report("127.0.0.1", result, findings, tmp)
            self.assertTrue(os.path.exists(jpath) and os.path.exists(tpath))
            with open(jpath, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertIn("AUTHORISED", data["label"])
            self.assertEqual(data["result"]["likelihood_pct"], 70.0)

    def test_target_cannot_escape_output_dir(self):
        name = _safe_name("../../etc/passwd")
        self.assertNotIn("/", name)
        self.assertFalse(name.startswith("."))

    def test_render_report_mentions_verdict(self):
        text = render_report("localhost", calculate_score([f(w=0.9)]))
        self.assertIn("VERY LIKELY", text)


if __name__ == "__main__":
    unittest.main()
