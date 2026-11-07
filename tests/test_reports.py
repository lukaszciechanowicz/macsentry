import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "skills/macsentry/scripts"))
import extension_advisories
import html_report


class ReportTests(unittest.TestCase):
    def test_untrusted_advisory_text_is_escaped_and_patched_is_separate(self):
        data = {"homebrew_vulnerabilities": {"data": {"complete": False, "findings": [{
            "formula": "<script>alert(1)</script>", "version": "1",
            "vulnerabilities": [{"id": "CVE-2026-1000", "summary": "<img src=x>"}],
            "patched": [{"id": "CVE-2026-2000"}]
        }]}}}
        page = html_report.render(data)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertNotIn("<img src=x>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertLess(page.index("CVE-2026-1000"), page.index("Patched or resolved"))
        self.assertGreater(page.index("CVE-2026-2000"), page.index("Patched or resolved"))
        self.assertIn("Incomplete or unknown", page)

    def test_unavailable_homebrew_is_not_reported_as_clean(self):
        page = html_report.render({})
        self.assertIn("Homebrew advisory results were not available", page)
        self.assertIn("Not assessed", page)
        self.assertNotIn("No open Homebrew advisory records returned", page)

    def test_lookup_errors_and_unverified_candidates_remain_distinct(self):
        inventory = {"firefox": {"profiles": [{"profile": "/private/profile", "extensions": [
            {"id": "first", "name": "Example", "version": "1.2"},
            {"id": "second", "name": "Example", "version": None},
            {"id": "builtin@mozilla.org", "name": "Built-in", "version": "1"}
        ]}]}}
        response = {"total_results": 1, "truncated": False,
                    "candidates": [{"id": "CVE-2026-1000", "description": "Candidate"}]}
        with patch.object(extension_advisories, "request_nvd", return_value=response) as request:
            results = extension_advisories.assess(inventory)["results"]
        self.assertEqual(request.call_count, 1)
        self.assertEqual(results[0]["status"], "potential matches")
        self.assertIn("version unknown", results[1]["version_warning"])
        self.assertEqual(results[1]["status"], "not assessed")
        self.assertEqual(results[2]["status"], "not assessed")
        self.assertNotIn("/private/profile", request.call_args.args[0])

    def test_version_comparison_is_conservative(self):
        candidate = {"configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True, "criteria": "cpe:2.3:a:vendor:example:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "1.2", "versionEndExcluding": "2.0"
        }]}]}]}
        compare = extension_advisories.cpe_version_range
        self.assertTrue(compare(candidate, "Example", "1.2.0").startswith("within"))
        self.assertTrue(compare(candidate, "Example", "2.0").startswith("outside"))
        self.assertEqual(compare(candidate, "Other", "1.2"), "unknown")
        self.assertEqual(compare(candidate, "Example", "1.2beta"), "unknown")

    def test_nvd_failure_is_not_assessed(self):
        inventory = {"chrome": {"profiles": [{"extensions": [{"name": "Example", "version": "1"}]}]}}
        with patch.object(extension_advisories, "request_nvd", side_effect=OSError("offline")):
            result = extension_advisories.assess(inventory)["results"][0]
        self.assertEqual(result["status"], "not assessed")
        self.assertIn("offline", result["reason"])


if __name__ == "__main__":
    unittest.main()
