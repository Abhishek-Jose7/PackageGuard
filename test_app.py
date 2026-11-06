"""
test_app.py - Automated Unit & Integration Tests for PackageGuard
================================================================
Verifies that:
1. Flask routes respond with 200 OK
2. SQLite database creates tables and stores records
3. Package scanner runs and scores correctly
4. Error conditions (404 package, empty input) return clear error messages without 500s
5. History viewing, report export, and clearing work as expected
6. MITRE ATT&CK scoring engine correctly computes category vector scores
"""

import unittest
from app import app, init_db, get_db_connection, get_recent_scans
import scanner


class PackageGuardTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_01_index_page_loads(self):
        """Verify home page loads successfully with correct title & telemetry stats."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"PackageGuard", response.data)
        self.assertIn(b"Supply Chain Risk Scanner", response.data)
        self.assertIn(b"Recent Audit History", response.data)
        self.assertIn(b"Packages Inspected", response.data)

    def test_02_empty_package_validation(self):
        """Verify submitting empty package name returns error message."""
        response = self.client.post("/", data={"package_name": "", "ecosystem": "pypi"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Package name cannot be empty", response.data)

    def test_03_invalid_package_404_handled_gracefully(self):
        """Verify non-existent package returns graceful 404 message without stack trace."""
        response = self.client.post("/", data={
            "package_name": "this-pkg-definitely-does-not-exist-9912",
            "ecosystem": "pypi"
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"was not found in the PYPI registry", response.data)

    def test_04_successful_scan_and_persistence(self):
        """Verify scan saves to database and displays verdict badge & MITRE metrics."""
        mock_result = {
            "success": True,
            "package": "test-pkg",
            "ecosystem": "pypi",
            "score": 0,
            "verdict": "LOW RISK",
            "badge_class": "low",
            "summary": "No malicious indicators found.",
            "issues_count": 0,
            "category_scores": {
                "Initial Access": 0,
                "Execution & Hooks": 0,
                "Evasion & Obfuscation": 0,
                "Data Exfiltration": 0,
            },
            "flagged_rules": [],
            "audit_report_md": "# Security Audit Report: test-pkg\nVerdict: LOW RISK",
            "raw_json": {"package": "test-pkg", "issues": 0},
            "raw_json_str": '{"package": "test-pkg", "issues": 0}',
        }

        from unittest.mock import patch
        with patch("scanner.scan_package", return_value=mock_result):
            response = self.client.post("/", data={
                "package_name": "test-pkg",
                "ecosystem": "pypi"
            })
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"test-pkg", response.data)
            self.assertIn(b"LOW RISK", response.data)
            self.assertIn(b"0", response.data)

            # Check that it exists in SQLite DB
            scans = get_recent_scans(5)
            self.assertTrue(any(s["package_name"] == "test-pkg" for s in scans))

    def test_05_view_historical_scan(self):
        """Verify clicking a historical scan loads its full details."""
        scans = get_recent_scans(1)
        self.assertTrue(len(scans) > 0)
        scan_id = scans[0]["id"]
        response = self.client.get(f"/scan/{scan_id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"test-pkg", response.data)
        self.assertIn(b"LOW RISK", response.data)

    def test_06_export_security_report(self):
        """Verify downloading formal Markdown audit report."""
        scans = get_recent_scans(1)
        self.assertTrue(len(scans) > 0)
        scan_id = scans[0]["id"]
        response = self.client.get(f"/export/{scan_id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security Audit Report", response.data)
        self.assertIn(b"test-pkg", response.data)

    def test_07_clear_history(self):
        """Verify clearing history resets the database."""
        response = self.client.post("/clear-history", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        scans = get_recent_scans(5)
        self.assertEqual(len(scans), 0)

    def test_08_scoring_logic_and_mitre_breakdown(self):
        """Verify scoring logic thresholds, weights, and category vectors directly."""
        # 1. Clean
        score, verdict, badge, summary, cats = scanner.compute_risk_score([])
        self.assertEqual(score, 0)
        self.assertEqual(verdict, "LOW RISK")
        self.assertEqual(badge, "low")
        self.assertEqual(cats["Initial Access"], 0)

        # 2. Medium threat with Evasion category
        med_rules = [{"severity": "Medium", "weight": 18, "category": "Evasion & Obfuscation"}]
        score_med, verdict_med, badge_med, _, cats_med = scanner.compute_risk_score(med_rules)
        self.assertEqual(score_med, 18)
        self.assertEqual(verdict_med, "LOW RISK")
        self.assertEqual(cats_med["Evasion & Obfuscation"], 18)

        # 3. High threat with Exfiltration category
        high_rules = [{"severity": "High", "weight": 35, "category": "Data Exfiltration"}]
        score_high, verdict_high, badge_high, _, cats_high = scanner.compute_risk_score(high_rules)
        self.assertGreaterEqual(score_high, 35)
        self.assertEqual(verdict_high, "MEDIUM RISK")
        self.assertEqual(cats_high["Data Exfiltration"], 35)

        # 4. Critical / High score
        crit_rules = [
            {"severity": "High", "weight": 35, "category": "Execution & Hooks"},
            {"severity": "High", "weight": 35, "category": "Data Exfiltration"},
            {"severity": "Medium", "weight": 18, "category": "Initial Access"},
        ]
        score_crit, verdict_crit, badge_crit, _, cats_crit = scanner.compute_risk_score(crit_rules)
        self.assertEqual(score_crit, 88)
        self.assertEqual(verdict_crit, "HIGH RISK")
        self.assertEqual(badge_crit, "high")
        self.assertEqual(cats_crit["Execution & Hooks"], 35)
        self.assertEqual(cats_crit["Data Exfiltration"], 35)
        self.assertEqual(cats_crit["Initial Access"], 18)

    def test_09_investigate_author_routes(self):
        """Verify author OSINT page and JSON API load successfully."""
        # Web page
        response = self.client.get("/investigate-author?username=kennethreitz")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Maintainer Threat Intelligence Lab", response.data)
        self.assertIn(b"kennethreitz", response.data)

        # JSON API
        api_res = self.client.get("/api/osint/kennethreitz")
        self.assertEqual(api_res.status_code, 200)
        json_data = api_res.get_json()
        self.assertEqual(json_data["username"], "kennethreitz")
        self.assertIn("reputation_score", json_data)
        self.assertIn("profiles", json_data)

    def test_10_presentation_routes(self):
        """Verify web slide deck and PPTX download endpoints."""
        deck_res = self.client.get("/presentation")
        self.assertEqual(deck_res.status_code, 200)
        self.assertIn(b"PackageGuard", deck_res.data)
        self.assertIn(b"Rubric 1", deck_res.data)
        self.assertIn(b"Rubric 2", deck_res.data)
        self.assertIn(b"Rubric 3", deck_res.data)
        self.assertIn(b"Rubric 4", deck_res.data)
        self.assertIn(b"Rubric 5", deck_res.data)

        dl_res = self.client.get("/download-presentation")
        self.assertEqual(dl_res.status_code, 200)
        self.assertIn("application/vnd.openxmlformats-officedocument.presentationml.presentation", dl_res.content_type)

    def test_11_registry_link_and_plain_english_rendering(self):
        """Verify that direct registry link (npmjs.com) and 3-point plain English triage render."""
        mock_npm_scan = {
            "success": True,
            "package": "express",
            "ecosystem": "npm",
            "score": 18,
            "verdict": "LOW RISK",
            "badge_class": "low",
            "summary": "1 minor heuristic flagged.",
            "issues_count": 1,
            "category_scores": {"Initial Access": 0, "Execution & Hooks": 0, "Evasion & Obfuscation": 18, "Data Exfiltration": 0},
            "registry_url": "https://www.npmjs.com/package/express",
            "metadata": {"author": "TJ Holowaychuk", "version": "4.18.2", "license": "MIT", "repository": "https://github.com/expressjs/express"},
            "author_osint": {"username": "tj", "reputation_score": 95, "reputation_verdict": "VERIFIED", "badge_class": "low", "summary": "Verified author", "profiles": []},
            "flagged_rules": [{
                "rule_id": "npm-api-obfuscation",
                "name": "API Obfuscation",
                "severity": "Low",
                "weight": 18,
                "category": "Evasion & Obfuscation",
                "mitre_tactic": "TA0005: Defense Evasion",
                "mitre_technique": "T1027",
                "mitre_url": "https://attack.mitre.org/techniques/T1027/",
                "description": "Dynamic method invocation",
                "remediation": "Review dynamic method binding",
                "plain_detection": "The package dispatches methods via reflection.",
                "risk_impact": "Dynamic method calls can hide payload execution.",
                "what_to_do": "Verify method tables.",
                "findings": [],
            }],
            "audit_report_md": "# Security Report",
            "raw_json_str": "{}",
        }

        from unittest.mock import patch
        with patch("scanner.scan_package", return_value=mock_npm_scan):
            res = self.client.post("/", data={"package_name": "express", "ecosystem": "npm"})
            self.assertEqual(res.status_code, 200)
            self.assertIn(b"https://www.npmjs.com/package/express", res.data)
            self.assertIn(b"View on npmjs.com", res.data)
            self.assertIn(b"1. What Was Detected (Plain English)", res.data)
            self.assertIn(b"2. Potential Risk &amp; Practical Impact", res.data)
            self.assertIn(b"3. What You Should Do (DevSecOps Fix)", res.data)


if __name__ == "__main__":
    unittest.main()
