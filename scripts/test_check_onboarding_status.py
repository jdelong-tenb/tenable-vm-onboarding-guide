#!/usr/bin/env python3
"""
Unit tests for check_onboarding_status.py. Stdlib only (unittest + unittest.mock)
to match the script's no-dependency constraint.

Run with: python3 scripts/test_check_onboarding_status.py
"""

import io
import json
import unittest
import urllib.error
from unittest.mock import patch, MagicMock

import check_onboarding_status as cos


def _http_response(payload):
    """Mocks the context-manager object urllib.request.urlopen() returns."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(payload).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False
    return mock_resp


def _http_error(code, body):
    return urllib.error.HTTPError(
        url="https://cloud.tenable.com/x",
        code=code,
        msg="error",
        hdrs=None,
        fp=io.BytesIO(body.encode("utf-8")),
    )


class RedactTests(unittest.TestCase):
    def test_redacts_access_and_secret_key(self):
        text = "bad request: accessKey=abc123; secretKey=def456 rejected"
        self.assertNotIn("abc123", cos._redact(text))
        self.assertNotIn("def456", cos._redact(text))
        self.assertIn("accessKey=<redacted>", cos._redact(text))


class ApiGetTests(unittest.TestCase):
    @patch("check_onboarding_status.urllib.request.urlopen")
    def test_http_error_message_is_redacted(self, mock_urlopen):
        mock_urlopen.side_effect = _http_error(403, "denied for accessKey=SECRETVALUE")
        with self.assertRaises(RuntimeError) as ctx:
            cos.api_get("/scanners", "SECRETVALUE", "s")
        self.assertNotIn("SECRETVALUE", str(ctx.exception))

    @patch("check_onboarding_status.urllib.request.urlopen")
    def test_url_error_raises_runtime_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("connection reset")
        with self.assertRaises(RuntimeError):
            cos.api_get("/scanners", "a", "s")

    @patch("check_onboarding_status.urllib.request.urlopen")
    def test_invalid_json_raises_runtime_error(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"<html>not json</html>"
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp
        with self.assertRaises(RuntimeError):
            cos.api_get("/scanners", "a", "s")


class CheckFindingsTests(unittest.TestCase):
    @patch("check_onboarding_status.api_get")
    def test_explicit_zero_vuln_count_is_not_masked(self, mock_api_get):
        mock_api_get.return_value = {"total_vuln_count": 0, "total": 999}
        self.assertEqual(cos.check_findings("a", "s"), 0)

    @patch("check_onboarding_status.api_get")
    def test_falls_back_to_total_when_total_vuln_count_missing(self, mock_api_get):
        mock_api_get.return_value = {"total": 42}
        self.assertEqual(cos.check_findings("a", "s"), 42)


class MainStageTests(unittest.TestCase):
    """Drives main() end-to-end by mocking connectivity + the network layer."""

    def setUp(self):
        self.env_patch = patch.dict(
            "os.environ", {"TIO_ACCESS_KEY": "ak", "TIO_SECRET_KEY": "sk"}
        )
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.connectivity_patch = patch("check_onboarding_status.check_connectivity", return_value=True)
        self.connectivity_patch.start()
        self.addCleanup(self.connectivity_patch.stop)

    def _run_main_with_responses(self, responses):
        """responses: dict mapping path (ignoring query string) -> payload or Exception."""
        def fake_api_get(path, access_key, secret_key):
            key = path.split("?")[0]
            resp = responses.get(key, {})
            if isinstance(resp, Exception):
                raise resp
            return resp

        with patch("check_onboarding_status.api_get", side_effect=fake_api_get):
            with patch("builtins.print") as mock_print:
                cos.main()
        printed = mock_print.call_args[0][0]
        return json.loads(printed)

    def test_both_linkage_checks_fail_no_scan_history_is_check_linkage_error(self):
        result = self._run_main_with_responses({
            "/scanners": RuntimeError("API error 403 on /scanners: denied"),
            "/agents": RuntimeError("API error 403 on /agents: denied"),
            "/scans": {"scans": []},
        })
        self.assertEqual(result["onboarding_stage"], "check_linkage_error")

    def test_scanner_403_but_scan_history_confirms_linkage(self):
        result = self._run_main_with_responses({
            "/scanners": {"scanners": []},
            "/agents": RuntimeError("API error 403 on /agents: denied"),
            "/scans": {"scans": [
                {"name": "Old Scan", "status": "completed", "last_modification_date": 100},
            ]},
            "/workbenches/vulnerabilities": {"total_vuln_count": 5},
            "/tags/values": {"pagination": {"total": 3}},
        })
        self.assertNotEqual(result["onboarding_stage"], "link_scanner_or_agent")

    def test_stale_completed_history_does_not_mask_a_fresh_failed_scan(self):
        """The bug the correctness reviewer flagged: old completed scans + a
        just-failed most recent scan must route to review_scan_status, not
        view_findings."""
        result = self._run_main_with_responses({
            "/scanners": {"scanners": [{"type": "local", "status": "on"}]},
            "/agents": {"agents": []},
            "/scans": {"scans": [
                {"name": "Old Scan", "status": "completed", "last_modification_date": 100},
                {"name": "Fresh Scan", "status": "aborted", "last_modification_date": 999},
            ]},
            "/workbenches/vulnerabilities": {"total_vuln_count": 5},
            "/tags/values": {"pagination": {"total": 3}},
        })
        self.assertEqual(result["most_recent_scan_status"], "aborted")
        self.assertEqual(result["onboarding_stage"], "review_scan_status")

    def test_confirmed_zero_tags_routes_to_setup_tagging(self):
        result = self._run_main_with_responses({
            "/scanners": {"scanners": [{"type": "local", "status": "on"}]},
            "/agents": {"agents": []},
            "/scans": {"scans": [
                {"name": "Scan", "status": "completed", "last_modification_date": 100},
            ]},
            "/workbenches/vulnerabilities": {"total_vuln_count": 5},
            "/tags/values": {"pagination": {"total": 0}},
        })
        self.assertEqual(result["onboarding_stage"], "setup_tagging")

    def test_tag_check_error_does_not_look_like_confirmed_zero_tags(self):
        result = self._run_main_with_responses({
            "/scanners": {"scanners": [{"type": "local", "status": "on"}]},
            "/agents": {"agents": []},
            "/scans": {"scans": [
                {"name": "Scan", "status": "completed", "last_modification_date": 100},
            ]},
            "/workbenches/vulnerabilities": {"total_vuln_count": 5},
            "/tags/values": RuntimeError("API error 403 on /tags/values: denied"),
        })
        self.assertIn("tag_check_error", result)
        self.assertNotIn("tag_count", result)
        # Stage falls through to view_findings rather than falsely claiming
        # tagging is unset — the check_tags failure doesn't get read as "0 tags."
        self.assertEqual(result["onboarding_stage"], "view_findings")

    def test_clean_scan_zero_vulns_routes_to_review_not_view_findings(self):
        result = self._run_main_with_responses({
            "/scanners": {"scanners": [{"type": "local", "status": "on"}]},
            "/agents": {"agents": []},
            "/scans": {"scans": [
                {"name": "Scan", "status": "completed", "last_modification_date": 100},
            ]},
            "/workbenches/vulnerabilities": {"total_vuln_count": 0},
            "/tags/values": {"pagination": {"total": 3}},
        })
        self.assertEqual(result["onboarding_stage"], "review_scan_status")

    def test_healthy_account_routes_to_view_findings(self):
        result = self._run_main_with_responses({
            "/scanners": {"scanners": [{"type": "local", "status": "on"}]},
            "/agents": {"agents": []},
            "/scans": {"scans": [
                {"name": "Scan", "status": "completed", "last_modification_date": 100},
            ]},
            "/workbenches/vulnerabilities": {"total_vuln_count": 5},
            "/tags/values": {"pagination": {"total": 3}},
        })
        self.assertEqual(result["onboarding_stage"], "view_findings")


if __name__ == "__main__":
    unittest.main()
