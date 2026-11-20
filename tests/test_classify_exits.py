import subprocess
import unittest
from unittest.mock import patch
import urllib.error

from scripts.classify_exits import LookupFailure, echo_pair, request_json


class IntelligenceFailureTests(unittest.TestCase):
    def test_rate_limit_is_recordable_lookup_failure_not_process_exit(self):
        error = urllib.error.HTTPError(
            "https://risk.example/api", 429, "Too Many Requests", None, None
        )
        with patch("scripts.classify_exits.urllib.request.urlopen", side_effect=error):
            with self.assertRaisesRegex(LookupFailure, "HTTP 429"):
                request_json("https://risk.example/api")

class ExitProbeBudgetTests(unittest.TestCase):
    def test_60_probe_budget_distributes_primary_and_supplemental_sources(self):
        from scripts.classify_exits import select_exit_candidates

        candidates = (
            [{"name": f"free-{i}"} for i in range(300)]
            + [{"name": f"VPNGate-KR-{i}"} for i in range(50)]
            + [{"name": f"VPNBook-US-{i}"} for i in range(50)]
        )
        selected = select_exit_candidates(candidates, 60)

        self.assertEqual(len(selected), 60)
        self.assertEqual(sum(x["name"].startswith("free-") for x in selected), 30)
        self.assertEqual(sum(x["name"].startswith("VPNGate-") for x in selected), 15)
        self.assertEqual(sum(x["name"].startswith("VPNBook-") for x in selected), 15)
        self.assertEqual(len({x["name"] for x in selected}), 60)


class ExitEchoRetryTests(unittest.TestCase):
    def test_transient_echo_failure_retries_both_independent_services(self):
        with patch(
            "scripts.classify_exits.curl_exit_ip",
            side_effect=[subprocess.CalledProcessError(28, "curl"), "203.0.113.7", "203.0.113.7"],
        ), patch("scripts.classify_exits.time.sleep"):
            self.assertEqual(echo_pair(), ("203.0.113.7", True))

    def test_transient_failure_on_second_endpoint_retries_only_that_endpoint(self):
        with patch(
            "scripts.classify_exits.curl_exit_ip",
            side_effect=["203.0.113.7", subprocess.CalledProcessError(28, "curl"), "203.0.113.7"],
        ), patch("scripts.classify_exits.time.sleep"):
            self.assertEqual(echo_pair(), ("203.0.113.7", True))
    def test_persistent_echo_disagreement_remains_unverified(self):
        with patch(
            "scripts.classify_exits.curl_exit_ip",
            side_effect=["203.0.113.7", "198.51.100.9", "203.0.113.7", "198.51.100.9"],
        ), patch("scripts.classify_exits.time.sleep"):
            self.assertEqual(echo_pair(), ("203.0.113.7", False))

    def test_zero_echo_attempts_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "positive"):
            echo_pair(attempts=0)

if __name__ == "__main__":
    unittest.main()
