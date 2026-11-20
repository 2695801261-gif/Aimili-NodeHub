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

class ExitEchoRetryTests(unittest.TestCase):
    def test_transient_echo_failure_retries_both_independent_services(self):
        with patch(
            "scripts.classify_exits.curl_exit_ip",
            side_effect=[subprocess.CalledProcessError(28, "curl"), "203.0.113.7", "203.0.113.7"],
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
