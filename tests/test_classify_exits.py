import unittest
from unittest.mock import patch
import urllib.error

from scripts.classify_exits import LookupFailure, request_json


class IntelligenceFailureTests(unittest.TestCase):
    def test_rate_limit_is_recordable_lookup_failure_not_process_exit(self):
        error = urllib.error.HTTPError(
            "https://risk.example/api", 429, "Too Many Requests", None, None
        )
        with patch("scripts.classify_exits.urllib.request.urlopen", side_effect=error):
            with self.assertRaisesRegex(LookupFailure, "HTTP 429"):
                request_json("https://risk.example/api")


if __name__ == "__main__":
    unittest.main()
