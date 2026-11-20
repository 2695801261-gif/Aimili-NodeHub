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
    def test_80_probe_budget_distributes_across_primary_vpngate_and_vpnbook(self):
        from scripts.classify_exits import select_exit_candidates

        candidates = (
            [{"name": f"free-{i}"} for i in range(400)]
            + [{"name": f"VPNGate-JP-{i}"} for i in range(50)]
            + [{"name": f"VPNBook-US-{i}"} for i in range(10)]
        )
        selected = select_exit_candidates(candidates, 80)

        self.assertEqual(len(selected), 80)
        self.assertEqual(sum(x["name"].startswith("free-") for x in selected), 40)
        self.assertEqual(sum(x["name"].startswith("VPNGate-") for x in selected), 30)
        self.assertEqual(sum(x["name"].startswith("VPNBook-") for x in selected), 10)
        self.assertEqual(len({x["name"] for x in selected}), 80)


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


class IPWhoMetadataTests(unittest.TestCase):
    def test_ipwho_metadata_preserves_type_and_security_flags(self):
        from scripts.classify_exits import lookup_ip_metadata

        response = {
            "success": True,
            "ip": "203.0.113.20",
            "country_code": "US",
            "type": "IPv4",
            "connection": {
                "asn": 7922,
                "isp": "Comcast Cable Communications, LLC",
                "org": "Comcast Cable",
            },
        }
        with patch("scripts.classify_exits.request_json", return_value=response), patch(
            "scripts.classify_exits.time.sleep"
        ):
            metadata, source = lookup_ip_metadata("203.0.113.20")
        self.assertEqual(source, "ipwho.is")
        self.assertEqual(metadata["ipwho_type"], "ipv4")
        self.assertEqual(metadata["ipwho_security"], {
            "hosting": None, "proxy": None, "vpn": None, "tor": None,
        })

    def test_ipinfo_fallback_does_not_fabricate_ipwho_evidence(self):
        from scripts.classify_exits import lookup_ip_metadata

        def response_for(url, **kwargs):
            if "ipwho.is" in url:
                raise LookupFailure("IPWHO unavailable")
            return {
                "ip": "203.0.113.21",
                "country": "US",
                "org": "AS7922 Comcast Cable",
            }

        with patch("scripts.classify_exits.request_json", side_effect=response_for), patch(
            "scripts.classify_exits.time.sleep"
        ):
            metadata, source = lookup_ip_metadata("203.0.113.21")
        self.assertEqual(source, "ipinfo.io")
        self.assertNotIn("ipwho_type", metadata)
        self.assertNotIn("ipwho_security", metadata)

if __name__ == "__main__":
    unittest.main()
