import os
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


    def test_us_advertised_candidates_are_prioritized_within_each_source_quota(self):
        from scripts.classify_exits import select_exit_candidates

        candidates = (
            [{"name": f"US · VMESS · primary · {i}"} for i in range(100)]
            + [{"name": f"JP · VMESS · primary · {i}"} for i in range(300)]
            + [{"name": f"VPNGate-US-{i}"} for i in range(25)]
            + [{"name": f"VPNGate-JP-{i}"} for i in range(25)]
            + [{"name": f"VPNBook-us{i}"} for i in range(5)]
            + [{"name": f"VPNBook-de{i}"} for i in range(5)]
        )
        selected = select_exit_candidates(candidates, 80)

        self.assertEqual(len(selected), 80)
        self.assertEqual(sum(x["name"].startswith("US ·") for x in selected), 40)
        self.assertEqual(sum(x["name"].startswith("VPNGate-") for x in selected), 30)
        self.assertEqual(sum(x["name"].startswith("VPNBook-") for x in selected), 10)
        self.assertGreaterEqual(
            sum(
                x["name"].startswith("US ·")
                or x["name"].startswith("VPNGate-US-")
                or x["name"].startswith("VPNBook-us")
                for x in selected
            ),
            70,
        )

    def test_us_hint_sampling_rotates_without_treating_labels_as_evidence(self):
        from scripts.classify_exits import select_exit_candidates

        candidates = (
            [{"name": f"US · primary · {i}"} for i in range(100)]
            + [{"name": f"JP · primary · {i}"} for i in range(300)]
            + [{"name": f"VPNGate-US-{i}"} for i in range(25)]
            + [{"name": f"VPNGate-JP-{i}"} for i in range(25)]
        )
        first = select_exit_candidates(candidates, 80, rotation=0)
        second = select_exit_candidates(candidates, 80, rotation=1)

        self.assertEqual(len(first), len(second))
        self.assertNotEqual(
            {x["name"] for x in first if x["name"].startswith("US ·")},
            {x["name"] for x in second if x["name"].startswith("US ·")},
        )

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


class IPApiIsMetadataTests(unittest.TestCase):
    def test_optional_ipapi_is_lookup_keeps_key_in_post_body(self):
        from scripts.classify_exits import lookup_ipapi_is

        response = {
            "203.0.113.20": {
                "ip": "203.0.113.20",
                "is_datacenter": False,
                "is_proxy": False,
                "is_tor": False,
                "is_abuser": False,
                "is_mobile": False,
                "is_satellite": False,
                "is_anycast": False,
                "is_crawler": False,
                "is_vpn": True,
                "company": {"name": "Comcast Cable", "type": "isp"},
                "asn": {"asn": 7922, "type": "isp"},
                "location": {"country_code": "US"},
            },
            "total_elapsed_ms": 1.0,
        }
        with patch.dict(os.environ, {"IPAPI_IS_API_KEY": "test-secret"}), patch(
            "scripts.classify_exits.request_json", return_value=response
        ) as request, patch("scripts.classify_exits.time.sleep"):
            evidence = lookup_ipapi_is("203.0.113.20")
        self.assertEqual(evidence["ipapi_is_status"], "ok")
        self.assertTrue(evidence["ipapi_is_vpn"])
        self.assertEqual(evidence["ipapi_is_asn"], 7922)
        request.assert_called_once_with(
            "https://api.ipapi.is",
            method="POST",
            payload={"ips": ["203.0.113.20"], "key": "test-secret"},
            timeout=10,
        )

    def test_ipapi_is_without_key_is_optional_and_skipped(self):
        from scripts.classify_exits import lookup_ipapi_is

        with patch.dict(os.environ, {}, clear=True), patch(
            "scripts.classify_exits.request_json"
        ) as request:
            evidence = lookup_ipapi_is("203.0.113.20")
        self.assertEqual(evidence, {"ipapi_is_status": "not_configured"})
        request.assert_not_called()


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
