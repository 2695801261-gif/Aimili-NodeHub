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


class CloudflareProbeUnderlayTests(unittest.TestCase):
    def test_underlay_is_attached_only_to_vpngate_probe_copies(self):
        from scripts.classify_exits import prepare_probe_candidates

        source = [
            {"name": "VPNGate-US-1", "type": "openvpn"},
            {"name": "free-vless-1", "type": "vless"},
            {"name": "VPNBook-US-1", "type": "openvpn"},
        ]
        front = {"name": "NODEHUB-CF-FRONT", "type": "vless"}
        prepared, count = prepare_probe_candidates(source, front)
        self.assertEqual(count, 1)
        self.assertEqual(prepared[0]["dialer-proxy"], "NODEHUB-CF-FRONT")
        self.assertNotIn("dialer-proxy", prepared[1])
        self.assertNotIn("dialer-proxy", prepared[2])
        self.assertTrue(all("dialer-proxy" not in item for item in source))

    def test_without_front_keeps_all_probe_candidates_direct(self):
        from scripts.classify_exits import prepare_probe_candidates

        source = [{"name": "VPNGate-US-1"}, {"name": "free-vless-1"}]
        prepared, count = prepare_probe_candidates(source, None)
        self.assertEqual(count, 0)
        self.assertEqual(prepared, source)
        self.assertTrue(all("dialer-proxy" not in item for item in prepared))


class CloudflareFrontURITests(unittest.TestCase):
    def test_parse_tls_websocket_vless_uri_for_probe_underlay(self):
        from scripts.classify_exits import parse_cloudflare_front_uri

        proxy = parse_cloudflare_front_uri(
            "vless://123e4567-e89b-12d3-a456-426614174000@cf.example.com:443"
            "?encryption=none&security=tls&type=ws&host=cf.example.com"
            "&sni=cf.example.com&path=%2F%3Fed%3D2048#cf-front"
        )
        self.assertEqual(proxy["type"], "vless")
        self.assertEqual(proxy["server"], "cf.example.com")
        self.assertEqual(proxy["port"], 443)
        self.assertEqual(proxy["uuid"], "123e4567-e89b-12d3-a456-426614174000")
        self.assertTrue(proxy["tls"])
        self.assertEqual(proxy["network"], "ws")
        self.assertEqual(proxy["ws-opts"]["path"], "/?ed=2048")
        self.assertEqual(proxy["ws-opts"]["headers"]["Host"], "cf.example.com")

    def test_parse_cloudflare_front_uses_sni_as_host_when_server_is_ip(self):
        from scripts.classify_exits import parse_cloudflare_front_uri

        proxy = parse_cloudflare_front_uri(
            "vless://123e4567-e89b-12d3-a456-426614174000@104.16.0.1:443"
            "?encryption=none&security=tls&type=ws&sni=cf.example.com&path=%2F"
        )
        self.assertEqual(proxy["server"], "104.16.0.1")
        self.assertEqual(proxy["servername"], "cf.example.com")
        self.assertEqual(proxy["ws-opts"]["headers"]["Host"], "cf.example.com")

    def test_parse_cloudflare_front_rejects_non_tls_or_non_ws_uri(self):
        from scripts.classify_exits import parse_cloudflare_front_uri

        base = "vless://123e4567-e89b-12d3-a456-426614174000@cf.example.com:443?"
        with self.assertRaisesRegex(ValueError, "TLS"):
            parse_cloudflare_front_uri(base + "encryption=none&type=ws")
        with self.assertRaisesRegex(ValueError, "TLS"):
            parse_cloudflare_front_uri(base + "encryption=none&security=tls&type=grpc")

    def test_parse_cloudflare_front_rejects_invalid_uuid(self):
        from scripts.classify_exits import parse_cloudflare_front_uri

        with self.assertRaisesRegex(ValueError, "UUID"):
            parse_cloudflare_front_uri(
                "vless://not-a-uuid@cf.example.com:443?encryption=none&security=tls&type=ws"
            )


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
