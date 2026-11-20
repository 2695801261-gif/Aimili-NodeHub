import base64
import socket
import unittest

from scripts.vpngate import (
    VPNGateError,
    merge_candidate_history,
    parse_directory,
    parse_ovpn_config,
    select_history_candidates,
    tcp_prescreen_history,
)


CA = """-----BEGIN CERTIFICATE-----
MIIBtestcertificate
-----END CERTIFICATE-----"""
TLS_AUTH = """-----BEGIN OpenVPN Static key V1-----
0123456789abcdef
-----END OpenVPN Static key V1-----"""


def profile(remote="8.8.8.20 443 udp"):
    return f"""
client
dev tun
proto udp
remote {remote}
auth-user-pass
cipher AES-128-CBC
data-ciphers AES-256-GCM:AES-128-GCM
auth SHA1
key-direction 1
<ca>
{CA}
</ca>
<tls-auth>
{TLS_AUTH}
</tls-auth>
"""


def csv_row(config, *, hostname="volunteer.example.net", ip="8.8.8.20",
            country="JP", score="1000", ping="20"):
    encoded = base64.b64encode(config.encode()).decode()
    return (
        f"{hostname},{ip},{score},{ping},100000,{country},{country},1,"
        f"100,100,100,0,operator,message,{encoded}"
    )


class TCPPrescreenTests(unittest.TestCase):
    class FakeSocket:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    def test_removes_unreachable_tcp_but_keeps_udp_without_probing_it(self):
        records = [
            {"node": {"name": "tcp-live", "server": "198.51.100.1", "port": 443, "proto": "tcp"}},
            {"node": {"name": "tcp-dead", "server": "198.51.100.2", "port": 443, "proto": "tcp"}},
            {"node": {"name": "udp-node", "server": "198.51.100.3", "port": 1194, "proto": "udp"}},
        ]
        calls = []

        def connector(address, timeout):
            calls.append(address)
            if address[0] == "198.51.100.2":
                raise ConnectionRefusedError("closed")
            return self.FakeSocket()

        survivors, report = tcp_prescreen_history(
            records, connector=connector, workers=2, timeout_seconds=0.2
        )

        self.assertEqual([item["node"]["name"] for item in survivors], ["tcp-live", "udp-node"])
        self.assertEqual(len(calls), 2)
        self.assertEqual(report["tcp_candidates"], 2)
        self.assertEqual(report["tcp_reachable"], 1)
        self.assertEqual(report["tcp_unreachable"], 1)
        self.assertEqual(report["tcp_skipped_non_tcp"], 1)
        self.assertEqual(report["runner_vantage"], "github-actions")

    def test_retries_transient_tcp_timeout_once(self):
        records = [
            {"node": {"name": "tcp-retry", "server": "198.51.100.4", "port": 443, "proto": "tcp"}}
        ]
        calls = []

        def connector(address, timeout):
            calls.append(address)
            if len(calls) == 1:
                raise socket.timeout("temporary timeout")
            return self.FakeSocket()

        survivors, report = tcp_prescreen_history(
            records, connector=connector, workers=1, timeout_seconds=0.2
        )

        self.assertEqual(len(survivors), 1)
        self.assertEqual(len(calls), 2)
        self.assertEqual(report["tcp_reachable"], 1)
        self.assertEqual(report["tcp_unreachable"], 0)

    def test_rejects_invalid_prescreen_limits(self):
        with self.assertRaisesRegex(ValueError, "positive"):
            tcp_prescreen_history([], workers=0)


class VPNGateParserTests(unittest.TestCase):
    def test_parses_openvpn_profile_into_mihomo_openvpn_proxy(self):
        proxy = parse_ovpn_config(profile().replace("\n", "\r\n"), "VPNGate-JP-test")
        self.assertEqual(proxy["type"], "openvpn")
        self.assertEqual(proxy["server"], "8.8.8.20")
        self.assertEqual(proxy["port"], 443)
        self.assertEqual(proxy["proto"], "udp")
        self.assertTrue(proxy["udp"])
        self.assertEqual(proxy["username"], "vpn")
        self.assertEqual(proxy["password"], "vpn")
        self.assertEqual(proxy["data-ciphers"], ["AES-256-GCM", "AES-128-GCM"])
        self.assertIn("tls-auth", proxy)
        self.assertEqual(proxy["key-direction"], "1")

    def test_parses_vpngate_certificate_auth_without_username_password(self):
        cert = "-----BEGIN CERTIFICATE-----\nMIIBclient\n-----END CERTIFICATE-----"
        key = "-----BEGIN PRIVATE KEY-----\nMIIBprivate\n-----END PRIVATE KEY-----"
        text = profile().replace("auth-user-pass\n", "")
        text += f"<cert>\n{cert}\n</cert>\n<key>\n{key}\n</key>\n"
        proxy = parse_ovpn_config(text, "VPNGate-JP-cert")
        self.assertNotIn("username", proxy)
        self.assertNotIn("password", proxy)
        self.assertEqual(proxy["cert"], cert)
        self.assertEqual(proxy["key"], key)

    def test_supports_combined_username_password_and_client_certificate_auth(self):
        cert = "-----BEGIN CERTIFICATE-----\nMIIBclient\n-----END CERTIFICATE-----"
        key = "-----BEGIN PRIVATE KEY-----\nMIIBprivate\n-----END PRIVATE KEY-----"
        text = profile() + f"<cert>\n{cert}\n</cert>\n<key>\n{key}\n</key>\n"
        proxy = parse_ovpn_config(text, "VPNBook-US1-combined", ("vpnbook", "current-pass"))
        self.assertEqual(proxy["username"], "vpnbook")
        self.assertEqual(proxy["password"], "current-pass")
        self.assertEqual(proxy["cert"], cert)
        self.assertEqual(proxy["key"], key)

    def test_uses_provider_supplied_credentials_for_vpnbook(self):
        proxy = parse_ovpn_config(profile(), "VPNBook-US1", ("vpnbook", "current-pass"))
        self.assertEqual(proxy["username"], "vpnbook")
        self.assertEqual(proxy["password"], "current-pass")

    def test_rejects_missing_ca(self):
        with self.assertRaisesRegex(VPNGateError, "CA certificate"):
            parse_ovpn_config("client\nremote 8.8.8.20 1194\n", "bad")

    def test_rejects_non_global_literal_remote(self):
        with self.assertRaisesRegex(VPNGateError, "not globally routable"):
            parse_ovpn_config(profile("127.0.0.1 443 udp"), "bad")

    def test_rejects_external_auth_file(self):
        text = profile().replace("auth-user-pass", "auth-user-pass /tmp/credentials")
        with self.assertRaisesRegex(VPNGateError, "external credential"):
            parse_ovpn_config(text, "bad")

    def test_parses_official_csv_comment_header_and_base64_config(self):
        csv_text = (
            "# comment\n"
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,"
            "Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
            + csv_row(profile())
            + "\n#\n"
        )
        proxies, report = parse_directory(csv_text, limit=10)
        self.assertEqual(len(proxies), 1)
        self.assertEqual(proxies[0]["type"], "openvpn")
        self.assertEqual(report["rows_seen"], 1)
        self.assertEqual(report["candidates_parsed"], 1)



    def test_history_retains_off_window_us_candidate_until_ttl(self):
        node = {
            "name": "VPNGate-US-8-8-8-20-volunteer",
            "type": "openvpn", "server": "8.8.8.20",
            "port": 443, "proto": "tcp",
        }
        previous = [{"node": node, "first_seen_at": 100.0, "last_seen_at": 900.0}]
        merged, stats = merge_candidate_history([], previous, now=1000.0, ttl_seconds=500)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["node"]["name"], node["name"])
        self.assertEqual(stats["off_window_retained"], 1)

    def test_history_expires_off_window_candidates_after_ttl(self):
        node = {
            "name": "VPNGate-US-8-8-8-21-volunteer",
            "type": "openvpn", "server": "8.8.8.21",
            "port": 443, "proto": "tcp",
        }
        previous = [{"node": node, "first_seen_at": 100.0, "last_seen_at": 100.0}]
        merged, stats = merge_candidate_history([], previous, now=1000.0, ttl_seconds=100)
        self.assertEqual(merged, [])
        self.assertEqual(stats["history_expired"], 1)

    def test_current_api_candidate_refreshes_existing_history_entry(self):
        node = {
            "name": "VPNGate-US-8-8-8-22-volunteer",
            "type": "openvpn", "server": "8.8.8.22",
            "port": 443, "proto": "tcp",
        }
        previous = [{"node": node, "first_seen_at": 100.0, "last_seen_at": 200.0}]
        merged, stats = merge_candidate_history([node], previous, now=500.0)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["first_seen_at"], 100.0)
        self.assertEqual(merged[0]["last_seen_at"], 500.0)
        self.assertEqual(stats["current_refreshed"], 1)

    def test_history_keeps_only_five_off_window_candidates_per_country(self):
        previous = []
        for index in range(7):
            node = {
                "name": f"VPNGate-JP-8-8-8-{30+index}-volunteer",
                "type": "openvpn", "server": f"8.8.8.{30+index}",
                "port": 443, "proto": "tcp",
            }
            previous.append({"node": node, "first_seen_at": 100.0, "last_seen_at": 900.0 + index})
        merged, stats = merge_candidate_history(
            [], previous, now=1000.0, ttl_seconds=500, max_stale_per_country=5
        )
        self.assertEqual(len(merged), 5)
        self.assertEqual(stats["off_window_retained"], 5)

    def test_history_rejects_vpngate_operated_endpoints(self):
        by_name = {
            "name": "VPNGate-US-8-8-8-23-public-vpn-255",
            "type": "openvpn", "server": "8.8.8.23",
            "port": 443, "proto": "tcp",
        }
        by_network = {
            "name": "VPNGate-JP-219-100-37-224-volunteer",
            "type": "openvpn", "server": "219.100.37.224",
            "port": 443, "proto": "tcp",
        }
        previous = [
            {"node": by_name, "first_seen_at": 100.0, "last_seen_at": 900.0},
            {"node": by_network, "first_seen_at": 100.0, "last_seen_at": 900.0},
        ]
        merged, stats = merge_candidate_history([], previous, now=1000.0, ttl_seconds=500)
        self.assertEqual(merged, [])
        self.assertEqual(stats["history_invalid"], 2)

    def test_history_selection_prioritizes_us_and_rotates_us_candidates(self):
        records = []
        for country, base_ip in (("JP", 30), ("US", 20)):
            for index in range(3):
                node = {
                    "name": f"VPNGate-{country}-8-8-8-{base_ip+index}-volunteer",
                    "type": "openvpn", "server": f"8.8.8.{base_ip+index}",
                    "port": 443, "proto": "tcp",
                }
                records.append({"node": node, "first_seen_at": 100.0, "last_seen_at": 100.0+index})
        first = select_history_candidates(records, limit=2, rotation=0)
        second = select_history_candidates(records, limit=2, rotation=1)
        self.assertTrue(first[0]["name"].startswith("VPNGate-US-"))
        self.assertTrue(second[0]["name"].startswith("VPNGate-US-"))
        self.assertNotEqual(first[0]["name"], second[0]["name"])

    def test_excludes_vpngate_operated_public_vpn_hostname(self):
        header = (
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,"
            "Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
        )
        row = csv_row(profile(), hostname="public-vpn-255", ip="8.8.8.20")
        proxies, report = parse_directory(header + row, limit=10)
        self.assertEqual(proxies, [])
        self.assertEqual(report["rejection_reasons"], {"vpngate_operated_public_vpn_hostname": 1})

    def test_excludes_vpngate_operated_public_vpn_ipv4_range(self):
        header = (
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,"
            "Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
        )
        ip = "219.100.37.224"
        row = csv_row(profile(f"{ip} 443 udp"), hostname="relay.example.net", ip=ip)
        proxies, report = parse_directory(header + row, limit=10)
        self.assertEqual(proxies, [])
        self.assertEqual(report["rejection_reasons"], {"vpngate_operated_public_vpn_network": 1})

    def test_keeps_non_operated_vpngate_volunteer_endpoint(self):
        header = (
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,"
            "Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
        )
        row = csv_row(profile("8.8.8.21 443 udp"), hostname="volunteer-home.example.net", ip="8.8.8.21")
        proxies, report = parse_directory(header + row, limit=10)
        self.assertEqual(len(proxies), 1)
        self.assertEqual(report["rejected"], 0)

    def test_rejects_csv_ip_that_disagrees_with_embedded_remote(self):
        header = (
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,"
            "Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
        )
        proxies, report = parse_directory(header + csv_row(profile(), ip="1.1.1.1"), limit=10)
        self.assertEqual(proxies, [])
        self.assertIn("CSV server IP does not match the embedded OpenVPN remote", report["rejection_reasons"])

    def test_selection_diversifies_advertised_countries_before_filling_by_score(self):
        header = (
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,"
            "Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
        )
        rows = [
            csv_row(profile("8.8.8.20 443 udp"), ip="8.8.8.20", country="JP", score="100"),
            csv_row(profile("8.8.8.21 443 udp"), ip="8.8.8.21", country="JP", score="90"),
            csv_row(profile("8.8.8.22 443 udp"), ip="8.8.8.22", country="JP", score="80"),
            csv_row(profile("8.8.8.23 443 udp"), ip="8.8.8.23", country="US", score="10"),
        ]
        proxies, report = parse_directory(header + "\n".join(rows), limit=2)
        self.assertEqual(len(proxies), 2)
        self.assertEqual({item["name"].split("-")[1] for item in proxies}, {"JP", "US"})
        self.assertEqual(report["selection_strategy"], "rotating_country_round_robin_then_score")

    def test_selects_top_scored_candidates_with_limit(self):
        rows = [
            csv_row(profile(f"8.8.8.{20+i} 443 udp"), ip=f"8.8.8.{20+i}",
                    score=str(i), ping=str(100-i))
            for i in range(5)
        ]
        header = (
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,"
            "Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
        )
        proxies, report = parse_directory(header + "\n".join(rows), limit=2)
        self.assertEqual(len(proxies), 2)
        self.assertTrue(proxies[0]["name"].startswith("VPNGate-JP-"))
        self.assertEqual(report["limit"], 2)


if __name__ == "__main__":
    unittest.main()
