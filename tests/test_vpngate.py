import base64
import unittest

from scripts.vpngate import VPNGateError, parse_directory, parse_ovpn_config


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


def csv_row(config, *, hostname="public-vpn.example.net", ip="8.8.8.20",
            country="JP", score="1000", ping="20"):
    encoded = base64.b64encode(config.encode()).decode()
    return (
        f"{hostname},{ip},{score},{ping},100000,{country},{country},1,"
        f"100,100,100,0,operator,message,{encoded}"
    )


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
