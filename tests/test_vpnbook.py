import unittest

from scripts.vpnbook import (
    VPNBookError,
    build_config_url,
    parse_configs,
    resolve_server_ip,
    parse_vpnbook_page,
)

CA = """-----BEGIN CERTIFICATE-----
MIIBtestcertificate
-----END CERTIFICATE-----"""
TLS_AUTH = """-----BEGIN OpenVPN Static key V1-----
0123456789abcdef
-----END OpenVPN Static key V1-----"""


def profile(remote="us16.vpnbook.com 443 tcp"):
    return f"""client
dev tun
proto tcp
remote {remote}
auth-user-pass
cipher AES-128-CBC
auth SHA1
key-direction 1
<ca>
{CA}
</ca>
<tls-auth>
{TLS_AUTH}
</tls-auth>
"""


class VPNBookSourceTests(unittest.TestCase):
    def setUp(self):
        self.server = {
            "id": "us16",
            "hostname": "us16.vpnbook.com",
            "ip": "147.135.15.16",
            "country": "US",
        }

    def test_parses_current_nextjs_credentials_and_server_directory(self):
        page = """
        <label>Username</label><code>vpnbook</code>
        <label>Password</label><code>CurrentPass123</code>
        <script>
        self.__next_f.push([1,"{&quot;id&quot;:&quot;us16&quot;,&quot;name&quot;:&quot;US Server 1&quot;,&quot;hostname&quot;:&quot;us16.vpnbook.com&quot;,&quot;ipAddress&quot;:&quot;147.135.15.16&quot;,&quot;countryCode&quot;:&quot;US&quot;}"])
        </script>
        """
        credentials, servers = parse_vpnbook_page(page)
        self.assertEqual(credentials, ("vpnbook", "CurrentPass123"))
        self.assertEqual(servers, [self.server])

    def test_supports_legacy_strong_credential_markup(self):
        page = """
        <div>Username: <strong>vpnbook</strong></div>
        <div>Password: <strong>LegacyPass123</strong></div>
        {"id":"us16","hostname":"us16.vpnbook.com","ipAddress":"147.135.15.16","countryCode":"US"}
        """
        credentials, servers = parse_vpnbook_page(page)
        self.assertEqual(credentials, ("vpnbook", "LegacyPass123"))
        self.assertEqual(servers[0]["id"], "us16")

    def test_rejects_pages_without_credentials_or_valid_servers(self):
        with self.assertRaises(VPNBookError):
            parse_vpnbook_page('<label>Username</label><code>vpnbook</code>')
        page = """
        <label>Username</label><code>vpnbook</code>
        <label>Password</label><code>CurrentPass123</code>
        {"id":"lan","hostname":"localhost","ipAddress":"127.0.0.1","countryCode":"US"}
        """
        with self.assertRaises(VPNBookError):
            parse_vpnbook_page(page)

    def test_falls_back_to_public_server_hostnames_when_embedded_json_changes(self):
        page = """
        <label>Username</label><code>vpnbook</code>
        <label>Password</label><code>CurrentPass123</code>
        <div>US Server 1 us16.vpnbook.com</div>
        <div>US Server 2 us178.vpnbook.com</div>
        <div>Canada Server 1 ca149.vpnbook.com</div>
        """
        credentials, servers = parse_vpnbook_page(page)
        self.assertEqual(credentials, ("vpnbook", "CurrentPass123"))
        self.assertEqual([item["hostname"] for item in servers], [
            "us16.vpnbook.com", "us178.vpnbook.com", "ca149.vpnbook.com"
        ])
        self.assertTrue(all(item["ip"] == "" for item in servers))

    def test_resolves_only_public_ipv4_for_official_server_hostname(self):
        from unittest.mock import patch

        records = [(None, None, None, None, ("147.135.15.16", 443))]
        with patch("scripts.vpnbook.socket.getaddrinfo", return_value=records):
            self.assertEqual(resolve_server_ip("us16.vpnbook.com"), "147.135.15.16")
        with patch("scripts.vpnbook.socket.getaddrinfo", return_value=[
            (None, None, None, None, ("127.0.0.1", 443))
        ]):
            with self.assertRaisesRegex(VPNBookError, "no public IPv4"):
                resolve_server_ip("us16.vpnbook.com")
        with self.assertRaisesRegex(VPNBookError, "non-server"):
            resolve_server_ip("localhost")

    def test_builds_official_api_url_from_validated_server_record(self):
        url = build_config_url(self.server)
        self.assertEqual(
            url,
            "https://www.vpnbook.com/api/openvpn?hostname=us16.vpnbook.com&protocol=tcp443&ip=147.135.15.16",
        )

    def test_rejects_profile_remote_that_disagrees_with_official_server_record(self):
        proxies, report = parse_configs(
            [(self.server, profile("8.8.8.8 443 tcp"))],
            ("vpnbook", "CurrentPass123"),
        )
        self.assertEqual(proxies, [])
        self.assertTrue(any("profile remote does not match" in key for key in report["rejection_reasons"]))

    def test_parses_profiles_with_runtime_credentials(self):
        proxies, report = parse_configs(
            [(self.server, profile())],
            ("vpnbook", "CurrentPass123"),
        )
        self.assertEqual(len(proxies), 1)
        self.assertEqual(proxies[0]["name"], "VPNBook-us16-tcp443")
        self.assertEqual(proxies[0]["username"], "vpnbook")
        self.assertEqual(proxies[0]["password"], "CurrentPass123")
        self.assertNotIn("source", proxies[0])
        self.assertEqual(report["candidates_parsed"], 1)


if __name__ == "__main__":
    unittest.main()
