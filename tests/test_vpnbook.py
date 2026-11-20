import io
import unittest
import zipfile

from scripts.vpnbook import VPNBookError, parse_archives, parse_vpnbook_page
from tests.test_vpngate import profile


class VPNBookSourceTests(unittest.TestCase):
    def test_extracts_runtime_credentials_and_only_official_zip_links(self):
        page = """
        <div>Username <strong>vpnbook</strong></div>
        <div>Password: <strong>CurrentPass123</strong></div>
        <a href="/free-openvpn-account/VPNBook.com-OpenVPN-US1.zip">US</a>
        <a href="https://evil.example/free-openvpn-account/evil.zip">bad</a>
        """
        credentials, links = parse_vpnbook_page(page)
        self.assertEqual(credentials, ("vpnbook", "CurrentPass123"))
        self.assertEqual(links, ["https://www.vpnbook.com/free-openvpn-account/VPNBook.com-OpenVPN-US1.zip"])

    def test_rejects_missing_password_or_archive_links(self):
        with self.assertRaises(VPNBookError):
            parse_vpnbook_page("<a href='/free-openvpn-account/x.zip'>x</a>")
        with self.assertRaises(VPNBookError):
            parse_vpnbook_page("<div>Password: <strong>validpass</strong></div>")

    def test_converts_ovpn_profiles_with_dynamic_credentials(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("vpnbook-us1-tcp443.ovpn", profile("8.8.8.20 443 tcp"))
        proxies, report = parse_archives(
            [("https://www.vpnbook.com/free-openvpn-account/test.zip", buffer.getvalue())],
            ("vpnbook", "current-pass"),
        )
        self.assertEqual(len(proxies), 1)
        self.assertEqual(proxies[0]["name"], "VPNBook-vpnbook-us1-tcp443")
        self.assertEqual(proxies[0]["username"], "vpnbook")
        self.assertEqual(proxies[0]["password"], "current-pass")
        self.assertEqual(report["candidates_parsed"], 1)


if __name__ == "__main__":
    unittest.main()
