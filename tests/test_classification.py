import unittest

from scripts.classification import classify


def base():
    return {
        "country_code": "US",
        "asn": 64500,
        "asn_kind": ["isp"],
        "asn_reports": 0,
        "ip_risk_status": "not_reported",
        "ip_kind": [],
        "ip_reports": None,
        "ipwhois_success": True,
        "oxl_asn_status": "ok",
        "exit_echo_agreement": True,
    }


class ClassificationTests(unittest.TestCase):
    def test_us_isp_is_candidate(self):
        self.assertEqual(classify(base()).pool, "us-residential")

    def test_non_us_isp_is_other_residential(self):
        evidence = base()
        evidence["country_code"] = "DE"
        self.assertEqual(classify(evidence).pool, "other-residential")

    def test_hosting_without_risk_is_low_risk_dc(self):
        evidence = base()
        evidence["asn_kind"] = ["hosting"]
        self.assertEqual(classify(evidence).pool, "low-risk-datacenter")

    def test_vpn_signal_quarantines(self):
        evidence = base()
        evidence["asn_kind"] = ["isp", "vpn"]
        self.assertIsNone(classify(evidence).pool)

    def test_abuse_report_quarantines(self):
        evidence = base()
        evidence["asn_reports"] = 1
        self.assertIsNone(classify(evidence).pool)

    def test_missing_asn_intelligence_quarantines(self):
        evidence = base()
        evidence["oxl_asn_status"] = "unavailable"
        self.assertIsNone(classify(evidence).pool)

    def test_echo_mismatch_quarantines(self):
        evidence = base()
        evidence["exit_echo_agreement"] = False
        self.assertIsNone(classify(evidence).pool)

    def test_unknown_is_quarantined(self):
        evidence = base()
        evidence["asn_kind"] = []
        self.assertIsNone(classify(evidence).pool)

    def test_hosting_ip_signal_is_allowed_for_dc(self):
        evidence = base()
        evidence["asn_kind"] = ["hosting"]
        evidence["ip_risk_status"] = "ok"
        evidence["ip_kind"] = ["hosting"]
        evidence["ip_reports"] = 0
        self.assertEqual(classify(evidence).pool, "low-risk-datacenter")

    def test_vpn_ip_signal_quarantines_isp(self):
        evidence = base()
        evidence["ip_risk_status"] = "ok"
        evidence["ip_kind"] = ["vpn"]
        evidence["ip_reports"] = 0
        self.assertIsNone(classify(evidence).pool)

    def test_missing_asn_report_count_quarantines(self):
        evidence = base()
        evidence["asn_reports"] = None
        self.assertIsNone(classify(evidence).pool)

    def test_conflicting_isp_and_hosting_ip_signals_quarantine(self):
        evidence = base()
        evidence["asn_kind"] = ["isp"]
        evidence["ip_risk_status"] = "ok"
        evidence["ip_kind"] = ["hosting"]
        evidence["ip_reports"] = 0
        self.assertIsNone(classify(evidence).pool)

    def test_live_kind_list_can_confirm_asn_without_report_record(self):
        evidence = base()
        evidence["oxl_asn_status"] = "not_reported"
        self.assertEqual(classify(evidence).pool, "us-residential")

    def test_unknown_country_is_quarantined(self):
        evidence = base()
        evidence["country_code"] = "ZZ"
        self.assertIsNone(classify(evidence).pool)


if __name__ == "__main__":
    unittest.main()
