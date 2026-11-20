import unittest

from scripts.classification import classify


def base():
    return {
        "exit_ip": "8.8.8.8",
        "country_code": "US",
        "asn": 64500,
        "isp": "Example Access Network",
        "asn_kind": ["isp"],
        "asn_reports": 0,
        "ip_risk_status": "not_reported",
        "ip_kind": [],
        "ip_reports": None,
        "ip_metadata_success": True,
        "net_asn_match": True,
        "net_prefix_match": True,
        "net_status": "ok",
        "net_kind": ["isp"],
        "net_reports": 0,
        "net_reputation": "ok",
        "net_source": "oxl-api",
        "oxl_asn_status": "ok",
        "exit_echo_agreement": True,
        "layer3_ip": "8.8.8.8",
        "layer3_type": "residential",
        "layer3_risk_level": "low",
        "layer3_risk_score": 5,
        "layer3_risk_reasons": [],
        "layer3_flags": {
            "anonymizer": False, "proxy": False, "vpn": False,
            "tor": False, "relay": False, "hosting": False,
        },
        "layer3_country": "US",
        "layer3_asn": 64500,
        "layer3_network_type": "access",
        "layer3_prefix": "8.8.8.0/24",
        "layer3_drop_listed": False,
        "layer3_sharing": None,
        "layer3_crawler": False,
    }


class ClassificationTests(unittest.TestCase):
    def test_us_residential_exit(self):
        self.assertEqual(classify(base()).pool, "us-residential")

    def test_non_us_residential_exit(self):
        evidence = base()
        evidence["country_code"] = "DE"
        evidence["layer3_country"] = "DE"
        self.assertEqual(classify(evidence).pool, "other-residential")

    def test_low_risk_hosting_exit(self):
        evidence = base()
        evidence["asn_kind"] = ["hosting"]
        evidence["net_kind"] = ["hosting"]
        evidence["layer3_type"] = "hosting"
        evidence["layer3_network_type"] = "hosting"
        evidence["layer3_flags"]["hosting"] = True
        evidence["layer3_risk_reasons"] = ["hosting"]
        evidence["net_kind"] = ["hosting"]
        self.assertEqual(classify(evidence).pool, "low-risk-datacenter")

    def test_unreported_oxl_network_can_use_layer3_network_evidence(self):
        evidence = base()
        evidence["net_status"] = "not_reported"
        self.assertEqual(classify(evidence).pool, "us-residential")

    def test_ambiguous_isp_address_type_is_quarantined(self):
        evidence = base()
        evidence["layer3_type"] = "isp"
        self.assertIsNone(classify(evidence).pool)

    def test_isp_proxy_is_quarantined(self):
        evidence = base()
        evidence["layer3_type"] = "isp_proxy"
        evidence["layer3_flags"]["anonymizer"] = True
        evidence["layer3_flags"]["proxy"] = True
        evidence["layer3_risk_reasons"] = ["isp_proxy"]
        self.assertIsNone(classify(evidence).pool)

    def test_residential_with_unknown_risk_reason_is_quarantined(self):
        evidence = base()
        evidence["layer3_risk_reasons"] = ["recent_reassignment"]
        self.assertIsNone(classify(evidence).pool)

    def test_medium_risk_is_quarantined(self):
        evidence = base()
        evidence["layer3_risk_level"] = "medium"
        evidence["layer3_risk_score"] = 25
        self.assertIsNone(classify(evidence).pool)

    def test_shared_address_is_quarantined(self):
        evidence = base()
        evidence["layer3_sharing"] = "cgnat"
        self.assertIsNone(classify(evidence).pool)

    def test_layer3_asn_mismatch_is_quarantined(self):
        evidence = base()
        evidence["layer3_asn"] = 64501
        self.assertIsNone(classify(evidence).pool)

    def test_layer3_prefix_mismatch_is_quarantined(self):
        evidence = base()
        evidence["layer3_prefix"] = "1.1.1.0/24"
        self.assertIsNone(classify(evidence).pool)

    def test_layer3_country_mismatch_is_quarantined(self):
        evidence = base()
        evidence["layer3_country"] = "CA"
        self.assertIsNone(classify(evidence).pool)

    def test_hosting_with_proxy_flag_is_quarantined(self):
        evidence = base()
        evidence["asn_kind"] = ["hosting"]
        evidence["net_kind"] = ["hosting"]
        evidence["layer3_type"] = "hosting"
        evidence["layer3_network_type"] = "hosting"
        evidence["layer3_flags"]["hosting"] = True
        evidence["layer3_flags"]["proxy"] = True
        evidence["layer3_risk_reasons"] = ["hosting", "datacenter_proxy"]
        self.assertIsNone(classify(evidence).pool)

    def test_vpn_asn_signal_quarantines(self):
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

    def test_unknown_asn_kind_is_quarantined(self):
        evidence = base()
        evidence["asn_kind"] = []
        self.assertIsNone(classify(evidence).pool)

    def test_ip_abuse_report_quarantines(self):
        evidence = base()
        evidence["ip_risk_status"] = "ok"
        evidence["ip_reports"] = 1
        self.assertIsNone(classify(evidence).pool)

    def test_vpn_ip_signal_quarantines(self):
        evidence = base()
        evidence["ip_risk_status"] = "ok"
        evidence["ip_kind"] = ["vpn"]
        evidence["ip_reports"] = 0
        self.assertIsNone(classify(evidence).pool)

    def test_missing_asn_report_count_quarantines(self):
        evidence = base()
        evidence["asn_reports"] = None
        self.assertIsNone(classify(evidence).pool)

    def test_unreported_hosting_asn_is_not_low_risk(self):
        evidence = base()
        evidence["asn_kind"] = ["hosting"]
        evidence["net_kind"] = ["hosting"]
        evidence["oxl_asn_status"] = "not_reported"
        self.assertIsNone(classify(evidence).pool)


    def test_unreported_asn_can_use_strict_independent_layer3_isp_evidence(self):
        evidence = base()
        evidence["oxl_asn_status"] = "not_reported"
        evidence["asn_kind"] = []
        evidence.pop("asn_reports")
        self.assertEqual(classify(evidence).pool, "us-residential")

    def test_unreported_asn_without_layer3_isp_confirmation_is_quarantined(self):
        evidence = base()
        evidence["oxl_asn_status"] = "not_reported"
        evidence["asn_kind"] = []
        evidence["layer3_network_type"] = "unknown"
        self.assertIsNone(classify(evidence).pool)

    def test_unreported_hosting_asn_requires_independent_layer3_hosting_evidence(self):
        evidence = base()
        evidence["oxl_asn_status"] = "not_reported"
        evidence["asn_kind"] = []
        evidence["layer3_type"] = "hosting"
        evidence["layer3_network_type"] = "hosting"
        evidence["layer3_flags"]["hosting"] = True
        evidence["layer3_risk_reasons"] = ["hosting"]
        evidence["net_kind"] = ["hosting"]
        self.assertEqual(classify(evidence).pool, "low-risk-datacenter")

    def test_unreported_asn_with_provider_error_remains_quarantined(self):
        evidence = base()
        evidence["oxl_asn_status"] = "unavailable"
        self.assertIsNone(classify(evidence).pool)

    def test_bad_oxl_network_reputation_quarantines(self):
        evidence = base()
        evidence["net_reputation"] = "warn"
        self.assertIsNone(classify(evidence).pool)

    def test_network_kind_conflict_quarantines(self):
        evidence = base()
        evidence["net_kind"] = ["hosting"]
        self.assertIsNone(classify(evidence).pool)

    def test_cgnat_relay_and_anycast_asn_signals_quarantine(self):
        for kind in ("cgnat", "relay", "anycast"):
            evidence = base()
            evidence["asn_kind"] = ["isp", kind]
            self.assertIsNone(classify(evidence).pool)


if __name__ == "__main__":
    unittest.main()
