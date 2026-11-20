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

    def test_hosting_only_baseline_is_eligible_for_datacenter_pool(self):
        evidence = base()
        evidence["asn_kind"] = ["hosting"]
        evidence["net_kind"] = ["hosting"]
        evidence["layer3_type"] = "hosting"
        evidence["layer3_network_type"] = "hosting"
        evidence["layer3_flags"]["hosting"] = True
        evidence["layer3_risk_level"] = "medium"
        evidence["layer3_risk_score"] = 50
        evidence["layer3_risk_reasons"] = ["hosting"]
        self.assertEqual(classify(evidence).pool, "low-risk-datacenter")

    def test_hosting_with_nearby_vpn_reason_is_quarantined(self):
        evidence = base()
        evidence["asn_kind"] = ["hosting"]
        evidence["net_kind"] = ["hosting"]
        evidence["layer3_type"] = "hosting"
        evidence["layer3_network_type"] = "hosting"
        evidence["layer3_flags"]["hosting"] = True
        evidence["layer3_risk_level"] = "medium"
        evidence["layer3_risk_score"] = 50
        evidence["layer3_risk_reasons"] = ["hosting", "nearby_vpn"]
        self.assertIsNone(classify(evidence).pool)

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


    def test_vpngate_vpn_on_isp_access_is_separated_as_unverified_candidate(self):
        evidence = base()
        evidence["node_name"] = "VPNGate-US-192-0-2-10-example"
        evidence["layer3_type"] = "vpn"
        evidence["layer3_risk_level"] = "high"
        evidence["layer3_risk_score"] = 75
        evidence["layer3_risk_reasons"] = ["vpn"]
        evidence["layer3_flags"]["anonymizer"] = True
        evidence["layer3_flags"]["vpn"] = True
        verdict = classify(evidence)
        self.assertIsNone(verdict.pool)
        self.assertEqual(verdict.reason, "vpngate_isp_access_relay_candidate_unverified")


    def test_vpngate_us_fixed_isp_brand_gets_specific_unverified_candidate_reason(self):
        evidence = base()
        evidence["node_name"] = "VPNGate-US-203-0-113-10-volunteer"
        evidence["isp"] = "Comcast Cable Communications, LLC"
        evidence["layer3_type"] = "vpn"
        evidence["layer3_risk_level"] = "high"
        evidence["layer3_risk_score"] = 75
        evidence["layer3_risk_reasons"] = ["vpn"]
        evidence["layer3_flags"]["anonymizer"] = True
        evidence["layer3_flags"]["vpn"] = True
        verdict = classify(evidence)
        self.assertIsNone(verdict.pool)
        self.assertEqual(verdict.reason, "vpngate_us_consumer_isp_candidate_unverified")

    def test_vpngate_non_us_fixed_isp_brand_gets_specific_unverified_candidate_reason(self):
        evidence = base()
        evidence["node_name"] = "VPNGate-KR-203-0-113-11-volunteer"
        evidence["country_code"] = "KR"
        evidence["layer3_country"] = "KR"
        evidence["isp"] = "Korea Telecom"
        evidence["layer3_type"] = "vpn"
        evidence["layer3_risk_level"] = "high"
        evidence["layer3_risk_score"] = 75
        evidence["layer3_risk_reasons"] = ["vpn"]
        evidence["layer3_flags"]["anonymizer"] = True
        evidence["layer3_flags"]["vpn"] = True
        verdict = classify(evidence)
        self.assertIsNone(verdict.pool)
        self.assertEqual(verdict.reason, "vpngate_other_consumer_isp_candidate_unverified")

    def test_mobile_isp_brand_is_not_treated_as_fixed_home_broadband_candidate(self):
        evidence = base()
        evidence["node_name"] = "VPNGate-US-203-0-113-12-volunteer"
        evidence["isp"] = "SoftBank Mobile Corp."
        evidence["layer3_type"] = "vpn"
        evidence["layer3_risk_level"] = "high"
        evidence["layer3_risk_score"] = 75
        evidence["layer3_risk_reasons"] = ["vpn"]
        evidence["layer3_flags"]["anonymizer"] = True
        evidence["layer3_flags"]["vpn"] = True
        verdict = classify(evidence)
        self.assertIsNone(verdict.pool)
        self.assertEqual(verdict.reason, "vpngate_isp_access_relay_candidate_unverified")


    def _vpngate_access_candidate(self):
        evidence = base()
        evidence["node_name"] = "VPNGate-US-203-0-113-10-volunteer"
        evidence["isp"] = "Comcast Cable Communications, LLC"
        evidence["metadata_source"] = "ipwho.is"
        evidence["ipwho_type"] = "ipv4"
        evidence["ipwho_security"] = {
            "hosting": None, "proxy": None, "vpn": None, "tor": None,
        }
        evidence["layer3_type"] = "vpn"
        evidence["layer3_network_type"] = "access"
        evidence["layer3_prefix_match"] = True
        evidence["layer3_risk_level"] = "high"
        evidence["layer3_risk_score"] = 75
        evidence["layer3_risk_reasons"] = ["vpn"]
        evidence["layer3_flags"]["anonymizer"] = True
        evidence["layer3_flags"]["vpn"] = True
        evidence["net_status"] = "not_reported"
        evidence["net_kind"] = ["isp"]
        evidence["net_source"] = "layer3-open-network"
        evidence["net_reports"] = 0
        evidence["net_reputation"] = "not_reported"
        evidence["oxl_asn_status"] = "ok"
        evidence["asn_kind"] = ["isp"]
        return evidence

    def test_vpngate_optional_ipapi_is_evidence_must_confirm_fixed_isp_and_clean_flags(self):
        evidence = self._vpngate_access_candidate()
        evidence.update({
            "ipapi_is_status": "ok",
            "ipapi_is_flags": {
                "is_datacenter": False, "is_proxy": False, "is_tor": False,
                "is_abuser": False, "is_mobile": False, "is_satellite": False,
                "is_anycast": False, "is_crawler": False,
            },
            "ipapi_is_vpn": True,
            "ipapi_is_company_type": "isp",
            "ipapi_is_asn_type": "isp",
            "ipapi_is_asn": 64500,
            "ipapi_is_country": "US",
        })
        self.assertEqual(classify(evidence).pool, "us-residential")

    def test_vpngate_ipapi_is_datacenter_or_mobile_flag_blocks_residential(self):
        for flag in ("is_datacenter", "is_mobile", "is_proxy", "is_tor", "is_abuser"):
            evidence = self._vpngate_access_candidate()
            evidence.update({
                "ipapi_is_status": "ok",
                "ipapi_is_flags": {
                    "is_datacenter": False, "is_proxy": False, "is_tor": False,
                    "is_abuser": False, "is_mobile": False, "is_satellite": False,
                    "is_anycast": False, "is_crawler": False,
                },
                "ipapi_is_company_type": "isp",
                "ipapi_is_asn_type": "isp",
                "ipapi_is_asn": 64500,
                "ipapi_is_country": "US",
            })
            evidence["ipapi_is_flags"][flag] = True
            self.assertIsNone(classify(evidence).pool, flag)

    def test_vpngate_ipapi_is_asn_and_country_must_match(self):
        evidence = self._vpngate_access_candidate()
        evidence.update({
            "ipapi_is_status": "ok",
            "ipapi_is_flags": {
                "is_datacenter": False, "is_proxy": False, "is_tor": False,
                "is_abuser": False, "is_mobile": False, "is_satellite": False,
                "is_anycast": False, "is_crawler": False,
            },
            "ipapi_is_company_type": "isp",
            "ipapi_is_asn_type": "isp",
            "ipapi_is_asn": 64501,
            "ipapi_is_country": "US",
        })
        self.assertIsNone(classify(evidence).pool)
        evidence["ipapi_is_asn"] = 64500
        evidence["ipapi_is_country"] = "CA"
        self.assertIsNone(classify(evidence).pool)


    def test_vpngate_fixed_isp_access_exit_passes_with_oxl_isp_asn(self):
        evidence = self._vpngate_access_candidate()
        verdict = classify(evidence)
        self.assertEqual(verdict.pool, "us-residential")
        self.assertEqual(verdict.reason, "vpngate_isp_access_layer3_confirmed")

    def test_vpngate_fixed_isp_access_exit_can_use_matching_layer3_when_oxl_asn_unreported(self):
        evidence = self._vpngate_access_candidate()
        evidence["oxl_asn_status"] = "not_reported"
        evidence["asn_kind"] = []
        verdict = classify(evidence)
        self.assertEqual(verdict.pool, "us-residential")
        self.assertEqual(verdict.reason, "vpngate_isp_access_layer3_confirmed")

    def test_vpngate_candidate_without_access_network_confirmation_is_not_promoted(self):
        evidence = self._vpngate_access_candidate()
        evidence["layer3_network_type"] = "hosting"
        self.assertIsNone(classify(evidence).pool)

    def test_vpngate_candidate_with_hosting_asn_is_not_promoted(self):
        evidence = self._vpngate_access_candidate()
        evidence["asn_kind"] = ["hosting"]
        self.assertIsNone(classify(evidence).pool)

    def test_vpngate_mobile_operator_is_not_promoted_to_fixed_residential(self):
        evidence = self._vpngate_access_candidate()
        evidence["isp"] = "SoftBank Mobile Corp."
        evidence["country_code"] = "JP"
        evidence["layer3_country"] = "JP"
        evidence["node_name"] = "VPNGate-JP-126-76-26-123-volunteer"
        self.assertIsNone(classify(evidence).pool)

    def test_vpngate_access_candidate_with_ip_abuse_reports_is_not_promoted(self):
        evidence = self._vpngate_access_candidate()
        evidence["ip_risk_status"] = "ok"
        evidence["ip_kind"] = ["isp"]
        evidence["ip_reports"] = 1
        self.assertEqual(classify(evidence).reason, "ip_has_abuse_reports")

    def test_vpngate_access_candidate_with_network_abuse_reports_is_not_promoted(self):
        evidence = self._vpngate_access_candidate()
        evidence["net_status"] = "ok"
        evidence["net_source"] = "oxl-api"
        evidence["net_reputation"] = "ok"
        evidence["net_reports"] = 1
        self.assertEqual(classify(evidence).reason, "network_has_abuse_reports")

    def test_same_vpn_signal_from_non_vpngate_source_remains_generic_quarantine(self):
        evidence = base()
        evidence["node_name"] = "OtherSource-US-example"
        evidence["layer3_type"] = "vpn"
        evidence["layer3_risk_level"] = "high"
        evidence["layer3_risk_score"] = 75
        evidence["layer3_risk_reasons"] = ["vpn"]
        evidence["layer3_flags"]["anonymizer"] = True
        evidence["layer3_flags"]["vpn"] = True
        verdict = classify(evidence)
        self.assertIsNone(verdict.pool)
        self.assertEqual(verdict.reason, "layer3_anonymizer_signal")

    def test_vpngate_relay_candidate_with_proxy_or_tor_signal_is_not_separated(self):
        evidence = base()
        evidence["node_name"] = "VPNGate-US-example"
        evidence["layer3_type"] = "vpn"
        evidence["layer3_risk_level"] = "high"
        evidence["layer3_risk_score"] = 75
        evidence["layer3_risk_reasons"] = ["vpn", "proxy"]
        evidence["layer3_flags"]["anonymizer"] = True
        evidence["layer3_flags"]["vpn"] = True
        evidence["layer3_flags"]["proxy"] = True
        verdict = classify(evidence)
        self.assertIsNone(verdict.pool)
        self.assertEqual(verdict.reason, "layer3_anonymizer_signal")

    def test_vpn_asn_signal_quarantines(self):
        evidence = base()
        evidence["asn_kind"] = ["isp", "vpn"]
        self.assertIsNone(classify(evidence).pool)

    def test_aggregate_asn_reports_do_not_override_clean_exact_exit_evidence(self):
        evidence = base()
        evidence["asn_reports"] = 2180
        self.assertEqual(classify(evidence).pool, "us-residential")

    def test_disqualifying_asn_kind_still_quarantines(self):
        evidence = base()
        evidence["asn_kind"] = ["isp", "scanner"]
        evidence["asn_reports"] = 0
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
        evidence["layer3_risk_level"] = "medium"
        evidence["layer3_risk_score"] = 50
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
