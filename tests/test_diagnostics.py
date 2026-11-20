import unittest

from scripts.diagnostics import build_diagnostics


class DiagnosticsTests(unittest.TestCase):
    def test_aggregates_reasons_provider_states_and_echo_results(self):
        report = build_diagnostics(
            [
                {"pool": None, "reason": "asn_has_abuse_reports",
                 "oxl_asn_status": "ok", "ip_risk_status": "not_reported",
                 "net_status": "not_reported", "exit_echo_agreement": True,
                 "metadata_source": "ipwho.is"},
                {"pool": None, "reason": "asn_intelligence_unavailable",
                 "oxl_asn_status": "unavailable", "ip_risk_status": "not_checked",
                 "metadata_status": "unavailable",
                 "net_status": "not_checked", "layer3_status": "not_checked",
                 "exit_echo_agreement": None,
                 "metadata_source": "ipinfo.io"},
                {"pool": "us-residential", "reason": "layer3_residential_access_and_isp_asn_confirmed",
                 "oxl_asn_status": "ok", "ip_risk_status": "ok",
                 "net_status": "ok", "exit_echo_agreement": True,
                 "metadata_source": "ipwho.is"},
            ],
            pool_sizes={"us-residential": 1, "other-residential": 0,
                        "low-risk-datacenter": 0},
            candidate_limit=25,
        )
        self.assertEqual(report["checked"], 3)
        self.assertEqual(report["accepted"], 1)
        self.assertEqual(report["quarantined"], 2)
        self.assertEqual(report["reason_counts"]["asn_has_abuse_reports"], 1)
        self.assertEqual(report["provider_status_counts"]["oxl_asn_status"]["unavailable"], 1)
        self.assertEqual(report["exit_echo"], {
            "agreement": 2, "disagreement": 0, "not_checked": 1
        })


    def test_unprobed_echo_is_not_counted_as_disagreement(self):
        report = build_diagnostics(
            [{"pool": None, "reason": "proxy_unavailable",
              "exit_echo_agreement": None, "layer3_status": "not_checked"}],
            pool_sizes={"us-residential": 0, "other-residential": 0,
                        "low-risk-datacenter": 0},
            candidate_limit=25,
        )
        self.assertEqual(report["exit_echo"], {
            "agreement": 0, "disagreement": 0, "not_checked": 1
        })
        self.assertEqual(report["provider_status_counts"]["layer3_status"]["not_checked"], 1)


if __name__ == "__main__":
    unittest.main()
