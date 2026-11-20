import unittest
from unittest.mock import Mock

from scripts.nodehub import run_pipeline


class NodeHubPipelineTests(unittest.TestCase):
    def test_runs_discovery_classification_and_publication_gate_in_order(self):
        discover = Mock()
        classify = Mock()
        verify = Mock()

        run_pipeline(discover, classify, verify)

        self.assertEqual(discover.call_count, 1)
        self.assertEqual(classify.call_count, 1)
        self.assertEqual(verify.call_count, 1)

    def test_discovery_failure_stops_before_classification_and_publication(self):
        discover = Mock(side_effect=RuntimeError("discovery failed"))
        classify = Mock()
        verify = Mock()

        with self.assertRaisesRegex(RuntimeError, "discovery failed"):
            run_pipeline(discover, classify, verify)

        classify.assert_not_called()
        verify.assert_not_called()

    def test_classification_failure_stops_before_publication_verification(self):
        discover = Mock()
        classify = Mock(side_effect=RuntimeError("classification failed"))
        verify = Mock()

        with self.assertRaisesRegex(RuntimeError, "classification failed"):
            run_pipeline(discover, classify, verify)

        discover.assert_called_once_with()
        verify.assert_not_called()


    def test_exit_probe_budget_is_spread_across_full_ranked_candidate_pool(self):
        from scripts.classify_exits import select_exit_candidates

        candidates = [{"name": str(index)} for index in range(500)]
        selected = select_exit_candidates(candidates, 25)

        self.assertEqual(len(selected), 25)
        self.assertEqual(selected[0]["name"], "10")
        self.assertEqual(selected[-1]["name"], "490")
        self.assertEqual(len({item["name"] for item in selected}), 25)

    def test_exit_probe_budget_includes_vpngate_candidates_by_source_quota(self):
        from scripts.classify_exits import select_exit_candidates

        candidates = (
            [{"name": f"free-{i}"} for i in range(400)]
            + [{"name": f"VPNGate-JP-{i}"} for i in range(100)]
        )
        selected = select_exit_candidates(candidates, 25)

        self.assertEqual(len(selected), 25)
        self.assertEqual(sum(item["name"].startswith("VPNGate-") for item in selected), 13)
        self.assertEqual(sum(item["name"].startswith("free-") for item in selected), 12)

    def test_vpngate_source_sampling_rotates_between_scheduled_runs(self):
        from scripts.classify_exits import select_exit_candidates

        candidates = (
            [{"name": f"free-{i}"} for i in range(400)]
            + [{"name": f"VPNGate-JP-{i}"} for i in range(100)]
        )
        first = select_exit_candidates(candidates, 25, rotation=0)
        second = select_exit_candidates(candidates, 25, rotation=1)
        first_vpn = {item["name"] for item in first if item["name"].startswith("VPNGate-")}
        second_vpn = {item["name"] for item in second if item["name"].startswith("VPNGate-")}

        self.assertEqual(len(first_vpn), 5)
        self.assertEqual(len(second_vpn), 5)
        self.assertTrue(first_vpn.isdisjoint(second_vpn))

    def test_exit_probe_selection_returns_all_when_pool_is_smaller_than_budget(self):
        from scripts.classify_exits import select_exit_candidates

        candidates = [{"name": str(index)} for index in range(4)]
        self.assertEqual(select_exit_candidates(candidates, 25), candidates)

    def test_exit_probe_selection_rejects_nonpositive_budget(self):
        from scripts.classify_exits import select_exit_candidates

        with self.assertRaisesRegex(ValueError, "positive"):
            select_exit_candidates([{"name": "one"}], 0)

    def test_combines_freenodes_and_vpngate_with_a_bounded_interleaved_pool(self):
        from scripts.classify_exits import combine_candidate_sources

        primary = [{"name": f"free-{i}"} for i in range(500)]
        vpn = [{"name": f"VPNGate-JP-{i}"} for i in range(120)]
        combined, counts = combine_candidate_sources(primary, vpn)

        self.assertEqual(len(combined), 500)
        self.assertEqual(counts["freenodes_included"], 400)
        self.assertEqual(counts["vpngate_included"], 100)
        self.assertEqual(combined[4]["name"], "VPNGate-JP-0")
        self.assertEqual(combined[9]["name"], "VPNGate-JP-1")

    def test_vpngate_candidates_remain_usable_when_freenodes_pool_is_empty(self):
        from scripts.classify_exits import combine_candidate_sources

        vpn = [{"name": f"VPNGate-JP-{i}"} for i in range(7)]
        combined, counts = combine_candidate_sources([], vpn)

        self.assertEqual(combined, vpn)
        self.assertEqual(counts["freenodes_included"], 0)
        self.assertEqual(counts["vpngate_included"], 7)

    def test_combined_pool_keeps_all_primary_candidates_without_vpngate(self):
        from scripts.classify_exits import combine_candidate_sources

        primary = [{"name": f"free-{i}"} for i in range(600)]
        combined, counts = combine_candidate_sources(primary, [])
        self.assertEqual(len(combined), 500)
        self.assertEqual(counts["vpngate_included"], 0)

    def test_publication_verification_runs_only_after_classification(self):
        order = []
        run_pipeline(lambda: order.append("discover"),
                     lambda: order.append("classify"),
                     lambda: order.append("verify"))
        self.assertEqual(order, ["discover", "classify", "verify"])


if __name__ == "__main__":
    unittest.main()
