import unittest
from unittest.mock import Mock, call

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
        self.assertLess(discover.call_args_list[0], classify.call_args_list[0])

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

    def test_publication_verification_runs_only_after_classification(self):
        order = []
        run_pipeline(lambda: order.append("discover"),
                     lambda: order.append("classify"),
                     lambda: order.append("verify"))
        self.assertEqual(order, ["discover", "classify", "verify"])


if __name__ == "__main__":
    unittest.main()
