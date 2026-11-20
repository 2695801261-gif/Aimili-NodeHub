import unittest

from scripts.check_publication import validate_publication

POOLS = ("us-residential", "other-residential", "low-risk-datacenter")


def profile(*names):
    return {
        "proxies": [{"name": name, "type": "ss"} for name in names],
        "proxy-groups": [{"name": "NODEHUB", "type": "select", "proxies": list(names)}],
    }


def valid_inputs():
    profiles = {pool: profile(pool + "-node") for pool in POOLS}
    evidence = {"pool_sizes": {pool: 1 for pool in POOLS}}
    return profiles, evidence


class PublicationGateTests(unittest.TestCase):
    def test_accepts_three_nonempty_consistent_pools(self):
        profiles, evidence = valid_inputs()
        self.assertEqual(validate_publication(profiles, evidence), {pool: 1 for pool in POOLS})

    def test_rejects_empty_pool(self):
        profiles, evidence = valid_inputs()
        profiles["other-residential"] = profile()
        evidence["pool_sizes"]["other-residential"] = 0
        with self.assertRaisesRegex(ValueError, "no verified proxies"):
            validate_publication(profiles, evidence)

    def test_rejects_cross_pool_duplicate(self):
        profiles, evidence = valid_inputs()
        profiles["other-residential"] = profile("us-residential-node")
        with self.assertRaisesRegex(ValueError, "multiple pools"):
            validate_publication(profiles, evidence)

    def test_rejects_missing_group_reference(self):
        profiles, evidence = valid_inputs()
        profiles["us-residential"]["proxy-groups"][0]["proxies"] = []
        with self.assertRaisesRegex(ValueError, "does not reference"):
            validate_publication(profiles, evidence)

    def test_rejects_evidence_count_mismatch(self):
        profiles, evidence = valid_inputs()
        evidence["pool_sizes"]["low-risk-datacenter"] = 0
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_publication(profiles, evidence)


if __name__ == "__main__":
    unittest.main()
