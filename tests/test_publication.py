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


class AtomicPublicationTests(unittest.TestCase):
    def test_empty_pool_preserves_all_previous_files(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from scripts.publication import publish_atomically

        with TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {pool: root / f"{pool}.yaml" for pool in POOLS}
            evidence_path = root / "evidence.json"
            for path in [*paths.values(), evidence_path]:
                path.write_text("previous-good", encoding="utf-8")
            profiles, evidence = valid_inputs()
            profiles["other-residential"] = profile()
            evidence["pool_sizes"]["other-residential"] = 0

            with self.assertRaisesRegex(ValueError, "no verified proxies"):
                publish_atomically(paths, profiles, evidence_path, evidence)

            self.assertTrue(all(path.read_text(encoding="utf-8") == "previous-good"
                                for path in [*paths.values(), evidence_path]))

    def test_mihomo_preflight_failure_preserves_previous_files(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from scripts.publication import publish_atomically

        with TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {pool: root / f"{pool}.yaml" for pool in POOLS}
            evidence_path = root / "evidence.json"
            for path in [*paths.values(), evidence_path]:
                path.write_text("previous-good", encoding="utf-8")
            profiles, evidence = valid_inputs()

            def reject_one(pool, rendered):
                if pool == "low-risk-datacenter":
                    raise ValueError("simulated Mihomo rejection")

            with self.assertRaisesRegex(ValueError, "simulated Mihomo"):
                publish_atomically(paths, profiles, evidence_path, evidence,
                                   validate_profile=reject_one)

            self.assertTrue(all(path.read_text(encoding="utf-8") == "previous-good"
                                for path in [*paths.values(), evidence_path]))

    def test_replacement_failure_rolls_back_already_replaced_files(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from unittest.mock import patch
        import os
        from scripts.publication import publish_atomically

        with TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {pool: root / f"{pool}.yaml" for pool in POOLS}
            evidence_path = root / "evidence.json"
            targets = [*paths.values(), evidence_path]
            for index, path in enumerate(targets):
                path.write_text(f"previous-{index}", encoding="utf-8")
            profiles, evidence = valid_inputs()
            real_replace = os.replace
            calls = 0

            def fail_second_replace(source, destination):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated disk failure")
                return real_replace(source, destination)

            with patch("scripts.publication.os.replace", side_effect=fail_second_replace):
                with self.assertRaisesRegex(OSError, "simulated disk failure"):
                    publish_atomically(paths, profiles, evidence_path, evidence)

            self.assertEqual([path.read_text(encoding="utf-8") for path in targets],
                             [f"previous-{index}" for index in range(len(targets))])


    def test_additional_diagnostic_file_is_published_in_same_batch(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from scripts.publication import publish_atomically

        with TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {pool: root / f"{pool}.yaml" for pool in POOLS}
            evidence_path = root / "evidence.json"
            diagnostics_path = root / "diagnostics.json"
            profiles, evidence = valid_inputs()
            publish_atomically(
                paths, profiles, evidence_path, evidence,
                additional_files={diagnostics_path: '{"checked": 3}\n'},
            )
            self.assertEqual(diagnostics_path.read_text(encoding="utf-8"),
                             '{"checked": 3}\n')


    def test_failure_reports_are_written_without_touching_subscriptions(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from scripts.publication import write_reports_atomically

        with TemporaryDirectory() as directory:
            root = Path(directory)
            subscriptions = [root / f"{pool}.yaml" for pool in POOLS]
            for path in subscriptions:
                path.write_text("last-good", encoding="utf-8")
            evidence = root / "classification" / "evidence.json"
            diagnostics = root / "classification" / "diagnostics.json"
            write_reports_atomically(
                evidence, '{"checked": 2}\n',
                {diagnostics: '{"quarantined": 2}\n'},
            )
            self.assertEqual(evidence.read_text(encoding="utf-8"), '{"checked": 2}\n')
            self.assertEqual(diagnostics.read_text(encoding="utf-8"), '{"quarantined": 2}\n')
            self.assertTrue(all(path.read_text(encoding="utf-8") == "last-good"
                                for path in subscriptions))


if __name__ == "__main__":
    unittest.main()
