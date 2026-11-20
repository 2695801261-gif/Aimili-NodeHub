"""Fail-closed validation of generated subscription profiles before publication."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
POOL_FILES = {
    "us-residential": ROOT / "subscriptions" / "us-residential.yaml",
    "other-residential": ROOT / "subscriptions" / "other-residential.yaml",
    "low-risk-datacenter": ROOT / "subscriptions" / "low-risk-datacenter.yaml",
}
EVIDENCE_FILE = ROOT / "classification" / "evidence.json"


def validate_publication(
    profiles: dict[str, dict[str, Any]], evidence: dict[str, Any]
) -> dict[str, int]:
    """Reject malformed, overlapping, or evidence-inconsistent pools.

    Empty pools are valid only when explicitly marked as preserved-empty. This
    allows first-time operation without fabricating nodes while preventing an
    accidental empty rewrite of an existing non-empty subscription.
    """
    if set(profiles) != set(POOL_FILES):
        raise ValueError("publication must contain exactly the three configured pools")

    seen: set[str] = set()
    sizes: dict[str, int] = {}
    for pool, profile in profiles.items():
        if not isinstance(profile, dict):
            raise ValueError(f"{pool}: profile must be a mapping")
        proxies = profile.get("proxies")
        if not isinstance(proxies, list) or not proxies:
            raise ValueError(f"{pool}: no verified proxies; refusing empty publication")

        names: list[str] = []
        for item in proxies:
            if not isinstance(item, dict):
                raise ValueError(f"{pool}: malformed proxy entry")
            name = item.get("name")
            if not isinstance(name, str) or not name.strip():
                raise ValueError(f"{pool}: proxy name missing")
            names.append(name)

        if len(names) != len(set(names)):
            raise ValueError(f"{pool}: duplicate proxy names")
        overlap = seen.intersection(names)
        if overlap:
            raise ValueError(f"proxy appears in multiple pools: {sorted(overlap)[:5]}")
        seen.update(names)

        groups = profile.get("proxy-groups")
        if not isinstance(groups, list) or not groups:
            raise ValueError(f"{pool}: no proxy groups")
        group_members = {
            member
            for group in groups if isinstance(group, dict)
            for member in (group.get("proxies") or [])
            if isinstance(member, str)
        }
        if not set(names).issubset(group_members):
            raise ValueError(f"{pool}: proxy group does not reference every proxy")
        sizes[pool] = len(names)

    reported = evidence.get("pool_sizes")
    if not isinstance(reported, dict):
        raise ValueError("evidence report has no pool_sizes mapping")
    for pool, size in sizes.items():
        if reported.get(pool) != size:
            raise ValueError(
                f"{pool}: evidence count {reported.get(pool)!r} "
                f"does not match profile count {size}"
            )
    return sizes


def main() -> None:
    profiles = {
        pool: yaml.safe_load(path.read_text(encoding="utf-8"))
        for pool, path in POOL_FILES.items()
    }
    evidence = json.loads(EVIDENCE_FILE.read_text(encoding="utf-8"))
    sizes = validate_publication(profiles, evidence)
    print("Publication gate passed:", json.dumps(sizes, sort_keys=True))


if __name__ == "__main__":
    main()
