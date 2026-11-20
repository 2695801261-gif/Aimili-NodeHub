"""Aggregate auditable classification diagnostics without weakening policy."""
from __future__ import annotations

from collections import Counter
from typing import Any, Iterable


def build_diagnostics(rows: Iterable[dict[str, Any]], *, pool_sizes: dict[str, int],
                      candidate_limit: int) -> dict[str, Any]:
    evidence = list(rows)
    reasons = Counter(str(row.get("reason") or "reason_missing") for row in evidence)
    fields = ("metadata_source", "metadata_status", "ip_risk_status", "net_status", "oxl_asn_status", "layer3_status", "ipapi_is_status")
    statuses = {
        field: dict(sorted(Counter(str(row.get(field) or "not_checked")
                                    for row in evidence).items()))
        for field in fields
    }
    return {
        "schema_version": 1,
        "candidate_limit": candidate_limit,
        "checked": len(evidence),
        "accepted": sum(1 for row in evidence if row.get("pool")),
        "quarantined": sum(1 for row in evidence if not row.get("pool")),
        "pool_sizes": dict(sorted(pool_sizes.items())),
        "reason_counts": dict(sorted(reasons.items())),
        "provider_status_counts": statuses,
        "exit_echo": {
            "agreement": sum(1 for row in evidence if row.get("exit_echo_agreement") is True),
            "disagreement": sum(1 for row in evidence if row.get("exit_echo_agreement") is False),
            "not_checked": sum(1 for row in evidence if row.get("exit_echo_agreement") is None),
        },
    }
