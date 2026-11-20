"""Single end-to-end NodeHub module: discover, classify, validate, publish.

FreeNodes supplies the multi-adapter subscription discovery, while VPN Gate
is collected independently as a native Mihomo OpenVPN source. This module
owns the orchestration boundary and only returns success after all three
non-empty subscriptions pass the publication gate.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
DISCOVERY_TIMEOUT_SECONDS = 25 * 60

FREE_NODES_PROFILE = ROOT / "nodes" / "merged.yaml"
SOURCE_REPORT = ROOT / "classification" / "source-discovery.json"
OPTIONAL_DISCOVERY_OUTPUTS = (
    ROOT / "nodes" / "v2ray.txt",
    ROOT / "nodes" / "publication-receipt.json",
)


def discover_nodes() -> None:
    """Run FreeNodes and VPN Gate independently so one source cannot block the other."""
    freenodes_status = "ok"
    freenodes_error = None
    try:
        subprocess.run(
            [sys.executable, str(ROOT / "main.py")],
            cwd=ROOT,
            check=True,
            timeout=DISCOVERY_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        freenodes_status = "timeout"
        freenodes_error = f"FreeNodes exceeded {DISCOVERY_TIMEOUT_SECONDS} seconds"
        print(f"FreeNodes discovery warning: {freenodes_error}", flush=True)
    except (subprocess.CalledProcessError, OSError) as error:
        freenodes_status = "failed"
        freenodes_error = f"{type(error).__name__}: {' '.join(str(error).split())[:220]}"
        print(f"FreeNodes discovery warning: {freenodes_error}", flush=True)

    # Never reuse a stale prior-run FreeNodes profile after an upstream failure.
    # An empty primary profile still allows the independent VPN Gate source to run.
    if freenodes_status != "ok" or not FREE_NODES_PROFILE.is_file() or FREE_NODES_PROFILE.stat().st_size == 0:
        FREE_NODES_PROFILE.parent.mkdir(parents=True, exist_ok=True)
        FREE_NODES_PROFILE.write_text("proxies: []\n", encoding="utf-8")

    missing_optional = [
        str(path.relative_to(ROOT)) for path in OPTIONAL_DISCOVERY_OUTPUTS
        if not path.is_file() or path.stat().st_size == 0
    ]
    from scripts.vpngate import collect_vpngate

    source_report = collect_vpngate()
    source_report["freenodes"] = {
        "status": freenodes_status,
        "error": freenodes_error,
        "missing_optional_outputs": missing_optional,
    }
    SOURCE_REPORT.parent.mkdir(parents=True, exist_ok=True)
    SOURCE_REPORT.write_text(
        json.dumps(source_report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print("Combined discovery source report:", json.dumps(source_report, ensure_ascii=False, sort_keys=True), flush=True)


def classify_and_publish() -> None:
    """Probe observed exits and atomically publish all three Mihomo profiles."""
    from scripts.classify_exits import run as classify_run

    classify_run()


def verify_published_subscriptions() -> None:
    """Run the independent on-disk publication gate after atomic publication."""
    from scripts.check_publication import main as publication_check

    publication_check()


def run_pipeline(
    discover: Callable[[], None] = discover_nodes,
    classify: Callable[[], None] = classify_and_publish,
    verify: Callable[[], None] = verify_published_subscriptions,
) -> None:
    """Execute the indivisible discovery-to-subscription pipeline in order."""
    discover()
    classify()
    verify()


def main() -> None:
    print("NodeHub pipeline: discovery -> exit verification -> three-pool publication",
          flush=True)
    run_pipeline()
    print("NodeHub pipeline complete: all three subscriptions passed validation.",
          flush=True)


if __name__ == "__main__":
    main()
