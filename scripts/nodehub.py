"""Single end-to-end NodeHub module: discover, classify, validate, publish.

The pinned FreeNodes engine remains the discovery implementation. This module
owns the orchestration boundary and only returns success after all three
non-empty subscriptions pass the publication gate.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
DISCOVERY_TIMEOUT_SECONDS = 25 * 60

REQUIRED_DISCOVERY_OUTPUTS = (
    ROOT / "nodes" / "merged.yaml",
    ROOT / "nodes" / "v2ray.txt",
    ROOT / "nodes" / "publication-receipt.json",
)


def discover_nodes() -> None:
    """Run the pinned upstream collector in the same locked Python environment."""
    subprocess.run(
        [sys.executable, str(ROOT / "main.py")],
        cwd=ROOT,
        check=True,
        timeout=DISCOVERY_TIMEOUT_SECONDS,
    )
    missing = [str(path.relative_to(ROOT)) for path in REQUIRED_DISCOVERY_OUTPUTS
               if not path.is_file() or path.stat().st_size == 0]
    if missing:
        raise RuntimeError("discovery did not produce required artifacts: " + ", ".join(missing))


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
