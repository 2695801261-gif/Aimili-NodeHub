"""Refresh the VPNGate rolling candidate cache without running exit probes."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

from scripts.vpngate import (
    HISTORY_FILE,
    VPNGATE_API,
    fetch_directory,
    load_candidate_history,
    merge_candidate_history,
    parse_directory,
    save_candidate_history,
)


def refresh_snapshot(
    *,
    fetcher: Callable[[], str] = fetch_directory,
    parser: Callable[[str], tuple[list[dict[str, Any]], dict[str, Any]]] = parse_directory,
    history_path: Path = HISTORY_FILE,
    now: float | None = None,
) -> dict[str, Any]:
    timestamp = time.time() if now is None else float(now)
    previous = load_candidate_history(history_path)
    try:
        csv_text = fetcher()
        current, source_report = parser(csv_text)
        history, stats = merge_candidate_history(current, previous, now=timestamp)
        save_candidate_history(history, path=history_path, now=timestamp)
        return {
            "source": "vpngate_official_csv",
            "endpoint": VPNGATE_API,
            "api_status": "ok",
            "status": "ok" if current else ("history_only" if history else "empty"),
            "rows_seen": source_report.get("rows_seen", 0),
            "current_candidates": len(current),
            "history_candidates": len(history),
            "off_window_retained": stats["off_window_retained"],
            "history_expired": stats["history_expired"],
            "history_invalid": stats["history_invalid"],
            "ttl_days": 14,
        }
    except Exception as error:
        history, stats = merge_candidate_history([], previous, now=timestamp)
        save_candidate_history(history, path=history_path, now=timestamp)
        return {
            "source": "vpngate_official_csv",
            "endpoint": VPNGATE_API,
            "api_status": "unavailable",
            "status": "history_only" if history else "unavailable",
            "error": f"{type(error).__name__}: {' '.join(str(error).split())[:200]}",
            "current_candidates": 0,
            "history_candidates": len(history),
            "off_window_retained": stats["off_window_retained"],
            "history_expired": stats["history_expired"],
            "history_invalid": stats["history_invalid"],
            "ttl_days": 14,
        }


def main() -> None:
    report = refresh_snapshot()
    print("VPN Gate candidate snapshot:", json.dumps(report, ensure_ascii=False, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
