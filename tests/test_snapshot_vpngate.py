import json

from scripts.snapshot_vpngate import refresh_snapshot
from scripts.vpngate import save_candidate_history


def candidate():
    return {
        "name": "VPNGate-US-8-8-8-20-volunteer",
        "type": "openvpn",
        "server": "8.8.8.20",
        "port": 443,
        "proto": "tcp",
    }


def test_snapshot_refreshes_current_api_candidates(tmp_path):
    history_path = tmp_path / "candidate-history.json"
    report = refresh_snapshot(
        fetcher=lambda: "csv",
        parser=lambda _: ([candidate()], {"rows_seen": 1}),
        history_path=history_path,
        now=1000.0,
    )
    payload = json.loads(history_path.read_text(encoding="utf-8"))
    assert report["status"] == "ok"
    assert report["current_candidates"] == 1
    assert report["history_candidates"] == 1
    assert payload["candidates"][0]["node"]["name"] == candidate()["name"]


def test_snapshot_preserves_history_when_api_is_unavailable(tmp_path):
    history_path = tmp_path / "candidate-history.json"
    save_candidate_history(
        [{"node": candidate(), "first_seen_at": 100.0, "last_seen_at": 900.0}],
        path=history_path,
        now=900.0,
    )

    def unavailable():
        raise TimeoutError("VPNGate API timed out")

    report = refresh_snapshot(fetcher=unavailable, history_path=history_path, now=1000.0)
    payload = json.loads(history_path.read_text(encoding="utf-8"))
    assert report["status"] == "history_only"
    assert report["api_status"] == "unavailable"
    assert report["history_candidates"] == 1
    assert len(payload["candidates"]) == 1


def test_snapshot_drops_expired_history_when_api_is_unavailable(tmp_path):
    history_path = tmp_path / "candidate-history.json"
    save_candidate_history(
        [{"node": candidate(), "first_seen_at": 1.0, "last_seen_at": 1.0}],
        path=history_path,
        now=1.0,
    )

    def unavailable():
        raise TimeoutError("VPNGate API timed out")

    report = refresh_snapshot(
        fetcher=unavailable,
        history_path=history_path,
        now=14 * 24 * 60 * 60 + 2.0,
    )
    assert report["status"] == "unavailable"
    assert report["history_candidates"] == 0
