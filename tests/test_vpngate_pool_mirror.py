import base64
import hashlib
import json
import tempfile
import unittest
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

from scripts.vpngate_pool_mirror import (
    INDEX_URL,
    RollingMirrorError,
    collect_vpngate_rolling,
    load_catalog,
    select_reachable_rows,
    _proxy_from_row,
)
from scripts.vpngate import VPNGateError


CA = """-----BEGIN CERTIFICATE-----
MIIBtestcertificate
-----END CERTIFICATE-----"""


def iso(value):
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def make_fixture(now):
    commit = "a" * 40
    config_files = {}
    rows = []

    specs = [
        ("US", "1.1.1.1", "reachable", timedelta(hours=1), timedelta(hours=1)),
        ("US", "8.8.8.8", "unreachable", timedelta(hours=1), timedelta(hours=1)),
        ("JP", "9.9.9.9", "reachable", timedelta(hours=1), timedelta(hours=1)),
        ("US", "4.2.2.2", "reachable", timedelta(hours=13), timedelta(hours=1)),
        ("US", "208.67.222.222", "reachable", timedelta(hours=1), timedelta(days=8)),
    ]
    for index, (country, ip, status, checked_age, seen_age) in enumerate(specs):
        config_text = (
            "client\n"
            "dev tun\n"
            "proto tcp-client\n"
            f"remote {ip} 443 tcp-client\n"
            "auth-user-pass\n"
            "<ca>\n"
            f"{CA}\n"
            "</ca>\n"
        )
        raw_config = config_text.encode("utf-8")
        config_hash = hashlib.sha256(raw_config).hexdigest()
        config_doc = {
            "schema_version": 1,
            "kind": "vpngate-pool-config",
            "openvpn_config_base64": base64.b64encode(raw_config).decode("ascii"),
            "openvpn_config_sha256": config_hash,
            "openvpn_config_bytes": len(raw_config),
        }
        config_body = json.dumps(config_doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        config_path = f"pool/configs/{config_hash}.json"
        config_files[config_path] = config_body
        endpoint = {"ip": ip, "port": 443}
        rows.append({
            "id": "v1:" + hashlib.sha256(f"node-{index}".encode()).hexdigest(),
            "hostname": f"vpn{index}.example.net",
            "ip": ip,
            "country_code": country,
            "country_name": "United States" if country == "US" else "Japan",
            "score": 1000 - index,
            "ping_ms": 20 + index,
            "speed_bps": 1000000,
            "num_vpn_sessions": 1,
            "openvpn_config_sha256": config_hash,
            "openvpn_config_bytes": len(raw_config),
            "first_seen_at": iso(now - timedelta(days=2)),
            "last_seen_at": iso(now - seen_age),
            "present_in_latest_source": False,
            "config": {
                "path": config_path,
                "sha256": hashlib.sha256(config_body).hexdigest(),
                "bytes": len(config_body),
            },
            "probe_targets": [endpoint],
            "probe_reason": "tcp",
            "tcp_probe": {
                "status": status,
                "probe_source": "cloudflare_workers",
                "checked_at": iso(now - checked_age),
                "last_success_at": iso(now - timedelta(hours=1)),
                "round": 1,
                "worker_id": "worker-test",
                "consecutive_failures": 0,
                "last_failure_round": None,
                "connect_ms": 35,
                "connected_endpoint": endpoint if status == "reachable" else None,
            },
        })

    # UDP is explicitly not applicable to the mirror's TCP-only Worker probe.
    udp_ip = "8.8.4.4"
    udp_config_text = (
        "client\n"
        "dev tun\n"
        "proto udp\n"
        f"remote {udp_ip} 1194 udp\n"
        "auth-user-pass\n"
        "<ca>\n"
        f"{CA}\n"
        "</ca>\n"
    )
    udp_raw = udp_config_text.encode("utf-8")
    udp_hash = hashlib.sha256(udp_raw).hexdigest()
    udp_doc = {
        "schema_version": 1,
        "kind": "vpngate-pool-config",
        "openvpn_config_base64": base64.b64encode(udp_raw).decode("ascii"),
        "openvpn_config_sha256": udp_hash,
        "openvpn_config_bytes": len(udp_raw),
    }
    udp_body = json.dumps(udp_doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    udp_path = f"pool/configs/{udp_hash}.json"
    config_files[udp_path] = udp_body
    rows.append({
        "id": "v1:" + hashlib.sha256(b"udp-node").hexdigest(),
        "hostname": "vpn-udp.example.net",
        "ip": udp_ip,
        "country_code": "US",
        "country_name": "United States",
        "score": 500,
        "ping_ms": 45,
        "speed_bps": 500000,
        "num_vpn_sessions": 2,
        "openvpn_config_sha256": udp_hash,
        "openvpn_config_bytes": len(udp_raw),
        "first_seen_at": iso(now - timedelta(days=1)),
        "last_seen_at": iso(now - timedelta(hours=1)),
        "present_in_latest_source": True,
        "config": {
            "path": udp_path,
            "sha256": hashlib.sha256(udp_body).hexdigest(),
            "bytes": len(udp_body),
        },
        "probe_targets": [],
        "probe_reason": "udp",
        "tcp_probe": {
            "status": "not_applicable",
            "probe_source": "cloudflare_workers",
            "checked_at": None,
            "last_success_at": None,
            "round": None,
            "worker_id": None,
            "consecutive_failures": 0,
            "last_failure_round": None,
            "connect_ms": None,
            "connected_endpoint": None,
        },
    })

    country_counts = Counter(row["country_code"] for row in rows)
    fetched_at = iso(now)
    servers_doc = {
        "kind": "vpngate-pool",
        "schema_version": 1,
        "source_fetched_at": fetched_at,
        "server_count": len(rows),
        "servers": rows,
    }
    countries_doc = {
        "kind": "vpngate-pool",
        "schema_version": 1,
        "source_fetched_at": fetched_at,
        "server_count": len(rows),
        "countries": [
            {"code": code, "names": [code], "server_count": count}
            for code, count in sorted(country_counts.items())
        ],
    }
    servers_body = json.dumps(servers_doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    countries_body = json.dumps(countries_doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    payloads = {
        "pool/servers.json": servers_body,
        "pool/countries.json": countries_body,
        **config_files,
    }
    index = {
        "kind": "vpngate-pool",
        "schema_version": 1,
        "source_url": "https://www.vpngate.net/api/iphone/",
        "source_fetched_at": fetched_at,
        "generated_at": fetched_at,
        "index_generated_at": fetched_at,
        "data_commit": commit,
        "server_count": len(rows),
        "files": {
            path: {"sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)}
            for path, body in payloads.items()
            if path in {"pool/servers.json", "pool/countries.json"}
        },
    }
    index_body = json.dumps(index, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()

    def read_url(url, max_bytes):
        if url == INDEX_URL:
            body = index_body
        else:
            body = next((value for path, value in payloads.items() if url.endswith("/" + path)), None)
            if body is None:
                raise OSError("fixture URL not found")
        if len(body) > max_bytes:
            raise OSError("fixture exceeds requested limit")
        return body

    return rows, read_url, payloads


class VPNGateRollingMirrorTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(UTC)
        self.rows, self.read_url, self.payloads = make_fixture(self.now)

    def test_load_catalog_checks_index_and_country_counts(self):
        index, rows, countries = load_catalog(read_url=self.read_url, now=self.now)

        self.assertEqual(index["server_count"], 6)
        self.assertEqual(len(rows), 6)
        self.assertEqual(countries, {"JP": 1, "US": 5})

    def test_selects_recent_tcp_reachable_nodes_and_prioritizes_us(self):
        selected, report = select_reachable_rows(
            self.rows, now=self.now, max_candidates=2, max_us_candidates=1
        )

        self.assertEqual([row["country_code"] for row in selected], ["US", "JP"])
        self.assertEqual(report["eligible_recent_tcp"], 2)
        self.assertEqual(report["eligible_recent_udp"], 1)
        self.assertEqual(report["eligible_recent_transport_total"], 3)
        self.assertEqual(report["eligible_us_recent_tcp"], 1)
        self.assertEqual(report["eligible_us_recent_udp"], 1)
        self.assertEqual(report["selected_us"], 1)
        self.assertEqual(report["rejected"]["tcp_not_reachable"], 1)
        self.assertEqual(report["rejected"]["stale_tcp_check"], 1)
        self.assertEqual(report["rejected"]["stale_node"], 1)

    def test_us_limit_cannot_exceed_total_candidate_budget(self):
        selected, report = select_reachable_rows(
            self.rows, now=self.now, max_candidates=1, max_us_candidates=10
        )
        self.assertEqual(len(selected), 1)
        self.assertEqual(report["us_candidate_limit"], 1)

    def test_catalog_download_rejects_checksum_mismatch(self):
        def corrupted(url, max_bytes):
            body = self.read_url(url, max_bytes)
            if url.endswith("/pool/servers.json"):
                return body + b" "
            return body

        with self.assertRaisesRegex(RollingMirrorError, "verified mirror download failed"):
            load_catalog(read_url=corrupted, now=self.now)

    def test_udp_candidate_requires_matching_advertised_ip_and_transport(self):
        row = next(item for item in self.rows if item.get("probe_reason") == "udp")
        config_doc = json.loads(self.payloads[row["config"]["path"]])
        config_text = base64.b64decode(config_doc["openvpn_config_base64"]).decode("utf-8")
        mismatched_ip = config_text.replace("remote 8.8.4.4 1194 udp", "remote 8.8.4.5 1194 udp")
        with self.assertRaisesRegex(VPNGateError, "does not match the rolling-pool IP"):
            _proxy_from_row(row, mismatched_ip)
        mismatched_transport = config_text.replace("proto udp", "proto tcp").replace("1194 udp", "1194 tcp")
        with self.assertRaisesRegex(VPNGateError, "does not match the OpenVPN transport"):
            _proxy_from_row(row, mismatched_transport)

    def test_collect_writes_only_verified_reachable_profiles(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "rolling-candidates.yaml"
            report = collect_vpngate_rolling(
                read_url=self.read_url,
                now=self.now,
                profile_path=output,
                max_candidates=3,
                max_us_candidates=2,
            )
            document = yaml.safe_load(output.read_text(encoding="utf-8"))

        proxies = document["proxies"]
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["pool_server_count"], 6)
        self.assertEqual(report["selected"], 3)
        self.assertEqual(report["selected_us"], 2)
        self.assertEqual(report["configs_written"], 3)
        self.assertEqual(len(proxies), 3)
        self.assertEqual({proxy["proto"] for proxy in proxies}, {"tcp", "udp"})
        self.assertEqual(next(p for p in proxies if p["proto"] == "udp")["udp"], True)
        self.assertTrue(any(proxy["name"].startswith("VPNGate-US-") for proxy in proxies))
        self.assertTrue(any(proxy["name"].startswith("VPNGate-JP-") for proxy in proxies))


if __name__ == "__main__":
    unittest.main()
