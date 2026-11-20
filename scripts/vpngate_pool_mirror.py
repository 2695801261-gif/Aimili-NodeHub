"""Consume the VPNGate rolling mirror as a checksum-verified candidate source.

The mirror's Cloudflare Workers provide only a recent TCP reachability signal.
NodeHub still performs its own Mihomo exit-IP, country, ASN and network-risk
checks before publishing any node.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

import yaml

from scripts.vpngate import VPNGateError, parse_ovpn_config

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "GeorgeXie2333/vpngate-list-mirror"
INDEX_URL = f"https://raw.githubusercontent.com/{REPOSITORY}/main/pool/latest.json"
SOURCE_URL = "https://www.vpngate.net/api/iphone/"
OUTPUT = ROOT / ".cache" / "vpngate" / "rolling-candidates.yaml"
USER_AGENT = "Aimili-NodeHub/0.1"
MAX_INDEX_BYTES = 128 * 1024
MAX_POOL_BYTES = 16 * 1024 * 1024
MAX_CONFIG_FILE_BYTES = 256 * 1024
MAX_OPENVPN_BYTES = 128 * 1024
MAX_POOL_SERVERS = 6000
MAX_CONFIG_WORKERS = 24
DEFAULT_MAX_CANDIDATES = 200
DEFAULT_MAX_US_CANDIDATES = 160
TCP_MAX_AGE = timedelta(hours=12)
NODE_MAX_AGE = timedelta(days=7)
INDEX_MAX_AGE = timedelta(hours=24)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class RollingMirrorError(RuntimeError):
    pass


def _utc(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise RollingMirrorError("missing timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise RollingMirrorError("invalid timestamp") from error
    if parsed.tzinfo is None:
        raise RollingMirrorError("timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _read_https(url: str, max_bytes: int) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=12) as response:
        body = response.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise RollingMirrorError("remote file exceeds the configured size limit")
    return body


def _descriptor(value: Any, *, max_bytes: int) -> tuple[str, int]:
    if not isinstance(value, dict):
        raise RollingMirrorError("file descriptor is missing")
    digest = value.get("sha256")
    size = value.get("bytes")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise RollingMirrorError("file descriptor has an invalid SHA-256")
    if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= max_bytes:
        raise RollingMirrorError("file descriptor has an invalid byte length")
    return digest, size


def _fetch_verified(
    path: str,
    descriptor: Any,
    commit: str,
    *,
    read_url: Callable[[str, int], bytes] = _read_https,
    max_bytes: int = MAX_POOL_BYTES,
) -> bytes:
    if not re.fullmatch(r"pool/(?:servers|countries)\.json|pool/configs/[0-9a-f]{64}\.json", path):
        raise RollingMirrorError("refusing an unexpected mirror path")
    expected_hash, expected_size = _descriptor(descriptor, max_bytes=max_bytes)
    urls = (
        f"https://cdn.jsdelivr.net/gh/{REPOSITORY}@{commit}/{path}",
        f"https://raw.githubusercontent.com/{REPOSITORY}/{commit}/{path}",
    )
    errors = []
    for url in urls:
        try:
            body = read_url(url, max_bytes)
            if len(body) != expected_size:
                raise RollingMirrorError("downloaded file size does not match its index")
            if hashlib.sha256(body).hexdigest() != expected_hash:
                raise RollingMirrorError("downloaded file SHA-256 does not match its index")
            return body
        except Exception as error:
            errors.append(type(error).__name__)
    raise RollingMirrorError("verified mirror download failed: " + ",".join(errors))


def _public_ip(value: Any) -> bool:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return bool(address.is_global and not (
        address.is_multicast or address.is_loopback or address.is_link_local
        or address.is_reserved or address.is_unspecified
    ))


def _country_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for row in rows:
        code = row.get("country_code")
        if isinstance(code, str) and re.fullmatch(r"[A-Z]{2}", code):
            counts[code] += 1
    return dict(counts)


def load_catalog(
    *,
    read_url: Callable[[str, int], bytes] = _read_https,
    now: datetime | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, int]]:
    now = (now or datetime.now(UTC)).astimezone(UTC)
    try:
        index_raw = read_url(INDEX_URL, MAX_INDEX_BYTES)
        index = json.loads(index_raw)
    except Exception as error:
        raise RollingMirrorError("could not read the rolling-pool index") from error
    if not isinstance(index, dict) or index.get("kind") != "vpngate-pool" or index.get("schema_version") != 1:
        raise RollingMirrorError("unsupported rolling-pool index schema")
    if index.get("source_url") != SOURCE_URL:
        raise RollingMirrorError("rolling-pool source URL does not match VPNGate")
    commit = index.get("data_commit")
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        raise RollingMirrorError("rolling-pool data commit is invalid")
    fetched_at = _utc(index.get("source_fetched_at"))
    if fetched_at > now + timedelta(minutes=5) or now - fetched_at > INDEX_MAX_AGE:
        raise RollingMirrorError("rolling-pool index is stale or from the future")
    server_count = index.get("server_count")
    if isinstance(server_count, bool) or not isinstance(server_count, int) or not 0 <= server_count <= MAX_POOL_SERVERS:
        raise RollingMirrorError("rolling-pool server count is outside the supported range")
    files = index.get("files")
    if not isinstance(files, dict):
        raise RollingMirrorError("rolling-pool file index is missing")
    for required in ("pool/servers.json", "pool/countries.json"):
        if required not in files:
            raise RollingMirrorError(f"rolling-pool index is missing {required}")

    servers_raw = _fetch_verified("pool/servers.json", files["pool/servers.json"], commit,
                                  read_url=read_url, max_bytes=MAX_POOL_BYTES)
    countries_raw = _fetch_verified("pool/countries.json", files["pool/countries.json"], commit,
                                    read_url=read_url, max_bytes=MAX_POOL_BYTES)
    try:
        catalog = json.loads(servers_raw)
        countries_doc = json.loads(countries_raw)
    except json.JSONDecodeError as error:
        raise RollingMirrorError("rolling-pool catalog JSON is malformed") from error
    for document in (catalog, countries_doc):
        if not isinstance(document, dict) or document.get("kind") != "vpngate-pool" or document.get("schema_version") != 1:
            raise RollingMirrorError("unsupported rolling-pool catalog schema")
        if document.get("server_count") != server_count or document.get("source_fetched_at") != index.get("source_fetched_at"):
            raise RollingMirrorError("rolling-pool catalog metadata does not match its index")
    rows = catalog.get("servers")
    countries = countries_doc.get("countries")
    if not isinstance(rows, list) or len(rows) != server_count or not isinstance(countries, list):
        raise RollingMirrorError("rolling-pool catalog count is inconsistent")
    computed = _country_counts(rows)
    declared = {
        item.get("code"): item.get("server_count")
        for item in countries
        if isinstance(item, dict)
    }
    if {key: value for key, value in declared.items() if isinstance(key, str)} != computed:
        raise RollingMirrorError("rolling-pool country counts do not match the server catalog")
    return index, rows, computed


def _row_sort_key(row: dict[str, Any]) -> tuple[float, float, float, str]:
    score = row.get("score")
    ping = row.get("ping_ms")
    speed = row.get("speed_bps")
    try:
        score_value = float(score)
    except (TypeError, ValueError):
        score_value = 0.0
    try:
        ping_value = float(ping)
    except (TypeError, ValueError):
        ping_value = 999999.0
    try:
        speed_value = float(speed)
    except (TypeError, ValueError):
        speed_value = 0.0
    return (-score_value, ping_value, -speed_value, str(row.get("id", "")))


def select_reachable_rows(
    rows: list[dict[str, Any]],
    *,
    now: datetime | None = None,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    max_us_candidates: int = DEFAULT_MAX_US_CANDIDATES,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if max_candidates < 1 or max_us_candidates < 0:
        raise ValueError("rolling-pool candidate limits are invalid")
    now = (now or datetime.now(UTC)).astimezone(UTC)
    eligible: list[dict[str, Any]] = []
    rejected: Counter[str] = Counter()
    seen_endpoints: set[tuple[str, str, str]] = set()
    for row in rows:
        if not isinstance(row, dict):
            rejected["invalid_row"] += 1
            continue
        country = row.get("country_code")
        if not isinstance(country, str) or not re.fullmatch(r"[A-Z]{2}", country):
            rejected["unknown_country"] += 1
            continue
        if not _public_ip(row.get("ip")):
            rejected["non_public_ip"] += 1
            continue
        try:
            last_seen = _utc(row.get("last_seen_at"))
        except RollingMirrorError:
            rejected["invalid_last_seen"] += 1
            continue
        if last_seen > now + timedelta(minutes=5) or now - last_seen > NODE_MAX_AGE:
            rejected["stale_node"] += 1
            continue

        transport = row.get("probe_reason")
        probe = row.get("tcp_probe")
        if not isinstance(probe, dict):
            rejected["invalid_probe_state"] += 1
            continue
        if transport == "udp":
            # UDP has no meaningful TCP port probe. It remains an untrusted
            # candidate and must pass the later real Mihomo tunnel/exit checks.
            if probe.get("status") != "not_applicable":
                rejected["udp_probe_state_invalid"] += 1
                continue
            if row.get("probe_targets") not in ([], None):
                rejected["udp_has_tcp_targets"] += 1
                continue
            identity = (str(row["ip"]), "udp", str(row.get("openvpn_config_sha256", "")))
        elif transport == "tcp":
            if probe.get("status") != "reachable":
                rejected["tcp_not_reachable"] += 1
                continue
            if probe.get("probe_source") != "cloudflare_workers":
                rejected["unexpected_probe_source"] += 1
                continue
            try:
                checked_at = _utc(probe.get("checked_at"))
            except RollingMirrorError:
                rejected["invalid_tcp_check_time"] += 1
                continue
            if checked_at > now + timedelta(minutes=5) or now - checked_at > TCP_MAX_AGE:
                rejected["stale_tcp_check"] += 1
                continue
            endpoint = probe.get("connected_endpoint")
            targets = row.get("probe_targets")
            if not isinstance(endpoint, dict) or not isinstance(targets, list) or endpoint not in targets:
                rejected["missing_connected_endpoint"] += 1
                continue
            endpoint_ip = endpoint.get("ip")
            try:
                endpoint_port = int(endpoint.get("port"))
            except (TypeError, ValueError):
                endpoint_port = 0
            if endpoint_ip != row.get("ip") or not 1 <= endpoint_port <= 65535:
                rejected["invalid_connected_endpoint"] += 1
                continue
            identity = (str(endpoint_ip), "tcp", str(endpoint_port))
        else:
            rejected["unsupported_transport"] += 1
            continue

        config = row.get("config")
        config_hash = row.get("openvpn_config_sha256")
        config_bytes = row.get("openvpn_config_bytes")
        if (
            not isinstance(config, dict)
            or not isinstance(config_hash, str)
            or not SHA256_RE.fullmatch(config_hash)
            or config.get("path") != f"pool/configs/{config_hash}.json"
            or isinstance(config_bytes, bool)
            or not isinstance(config_bytes, int)
            or not 1 <= config_bytes <= MAX_OPENVPN_BYTES
        ):
            rejected["invalid_config_reference"] += 1
            continue
        if identity in seen_endpoints:
            rejected["duplicate_endpoint"] += 1
            continue
        seen_endpoints.add(identity)
        eligible.append(row)

    tcp_rows = [row for row in eligible if row.get("probe_reason") == "tcp"]
    udp_rows = [row for row in eligible if row.get("probe_reason") == "udp"]
    us_rows = sorted((row for row in eligible if row["country_code"] == "US"), key=_row_sort_key)
    other_by_country: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in eligible:
        if row["country_code"] != "US":
            other_by_country[row["country_code"]].append(row)
    for country_rows in other_by_country.values():
        country_rows.sort(key=_row_sort_key)

    us_limit = min(max_us_candidates, max_candidates)
    selected = us_rows[:us_limit]
    remaining = max_candidates - len(selected)
    countries = sorted(other_by_country)
    cursor = {country: 0 for country in countries}
    while remaining > 0 and countries:
        progressed = False
        for country in countries:
            index = cursor[country]
            if index < len(other_by_country[country]):
                selected.append(other_by_country[country][index])
                cursor[country] += 1
                remaining -= 1
                progressed = True
                if remaining == 0:
                    break
        if not progressed:
            break

    report = {
        "pool_rows": len(rows),
        "eligible_recent_tcp": len(tcp_rows),
        "eligible_recent_udp": len(udp_rows),
        "eligible_recent_transport_total": len(eligible),
        "eligible_us_recent_tcp": sum(row["country_code"] == "US" for row in tcp_rows),
        "eligible_us_recent_udp": sum(row["country_code"] == "US" for row in udp_rows),
        "selected": len(selected),
        "selected_us": sum(row["country_code"] == "US" for row in selected),
        "rejected": dict(rejected),
        "tcp_check_max_age_hours": TCP_MAX_AGE.total_seconds() / 3600,
        "node_max_age_days": NODE_MAX_AGE.days,
        "candidate_limit": max_candidates,
        "us_candidate_limit": us_limit,
        "udp_candidates_require_live_tunnel_verification": True,
    }
    return selected, report

def _load_config(
    row: dict[str, Any],
    commit: str,
    *,
    read_url: Callable[[str, int], bytes] = _read_https,
) -> str:
    metadata = row["config"]
    body = _fetch_verified(metadata["path"], metadata, commit, read_url=read_url,
                           max_bytes=MAX_CONFIG_FILE_BYTES)
    try:
        document = json.loads(body)
    except json.JSONDecodeError as error:
        raise RollingMirrorError("rolling-pool config JSON is malformed") from error
    if not isinstance(document, dict) or document.get("kind") != "vpngate-pool-config" or document.get("schema_version") != 1:
        raise RollingMirrorError("unsupported rolling-pool config schema")
    if document.get("openvpn_config_sha256") != row["openvpn_config_sha256"]:
        raise RollingMirrorError("OpenVPN config hash does not match the server row")
    if document.get("openvpn_config_bytes") != row["openvpn_config_bytes"]:
        raise RollingMirrorError("OpenVPN config length does not match the server row")
    encoded = document.get("openvpn_config_base64")
    if not isinstance(encoded, str):
        raise RollingMirrorError("rolling-pool config has no base64 OpenVPN profile")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise RollingMirrorError("rolling-pool OpenVPN profile is not valid base64") from error
    if len(raw) != row["openvpn_config_bytes"] or hashlib.sha256(raw).hexdigest() != row["openvpn_config_sha256"]:
        raise RollingMirrorError("decoded OpenVPN profile failed its hash or length check")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RollingMirrorError("OpenVPN profile is not UTF-8") from error


def _proxy_from_row(row: dict[str, Any], config_text: str) -> dict[str, Any]:
    country = row["country_code"]
    ip = str(row["ip"])
    ip_token = ip.replace(".", "-").replace(":", "-")
    hostname = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(row.get("hostname") or "server"))[:48].strip("-")
    transport = row.get("probe_reason")
    if transport not in {"tcp", "udp"}:
        raise VPNGateError("rolling-pool transport is unsupported")
    name = f"VPNGate-{country}-{ip_token}-{hostname}-{transport}"
    proxy = parse_ovpn_config(config_text, name)
    try:
        config_ip = ipaddress.ip_address(proxy["server"])
        row_ip = ipaddress.ip_address(ip)
    except ValueError as error:
        raise VPNGateError("OpenVPN remote address is not the advertised numeric IP") from error
    if config_ip != row_ip:
        raise VPNGateError("OpenVPN remote address does not match the rolling-pool IP")

    if transport == "udp":
        if proxy.get("proto") != "udp":
            raise VPNGateError("rolling-pool UDP candidate does not match the OpenVPN transport")
        # UDP is intentionally not TCP-prescreened. Mihomo must establish the
        # actual OpenVPN tunnel and prove the exit before this node can publish.
        proxy["proto"] = "udp"
        proxy["udp"] = True
        return proxy
    if transport != "tcp" or proxy.get("proto") != "tcp":
        raise VPNGateError("rolling-pool TCP probe does not match the OpenVPN transport")
    endpoint = row["tcp_probe"]["connected_endpoint"]
    if endpoint.get("ip") != ip:
        raise VPNGateError("TCP probe endpoint does not match the advertised IP")
    proxy["server"] = endpoint["ip"]
    proxy["port"] = int(endpoint["port"])
    proxy["proto"] = "tcp"
    proxy["udp"] = False
    return proxy


def collect_vpngate_rolling(
    *,
    read_url: Callable[[str, int], bytes] = _read_https,
    now: datetime | None = None,
    profile_path: Path = OUTPUT,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    max_us_candidates: int = DEFAULT_MAX_US_CANDIDATES,
) -> dict[str, Any]:
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    if os.getenv("NODEHUB_VPNGATE_ROLLING_ENABLED", "1").strip().casefold() in {"0", "false", "no"}:
        profile_path.write_text("proxies: []\n", encoding="utf-8")
        return {"status": "disabled", "selected": 0}
    report: dict[str, Any] = {"status": "failed", "selected": 0}
    try:
        index, rows, country_counts = load_catalog(read_url=read_url, now=now)
        selected, selection_report = select_reachable_rows(
            rows, now=now, max_candidates=max_candidates, max_us_candidates=max_us_candidates
        )
        commit = index["data_commit"]
        config_rows = {row["openvpn_config_sha256"]: row for row in selected}

        def fetch_config(item):
            digest, row = item
            try:
                return digest, _load_config(row, commit, read_url=read_url), None
            except Exception as error:
                return digest, None, type(error).__name__

        config_cache: dict[str, str] = {}
        failures: Counter[str] = Counter()
        if config_rows:
            with ThreadPoolExecutor(max_workers=min(MAX_CONFIG_WORKERS, len(config_rows))) as executor:
                for digest, config_text, error_type in executor.map(fetch_config, config_rows.items()):
                    if config_text is None:
                        failures[error_type or "config_error"] += 1
                    else:
                        config_cache[digest] = config_text

        proxies: list[dict[str, Any]] = []
        seen_transport_endpoints: set[tuple[str, int, str]] = set()
        for row in selected:
            config_text = config_cache.get(row["openvpn_config_sha256"])
            if config_text is None:
                continue
            try:
                proxy = _proxy_from_row(row, config_text)
                endpoint_key = (proxy["server"], int(proxy["port"]), proxy["proto"])
                if endpoint_key in seen_transport_endpoints:
                    failures["duplicate_transport_endpoint"] += 1
                    continue
                seen_transport_endpoints.add(endpoint_key)
                proxies.append(proxy)
            except Exception as error:
                failures[type(error).__name__] += 1
        profile_path.write_text(
            yaml.safe_dump({"proxies": proxies}, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        report = {
            "status": "ok" if proxies else "empty",
            "repository": REPOSITORY,
            "data_commit": commit,
            "source_fetched_at": index["source_fetched_at"],
            "pool_server_count": index["server_count"],
            "country_counts": country_counts,
            **selection_report,
            "configs_written": len(proxies),
            "config_failures": dict(failures),
        }
    except Exception as error:
        profile_path.write_text("proxies: []\n", encoding="utf-8")
        report = {
            "status": "failed",
            "selected": 0,
            "error_type": type(error).__name__,
        }
    return report


if __name__ == "__main__":
    print(json.dumps(collect_vpngate_rolling(), ensure_ascii=False, sort_keys=True))
