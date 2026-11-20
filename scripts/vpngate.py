"""Fetch VPN Gate's public OpenVPN directory and convert profiles to Mihomo nodes."""
from __future__ import annotations

import base64
import concurrent.futures
import csv
import ipaddress
import json
import os
import re
import shlex
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
VPNGATE_API = "https://www.vpngate.net/api/iphone/"
OUTPUT = ROOT / ".cache" / "vpngate" / "candidates.yaml"
HISTORY_FILE = ROOT / ".cache" / "vpngate" / "candidate-history.json"
REPORT = ROOT / "classification" / "source-discovery.json"
MIHOMO = ROOT / ".cache" / "mihomo" / "mihomo"
MAX_NODES = int(os.getenv("NODEHUB_MAX_VPNGATE_NODES", "100"))
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_CONFIG_BYTES = 128 * 1024
HISTORY_TTL_SECONDS = 14 * 24 * 60 * 60
HISTORY_MAX_STALE_PER_COUNTRY = 5
HISTORY_MAX_NODES = 300
HISTORY_PROBE_LIMIT = 50
TCP_PRESCREEN_WORKERS = 64
TCP_PRESCREEN_TIMEOUT_SECONDS = 2.5
VPNGATE_OPERATED_IPV4_NETWORK = ipaddress.ip_network("219.100.37.0/24")
VPNGATE_OPERATED_HOST_PREFIX = "public-vpn"


class VPNGateError(RuntimeError):
    pass


def fetch_directory(url: str = VPNGATE_API, timeout: float = 30) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Aimili-NodeHub/0.1",
            "Accept": "text/csv,text/plain;q=0.9,*/*;q=0.1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise VPNGateError(f"VPN Gate API request failed: {type(error).__name__}") from error
    if len(raw) > MAX_RESPONSE_BYTES:
        raise VPNGateError("VPN Gate API response exceeded the configured size limit")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise VPNGateError("VPN Gate API did not return UTF-8 CSV") from error


def _header_and_rows(csv_text: str) -> tuple[list[str], list[dict[str, str]]]:
    lines = csv_text.splitlines()
    header_index = next(
        (
            index for index, line in enumerate(lines)
            if line.lstrip("#").casefold().startswith("hostname,")
        ),
        None,
    )
    if header_index is None:
        raise VPNGateError("VPN Gate CSV header was not found")
    header_line = lines[header_index].lstrip("#")
    reader = csv.DictReader([header_line, *lines[header_index + 1 :]])
    if not reader.fieldnames:
        raise VPNGateError("VPN Gate CSV header is empty")
    normalized = {
        field.strip().lstrip("*").casefold(): field
        for field in reader.fieldnames if field
    }
    required = {"hostname", "ip", "countryshort", "openvpn_configdata_base64"}
    if not required.issubset(normalized):
        missing = ", ".join(sorted(required - set(normalized)))
        raise VPNGateError(f"VPN Gate CSV is missing required columns: {missing}")
    rows: list[dict[str, str]] = []
    for raw in reader:
        row = {
            key: (raw.get(original) or "").strip()
            for key, original in normalized.items()
        }
        if row.get("hostname") and row.get("ip") and row.get("openvpn_configdata_base64"):
            rows.append(row)
    return list(normalized), rows


def _inline_blocks(text: str) -> tuple[str, dict[str, str]]:
    blocks: dict[str, str] = {}
    pattern = re.compile(
        r"(?ims)^[ \t]*<(ca|cert|key|tls-auth|tls-crypt|tls-crypt-v2)>[ \t]*\r?\n"
        r"(.*?)^[ \t]*</\1>[ \t]*\r?$"
    )

    def replace(match: re.Match[str]) -> str:
        tag = match.group(1).casefold()
        if tag in blocks:
            raise VPNGateError(f"duplicate inline {tag} block")
        blocks[tag] = match.group(2).strip()
        return ""

    return pattern.sub(replace, text), blocks


def _int_directive(directives: dict[str, list[list[str]]], key: str) -> int | None:
    values = directives.get(key)
    if not values:
        return None
    try:
        value = int(values[-1][0])
    except (ValueError, IndexError) as error:
        raise VPNGateError(f"invalid OpenVPN {key} directive") from error
    if value < 0 or value > 86400:
        raise VPNGateError(f"OpenVPN {key} is outside the accepted range")
    return value


def parse_ovpn_config(config_text: str, name: str, credentials: tuple[str, str] = ("vpn", "vpn")) -> dict[str, Any]:
    if not config_text.strip() or len(config_text.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise VPNGateError("OpenVPN profile is empty or too large")
    without_blocks, blocks = _inline_blocks(config_text)
    directives: dict[str, list[list[str]]] = {}
    for raw_line in without_blocks.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        try:
            parts = shlex.split(line, comments=True, posix=True)
        except ValueError as error:
            raise VPNGateError("malformed OpenVPN directive") from error
        if parts:
            directives.setdefault(parts[0].casefold(), []).append(parts[1:])

    remotes = directives.get("remote", [])
    if not remotes or len(remotes[0]) < 2:
        raise VPNGateError("OpenVPN profile has no usable remote directive")
    server = remotes[0][0].strip().strip("[]")
    try:
        port = int(remotes[0][1])
    except ValueError as error:
        raise VPNGateError("OpenVPN remote port is invalid") from error
    if not 1 <= port <= 65535:
        raise VPNGateError("OpenVPN remote port is outside the valid range")
    try:
        address = ipaddress.ip_address(server)
        if not address.is_global:
            raise VPNGateError("OpenVPN remote address is not globally routable")
    except ValueError:
        if not re.fullmatch(
            r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",
            server,
        ):
            raise VPNGateError("OpenVPN remote host is invalid")

    if not blocks.get("ca"):
        raise VPNGateError("OpenVPN profile has no inline CA certificate")
    if bool(blocks.get("cert")) != bool(blocks.get("key")):
        raise VPNGateError("OpenVPN client certificate and key must be supplied together")
    if sum(bool(blocks.get(tag)) for tag in ("tls-auth", "tls-crypt", "tls-crypt-v2")) > 1:
        raise VPNGateError("OpenVPN profile has conflicting TLS key blocks")

    proto_values = directives.get("proto", [])
    proto = proto_values[-1][0].casefold() if proto_values and proto_values[-1] else "udp"
    if len(remotes[0]) >= 3:
        proto = remotes[0][2].casefold()
    if proto.startswith("tcp"):
        proto = "tcp"
    elif proto.startswith("udp"):
        proto = "udp"
    else:
        raise VPNGateError(f"unsupported OpenVPN transport: {proto}")

    auth_user_pass = directives.get("auth-user-pass", [])
    if auth_user_pass and auth_user_pass[-1]:
        raise VPNGateError("OpenVPN profile references an external credential file")
    certificate_auth = bool(blocks.get("cert") and blocks.get("key"))
    if not auth_user_pass and not certificate_auth:
        raise VPNGateError("OpenVPN profile has neither auth-user-pass nor client certificate credentials")

    proxy: dict[str, Any] = {
        "name": name,
        "type": "openvpn",
        "server": server,
        "port": port,
        "proto": proto,
        "udp": proto == "udp",
        "ca": blocks["ca"],
    }
    if auth_user_pass:
        proxy.update({"username": credentials[0], "password": credentials[1]})
    for tag in ("cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"):
        if blocks.get(tag):
            proxy[tag] = blocks[tag]
    key_direction = directives.get("key-direction", [])
    if key_direction and key_direction[-1]:
        direction = key_direction[-1][0]
        if direction not in {"0", "1"}:
            raise VPNGateError("OpenVPN key-direction must be 0 or 1")
        proxy["key-direction"] = direction

    for key in ("cipher", "data-ciphers-fallback", "auth", "comp-lzo"):
        values = directives.get(key)
        if values and values[-1]:
            proxy[key] = values[-1][0]
    data_ciphers = directives.get("data-ciphers")
    if data_ciphers and data_ciphers[-1]:
        values = " ".join(data_ciphers[-1]).replace(",", ":").split(":")
        proxy["data-ciphers"] = [value for value in values if value]
    for key in ("ping", "ping-restart", "tran-window", "mtu"):
        value = _int_directive(directives, key)
        if value is not None:
            proxy[key] = value
    return proxy


def _decode_row(row: dict[str, str]) -> dict[str, Any]:
    encoded = row.get("openvpn_configdata_base64", "")
    try:
        raw = base64.b64decode(encoded, validate=True)
        config = raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise VPNGateError("invalid Base64 OpenVPN profile") from error
    if len(raw) > MAX_CONFIG_BYTES:
        raise VPNGateError("OpenVPN profile exceeded the configured size limit")
    country = row.get("countryshort", "XX").upper()
    if not re.fullmatch(r"[A-Z]{2}", country):
        country = "XX"
    ip_hint = row.get("ip", "unknown").replace(".", "-")
    hostname = re.sub(r"[^A-Za-z0-9_.-]+", "-", row.get("hostname", "relay"))[:48]
    name = f"VPNGate-{country}-{ip_hint}-{hostname}"
    proxy = parse_ovpn_config(config, name)
    try:
        row_ip = ipaddress.ip_address(row.get("ip", ""))
    except ValueError:
        row_ip = None
    try:
        remote_ip = ipaddress.ip_address(proxy["server"])
    except ValueError:
        remote_ip = None
    if row_ip is not None and remote_ip is not None and row_ip != remote_ip:
        raise VPNGateError("CSV server IP does not match the embedded OpenVPN remote")
    return proxy


def parse_directory(csv_text: str, *, limit: int = MAX_NODES) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if limit < 1:
        raise ValueError("VPN Gate node limit must be positive")
    _, rows = _header_and_rows(csv_text)
    scored: list[tuple[int, int, int, dict[str, str]]] = []
    for index, row in enumerate(rows):
        try:
            score = int(row.get("score") or 0)
        except ValueError:
            score = 0
        try:
            ping = int(row.get("ping") or 999999)
        except ValueError:
            ping = 999999
        scored.append((-score, ping, index, row))
    scored.sort(key=lambda item: (item[0], item[1], item[2]))

    # CountryShort is only a discovery-diversity hint, never classification
    # evidence. Round-robin the ranked list by advertised server country so
    # one large country cannot crowd every other region out of the 100-node
    # candidate budget. Rotate the starting country between scheduled runs.
    by_country: dict[str, list[tuple[int, int, int, dict[str, str]]]] = {}
    for item in scored:
        country = (item[3].get("countryshort") or "XX").upper()
        by_country.setdefault(country, []).append(item)
    countries = sorted(by_country)
    if countries:
        offset = int(os.getenv("GITHUB_RUN_NUMBER", "0")) % len(countries)
        countries = countries[offset:] + countries[:offset]
    diversified: list[tuple[int, int, int, dict[str, str]]] = []
    cursor = {country: 0 for country in countries}
    while len(diversified) < len(scored):
        progressed = False
        for country in countries:
            position = cursor[country]
            if position < len(by_country[country]):
                diversified.append(by_country[country][position])
                cursor[country] += 1
                progressed = True
        if not progressed:
            break

    accepted: list[dict[str, Any]] = []
    rejected: Counter[str] = Counter()
    seen: set[tuple[str, int, str]] = set()
    for _, _, _, row in diversified:
        if len(accepted) >= limit:
            break
        hostname = row.get("hostname", "").strip().casefold()
        if hostname.startswith(VPNGATE_OPERATED_HOST_PREFIX):
            rejected["vpngate_operated_public_vpn_hostname"] += 1
            continue
        try:
            row_address = ipaddress.ip_address(row.get("ip", ""))
        except ValueError:
            row_address = None
        if isinstance(row_address, ipaddress.IPv4Address) and row_address in VPNGATE_OPERATED_IPV4_NETWORK:
            rejected["vpngate_operated_public_vpn_network"] += 1
            continue
        try:
            proxy = _decode_row(row)
            identity = (proxy["server"], proxy["port"], proxy["proto"])
            if identity in seen:
                rejected["duplicate_endpoint"] += 1
                continue
            seen.add(identity)
            accepted.append(proxy)
        except VPNGateError as error:
            rejected[str(error)] += 1
    report = {
        "source": "vpngate_official_csv",
        "endpoint": VPNGATE_API,
        "rows_seen": len(rows),
        "candidates_parsed": len(accepted),
        "rejected": sum(rejected.values()),
        "rejection_reasons": dict(rejected),
        "limit": limit,
        "selection_strategy": "rotating_country_round_robin_then_score",
    }
    return accepted, report


def _mihomo_profile(proxies: list[dict[str, Any]]) -> dict[str, Any]:
    names = [proxy["name"] for proxy in proxies]
    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "proxies": proxies,
        "proxy-groups": [{"name": "VPNGATE-CHECK", "type": "select", "proxies": names}],
        "rules": ["MATCH,VPNGATE-CHECK"],
    }


def _validate_batch(proxies: list[dict[str, Any]], binary: Path) -> tuple[list[dict[str, Any]], int]:
    if not proxies:
        return [], 0
    with tempfile.TemporaryDirectory(prefix="nodehub-vpngate-check-") as directory:
        root = Path(directory)
        profile = root / "config.yaml"
        profile.write_text(
            yaml.safe_dump(_mihomo_profile(proxies), allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        result = subprocess.run(
            [str(binary), "-t", "-d", str(root), "-f", str(profile)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    if result.returncode == 0:
        return proxies, 0
    if len(proxies) == 1:
        return [], 1
    middle = len(proxies) // 2
    left, left_rejected = _validate_batch(proxies[:middle], binary)
    right, right_rejected = _validate_batch(proxies[middle:], binary)
    return left + right, left_rejected + right_rejected



def _candidate_identity(node: dict[str, Any]) -> tuple[str, int, str] | None:
    if not isinstance(node, dict) or node.get("type") != "openvpn":
        return None
    name = node.get("name")
    if not isinstance(name, str) or not name.startswith("VPNGate-"):
        return None
    if "public-vpn" in name.casefold():
        return None
    server = node.get("server")
    if not isinstance(server, str) or not server.strip():
        return None
    try:
        address = ipaddress.ip_address(server)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9.-]+", server):
            return None
        identity_host = server.casefold()
    else:
        if not address.is_global:
            return None
        if isinstance(address, ipaddress.IPv4Address) and address in VPNGATE_OPERATED_IPV4_NETWORK:
            return None
        identity_host = str(address)
    port = node.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        return None
    proto = node.get("proto")
    if proto not in {"tcp", "udp"}:
        return None
    return identity_host, port, proto


def _candidate_country(node: dict[str, Any]) -> str:
    parts = str(node.get("name") or "").split("-", 2)
    if len(parts) >= 2 and parts[0] == "VPNGate" and re.fullmatch(r"[A-Z]{2}", parts[1]):
        return parts[1]
    return "XX"


def load_candidate_history(path: Path = HISTORY_FILE) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        return []
    records = payload.get("candidates")
    return records if isinstance(records, list) else []


def merge_candidate_history(
    current: list[dict[str, Any]],
    previous: list[dict[str, Any]],
    *,
    now: float | None = None,
    ttl_seconds: int = HISTORY_TTL_SECONDS,
    max_stale_per_country: int = HISTORY_MAX_STALE_PER_COUNTRY,
    max_total: int = HISTORY_MAX_NODES,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Keep a short rolling history; old profiles remain candidates, never proof of liveness."""
    now = time.time() if now is None else float(now)
    records: dict[tuple[str, int, str], dict[str, Any]] = {}
    stats = {
        "history_loaded": 0,
        "history_expired": 0,
        "history_invalid": 0,
        "current_new": 0,
        "current_refreshed": 0,
    }
    for record in previous:
        if not isinstance(record, dict):
            stats["history_invalid"] += 1
            continue
        node = record.get("node")
        identity = _candidate_identity(node) if isinstance(node, dict) else None
        last_seen = record.get("last_seen_at")
        first_seen = record.get("first_seen_at", last_seen)
        if (
            identity is None
            or isinstance(last_seen, bool)
            or not isinstance(last_seen, (int, float))
            or isinstance(first_seen, bool)
            or not isinstance(first_seen, (int, float))
            or last_seen > now + 300
        ):
            stats["history_invalid"] += 1
            continue
        if now - last_seen > ttl_seconds:
            stats["history_expired"] += 1
            continue
        existing = records.get(identity)
        normalized = {
            "node": node,
            "first_seen_at": float(first_seen),
            "last_seen_at": float(last_seen),
        }
        if existing is None or normalized["last_seen_at"] > existing["last_seen_at"]:
            records[identity] = normalized
        stats["history_loaded"] += 1

    current_ids: set[tuple[str, int, str]] = set()
    for node in current:
        identity = _candidate_identity(node) if isinstance(node, dict) else None
        if identity is None:
            continue
        current_ids.add(identity)
        existing = records.get(identity)
        if existing is None:
            records[identity] = {
                "node": node,
                "first_seen_at": now,
                "last_seen_at": now,
            }
            stats["current_new"] += 1
        else:
            existing["node"] = node
            existing["last_seen_at"] = now
            stats["current_refreshed"] += 1

    grouped: dict[str, list[tuple[tuple[str, int, str], dict[str, Any]]]] = {}
    for identity, record in records.items():
        grouped.setdefault(_candidate_country(record["node"]), []).append((identity, record))

    retained: list[tuple[tuple[str, int, str], dict[str, Any]]] = []
    for items in grouped.values():
        current_items = [item for item in items if item[0] in current_ids]
        stale_items = [item for item in items if item[0] not in current_ids]
        stale_items.sort(
            key=lambda item: (item[1]["last_seen_at"], item[1]["node"].get("name", "")),
            reverse=True,
        )
        retained.extend(current_items)
        retained.extend(stale_items[:max_stale_per_country])

    retained.sort(
        key=lambda item: (
            _candidate_country(item[1]["node"]) != "US",
            item[0] not in current_ids,
            -item[1]["last_seen_at"],
            item[1]["node"].get("name", ""),
        )
    )
    retained = retained[:max_total]
    result = [record for _, record in retained]
    stats["history_retained"] = len(result)
    stats["off_window_retained"] = sum(identity not in current_ids for identity, _ in retained)
    return result, stats


def select_history_candidates(
    records: list[dict[str, Any]],
    *,
    limit: int = HISTORY_PROBE_LIMIT,
    rotation: int = 0,
) -> list[dict[str, Any]]:
    """Select a country-balanced rotating sample, giving US-labelled sources first look."""
    if limit < 1:
        raise ValueError("VPN Gate history probe limit must be positive")
    groups: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        node = record.get("node") if isinstance(record, dict) else None
        if isinstance(node, dict) and _candidate_identity(node) is not None:
            groups.setdefault(_candidate_country(node), []).append(record)
    countries = sorted(groups, key=lambda country: (country != "US", country))
    rotation = max(0, int(rotation))
    for country in countries:
        group = sorted(
            groups[country],
            key=lambda record: (
                record.get("last_seen_at", 0),
                record["node"].get("name", ""),
            ),
            reverse=True,
        )
        offset = rotation % len(group)
        groups[country] = group[offset:] + group[:offset]

    selected: list[dict[str, Any]] = []
    cursor = {country: 0 for country in countries}
    while len(selected) < limit:
        progressed = False
        for country in countries:
            position = cursor[country]
            if position < len(groups[country]):
                selected.append(groups[country][position]["node"])
                cursor[country] += 1
                progressed = True
                if len(selected) >= limit:
                    break
        if not progressed:
            break
    return selected


def tcp_prescreen_history(
    records: list[dict[str, Any]],
    *,
    connector=None,
    workers: int = TCP_PRESCREEN_WORKERS,
    timeout_seconds: float = TCP_PRESCREEN_TIMEOUT_SECONDS,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fast first-stage reachability check for TCP VPNGate nodes.

    UDP nodes are deliberately retained without TCP probing. Failed TCP checks
    are excluded only from this run's candidate history; a later fresh API
    snapshot can re-admit them. This is runner-vantage evidence, not a global
    statement that a server is permanently offline.
    """
    if workers < 1 or timeout_seconds <= 0:
        raise ValueError("TCP prescreen limits must be positive")
    connect = connector or socket.create_connection
    tcp_items: list[tuple[int, str, int]] = []
    skipped_non_tcp = 0
    skipped_invalid = 0
    for index, record in enumerate(records):
        node = record.get("node") if isinstance(record, dict) else None
        if not isinstance(node, dict):
            skipped_invalid += 1
            continue
        proto = str(node.get("proto") or "").casefold()
        if not proto.startswith("tcp"):
            skipped_non_tcp += 1
            continue
        host = str(node.get("server") or "").strip()
        try:
            port = int(node.get("port"))
        except (TypeError, ValueError):
            port = 0
        if not host or not 1 <= port <= 65535:
            skipped_invalid += 1
            continue
        tcp_items.append((index, host, port))

    def probe(item: tuple[int, str, int]) -> tuple[int, bool, str]:
        index, host, port = item
        last_error: OSError | None = None
        for attempt in range(2):
            try:
                connection = connect((host, port), timeout=timeout_seconds)
                try:
                    connection.close()
                except Exception:
                    pass
                return index, True, ""
            except OSError as error:
                last_error = error
                if isinstance(error, ConnectionRefusedError) or attempt == 1:
                    break
                time.sleep(0.15)
        return index, False, type(last_error).__name__ if last_error else "unknown"

    outcomes: dict[int, tuple[bool, str]] = {}
    active_workers = min(workers, len(tcp_items))
    if tcp_items:
        with concurrent.futures.ThreadPoolExecutor(max_workers=active_workers) as executor:
            for index, reachable, reason in executor.map(probe, tcp_items):
                outcomes[index] = (reachable, reason)

    survivors = [
        record
        for index, record in enumerate(records)
        if index not in outcomes or outcomes[index][0]
    ]
    errors = Counter(
        reason for reachable, reason in outcomes.values() if not reachable
    )
    report = {
        "runner_vantage": "github-actions",
        "tcp_candidates": len(tcp_items),
        "tcp_reachable": sum(reachable for reachable, _ in outcomes.values()),
        "tcp_unreachable": sum(not reachable for reachable, _ in outcomes.values()),
        "tcp_skipped_non_tcp": skipped_non_tcp,
        "tcp_skipped_invalid_endpoint": skipped_invalid,
        "workers": active_workers,
        "timeout_seconds": timeout_seconds,
        "failure_types": dict(errors),
        "history_before": len(records),
        "history_after": len(survivors),
    }
    return survivors, report


def prescreen_history_for_run(
    records: list[dict[str, Any]],
    *,
    connector=None,
    workers: int = TCP_PRESCREEN_WORKERS,
    timeout_seconds: float = TCP_PRESCREEN_TIMEOUT_SECONDS,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Skip direct TCP filtering when VPNGate probes will use a CF dialer front."""
    if os.getenv("NODEHUB_CF_FRONT_URI", "").strip():
        tcp_candidates = 0
        skipped_non_tcp = 0
        skipped_invalid = 0
        for record in records:
            node = record.get("node") if isinstance(record, dict) else None
            if not isinstance(node, dict):
                skipped_invalid += 1
                continue
            if not str(node.get("proto") or "").casefold().startswith("tcp"):
                skipped_non_tcp += 1
                continue
            host = str(node.get("server") or "").strip()
            try:
                port = int(node.get("port"))
            except (TypeError, ValueError):
                port = 0
            if not host or not 1 <= port <= 65535:
                skipped_invalid += 1
            else:
                tcp_candidates += 1
        return records, {
            "runner_vantage": "github-actions",
            "skipped": True,
            "skip_reason": "cloudflare_vless_probe_underlay_configured",
            "tcp_candidates": tcp_candidates,
            "tcp_reachable": 0,
            "tcp_unreachable": 0,
            "tcp_skipped_non_tcp": skipped_non_tcp,
            "tcp_skipped_invalid_endpoint": skipped_invalid,
            "workers": 0,
            "timeout_seconds": timeout_seconds,
            "failure_types": {},
            "history_before": len(records),
            "history_after": len(records),
        }
    return tcp_prescreen_history(
        records,
        connector=connector,
        workers=workers,
        timeout_seconds=timeout_seconds,
    )


def save_candidate_history(
    records: list[dict[str, Any]],
    *,
    path: Path = HISTORY_FILE,
    now: float | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "source": VPNGATE_API,
        "updated_at": time.time() if now is None else float(now),
        "history_ttl_seconds": HISTORY_TTL_SECONDS,
        "candidates": records,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def collect_vpngate() -> dict[str, Any]:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    previous = load_candidate_history()
    try:
        csv_text = fetch_directory()
        current, report = parse_directory(csv_text)
        if not MIHOMO.is_file():
            raise VPNGateError("pinned Mihomo binary is missing; cannot validate OpenVPN profiles")
        current_valid, current_rejected = _validate_batch(current, MIHOMO)
        history, history_stats = merge_candidate_history(current_valid, previous, now=now)
        history, tcp_prescreen = prescreen_history_for_run(history)
        try:
            rotation = int(os.getenv("GITHUB_RUN_NUMBER", "0"))
        except ValueError:
            rotation = 0
        selected = select_history_candidates(
            history, limit=HISTORY_PROBE_LIMIT, rotation=rotation
        )
        valid, rejected = _validate_batch(selected, MIHOMO)
        valid_ids = {_candidate_identity(node) for node in valid}
        selected_ids = {_candidate_identity(node) for node in selected}
        invalid_ids = selected_ids - valid_ids
        history = [
            record for record in history
            if _candidate_identity(record["node"]) not in invalid_ids
        ]
        save_candidate_history(history, now=now)
        report.update({
            "current_mihomo_validated": len(current_valid),
            "current_mihomo_rejected": current_rejected,
            "history_candidates_available": len(history),
            "history_candidates_selected": len(selected),
            "history_off_window_retained": history_stats["off_window_retained"],
            "history_expired": history_stats["history_expired"],
            "history_invalid": history_stats["history_invalid"],
            "history_ttl_days": HISTORY_TTL_SECONDS // (24 * 60 * 60),
            "tcp_prescreen": tcp_prescreen,
            "probe_rotation": rotation,
            "mihomo_validated": len(valid),
            "mihomo_rejected": rejected,
            "status": "ok" if valid else "empty",
        })
        OUTPUT.write_text(
            yaml.safe_dump({"proxies": valid}, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
    except Exception as error:
        try:
            rotation = int(os.getenv("GITHUB_RUN_NUMBER", "0"))
        except ValueError:
            rotation = 0
        fallback_history, history_stats = merge_candidate_history([], previous, now=now)
        fallback_history, tcp_prescreen = prescreen_history_for_run(fallback_history)
        valid: list[dict[str, Any]] = []
        rejected = 0
        if MIHOMO.is_file():
            selected = select_history_candidates(
                fallback_history, limit=HISTORY_PROBE_LIMIT, rotation=rotation
            )
            valid, rejected = _validate_batch(selected, MIHOMO)
            valid_ids = {_candidate_identity(node) for node in valid}
            selected_ids = {_candidate_identity(node) for node in selected}
            invalid_ids = selected_ids - valid_ids
            fallback_history = [
                record for record in fallback_history
                if _candidate_identity(record["node"]) not in invalid_ids
            ]
            save_candidate_history(fallback_history, now=now)
        report = {
            "source": "vpngate_official_csv",
            "endpoint": VPNGATE_API,
            "api_status": "unavailable",
            "status": "history_fallback" if valid else "unavailable",
            "error": f"{type(error).__name__}: {' '.join(str(error).split())[:240]}",
            "history_candidates_available": len(fallback_history),
            "history_candidates_selected": len(valid),
            "history_off_window_retained": history_stats["off_window_retained"],
            "history_expired": history_stats["history_expired"],
            "history_invalid": history_stats["history_invalid"],
            "history_ttl_days": HISTORY_TTL_SECONDS // (24 * 60 * 60),
            "tcp_prescreen": tcp_prescreen,
            "probe_rotation": rotation,
            "mihomo_validated": len(valid),
            "mihomo_rejected": rejected,
        }
        OUTPUT.write_text(
            yaml.safe_dump({"proxies": valid}, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
    REPORT.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print("VPN Gate discovery:", json.dumps(report, ensure_ascii=False, sort_keys=True), flush=True)
    return report

if __name__ == "__main__":
    collect_vpngate()
