"""Fetch VPN Gate's public OpenVPN directory and convert profiles to Mihomo nodes."""
from __future__ import annotations

import base64
import csv
import ipaddress
import json
import os
import re
import shlex
import subprocess
import tempfile
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
VPNGATE_API = "https://www.vpngate.net/api/iphone/"
OUTPUT = ROOT / ".cache" / "vpngate" / "candidates.yaml"
REPORT = ROOT / "classification" / "source-discovery.json"
MIHOMO = ROOT / ".cache" / "mihomo" / "mihomo"
MAX_NODES = int(os.getenv("NODEHUB_MAX_VPNGATE_NODES", "100"))
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_CONFIG_BYTES = 128 * 1024


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


def parse_ovpn_config(config_text: str, name: str) -> dict[str, Any]:
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
    if auth_user_pass and certificate_auth:
        raise VPNGateError("OpenVPN profile mixes username/password and client certificate authentication")
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
        proxy.update({"username": "vpn", "password": "vpn"})
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

    accepted: list[dict[str, Any]] = []
    rejected: Counter[str] = Counter()
    seen: set[tuple[str, int, str]] = set()
    for _, _, _, row in scored:
        if len(accepted) >= limit:
            break
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


def collect_vpngate() -> dict[str, Any]:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    try:
        csv_text = fetch_directory()
        proxies, report = parse_directory(csv_text)
        if not MIHOMO.is_file():
            raise VPNGateError("pinned Mihomo binary is missing; cannot validate OpenVPN profiles")
        valid, rejected = _validate_batch(proxies, MIHOMO)
        report["mihomo_validated"] = len(valid)
        report["mihomo_rejected"] = rejected
        report["status"] = "ok" if valid else "empty"
        OUTPUT.write_text(
            yaml.safe_dump({"proxies": valid}, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
    except Exception as error:
        report = {
            "source": "vpngate_official_csv",
            "endpoint": VPNGATE_API,
            "status": "unavailable",
            "error": f"{type(error).__name__}: {' '.join(str(error).split())[:240]}",
            "mihomo_validated": 0,
        }
        OUTPUT.write_text(yaml.safe_dump({"proxies": []}, sort_keys=False), encoding="utf-8")
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("VPN Gate discovery:", json.dumps(report, ensure_ascii=False, sort_keys=True), flush=True)
    return report


if __name__ == "__main__":
    collect_vpngate()
