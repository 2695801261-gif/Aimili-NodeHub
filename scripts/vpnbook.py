"""Official VPNBook OpenVPN API adapter; credentials are runtime-only."""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import unescape
from pathlib import Path
from typing import Any

import yaml

from scripts.vpngate import MIHOMO, VPNGateError, _validate_batch, parse_ovpn_config

ROOT = Path(__file__).resolve().parents[1]
PAGE_URL = "https://www.vpnbook.com/freevpn/openvpn"
API_URL = "https://www.vpnbook.com/api/openvpn"
OUTPUT = ROOT / ".cache" / "vpnbook" / "candidates.yaml"
REPORT = ROOT / "classification" / "vpnbook-discovery.json"
MAX_PAGE_BYTES = 2 * 1024 * 1024
MAX_CONFIG_BYTES = 256 * 1024
MAX_SERVERS = 20
MAX_PROFILES = 20
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)


class VPNBookError(RuntimeError):
    pass


def _fetch(url: str, limit: int) -> bytes:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "www.vpnbook.com":
        raise VPNBookError("refusing non-official VPNBook URL")
    if parsed.path not in {"/freevpn/openvpn", "/api/openvpn"}:
        raise VPNBookError("refusing unexpected VPNBook endpoint")
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/octet-stream,text/plain,*/*",
        "Referer": PAGE_URL,
    }
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            if response.status != 200:
                raise VPNBookError(f"VPNBook returned HTTP {response.status}")
            data = response.read(limit + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise VPNBookError(f"VPNBook request failed: {type(error).__name__}") from error
    if len(data) > limit:
        raise VPNBookError("VPNBook response exceeded configured size limit")
    return data


def parse_vpnbook_page(page: str) -> tuple[tuple[str, str], list[dict[str, str]]]:
    """Parse current Next.js page credentials and its embedded server directory."""
    user_match = re.search(
        r">Username</label>.*?<code[^>]*>\s*([^<\s]{1,64})\s*</code>",
        page,
        re.I | re.S,
    )
    password_match = re.search(
        r">Password</label>.*?<code[^>]*>\s*([^<\s]{4,64})\s*</code>",
        page,
        re.I | re.S,
    )

    # Older official page variants used strong tags rather than label/code.
    if not user_match:
        user_match = re.search(
            r"Username\s*:?[\s\S]{0,180}?<(?:strong|b)[^>]*>\s*([^<\s]{1,64})\s*</",
            page,
            re.I,
        )
    if not password_match:
        password_match = re.search(
            r"Password\s*:?[\s\S]{0,180}?<(?:strong|b)[^>]*>\s*([^<\s]{4,64})\s*</",
            page,
            re.I,
        )
    if not user_match or not password_match:
        raise VPNBookError("current shared credentials not found in official page")

    decoded = unescape(page)
    server_pattern = re.compile(
        r'"id"\s*:\s*"([a-z0-9]+)"'
        r'.*?"hostname"\s*:\s*"([^"]+)"'
        r'.*?"ipAddress"\s*:\s*"([^"]+)"'
        r'.*?"countryCode"\s*:\s*"([A-Z]{2})"',
        re.I | re.S,
    )
    servers: list[dict[str, str]] = []
    seen: set[str] = set()
    for match in server_pattern.finditer(decoded):
        server_id, hostname, ip_text, country = match.groups()
        hostname = hostname.lower().rstrip(".")
        try:
            address = ipaddress.ip_address(ip_text)
        except ValueError:
            continue
        if (
            server_id in seen
            or not address.is_global
            or not re.fullmatch(r"[a-z0-9-]+\.vpnbook\.com", hostname)
        ):
            continue
        seen.add(server_id)
        servers.append({
            "id": server_id,
            "hostname": hostname,
            "ip": str(address),
            "country": country.upper(),
        })
        if len(servers) >= MAX_SERVERS:
            break
    if not servers:
        # The current page also renders the OpenVPN server hostnames as visible
        # text. Resolve those names at runtime rather than falling back to
        # stale IP literals when its embedded JSON shape changes.
        hostnames = re.findall(
            r"\b([a-z]{2}\d{1,4})\.vpnbook\.com\b",
            decoded,
            re.I,
        )
        for server_id in hostnames:
            hostname = f"{server_id.lower()}.vpnbook.com"
            if server_id.lower() in seen:
                continue
            seen.add(server_id.lower())
            servers.append({
                "id": server_id.lower(),
                "hostname": hostname,
                "ip": "",
                "country": server_id[:2].upper(),
            })
            if len(servers) >= MAX_SERVERS:
                break
    if not servers:
        raise VPNBookError("official page exposed no valid OpenVPN server records")
    return (
        user_match.group(1).strip(),
        password_match.group(1).strip(),
    ), servers


def resolve_server_ip(hostname: str) -> str:
    if not re.fullmatch(r"[a-z]{2}\d{1,4}\.vpnbook\.com", hostname, re.I):
        raise VPNBookError("refusing to resolve a non-server VPNBook hostname")
    try:
        records = socket.getaddrinfo(
            hostname,
            443,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )
    except OSError as error:
        raise VPNBookError(f"VPNBook server DNS lookup failed: {type(error).__name__}") from error
    for record in records:
        try:
            address = ipaddress.ip_address(record[4][0])
        except (ValueError, IndexError):
            continue
        if address.is_global:
            return str(address)
    raise VPNBookError("VPNBook server hostname resolved to no public IPv4 address")


def build_config_url(server: dict[str, str]) -> str:
    """Build the documented official per-host OpenVPN configuration API URL."""
    query = urllib.parse.urlencode({
        "hostname": server["hostname"],
        "protocol": "tcp443",
        "ip": server["ip"],
    })
    return f"{API_URL}?{query}"


def parse_configs(
    configs: list[tuple[dict[str, str], str]],
    credentials: tuple[str, str],
    limit: int = MAX_PROFILES,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    proxies: list[dict[str, Any]] = []
    rejected: dict[str, int] = {}
    seen: set[tuple[str, int, str]] = set()
    for server, profile in configs:
        if len(proxies) >= limit:
            break
        try:
            proxy = parse_ovpn_config(
                profile,
                f"VPNBook-{server['id']}-tcp443",
                credentials,
            )
            if proxy["server"].casefold() not in {
                server["hostname"].casefold(),
                server["ip"],
            }:
                raise VPNBookError("profile remote does not match the official server record")
            identity = (proxy["server"], proxy["port"], proxy["proto"])
            if identity in seen:
                rejected["duplicate_endpoint"] = rejected.get("duplicate_endpoint", 0) + 1
                continue
            seen.add(identity)
            proxies.append(proxy)
        except (VPNGateError, VPNBookError, KeyError) as error:
            reason = f"{type(error).__name__}:{str(error)[:120]}"
            rejected[reason] = rejected.get(reason, 0) + 1
    return proxies, {
        "source": "vpnbook_official_api",
        "servers_seen": len(configs),
        "candidates_parsed": len(proxies),
        "rejection_reasons": rejected,
        "limit": limit,
    }


def collect_vpnbook() -> dict[str, Any]:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    try:
        page = _fetch(PAGE_URL, MAX_PAGE_BYTES).decode("utf-8", errors="replace")
        credentials, servers = parse_vpnbook_page(page)
        for server in servers:
            if not server.get("ip"):
                server["ip"] = resolve_server_ip(server["hostname"])
        downloaded: list[tuple[dict[str, str], str]] = []
        failures: dict[str, int] = {}
        with ThreadPoolExecutor(max_workers=5) as executor:
            pending = {
                executor.submit(_fetch, build_config_url(server), MAX_CONFIG_BYTES): server
                for server in servers
            }
            for future in as_completed(pending, timeout=120):
                server = pending[future]
                try:
                    profile = future.result().decode("utf-8-sig", errors="strict")
                    if not profile.lstrip().startswith("client"):
                        raise VPNBookError("official API response is not an OpenVPN profile")
                    downloaded.append((server, profile))
                except Exception as error:
                    reason = type(error).__name__
                    failures[reason] = failures.get(reason, 0) + 1
        proxies, report = parse_configs(downloaded, credentials)
        report["servers_discovered"] = len(servers)
        report["download_failures"] = failures
        if not MIHOMO.is_file():
            raise VPNBookError("pinned Mihomo binary is missing; cannot validate OpenVPN profiles")
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
            "source": "vpnbook_official_api",
            "status": "unavailable",
            "error": f"{type(error).__name__}: {' '.join(str(error).split())[:220]}",
            "candidates_parsed": 0,
        }
        OUTPUT.write_text(yaml.safe_dump({"proxies": []}, sort_keys=False), encoding="utf-8")
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("VPNBook discovery:", json.dumps(report, ensure_ascii=False, sort_keys=True), flush=True)
    return report


if __name__ == "__main__":
    collect_vpnbook()
