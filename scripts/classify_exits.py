#!/usr/bin/env python3
"""Probe Mihomo exit IPs and publish conservative classified subscriptions."""
from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from scripts.classification import classify

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PROFILE = ROOT / "nodes" / "merged.yaml"
MIHOMO = ROOT / ".cache" / "mihomo" / "mihomo"
OUTPUTS = {
    "us-residential": ROOT / "subscriptions" / "us-residential.yaml",
    "other-residential": ROOT / "subscriptions" / "other-residential.yaml",
    "low-risk-datacenter": ROOT / "subscriptions" / "low-risk-datacenter.yaml",
}
EVIDENCE_PATH = ROOT / "classification" / "evidence.json"
DIAGNOSTICS_PATH = ROOT / "classification" / "diagnostics.json"
VPNGATE_PROFILE = ROOT / ".cache" / "vpngate" / "candidates.yaml"
VPNGATE_ROLLING_PROFILE = ROOT / ".cache" / "vpngate" / "rolling-candidates.yaml"
VPNBOOK_PROFILE = ROOT / ".cache" / "vpnbook" / "candidates.yaml"
SOURCE_REPORT = ROOT / "classification" / "source-discovery.json"
MAX_CANDIDATES = int(os.getenv("NODEHUB_MAX_EXIT_PROBES", "80"))
MAX_TOTAL_CANDIDATES = 1500
MAX_VPNGATE_CANDIDATES = 300
MAX_SUPPLEMENTAL_CANDIDATES = MAX_VPNGATE_CANDIDATES + 10
CONTROLLER = "http://127.0.0.1:9090"
SOCKS = "socks5h://127.0.0.1:7891"
SECRET = "nodehub-local-controller-secret"
USER_AGENT = "Aimili-NodeHub/0.1"


class LookupFailure(RuntimeError):
    pass


def request_json(url: str, *, method: str = "GET", payload: dict[str, Any] | None = None,
                 controller: bool = False, timeout: float = 12) -> dict[str, Any]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    body = None
    if payload is not None:
        body = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    if controller:
        headers["Authorization"] = f"Bearer {SECRET}"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            result = json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise
        if error.code == 429 or error.code >= 500:
            raise LookupFailure(f"intelligence source unavailable: HTTP {error.code}") from error
        raise LookupFailure(f"lookup rejected: HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise LookupFailure(f"lookup failed: {type(error).__name__}") from error
    if not isinstance(result, dict):
        raise LookupFailure("unexpected JSON response shape")
    return result


def lookup_ip_metadata(exit_ip: str) -> tuple[dict[str, Any], str]:
    failures: list[str] = []
    try:
        time.sleep(1.0)
        data = request_json(f"https://ipwho.is/{exit_ip}", timeout=5)
        connection = data.get("connection") or {}
        raw_asn = connection.get("asn")
        asn = int(str(raw_asn).upper().removeprefix("AS"))
        country = data.get("country_code")
        isp = connection.get("isp") or connection.get("org")
        if data.get("success") is True and data.get("ip") == exit_ip:
            if isinstance(country, str) and len(country) == 2 and country.upper() not in {"ZZ", "XX", "T1", "A1", "EU", "AP"} and isinstance(isp, str) and isp.strip():
                security = data.get("security") or {}
                if not isinstance(security, dict):
                    security = {}
                ipwho_security = {
                    key: security.get(key) if isinstance(security.get(key), bool) else None
                    for key in ("hosting", "proxy", "vpn", "tor")
                }
                return {
                    "country_code": country.upper(),
                    "asn": asn,
                    "isp": isp.strip(),
                    "ipwho_type": str(data.get("type") or "").strip().casefold(),
                    "ipwho_security": ipwho_security,
                }, "ipwho.is"
        failures.append("ipwho.is returned incomplete or mismatched metadata")
    except (LookupFailure, urllib.error.HTTPError, TypeError, ValueError) as error:
        failures.append(f"ipwho.is: {type(error).__name__}: {error}")

    try:
        time.sleep(1.0)
        data = request_json(f"https://ipinfo.io/{exit_ip}/json", timeout=8)
        org = data.get("org")
        match = re.match(r"^AS(\d+)\s+(.+)$", org.strip()) if isinstance(org, str) else None
        country = data.get("country")
        if data.get("ip") != exit_ip or not match:
            raise LookupFailure("IPinfo returned incomplete or mismatched metadata")
        if not isinstance(country, str) or len(country) != 2 or country.upper() in {"ZZ", "XX", "T1", "A1", "EU", "AP"}:
            raise LookupFailure("IPinfo returned no usable country code")
        return {
            "country_code": country.upper(),
            "asn": int(match.group(1)),
            "isp": match.group(2).strip(),
        }, "ipinfo.io"
    except (LookupFailure, urllib.error.HTTPError, TypeError, ValueError) as error:
        failures.append(f"ipinfo.io: {type(error).__name__}: {error}")
    raise LookupFailure("all IP metadata providers failed: " + " | ".join(failures))


def parse_cloudflare_front_config(raw: str) -> dict[str, Any]:
    """Accept a VLESS share URI or a Mihomo YAML subscription/config."""
    value = raw.strip()
    if value.casefold().startswith("vless://"):
        return parse_cloudflare_front_uri(value)
    try:
        document = yaml.safe_load(value)
    except yaml.YAMLError as error:
        raise ValueError("Cloudflare front secret must be a VLESS URI or Mihomo YAML") from error
    if isinstance(document, dict) and isinstance(document.get("proxies"), list):
        items = document["proxies"]
    elif isinstance(document, list):
        items = document
    elif isinstance(document, dict):
        items = [document]
    else:
        raise ValueError("Cloudflare front YAML contains no proxy object")
    for item in items:
        if not isinstance(item, dict) or str(item.get("type") or "").casefold() != "vless":
            continue
        if item.get("tls") is not True or str(item.get("network") or "").casefold() != "ws":
            continue
        if item.get("skip-cert-verify") is True:
            continue
        ws_options = item.get("ws-opts") if isinstance(item.get("ws-opts"), dict) else {}
        headers = ws_options.get("headers") if isinstance(ws_options.get("headers"), dict) else {}
        server = str(item.get("server") or "").strip()
        user_id = str(item.get("uuid") or "").strip()
        host_header = str(headers.get("Host") or headers.get("host") or item.get("servername") or server).strip()
        servername = str(item.get("servername") or host_header).strip()
        path = str(ws_options.get("path") or "/").strip()
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue
        if not server or not user_id or not host_header or not servername or not 1 <= port <= 65535:
            continue
        netloc_host = f"[{server}]" if ":" in server and not server.startswith("[") else server
        query = urllib.parse.urlencode({
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": host_header,
            "sni": servername,
            "path": path,
        })
        try:
            return parse_cloudflare_front_uri(f"vless://{user_id}@{netloc_host}:{port}?{query}")
        except ValueError:
            continue
    raise ValueError("Cloudflare front YAML has no valid VLESS + TLS + WebSocket proxy")


def prepare_probe_candidates(
    candidates: list[dict[str, Any]], front_proxy: dict[str, Any] | None
) -> tuple[list[dict[str, Any]], int]:
    """Attach a private underlay to VPNGate probes without mutating publishable nodes."""
    prepared = [dict(item) for item in candidates]
    count = 0
    if front_proxy:
        for item in prepared:
            if str(item.get("name") or "").startswith("VPNGate-"):
                item["dialer-proxy"] = front_proxy["name"]
                count += 1
    return prepared, count


def parse_cloudflare_front_uri(uri: str) -> dict[str, Any]:
    """Parse a TLS WebSocket VLESS URI for VPNGate probe-only dialer chaining."""
    parsed = urllib.parse.urlsplit(uri.strip())
    if parsed.scheme.casefold() != "vless" or not parsed.hostname or not parsed.username:
        raise ValueError("Cloudflare front must be a vless:// URI with UUID and server")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("Cloudflare front URI has an invalid port") from error
    if port is None or not 1 <= port <= 65535:
        raise ValueError("Cloudflare front URI must include a valid port")
    try:
        address = ipaddress.ip_address(parsed.hostname)
        if not address.is_global:
            raise ValueError("Cloudflare front server IP must be globally routable")
    except ValueError as error:
        if "globally routable" in str(error):
            raise
        if not re.fullmatch(
            r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",
            parsed.hostname,
        ):
            raise ValueError("Cloudflare front server hostname is invalid") from error
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    def value(key: str, default: str = "") -> str:
        values = query.get(key)
        return values[-1].strip() if values else default

    if value("security").casefold() != "tls" or value("type").casefold() != "ws":
        raise ValueError("Cloudflare front must use TLS WebSocket transport")
    if value("encryption", "none").casefold() != "none":
        raise ValueError("Cloudflare front must use VLESS encryption=none")
    user_id = urllib.parse.unquote(parsed.username)
    if not re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        user_id,
    ):
        raise ValueError("Cloudflare front VLESS UUID is invalid")
    server = parsed.hostname
    host_header = value("host", value("sni", server))
    servername = value("sni", host_header)
    path = value("path", "/") or "/"
    if not path.startswith("/"):
        path = "/" + path
    if not host_header or not servername:
        raise ValueError("Cloudflare front Host and SNI must not be empty")
    return {
        "name": "NODEHUB-CF-FRONT",
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": user_id,
        "udp": True,
        "tls": True,
        "servername": servername,
        "client-fingerprint": "chrome",
        "network": "ws",
        "ws-opts": {"path": path, "headers": {"Host": host_header}},
    }


def lookup_ipapi_is(exit_ip: str) -> dict[str, Any]:
    """Optional HTTPS enrichment; requires the user's server-side free API key."""
    key = os.getenv("IPAPI_IS_API_KEY", "").strip()
    if not key:
        return {"ipapi_is_status": "not_configured"}
    time.sleep(0.15)
    response = request_json(
        "https://api.ipapi.is",
        method="POST",
        payload={"ips": [exit_ip], "key": key},
        timeout=10,
    )
    item = response.get(exit_ip)
    if not isinstance(item, dict) or item.get("ip") != exit_ip:
        raise LookupFailure("ipapi.is returned missing or mismatched exit-IP evidence")
    company = item.get("company") if isinstance(item.get("company"), dict) else {}
    asn = item.get("asn") if isinstance(item.get("asn"), dict) else {}
    location = item.get("location") if isinstance(item.get("location"), dict) else {}
    flags = {
        field: item.get(field)
        for field in (
            "is_datacenter", "is_proxy", "is_tor", "is_abuser",
            "is_mobile", "is_satellite", "is_anycast", "is_crawler",
        )
    }
    return {
        "ipapi_is_status": "ok",
        "ipapi_is_flags": flags,
        "ipapi_is_vpn": bool(item.get("is_vpn")) if item.get("is_vpn") is not None else None,
        "ipapi_is_company_type": company.get("type"),
        "ipapi_is_asn_type": asn.get("type"),
        "ipapi_is_asn": asn.get("asn"),
        "ipapi_is_country": location.get("country_code"),
        "ipapi_is_operator": company.get("name"),
    }


def parse_public_ip(raw: str) -> str:
    address = ipaddress.ip_address(raw.strip())
    if not address.is_global:
        raise ValueError("echo endpoint returned a non-public address")
    return str(address)


def curl_exit_ip(url: str) -> str:
    result = subprocess.run(
        ["curl", "--silent", "--show-error", "--fail",
         "--connect-timeout", "5", "--max-time", "8",
         "--proxy", SOCKS, url],
        check=True, capture_output=True, text=True,
    )
    return parse_public_ip(result.stdout)


def echo_pair(*, attempts: int = 2) -> tuple[str, bool]:
    """Confirm the tunnel egress by two-of-three independent echo services."""
    if attempts < 1:
        raise ValueError("echo attempts must be positive")

    def query(url: str) -> str:
        last_error: Exception | None = None
        for attempt in range(attempts):
            try:
                return curl_exit_ip(url)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError) as error:
                last_error = error
                if attempt + 1 < attempts:
                    time.sleep(1.0 * (attempt + 1))
        if last_error is not None:
            raise last_error
        raise LookupFailure("exit-IP echo failed without a diagnostic")

    endpoints = (
        "https://api.ipify.org",
        "https://checkip.amazonaws.com",
    )
    results: list[str] = []
    errors: list[Exception] = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(query, endpoint) for endpoint in endpoints]
        for future in futures:
            try:
                results.append(future.result())
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError) as error:
                errors.append(error)

    if len(results) == 2 and results[0] == results[1]:
        return results[0], True

    try:
        results.append(query("https://icanhazip.com"))
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError) as error:
        errors.append(error)

    if results:
        ip, votes = Counter(results).most_common(1)[0]
        return ip, votes >= 2
    if errors:
        raise errors[0]
    raise LookupFailure("no independent exit-IP echo service returned an address")

def oxl_lookup(kind: str, value: str) -> tuple[str, dict[str, Any] | None]:
    url = f"https://risk.oxl.app/api/{kind}/{urllib.parse.quote(value, safe='')}"
    try:
        return "ok", request_json(url)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return "not_reported", None
        raise


def layer3_lookup(exit_ip: str) -> dict[str, Any]:
    address = ipaddress.ip_address(exit_ip)
    if address.version != 4:
        raise LookupFailure("Layer3 Open API currently documents IPv4 address lookups only")
    data = request_json(f"https://api.layer3intel.com/open/{exit_ip}", timeout=10)
    network = data.get("network") or {}
    location = data.get("location") or {}
    risk = data.get("risk") or {}
    flags = data.get("flags") or {}
    if data.get("ip") != exit_ip:
        raise LookupFailure("Layer3 returned a mismatched IP")
    if not isinstance(network, dict) or not isinstance(location, dict):
        raise LookupFailure("Layer3 returned incomplete network or location data")
    if not isinstance(risk, dict) or not isinstance(flags, dict):
        raise LookupFailure("Layer3 returned incomplete risk or flag data")
    reasons = risk.get("reasons")
    if not isinstance(reasons, list):
        raise LookupFailure("Layer3 returned no risk-reason list")
    try:
        layer3_asn = int(network.get("asn"))
    except (TypeError, ValueError):
        raise LookupFailure("Layer3 returned no valid network ASN")
    try:
        layer3_network = ipaddress.ip_network(network.get("prefix"), strict=False)
    except (TypeError, ValueError) as error:
        raise LookupFailure("Layer3 returned no valid network prefix") from error
    if address not in layer3_network:
        raise LookupFailure("Layer3 network prefix does not contain the observed exit IP")
    return {
        "layer3_ip": data.get("ip"),
        "layer3_prefix_match": True,
        "layer3_type": data.get("type"),
        "layer3_risk_level": risk.get("level"),
        "layer3_risk_score": risk.get("score"),
        "layer3_risk_reasons": reasons,
        "layer3_flags": flags,
        "layer3_country": location.get("country"),
        "layer3_asn": layer3_asn,
        "layer3_network_type": network.get("type"),
        "layer3_prefix": network.get("prefix"),
        "layer3_drop_listed": network.get("drop_listed") is True,
        "layer3_sharing": data.get("sharing"),
        "layer3_crawler": bool(data.get("crawler")),
    }


def report_sum(data: dict[str, Any] | None) -> float | None:
    if not data:
        return None
    reports = data.get("reports")
    if not isinstance(reports, dict):
        return None
    value = reports.get("sum")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def make_profile(proxies: list[dict[str, Any]], pool: str) -> dict[str, Any]:
    names = [item["name"] for item in proxies]
    groups = [{"name": "NODEHUB", "type": "select", "proxies": names or ["DIRECT"]}]
    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "ipv6": True,
        "proxies": proxies,
        "proxy-groups": groups,
        "rules": ["MATCH,NODEHUB"],
        "profile": {"store-selected": True, "store-fake-ip": True},
    }


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def validate_profile_content(content: str, pool: str) -> None:
    with tempfile.TemporaryDirectory(prefix="nodehub-profile-check-") as temporary:
        home = Path(temporary)
        profile_path = home / f"{pool}.yaml"
        profile_path.write_text(content, encoding="utf-8")
        result = subprocess.run(
            [str(MIHOMO), "-t", "-d", str(home), "-f", str(profile_path)],
            capture_output=True, text=True, timeout=20,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout)[-1200:]
            raise LookupFailure(f"Mihomo rejected {pool} profile: {detail}")




def combine_candidate_sources(primary, supplemental, *, total_limit=MAX_TOTAL_CANDIDATES, supplemental_limit=MAX_SUPPLEMENTAL_CANDIDATES):
    """Interleave FreeNodes and bounded supplemental OpenVPN candidates."""
    if total_limit < 1 or supplemental_limit < 0:
        raise ValueError("candidate limits are invalid")
    supplemental = supplemental[:min(supplemental_limit, total_limit)]
    primary = primary[:max(0, total_limit-len(supplemental))]
    merged, seen = [], set()
    if supplemental:
        for index, extra in enumerate(supplemental):
            left, right = index*len(primary)//len(supplemental), (index+1)*len(primary)//len(supplemental)
            for item in primary[left:right] + [extra]:
                name = item.get("name")
                if isinstance(name,str) and name not in seen:
                    seen.add(name); merged.append(item)
        for item in primary:
            name=item.get("name")
            if isinstance(name,str) and name not in seen:
                seen.add(name); merged.append(item)
    else:
        for item in primary:
            name=item.get("name")
            if isinstance(name,str) and name not in seen:
                seen.add(name); merged.append(item)
    merged=merged[:total_limit]
    return merged, {
        "freenodes_included":sum(not str(x.get("name","")).startswith(("VPNGate-","VPNBook-")) for x in merged),
        "vpngate_included":sum(str(x.get("name","")).startswith("VPNGate-") for x in merged),
        "vpnbook_included":sum(str(x.get("name","")).startswith("VPNBook-") for x in merged),
        "total":len(merged),
    }

def _is_us_advertised(candidate: dict[str, Any]) -> bool:
    """Use source labels only as a sampling hint; never as exit-country evidence."""
    name = str(candidate.get("name", "")).strip()
    return bool(
        re.match(r"^(?:VPNGate|VPNBook)-US(?:-|$)", name, re.IGNORECASE)
        or re.match(r"^US(?:\s|[·:_-])", name, re.IGNORECASE)
    )


def _rotating_pick(indices: list[int], budget: int, rotation: int) -> list[int]:
    if budget <= 0 or not indices:
        return []
    if budget >= len(indices):
        return list(indices)
    size = len(indices)
    return [
        indices[(((2 * index + 1) * size) // (2 * budget) + rotation) % size]
        for index in range(budget)
    ]


def _sample_source_group(candidates, indices: list[int], budget: int, rotation: int) -> list[int]:
    """Prefer US-advertised candidates within each source quota, then rotate the rest."""
    us = [index for index in indices if _is_us_advertised(candidates[index])]
    us_set = set(us)
    other = [index for index in indices if index not in us_set]
    chosen = _rotating_pick(us, min(len(us), budget), rotation)
    chosen.extend(_rotating_pick(other, budget - len(chosen), rotation + (1 if chosen else 0)))
    return chosen


def select_exit_candidates(candidates, limit, *, rotation=0):
    """Rotate source quotas while giving US-advertised candidates first look.

    Country labels are untrusted discovery hints only. Actual exit country and
    network classification still come exclusively from the observed proxy egress.
    """
    if limit < 1:
        raise ValueError("candidate limit must be positive")
    rotation = max(0, rotation)
    if len(candidates) <= limit:
        return list(candidates)

    groups = {
        "primary": [
            i for i, item in enumerate(candidates)
            if not str(item.get("name", "")).startswith(("VPNGate-", "VPNBook-"))
        ],
        "VPNGate": [
            i for i, item in enumerate(candidates)
            if str(item.get("name", "")).startswith("VPNGate-")
        ],
        "VPNBook": [
            i for i, item in enumerate(candidates)
            if str(item.get("name", "")).startswith("VPNBook-")
        ],
    }
    secondary = [key for key in ("VPNGate", "VPNBook") if groups[key]]
    if not secondary:
        chosen = _sample_source_group(candidates, groups["primary"], limit, rotation)
        return [item for index, item in enumerate(candidates) if index in set(chosen)]

    sec_budget = min(sum(len(groups[key]) for key in secondary), (limit + 1) // 2)
    primary_budget = min(len(groups["primary"]), limit - sec_budget)
    sec_budget = min(sum(len(groups[key]) for key in secondary), limit - primary_budget)
    base, remainder = divmod(sec_budget, len(secondary))
    budgets = {
        key: min(len(groups[key]), base + (index < remainder))
        for index, key in enumerate(secondary)
    }
    unused = sec_budget - sum(budgets.values())
    while unused:
        changed = False
        for key in secondary:
            if budgets[key] < len(groups[key]):
                budgets[key] += 1
                unused -= 1
                changed = True
                if not unused:
                    break
        if not changed:
            break

    chosen = set()
    for source_index, (key, budget) in enumerate(
        [("primary", primary_budget)] + [(key, budgets[key]) for key in secondary]
    ):
        chosen.update(_sample_source_group(candidates, groups[key], budget, rotation + source_index))
    return [item for index, item in enumerate(candidates) if index in chosen]

def run() -> None:
    if not SOURCE_PROFILE.is_file() or not MIHOMO.is_file():
        raise SystemExit("Required merged profile or pinned Mihomo binary is missing")
    source = yaml.safe_load(SOURCE_PROFILE.read_text(encoding="utf-8"))
    candidates = source.get("proxies") if isinstance(source, dict) else None
    if not isinstance(candidates, list):
        candidates = []
    candidates = [item for item in candidates if isinstance(item, dict) and isinstance(item.get("name"), str)]
    primary_candidates = candidates
    supplemental_candidates: list[dict[str, Any]] = []
    for source_name, source_path, source_limit in (
        ("VPN Gate", VPNGATE_PROFILE, 100),
        ("VPN Gate rolling mirror", VPNGATE_ROLLING_PROFILE, MAX_VPNGATE_CANDIDATES - 100),
        ("VPNBook", VPNBOOK_PROFILE, 10),
    ):
        if source_path.is_file():
            try:
                supplemental_doc = yaml.safe_load(source_path.read_text(encoding="utf-8"))
                raw_supplemental = supplemental_doc.get("proxies") if isinstance(supplemental_doc, dict) else None
                if isinstance(raw_supplemental, list):
                    supplemental_candidates.extend(
                        x for x in raw_supplemental[:source_limit]
                        if isinstance(x, dict) and isinstance(x.get("name"), str)
                    )
            except (OSError, yaml.YAMLError) as error:
                print(f"{source_name} candidate artifact unavailable: {type(error).__name__}: {error}", flush=True)
    candidates, source_candidate_counts = combine_candidate_sources(
        primary_candidates, supplemental_candidates
    )
    available_candidates = len(candidates)
    source_discovery = {}
    if SOURCE_REPORT.is_file():
        try:
            source_discovery = json.loads(SOURCE_REPORT.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            source_discovery = {"status": "unreadable"}
    if not candidates:
        raise SystemExit("No usable proxies found across FreeNodes, VPN Gate and VPNBook sources")
    rotation = int(os.getenv("GITHUB_RUN_NUMBER", "0"))
    advertised_us_available = sum(_is_us_advertised(item) for item in candidates)
    candidates = select_exit_candidates(candidates, MAX_CANDIDATES, rotation=rotation)
    advertised_us_selected = sum(_is_us_advertised(item) for item in candidates)

    proxy_names = [item["name"] for item in candidates]
    if len(proxy_names) != len(set(proxy_names)):
        raise SystemExit("Duplicate proxy names; refusing ambiguous exit selection")

    # Optional Cloudflare VLESS front is used only as the CI probe underlay.
    # Never serialize its private UUID into the public subscription artifacts.
    cf_front_uri = os.getenv("NODEHUB_CF_FRONT_URI", "").strip()
    cf_front = parse_cloudflare_front_config(cf_front_uri) if cf_front_uri else None
    probe_candidates, vpngate_probe_count = prepare_probe_candidates(candidates, cf_front)
    if cf_front and vpngate_probe_count:
        print(
            f"VPNGate probe underlay: {cf_front['name']} enabled for {vpngate_probe_count} selected candidates; URI omitted from artifacts",
            flush=True,
        )

    grouped: dict[str, list[dict[str, Any]]] = {key: [] for key in OUTPUTS}
    evidence_rows: list[dict[str, Any]] = []
    counters: Counter[str] = Counter()
    asn_cache: dict[int, tuple[str, dict[str, Any] | None]] = {}
    ip_cache: dict[str, tuple[str, dict[str, Any] | None, dict[str, Any], str]] = {}
    net_cache: dict[str, tuple[str, dict[str, Any] | None]] = {}
    layer3_cache: dict[str, dict[str, Any]] = {}

    with tempfile.TemporaryDirectory(prefix="nodehub-exit-check-") as temporary:
        work = Path(temporary)
        config = {
            "socks-port": 7891,
            "allow-lan": False,
            "mode": "rule",
            "log-level": "error",
            "ipv6": True,
            "external-controller": "127.0.0.1:9090",
            "secret": SECRET,
            "proxies": probe_candidates + ([cf_front] if cf_front and vpngate_probe_count else []),
            "proxy-groups": [{
                "name": "EXIT",
                "type": "select",
                "proxies": proxy_names,
            }],
            "rules": ["MATCH,EXIT"],
        }
        config_path = work / "config.yaml"
        config_path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
        process = subprocess.Popen(
            [str(MIHOMO), "-d", str(work), "-f", str(config_path)],
            cwd=work, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            ready = False
            for _ in range(40):
                if process.poll() is not None:
                    raise SystemExit("Mihomo exited before its controller became ready")
                try:
                    request_json(f"{CONTROLLER}/version", controller=True, timeout=1)
                    ready = True
                    break
                except Exception:
                    time.sleep(0.5)
            if not ready:
                raise SystemExit("Mihomo controller startup timed out")

            for index, proxy in enumerate(candidates, start=1):
                name = proxy["name"]
                row: dict[str, Any] = {
                    "node_name": name,
                    "checked_at": datetime.now(UTC).isoformat(),
                    "exit_echo_agreement": None,
                    "metadata_status": "not_checked",
                    "layer3_status": "not_checked",
                    "ip_metadata_success": False,
                    "oxl_asn_status": "not_checked",
                    "ip_risk_status": "not_checked",
                    "net_status": "not_checked",
                    "probe_underlay": "NODEHUB-CF-FRONT" if cf_front and name.startswith("VPNGate-") else "DIRECT",
                }
                try:
                    request_json(
                        f"{CONTROLLER}/proxies/EXIT",
                        method="PUT", payload={"name": name}, controller=True,
                    )
                    selected = request_json(f"{CONTROLLER}/proxies/EXIT", controller=True)
                    if selected.get("now") != name:
                        raise LookupFailure("Mihomo did not confirm the requested node")
                    time.sleep(0.25)
                    exit_ip, agreement = echo_pair()
                    row["exit_ip"] = exit_ip
                    row["exit_echo_agreement"] = agreement
                    if not agreement:
                        raise ValueError("insufficient independent exit-IP consensus")

                    row["metadata_status"] = "pending"
                    if exit_ip in ip_cache:
                        ip_status, ip_data, metadata, metadata_source = ip_cache[exit_ip]
                    else:
                        metadata, metadata_source = lookup_ip_metadata(exit_ip)
                        row["metadata_status"] = "ok"
                        row["ip_risk_status"] = "pending"
                        time.sleep(1.25)
                        ip_status, ip_data = oxl_lookup("ip", exit_ip)
                        if ip_status == "not_reported":
                            time.sleep(1.25)
                            ip_status, ip_data = oxl_lookup("ip", exit_ip)
                        ip_cache[exit_ip] = (ip_status, ip_data, metadata, metadata_source)

                    row["metadata_status"] = "ok"
                    row["ip_risk_status"] = ip_status
                    row.update(metadata)
                    row["metadata_source"] = metadata_source
                    row["ip_metadata_success"] = True
                    row["layer3_status"] = "pending"
                    if exit_ip not in layer3_cache:
                        time.sleep(0.5)
                        layer3_cache[exit_ip] = layer3_lookup(exit_ip)
                    row.update(layer3_cache[exit_ip])
                    row["layer3_status"] = "ok"
                    row["ip_risk_status"] = ip_status
                    row["net_status"] = "pending"
                    if exit_ip not in net_cache:
                        time.sleep(1.25)
                        net_cache[exit_ip] = oxl_lookup("net", exit_ip)
                    net_status, net_data = net_cache[exit_ip]
                    row["net_status"] = net_status
                    if net_data:
                        row["net_source"] = "oxl-api"
                        row["net_kind"] = net_data.get("kind", [])
                        row["net_reports"] = report_sum(net_data)
                        row["net_reputation"] = net_data.get("reputation")
                        row["net_asn_match"] = net_data.get("asn") == row["asn"]
                        try:
                            network = ipaddress.ip_network(net_data.get("network"), strict=False)
                            row["net_prefix_match"] = ipaddress.ip_address(exit_ip) in network
                        except (TypeError, ValueError):
                            row["net_prefix_match"] = False
                    elif net_status == "not_reported":
                        # A missing O-X-L network report is not called "clean".
                        # Layer3 supplies independent address/network/risk evidence.
                        layer3_type = row.get("layer3_network_type")
                        if layer3_type == "access":
                            row["net_kind"] = ["isp"]
                        elif layer3_type == "hosting":
                            row["net_kind"] = ["hosting"]
                        else:
                            row["net_kind"] = []
                        row["net_source"] = "layer3-open-network"
                        row["net_reports"] = 0
                        row["net_reputation"] = "not_reported"
                        row["net_asn_match"] = row.get("layer3_asn") == row["asn"]
                        row["net_prefix_match"] = row.get("layer3_prefix_match") is True
                    if ip_data:
                        row["ip_kind"] = ip_data.get("kind", [])
                        row["ip_reports"] = report_sum(ip_data)

                    asn = row["asn"]
                    row["oxl_asn_status"] = "pending"
                    if asn not in asn_cache:
                        time.sleep(1.25)
                        asn_cache[asn] = oxl_lookup("asn", str(asn))
                    asn_status, asn_data = asn_cache[asn]
                    row["oxl_asn_status"] = asn_status
                    if asn_data:
                        row["asn_kind"] = asn_data.get("kind", [])
                        row["asn_reports"] = report_sum(asn_data)
                    else:
                        row["asn_kind"] = []
                        row["asn_reports"] = 0
                    if (
                        name.startswith("VPNGate-")
                        and row.get("layer3_type") == "vpn"
                        and row.get("layer3_network_type") == "access"
                    ):
                        row.update(lookup_ipapi_is(exit_ip))

                    verdict = classify(row)
                    row["pool"] = verdict.pool
                    row["reason"] = verdict.reason
                    if verdict.pool:
                        grouped[verdict.pool].append(proxy)
                        counters[verdict.pool] += 1
                    else:
                        counters["quarantined"] += 1
                except (LookupFailure, ValueError, subprocess.CalledProcessError, urllib.error.HTTPError) as error:
                    for status_field in (
                        "metadata_status", "layer3_status", "ip_risk_status",
                        "net_status", "oxl_asn_status",
                    ):
                        if row.get(status_field) == "pending":
                            row[status_field] = "unavailable"
                    row["pool"] = None
                    detail = " ".join(str(error).split())[:220]
                    row["reason"] = f"quarantined:{type(error).__name__}:{detail}"
                    counters["quarantined"] += 1
                evidence_rows.append(row)
                print(f"[{index}/{len(candidates)}] {name[:64]} -> {row.get('pool') or row.get('reason')}", flush=True)
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    report = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "source_profile": "nodes/merged.yaml",
        "candidate_limit": MAX_CANDIDATES,
        "candidate_selection": {
            "strategy": "source_stratified_with_us_hint_priority",
            "available": available_candidates,
            "selected": len(candidates),
            "advertised_us_available": advertised_us_available,
            "advertised_us_selected": advertised_us_selected,
        },
        "source_candidate_counts": source_candidate_counts,
        "source_discovery": source_discovery,
        "checked": len(evidence_rows),
        "counts": dict(counters),
        "pool_sizes": {pool: len(items) for pool, items in grouped.items()},
        "evidence": evidence_rows,
        "notes": [
            "Residential pool means ISP-network candidates, not proof of a household line.",
            "Low-risk means no disqualifying signal was found in the selected sources; it is not a safety guarantee.",
            "Unverified, conflicting, or failed lookups are quarantined.",
            "A pool with no new verified candidates keeps its last known-good profile; first-run empty pools remain explicitly empty.",
        ],
    }
    from scripts.diagnostics import build_diagnostics
    from scripts.publication import publish_atomically, write_reports_atomically

    diagnostics = build_diagnostics(
        evidence_rows,
        pool_sizes=report["pool_sizes"],
        candidate_limit=MAX_CANDIDATES,
    )
    report["diagnostics"] = diagnostics
    diagnostic_text = json.dumps(diagnostics, ensure_ascii=False, indent=2) + "\n"
    # Persist failure evidence before the publication gate; subscriptions stay untouched.
    write_reports_atomically(
        EVIDENCE_PATH,
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        {DIAGNOSTICS_PATH: diagnostic_text},
    )
    print("Classification diagnostics:", json.dumps(diagnostics, sort_keys=True), flush=True)

    if not any(row.get("ip_metadata_success") for row in evidence_rows):
        raise SystemExit("No exit IPs could be independently verified; previous subscriptions preserved")

    profiles = {
        pool: make_profile(grouped[pool], pool)
        for pool in OUTPUTS
    }
    for pool, profile in profiles.items():
        rendered = yaml.safe_dump(profile, allow_unicode=True, sort_keys=False)
        validate_profile_content(rendered, pool)

    # Validate every pool and every Mihomo profile before touching the last
    # known-good subscriptions. A failed run must never replace them with empties.
    publish_atomically(
        OUTPUTS,
        profiles,
        EVIDENCE_PATH,
        report,
        validate_profile=validate_profile_content,
        additional_files={
            DIAGNOSTICS_PATH: diagnostic_text
        },
    )
    print("Classification summary:", json.dumps(report["pool_sizes"], sort_keys=True))
    print("Diagnostic rejection reasons:", json.dumps(diagnostics["reason_counts"], sort_keys=True))


if __name__ == "__main__":
    run()
