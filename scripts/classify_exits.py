#!/usr/bin/env python3
"""Probe Mihomo exit IPs and publish conservative classified subscriptions."""
from __future__ import annotations

import ipaddress
import json
import os
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
MAX_CANDIDATES = int(os.getenv("NODEHUB_MAX_EXIT_PROBES", "100"))
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
            result = json.loads(response.read())
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise
        if error.code == 429 or error.code >= 500:
            raise SystemExit(f"Intelligence source unavailable: HTTP {error.code}; previous subscriptions are preserved") from error
        raise LookupFailure(f"lookup rejected: HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise LookupFailure(f"lookup failed: {type(error).__name__}") from error
    if not isinstance(result, dict):
        raise LookupFailure("unexpected JSON response shape")
    return result


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


def echo_pair() -> tuple[str, bool]:
    first = curl_exit_ip("https://api.ipify.org")
    second = curl_exit_ip("https://checkip.amazonaws.com")
    return first, first == second


def oxl_lookup(kind: str, value: str) -> tuple[str, dict[str, Any] | None]:
    url = f"https://risk.oxl.app/api/{kind}/{urllib.parse.quote(value, safe='')}"
    try:
        return "ok", request_json(url)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return "not_reported", None
        raise


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


def run() -> None:
    if not SOURCE_PROFILE.is_file() or not MIHOMO.is_file():
        raise SystemExit("Required merged profile or pinned Mihomo binary is missing")
    source = yaml.safe_load(SOURCE_PROFILE.read_text(encoding="utf-8"))
    candidates = source.get("proxies") if isinstance(source, dict) else None
    if not isinstance(candidates, list) or not candidates:
        raise SystemExit("No validated proxies found in merged profile")
    candidates = [item for item in candidates if isinstance(item, dict) and isinstance(item.get("name"), str)]
    candidates = candidates[:MAX_CANDIDATES]
    if not candidates:
        raise SystemExit("No usable proxy entries found")

    proxy_names = [item["name"] for item in candidates]
    if len(proxy_names) != len(set(proxy_names)):
        raise SystemExit("Duplicate proxy names; refusing ambiguous exit selection")

    grouped: dict[str, list[dict[str, Any]]] = {key: [] for key in OUTPUTS}
    evidence_rows: list[dict[str, Any]] = []
    counters: Counter[str] = Counter()
    asn_cache: dict[int, tuple[str, dict[str, Any] | None]] = {}
    ip_cache: dict[str, tuple[str, dict[str, Any] | None, dict[str, Any]]] = {}

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
            "proxies": candidates,
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
                    "exit_echo_agreement": False,
                    "ipwhois_success": False,
                    "oxl_asn_status": "not_checked",
                    "ip_risk_status": "not_checked",
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
                        raise ValueError("independent exit-IP echo services disagree")

                    if exit_ip in ip_cache:
                        ip_status, ip_data, ip_info = ip_cache[exit_ip]
                    else:
                        time.sleep(0.35)
                        ip_info = request_json(f"https://ipwho.is/{exit_ip}")
                        if ip_info.get("success") is not True or ip_info.get("ip") != exit_ip:
                            raise LookupFailure("IPWhois did not verify the observed exit IP")
                        ip_status, ip_data = oxl_lookup("ip", exit_ip)
                        ip_cache[exit_ip] = (ip_status, ip_data, ip_info)

                    connection = ip_info.get("connection") or {}
                    asn_raw = connection.get("asn")
                    try:
                        asn = int(str(asn_raw).upper().removeprefix("AS"))
                    except (TypeError, ValueError):
                        raise LookupFailure("IPWhois response has no usable ASN")
                    country = ip_info.get("country_code")
                    if not isinstance(country, str) or len(country) != 2:
                        raise LookupFailure("IPWhois response has no country code")
                    row.update({
                        "country_code": country.upper(),
                        "asn": asn,
                        "isp": connection.get("isp") or connection.get("org"),
                        "ipwhois_success": True,
                    })
                    row["ip_risk_status"] = ip_status
                    if ip_data:
                        row["ip_kind"] = ip_data.get("kind", [])
                        row["ip_reports"] = report_sum(ip_data)

                    asn = row["asn"]
                    if asn not in asn_cache:
                        time.sleep(1.25)
                        asn_cache[asn] = oxl_lookup("asn", str(asn))
                    asn_status, asn_data = asn_cache[asn]
                    row["oxl_asn_status"] = asn_status
                    if asn_data:
                        row["asn_kind"] = asn_data.get("kind", [])
                        row["asn_reports"] = report_sum(asn_data)

                    verdict = classify(row)
                    row["pool"] = verdict.pool
                    row["reason"] = verdict.reason
                    if verdict.pool:
                        grouped[verdict.pool].append(proxy)
                        counters[verdict.pool] += 1
                    else:
                        counters["quarantined"] += 1
                except (LookupFailure, ValueError, subprocess.CalledProcessError, urllib.error.HTTPError) as error:
                    row["pool"] = None
                    row["reason"] = f"quarantined:{type(error).__name__}"
                    counters["quarantined"] += 1
                evidence_rows.append(row)
                print(f"[{index}/{len(candidates)}] {name[:64]} -> {row.get('pool') or row.get('reason')}")
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    if not any(row.get("ipwhois_success") for row in evidence_rows):
        raise SystemExit("No exit IPs could be independently verified; keeping previous classified subscriptions")

    for pool, path in OUTPUTS.items():
        profile = make_profile(grouped[pool], pool)
        atomic_write(path, yaml.safe_dump(profile, allow_unicode=True, sort_keys=False))

    report = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "source_profile": "nodes/merged.yaml",
        "candidate_limit": MAX_CANDIDATES,
        "checked": len(evidence_rows),
        "counts": dict(counters),
        "pool_sizes": {pool: len(items) for pool, items in grouped.items()},
        "evidence": evidence_rows,
        "notes": [
            "Residential pool means ISP-network candidates, not proof of a household line.",
            "Low-risk means no disqualifying signal was found in the selected sources; it is not a safety guarantee.",
            "Unverified, conflicting, or failed lookups are quarantined.",
        ],
    }
    atomic_write(EVIDENCE_PATH, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print("Classification summary:", json.dumps(report["pool_sizes"], sort_keys=True))


if __name__ == "__main__":
    run()
