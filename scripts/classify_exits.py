#!/usr/bin/env python3
"""Probe Mihomo exit IPs and publish conservative classified subscriptions."""
from __future__ import annotations

import ipaddress
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
MAX_CANDIDATES = int(os.getenv("NODEHUB_MAX_EXIT_PROBES", "25"))
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
            raise SystemExit(f"Intelligence source unavailable: HTTP {error.code}; previous subscriptions are preserved") from error
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
                return {"country_code": country.upper(), "asn": asn, "isp": isp.strip()}, "ipwho.is"
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
    return {
        "layer3_ip": data.get("ip"),
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


NETWORK_KIND_LISTS = ("crawler", "dynamic", "education", "hosting", "isp", "scanner", "vpn")


def load_network_kind_index() -> dict[tuple[int, int, int], set[str]]:
    """Load O-X-L's published network CIDR kind lists once per run."""
    index: dict[tuple[int, int, int], set[str]] = {}
    for kind in NETWORK_KIND_LISTS:
        url = f"https://raw.githubusercontent.com/O-X-L/risk-db-lists/main/net/kind_{kind}.txt"
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                raw = response.read()
        except (urllib.error.URLError, TimeoutError) as error:
            raise SystemExit(
                f"Cannot load O-X-L network kind list ({kind}); preserving previous subscriptions"
            ) from error
        if not raw:
            if kind == "dynamic":
                continue
            raise SystemExit(
                f"O-X-L network kind list ({kind}) is unexpectedly empty; preserving previous subscriptions"
            )
        loaded = 0
        for line in raw.decode("utf-8", errors="strict").splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as error:
                raise SystemExit(
                    f"Invalid CIDR in O-X-L {kind} list: {value!r}"
                ) from error
            key = (network.version, network.prefixlen, int(network.network_address))
            index.setdefault(key, set()).add(kind)
            loaded += 1
        if kind != "dynamic" and loaded == 0:
            raise SystemExit(
                f"O-X-L network kind list ({kind}) had no valid CIDRs; preserving previous subscriptions"
            )
        print(f"Loaded O-X-L {kind} network ranges: {loaded}", flush=True)
    return index


def network_kinds_for_ip(
    exit_ip: str, index: dict[tuple[int, int, int], set[str]]
) -> set[str]:
    address = ipaddress.ip_address(exit_ip)
    bits = address.max_prefixlen
    value = int(address)
    kinds: set[str] = set()
    for prefix in range(bits + 1):
        mask = ((1 << prefix) - 1) << (bits - prefix) if prefix else 0
        network_address = value & mask
        kinds.update(index.get((address.version, prefix, network_address), set()))
    return kinds


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
    ip_cache: dict[str, tuple[str, dict[str, Any] | None, dict[str, Any], str]] = {}
    net_cache: dict[str, tuple[str, dict[str, Any] | None]] = {}
    network_kind_index = load_network_kind_index()

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
                    "ip_metadata_success": False,
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
                        ip_status, ip_data, metadata, metadata_source = ip_cache[exit_ip]
                    else:
                        metadata, metadata_source = lookup_ip_metadata(exit_ip)
                        time.sleep(1.25)
                        ip_status, ip_data = oxl_lookup("ip", exit_ip)
                        if ip_status == "not_reported":
                            time.sleep(1.25)
                            ip_status, ip_data = oxl_lookup("ip", exit_ip)
                        ip_cache[exit_ip] = (ip_status, ip_data, metadata, metadata_source)

                    row.update(metadata)
                    row["metadata_source"] = metadata_source
                    row["ip_metadata_success"] = True
                    time.sleep(0.5)
                    row.update(layer3_lookup(exit_ip))
                    row["ip_risk_status"] = ip_status
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
                        # The O-X-L lookup API only returns network objects for reported
                        # networks. Use its separately published CIDR kind lists to
                        # establish network class; absence of an API record is recorded
                        # as "not_reported", never as an "ok" reputation verdict.
                        static_kinds = network_kinds_for_ip(exit_ip, network_kind_index)
                        row["net_source"] = "oxl-kind-cidr-list"
                        row["net_kind"] = sorted(static_kinds)
                        row["net_reports"] = 0
                        row["net_reputation"] = "not_reported"
                        row["net_prefix_match"] = bool(static_kinds)
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
                    else:
                        row["asn_kind"] = []
                        row["asn_reports"] = 0
                    if net_status == "not_reported":
                        row["net_asn_match"] = bool(
                            set(row.get("net_kind", [])) & set(row.get("asn_kind", []))
                        )

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

    if not any(row.get("ip_metadata_success") for row in evidence_rows):
        failures = Counter(row.get("reason", "unknown") for row in evidence_rows)
        print("Exit verification failure summary:", failures.most_common(10), flush=True)
        raise SystemExit("No exit IPs could be independently verified; keeping previous classified subscriptions")

    rendered_profiles: list[tuple[Path, str]] = []
    for pool, path in OUTPUTS.items():
        profile = make_profile(grouped[pool], pool)
        rendered = yaml.safe_dump(profile, allow_unicode=True, sort_keys=False)
        validate_profile_content(rendered, pool)
        rendered_profiles.append((path, rendered))
    for path, rendered in rendered_profiles:
        atomic_write(path, rendered)

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
