"""Fail-closed classification rules for observed proxy exit IPs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

DISQUALIFYING_KINDS = {
    "vpn", "proxy", "tor", "scanner", "crawler", "education",
    "maybe_hacked", "mobile", "hosting", "business", "government",
}


@dataclass(frozen=True)
class Verdict:
    pool: str | None
    reason: str


def _kinds(value: Any) -> set[str]:
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        return set()
    return {x.strip().casefold() for x in value}


def classify(evidence: dict[str, Any]) -> Verdict:
    """Classify only when every required evidence field is present and consistent."""
    country = evidence.get("country_code")
    asn = evidence.get("asn")
    isp_name = evidence.get("isp")
    if not isinstance(evidence.get("asn_kind"), list):
        return Verdict(None, "asn_network_type_missing")
    asn_kinds = _kinds(evidence.get("asn_kind"))
    ip_status = evidence.get("ip_risk_status")
    if ip_status == "ok" and not isinstance(evidence.get("ip_kind"), list):
        return Verdict(None, "ip_network_type_missing")
    ip_kinds = _kinds(evidence.get("ip_kind", []))
    asn_reports = evidence.get("asn_reports")
    ip_reports = evidence.get("ip_reports")

    if not isinstance(country, str) or len(country) != 2 or country.upper() in {"ZZ", "XX", "T1", "A1", "EU", "AP"}:
        return Verdict(None, "missing_or_invalid_country")
    if isinstance(asn, bool) or not isinstance(asn, int) or asn <= 0:
        return Verdict(None, "missing_or_invalid_asn")
    if not isinstance(isp_name, str) or not isp_name.strip():
        return Verdict(None, "network_operator_name_missing")
    if evidence.get("exit_echo_agreement") is not True:
        return Verdict(None, "exit_echo_mismatch")
    if evidence.get("ipwhois_success") is not True:
        return Verdict(None, "exit_ip_lookup_failed")
    if evidence.get("oxl_asn_status") not in {"ok", "not_reported"}:
        return Verdict(None, "asn_intelligence_unavailable")
    if isinstance(asn_reports, bool) or not isinstance(asn_reports, (int, float)):
        return Verdict(None, "asn_risk_count_missing")
    if asn_reports != 0:
        return Verdict(None, "asn_has_abuse_reports")
    if ip_status not in {"ok", "not_reported"}:
        return Verdict(None, "ip_risk_lookup_failed")
    if ip_status == "ok":
        if isinstance(ip_reports, bool) or not isinstance(ip_reports, (int, float)):
            return Verdict(None, "ip_risk_count_missing")
        if ip_reports != 0:
            return Verdict(None, "ip_has_abuse_reports")
    if ip_kinds & (DISQUALIFYING_KINDS - {"hosting"}):
        return Verdict(None, "ip_has_disqualifying_network_signal")

    if "isp" in asn_kinds:
        if "hosting" in ip_kinds:
            return Verdict(None, "conflicting_isp_hosting_ip_signal")
        if asn_kinds & (DISQUALIFYING_KINDS - {"hosting"}):
            return Verdict(None, "conflicting_isp_asn_signals")
        if "hosting" in asn_kinds:
            return Verdict(None, "conflicting_isp_hosting_signals")
        return Verdict(
            "us-residential" if country == "US" else "other-residential",
            "isp_asn_list_confirmed_no_known_disqualifying_signal",
        )

    if "hosting" in asn_kinds:
        if evidence.get("oxl_asn_status") != "ok":
            return Verdict(None, "hosting_asn_risk_lookup_missing")
        if "isp" in ip_kinds:
            return Verdict(None, "conflicting_isp_hosting_ip_signal")
        if asn_kinds & (DISQUALIFYING_KINDS - {"hosting"}):
            return Verdict(None, "conflicting_hosting_asn_signals")
        if "isp" in asn_kinds:
            return Verdict(None, "conflicting_isp_hosting_signals")
        return Verdict("low-risk-datacenter", "hosting_asn_list_confirmed_no_known_risk_signal")

    return Verdict(None, "network_type_not_confirmed")
