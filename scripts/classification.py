"""Fail-closed classification using observed exit IP and independent Layer3 intelligence."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

DISQUALIFYING_KINDS = {
    "vpn", "proxy", "tor", "scanner", "crawler", "education",
    "maybe_hacked", "mobile", "dynamic", "cgnat", "relay", "anycast", "business", "government",
}
ANONYMIZER_FLAGS = ("anonymizer", "proxy", "vpn", "tor", "relay")


@dataclass(frozen=True)
class Verdict:
    pool: str | None
    reason: str


def _kinds(value: Any) -> set[str]:
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        return set()
    return {x.strip().casefold() for x in value}



US_RESIDENTIAL_ISP_BRANDS = (
    "comcast", "xfinity", "charter communications", "spectrum",
    "frontier communications", "fidium", "consolidated communications",
    "wave broadband", "verizon fios", "verizon online",
    "cox communications", "cox cable", "at&t", "att internet",
    "att services", "att broadband", "optimum", "altice usa",
    "altafiber", "breezeline", "windstream", "mediacom",
    "centurylink", "century link", "lumen", "tds telecom",
    "wideopenwest", "wow", "rcn", "astound", "ziply", "starry",
    "google fiber", "sonic", "suddenlink", "armstrong", "buckeye",
    "atlantic broadband", "lumos", "hawaiian telcom", "cable one",
    "sparklight", "earthlink", "cablevision", "blue ridge communications",
    "grande communications",
)
OTHER_FIXED_RESIDENTIAL_ISP_BRANDS = (
    "korea telecom", "kt corporation", "sk broadband", "lg u+",
    "lgu+", "lg uplus", "lg hellovision", "hellovision",
    "so-net", "sony network communications", "jcom",
    "chubu telecommunications", "commufa", "ctcx", "asahi net",
    "asahi-net", "ocn", "ntt-me", "wakwak", "biglobe", "plala",
    "nifty", "@nifty", "orange", "etisalat", "arteria",
    "hawaiian telcom", "tt dotcom", "ttnet",
)


def _vpngate_residential_brand_candidate(evidence: dict[str, Any]) -> str | None:
    """Use XEHN-style fixed-ISP brand evidence as support, never by itself."""
    if not str(evidence.get("node_name") or "").startswith("VPNGate-"):
        return None
    isp = str(evidence.get("isp") or "").casefold()
    if not isp or any(term in isp for term in ("mobile", "mobility", "wireless", "cellular", "lte", "5g", "4g")):
        return None
    country = str(evidence.get("country_code") or "").upper()
    if country == "US" and any(brand in isp for brand in US_RESIDENTIAL_ISP_BRANDS):
        return "us"
    if country != "US" and any(brand in isp for brand in OTHER_FIXED_RESIDENTIAL_ISP_BRANDS):
        return "other"
    return None


def _is_vpngate_relay_transport_signal(evidence: dict[str, Any]) -> bool:
    """Recognize only VPNGate's exact VPN-on-ISP-access signature for audit.

    This does not make the exit residential or publishable. It separates the
    volunteer relay transport signal from the underlying access-network clue,
    so a later independent verifier can examine it without weakening the
    normal residential/datacenter admission gates.
    """
    flags = evidence.get("layer3_flags")
    return (
        isinstance(evidence.get("node_name"), str)
        and evidence["node_name"].startswith("VPNGate-")
        and evidence.get("layer3_type") == "vpn"
        and evidence.get("layer3_network_type") == "access"
        and evidence.get("layer3_risk_level") == "high"
        and evidence.get("layer3_risk_score") == 75
        and evidence.get("layer3_risk_reasons") == ["vpn"]
        and isinstance(flags, dict)
        and flags.get("anonymizer") is True
        and flags.get("vpn") is True
        and flags.get("proxy") is False
        and flags.get("tor") is False
        and flags.get("relay") is False
        and flags.get("hosting") is False
    )


def _vpngate_access_isp_confirmation(evidence: dict[str, Any]) -> bool:
    """Confirm a VPNGate relay on an ISP access prefix without misreading IPWHO.

    IPWHO's top-level type is the address family (for example, ipv4), not the
    ISP category. Use the matched Layer3 access prefix, ISP network type,
    IPWHO operator name, and (when present) O-X-L ASN/network evidence instead.
    """
    isp = str(evidence.get("isp") or "").casefold()
    country = str(evidence.get("country_code") or "").upper()
    brand_class = _vpngate_residential_brand_candidate(evidence)
    known_fixed_isp = brand_class == ("us" if country == "US" else "other")
    asn_status = evidence.get("oxl_asn_status")
    asn_kinds = _kinds(evidence.get("asn_kind"))
    asn_confirmed = (
        asn_status == "ok"
        and "isp" in asn_kinds
        and "hosting" not in asn_kinds
        and not (asn_kinds & (DISQUALIFYING_KINDS - {"vpn"}))
    )
    asn_not_reported_but_layer3_matches = (
        asn_status == "not_reported"
        and evidence.get("layer3_asn") == evidence.get("asn")
        and evidence.get("layer3_prefix_match") is True
    )
    net_kinds = _kinds(evidence.get("net_kind"))
    network_confirmed = (
        "isp" in net_kinds
        and "hosting" not in net_kinds
        and evidence.get("net_asn_match") is True
        and evidence.get("net_prefix_match") is True
        and evidence.get("net_source") in {"oxl-api", "layer3-open-network"}
    )
    ipapi_status = evidence.get("ipapi_is_status")
    ipapi_confirmed = ipapi_status in {None, "not_configured"}
    if ipapi_status == "ok":
        flags = evidence.get("ipapi_is_flags")
        required_false = (
            "is_datacenter", "is_proxy", "is_tor", "is_abuser",
            "is_mobile", "is_satellite", "is_anycast", "is_crawler",
        )
        ipapi_confirmed = (
            isinstance(flags, dict)
            and all(flags.get(flag) is False for flag in required_false)
            and evidence.get("ipapi_is_company_type") == "isp"
            and evidence.get("ipapi_is_asn_type") == "isp"
            and evidence.get("ipapi_is_asn") == evidence.get("asn")
            and evidence.get("ipapi_is_country") == country
        )
    elif ipapi_status not in {None, "not_configured"}:
        ipapi_confirmed = False
    return (
        _is_vpngate_relay_transport_signal(evidence)
        and evidence.get("metadata_source") == "ipwho.is"
        and known_fixed_isp
        and evidence.get("layer3_network_type") == "access"
        and network_confirmed
        and (asn_confirmed or asn_not_reported_but_layer3_matches)
        and ipapi_confirmed
    )


def _valid_layer3(evidence: dict[str, Any]) -> tuple[str | None, str]:
    ip = evidence.get("exit_ip")
    if not isinstance(ip, str):
        return None, "layer3_exit_ip_missing"
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None, "layer3_exit_ip_invalid"

    if address.version != 4:
        return None, "layer3_open_api_ipv4_only"

    if evidence.get("layer3_ip") != ip:
        return None, "layer3_ip_mismatch"
    asn = evidence.get("asn")
    layer3_asn = evidence.get("layer3_asn")
    if isinstance(layer3_asn, bool) or not isinstance(layer3_asn, int) or layer3_asn != asn:
        return None, "layer3_asn_mismatch"

    prefix = evidence.get("layer3_prefix")
    try:
        network = ipaddress.ip_network(prefix, strict=False)
    except (TypeError, ValueError):
        return None, "layer3_prefix_invalid"
    if address not in network:
        return None, "layer3_prefix_mismatch"

    layer3_country = evidence.get("layer3_country")
    if not isinstance(layer3_country, str) or layer3_country.upper() != evidence.get("country_code"):
        return None, "layer3_country_mismatch"

    risk_level = evidence.get("layer3_risk_level")
    risk_score = evidence.get("layer3_risk_score")
    if (
        risk_level not in {"low", "medium", "high", "critical"}
        or isinstance(risk_score, bool)
        or not isinstance(risk_score, (int, float))
        or not 0 <= risk_score <= 100
    ):
        return None, "layer3_risk_evidence_invalid"

    flags = evidence.get("layer3_flags")
    if not isinstance(flags, dict):
        return None, "layer3_flags_missing"
    for flag in ANONYMIZER_FLAGS:
        if flags.get(flag) is not False and not _is_vpngate_relay_transport_signal(evidence):
            return None, f"layer3_{flag}_signal"

    reasons = evidence.get("layer3_risk_reasons")
    if not isinstance(reasons, list) or any(not isinstance(item, str) for item in reasons):
        return None, "layer3_risk_reasons_missing"
    if evidence.get("layer3_sharing") is not None:
        return None, "layer3_shared_address"
    if evidence.get("layer3_drop_listed") is True:
        return None, "layer3_drop_listed"
    if evidence.get("layer3_crawler") is True:
        return None, "layer3_crawler_signal"

    return evidence.get("layer3_type"), ""


def classify(evidence: dict[str, Any]) -> Verdict:
    """Classify only when all required IP, ASN, route and risk evidence agrees."""
    country = evidence.get("country_code")
    asn = evidence.get("asn")
    isp_name = evidence.get("isp")
    if not isinstance(evidence.get("asn_kind"), list):
        return Verdict(None, "asn_network_type_missing")
    asn_kinds = _kinds(evidence.get("asn_kind"))

    if evidence.get("exit_echo_agreement") is not True:
        return Verdict(None, "exit_echo_mismatch")
    if evidence.get("ip_metadata_success") is not True:
        return Verdict(None, "exit_ip_lookup_failed")
    if not isinstance(country, str) or len(country) != 2 or country.upper() in {"ZZ", "XX", "T1", "A1", "EU", "AP"}:
        return Verdict(None, "missing_or_invalid_country")
    if isinstance(asn, bool) or not isinstance(asn, int) or asn <= 0:
        return Verdict(None, "missing_or_invalid_asn")
    if not isinstance(isp_name, str) or not isp_name.strip():
        return Verdict(None, "network_operator_name_missing")

    vpngate_access_isp = _vpngate_access_isp_confirmation(evidence)
    asn_status = evidence.get("oxl_asn_status")
    if asn_status == "ok":
        asn_reports = evidence.get("asn_reports")
        if isinstance(asn_reports, bool) or not isinstance(asn_reports, (int, float)):
            return Verdict(None, "asn_risk_count_missing")
        # O-X-L ASN report totals are aggregate network context, not
        # reports against this observed exit IP. Keep the count in evidence,
        # but do not treat it as an IP-level abuse finding. Require positive
        # ASN type agreement and apply zero-report gates to exact IP/network
        # records below.
        if asn_kinds & DISQUALIFYING_KINDS:
            if not (
                vpngate_access_isp
                and "isp" in asn_kinds
                and asn_kinds <= {"isp", "vpn"}
            ):
                return Verdict(None, "asn_has_disqualifying_signal")
    elif asn_status != "not_reported":
        # Provider errors and rate limits are not equivalent to an empty record.
        return Verdict(None, "asn_intelligence_unavailable")
    # A missing O-X-L ASN record is only eligible for consideration when the
    # independent Layer3 response later confirms the exact exit IP, ASN, prefix,
    # country, low risk score, and network/address type.

    ip_status = evidence.get("ip_risk_status")
    if ip_status not in {"ok", "not_reported"}:
        return Verdict(None, "ip_risk_lookup_failed")
    if ip_status == "ok":
        if not isinstance(evidence.get("ip_kind"), list):
            return Verdict(None, "ip_network_type_missing")
        ip_reports = evidence.get("ip_reports")
        if isinstance(ip_reports, bool) or not isinstance(ip_reports, (int, float)):
            return Verdict(None, "ip_risk_count_missing")
        if ip_reports != 0:
            return Verdict(None, "ip_has_abuse_reports")
    ip_kinds = _kinds(evidence.get("ip_kind", []))
    if ip_kinds & DISQUALIFYING_KINDS:
        if not (vpngate_access_isp and ip_kinds <= {"vpn"}):
            return Verdict(None, "ip_has_disqualifying_network_signal")

    net_status = evidence.get("net_status")
    net_kinds: set[str] = set()
    if net_status == "ok":
        if not isinstance(evidence.get("net_kind"), list):
            return Verdict(None, "network_kind_missing")
        net_kinds = _kinds(evidence.get("net_kind"))
        net_reports = evidence.get("net_reports")
        if isinstance(net_reports, bool) or not isinstance(net_reports, (int, float)):
            return Verdict(None, "network_report_count_missing")
        if net_reports != 0:
            return Verdict(None, "network_has_abuse_reports")
        if evidence.get("net_reputation") not in {"ok", "info"}:
            return Verdict(None, "network_reputation_not_acceptable")
        if evidence.get("net_asn_match") is not True or evidence.get("net_prefix_match") is not True:
            return Verdict(None, "network_prefix_or_asn_mismatch")
        if net_kinds & DISQUALIFYING_KINDS:
            if not (
                vpngate_access_isp
                and "isp" in net_kinds
                and net_kinds <= {"isp", "vpn"}
            ):
                return Verdict(None, "network_has_disqualifying_signal")
    elif net_status != "not_reported":
        return Verdict(None, "network_intelligence_unavailable")

    layer3_type, layer3_error = _valid_layer3(evidence)
    if layer3_error:
        return Verdict(None, layer3_error)

    if layer3_type == "residential":
        if (
            evidence.get("layer3_risk_level") != "low"
            or evidence.get("layer3_risk_score") >= 25
        ):
            return Verdict(None, "residential_risk_not_low")
        if evidence.get("layer3_network_type") != "access":
            return Verdict(None, "residential_network_type_not_access")
        if evidence.get("layer3_flags", {}).get("hosting") is not False:
            return Verdict(None, "residential_hosting_signal")
        if evidence.get("layer3_risk_reasons") != []:
            return Verdict(None, "residential_risk_reason_present")
        if asn_status == "ok":
            if "isp" not in asn_kinds or "hosting" in asn_kinds:
                return Verdict(None, "isp_asn_not_confirmed")
        elif evidence.get("layer3_network_type") != "access":
            return Verdict(None, "unreported_asn_lacks_independent_isp_confirmation")
        if net_status == "ok" and ("isp" not in net_kinds or "hosting" in net_kinds):
            return Verdict(None, "isp_network_conflict")
        if "hosting" in ip_kinds:
            return Verdict(None, "isp_hosting_ip_conflict")
        return Verdict(
            "us-residential" if country.upper() == "US" else "other-residential",
            "layer3_residential_access_and_isp_asn_confirmed",
        )

    if layer3_type == "vpn" and _is_vpngate_relay_transport_signal(evidence):
        # Permit only the narrow VPNGate VPN-on-access exception when the
        # fixed-line ISP name and exact Layer3 access prefix/ASN/network agree.
        # IPWHO's type is an address family, not an ISP type. The VPN flag is
        # expected from this transport; it does not prove a household line.
        if not vpngate_access_isp:
            brand_class = _vpngate_residential_brand_candidate(evidence)
            if brand_class == "us":
                return Verdict(None, "vpngate_us_consumer_isp_candidate_unverified")
            if brand_class == "other":
                return Verdict(None, "vpngate_other_consumer_isp_candidate_unverified")
            return Verdict(None, "vpngate_isp_access_relay_candidate_unverified")
        if not (asn_status == "ok" and "isp" in asn_kinds and "hosting" not in asn_kinds) and not (asn_status == "not_reported" and evidence.get("layer3_asn") == evidence.get("asn") and evidence.get("layer3_prefix_match") is True):
            return Verdict(None, "vpngate_access_isp_without_isp_asn_confirmation")
        if ip_status == "ok" and evidence.get("ip_reports") != 0:
            return Verdict(None, "vpngate_access_isp_without_clean_ip_reputation")
        if net_status == "ok" and ("isp" not in net_kinds or "hosting" in net_kinds):
            return Verdict(None, "vpngate_access_isp_network_conflict")
        if net_status not in {"ok", "not_reported"}:
            return Verdict(None, "vpngate_access_isp_network_unavailable")
        return Verdict(
            "us-residential" if country.upper() == "US" else "other-residential",
            "vpngate_isp_access_layer3_confirmed",
        )

    if layer3_type == "hosting":
        # Layer3's documented risk model assigns ordinary hosting a baseline
        # score of 50 (medium) with reason ["hosting"]. Admit only that exact
        # baseline; any additional reason/score remains quarantined.
        if (
            evidence.get("layer3_risk_level") != "medium"
            or evidence.get("layer3_risk_score") != 50
            or evidence.get("layer3_risk_reasons") != ["hosting"]
        ):
            return Verdict(None, "hosting_risk_exceeds_baseline")
        if evidence.get("layer3_network_type") != "hosting":
            return Verdict(None, "hosting_network_type_not_confirmed")
        if evidence.get("layer3_flags", {}).get("hosting") is not True:
            return Verdict(None, "hosting_flag_missing")
        allowed_reasons = {"hosting"}
        if any(reason not in allowed_reasons for reason in evidence.get("layer3_risk_reasons", [])):
            return Verdict(None, "hosting_risk_reason_present")
        if asn_status == "ok":
            if "hosting" not in asn_kinds:
                return Verdict(None, "hosting_asn_not_confirmed")
        elif evidence.get("layer3_network_type") != "hosting":
            return Verdict(None, "unreported_asn_lacks_independent_hosting_confirmation")
        if net_status == "ok" and ("hosting" not in net_kinds or "isp" in net_kinds):
            return Verdict(None, "hosting_network_conflict")
        if "isp" in ip_kinds:
            return Verdict(None, "hosting_isp_ip_conflict")
        return Verdict("low-risk-datacenter", "layer3_low_risk_hosting_and_asn_confirmed")

    return Verdict(None, "layer3_address_type_not_publishable")
