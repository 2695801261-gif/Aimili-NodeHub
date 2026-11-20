"""Official VPNBook OpenVPN source adapter. Credentials are runtime-only."""
from __future__ import annotations
import io, json, re, urllib.error, urllib.parse, urllib.request, zipfile
from html import unescape
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from collections import Counter
from pathlib import Path
from typing import Any
import yaml
from scripts.vpngate import MIHOMO, VPNGateError, _validate_batch, parse_ovpn_config

ROOT = Path(__file__).resolve().parents[1]
PAGE_URL = "https://www.vpnbook.com/freevpn/openvpn"
BASE_URL = "https://www.vpnbook.com"
OUTPUT = ROOT / ".cache" / "vpnbook" / "candidates.yaml"
REPORT = ROOT / "classification" / "vpnbook-discovery.json"
MAX_PAGE_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_PROFILES = 60

class VPNBookError(RuntimeError):
    pass

def _fetch(url: str, limit: int) -> bytes:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "www.vpnbook.com":
        raise VPNBookError("refusing non-official VPNBook URL")
    req = urllib.request.Request(url, headers={"User-Agent":"Aimili-NodeHub/0.1","Accept":"*/*"})
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            data = response.read(limit + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise VPNBookError(f"VPNBook request failed: {type(error).__name__}") from error
    if len(data) > limit:
        raise VPNBookError("VPNBook response exceeded configured size limit")
    return data

def parse_vpnbook_page(page: str) -> tuple[tuple[str,str], list[str]]:
    # Parse visible text rather than relying on a particular HTML element name.
    # The official page also mentions the password update date elsewhere, so
    # prefer the dedicated VPN Credentials section before looking at the FAQ.
    plain = unescape(re.sub(r"<[^>]+>", " ", page))
    plain = re.sub(r"\\s+", " ", plain)
    section = plain
    if re.search(r"VPN\\s+Credentials", plain, re.I):
        section = re.split(r"VPN\\s+Credentials", plain, maxsplit=1, flags=re.I)[1]
        section = re.split(r"Last\\s+updated", section, maxsplit=1, flags=re.I)[0]
    password = re.search(
        r"\\bPassword\\b\\s*:?[\\s]+([A-Za-z0-9!@#$%^&*()_+\\-]{4,64})",
        section,
        re.I,
    )
    if not password:
        # Legacy page variants label the value directly in the FAQ.
        password = re.search(
            r"Username\\s*:\\s*vpnbook[.\\s]+Password\\s*:\\s*([A-Za-z0-9!@#$%^&*()_+\\-]{4,64})",
            plain,
            re.I,
        )
    if not password:
        raise VPNBookError("current shared password not found on official page")
    links = re.findall(r"""href=["']([^"']+\\.zip(?:\\?[^"']*)?)["']""", page, re.I)
    urls = []
    for link in links:
        absolute = urllib.parse.urljoin(BASE_URL, link)
        parsed = urllib.parse.urlparse(absolute)
        if parsed.scheme == "https" and parsed.hostname == "www.vpnbook.com" and parsed.path.startswith("/free-openvpn-account/") and parsed.path.lower().endswith(".zip"):
            if absolute not in urls:
                urls.append(absolute)
    if not urls:
        raise VPNBookError("official page exposed no OpenVPN ZIP links")
    return ("vpnbook", password.group(1).strip()), urls


