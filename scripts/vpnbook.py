"""Official VPNBook OpenVPN source adapter. Credentials are runtime-only."""
from __future__ import annotations
import io, json, re, urllib.error, urllib.parse, urllib.request, zipfile
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
    password = re.search(r"Password(?:\s|&nbsp;|<[^>]*>)*:?(?:\s|&nbsp;|<[^>]*>)*<strong>\s*([^<]{4,64})", page, re.I)
    if not password:
        raise VPNBookError("current shared password not found on official page")
    links = re.findall(r"""href=["']([^"']+\.zip(?:\?[^"']*)?)["']""", page, re.I)
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

def parse_archives(archives: list[tuple[str,bytes]], credentials: tuple[str,str], limit: int = MAX_PROFILES) -> tuple[list[dict[str,Any]],dict[str,Any]]:
    proxies, rejected, seen = [], Counter(), set()
    for url, raw in archives:
        if len(raw) > MAX_ARCHIVE_BYTES:
            rejected["archive_too_large"] += 1
            continue
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                for info in archive.infolist():
                    if info.is_dir() or not info.filename.lower().endswith(".ovpn"):
                        continue
                    if info.file_size < 1 or info.file_size > 128 * 1024:
                        rejected["profile_size_invalid"] += 1
                        continue
                    try:
                        profile = archive.read(info).decode("utf-8-sig")
                        basename = Path(info.filename).name
                        proxy = parse_ovpn_config(profile, "VPNBook-" + basename[:-5], credentials)
                    except (VPNGateError, UnicodeDecodeError, zipfile.BadZipFile) as error:
                        rejected[type(error).__name__ + ":" + str(error)[:100]] += 1
                        continue
                    key = (proxy["server"], proxy["port"], proxy["proto"])
                    if key in seen:
                        continue
                    seen.add(key)
                    proxy["source"] = "vpnbook_official"
                    proxies.append(proxy)
                    if len(proxies) >= limit:
                        break
        except (zipfile.BadZipFile, OSError):
            rejected["invalid_zip"] += 1
        if len(proxies) >= limit:
            break
    return proxies, {"source":"vpnbook_official","archives_seen":len(archives),"candidates_parsed":len(proxies),"rejection_reasons":dict(rejected),"limit":limit}

def collect_vpnbook() -> dict[str,Any]:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    try:
        page = _fetch(PAGE_URL, MAX_PAGE_BYTES).decode("utf-8", errors="replace")
        credentials, links = parse_vpnbook_page(page)
        archives = []
        fetch_errors = Counter()
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [(url, executor.submit(_fetch, url, MAX_ARCHIVE_BYTES)) for url in links[:12]]
            for url, future in futures:
                try:
                    archives.append((url, future.result(timeout=30)))
                except (Exception, FutureTimeout) as error:
                    fetch_errors[type(error).__name__] += 1
        if not archives:
            raise VPNBookError("all official VPNBook configuration archives failed to download")
        proxies, report = parse_archives(archives, credentials)
        report["archive_fetch_errors"] = dict(fetch_errors)
        if not MIHOMO.is_file():
            raise VPNBookError("pinned Mihomo binary is missing; cannot validate OpenVPN profiles")
        valid, rejected = _validate_batch(proxies, MIHOMO)
        report["mihomo_validated"] = len(valid)
        report["mihomo_rejected"] = rejected
        report["status"] = "ok" if valid else "empty"
        OUTPUT.write_text(yaml.safe_dump({"proxies":valid},allow_unicode=True,sort_keys=False),encoding="utf-8")
    except Exception as error:
        report = {"source":"vpnbook_official","status":"unavailable","error":f"{type(error).__name__}: {' '.join(str(error).split())[:220]}","candidates_parsed":0}
        OUTPUT.write_text(yaml.safe_dump({"proxies":[]},sort_keys=False),encoding="utf-8")
    REPORT.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("VPNBook discovery:",json.dumps(report,ensure_ascii=False,sort_keys=True),flush=True)
    return report

if __name__ == "__main__":
    collect_vpnbook()
