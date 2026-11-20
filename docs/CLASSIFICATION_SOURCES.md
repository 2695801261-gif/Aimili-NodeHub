# Classification data sources and evidence

This document describes the sources actually used by the current first-version classifier. Classification is based on the **proxy's observed exit IP**, never on the node endpoint or its remark.

## Sources

### IPWhois (ipwho.is)

- Documentation: https://ipwhois.io/documentation
- Endpoint: `https://ipwho.is/{exit-ip}`
- Role: resolve the observed public exit IP to country, ASN, ISP and organization.
- It does not provide authoritative VPN/proxy/Tor or abuse-risk verdicts.

### O-X-L Risk Database

- Main project: https://github.com/O-X-L/risk-db
- ASN kind lists: `https://risk.oxl.app/api/list/asn/{isp|hosting|vpn|scanner|crawler|education}`
- Per-IP lookup: `https://risk.oxl.app/api/ip/{exit-ip}`
- Per-ASN lookup: `https://risk.oxl.app/api/asn/{asn}`
- API documentation: https://risk.oxl.app/api/docs/
- Published database license: BSD-3-Clause. The project’s separate scripts are GPLv3; this repository does not copy those scripts.
- Role: positive ISP/hosting network labels and IP/ASN risk signals. The classifier downloads the six ASN kind lists once per run and caches per-IP/per-ASN lookups.
- The project's own documentation warns that reports may contain false positives and should be treated as risk signals, not proof of malicious intent.
- The project documents unauthenticated API limits of 500 requests per 10 minutes and 5,000 per day. The classifier caps exit probes at 100, spaces requests, caches lookups, and aborts on rate limiting or server errors.

## Admission policy implemented by the current classifier

Every candidate must first pass these gates:

1. Mihomo selects the exact requested proxy node.
2. Two independent HTTPS IP-echo services agree on the same globally routable exit IP.
3. IPWhois successfully resolves that exact exit IP and returns a valid country, ASN and non-empty operator name.
4. O-X-L ASN kind lists are successfully downloaded. An ASN must be positively listed as ISP or hosting; an unknown/unlisted ASN is quarantined.
5. O-X-L ASN risk lookup returns zero reports, or the ASN endpoint explicitly returns its documented “not reported” response. Other lookup failures are not treated as clean.
6. O-X-L IP lookup returns zero reports, or the IP endpoint returns “not reported” after a retry. The API documents IP 404 as “not reported or temporary lookup failure”, so this is an uncertainty and not proof of zero abuse; it is retained in the evidence record.
7. VPN, proxy, Tor, scanner, crawler, education, maybe-hacked and conflicting network-kind signals cause quarantine. Hosting is permitted only for the hosting/datacenter pool.

### US residential candidate

- The ASN must be in O-X-L's ISP list.
- The observed exit country must be `US`.
- No disqualifying or conflicting signal may be present.

### Other-country residential candidate

- The ASN must be in O-X-L's ISP list.
- The observed exit country must be a valid country other than `US`.
- No disqualifying or conflicting signal may be present.

These are ISP-network residential *candidates*, not proof that the address belongs to a household broadband line. A residential proxy can exit through a real ISP ASN.

### Low-risk datacenter candidate

- The ASN must be in O-X-L's hosting list.
- The observed exit IP and ASN must pass the same lookup and zero-report gates.
- No VPN, proxy, Tor, scanner, crawler, education or conflicting ISP signal may be present.

“Low-risk” means only that the selected public sources did not return the configured exclusion signals at check time. It is not a safety guarantee. The current implementation does not claim a separate network-reputation lookup or an independent OpenASN cross-check.

## Quarantine

Unknown/unlisted network types, mobile or other unsupported types, VPN, proxy, Tor, scanner, crawler, education, conflicting evidence, missing exit IP, failed echo agreement, invalid lookup responses, API errors, rate limits and unsupported address families are not published.

## Privacy and operational limits

- Only proxy exit IPs and their ASNs are sent to public intelligence services. Node names are retained in the private-to-this-repository evidence file for troubleshooting; no user account credentials or personal browsing history are sent.
- Raw evidence records the observed exit IP, country, ASN, operator, risk status, pool verdict and reason.
- The workflow writes new classified subscriptions only after classification completes and validates each generated profile with Mihomo. A failed classification run does not publish partially generated pools.
