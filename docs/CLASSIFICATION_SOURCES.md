# Classification data sources and evidence

This document describes the sources used by the current classifier. Classification is performed on the **proxy's observed exit IP**, never on the node endpoint or its remark.

## Sources

### IPWhois (ipwho.is)

- Documentation: https://ipwhois.io/documentation
- Endpoint: `https://ipwho.is/{exit-ip}`
- Role: resolve the observed public exit IP to country, ASN, ISP and organization.
- It does not provide authoritative VPN/proxy/Tor or abuse-risk verdicts.

### O-X-L Risk Database

- Main project: https://github.com/O-X-L/risk-db
- IP lookup: `https://risk.oxl.app/api/ip/{exit-ip}`
- Network lookup: `https://risk.oxl.app/api/net/{exit-ip}`
- ASN lookup: `https://risk.oxl.app/api/asn/{asn}`
- API documentation: https://risk.oxl.app/api/docs/
- Published database license: BSD-3-Clause. The project's separate scripts are GPLv3; this repository does not copy those scripts.
- Role: per-IP and per-network kind/reputation/report checks plus per-ASN kind/report checks. The current implementation deliberately uses the documented per-IP/per-network/per-ASN lookup endpoints rather than relying on the ASN kind-list endpoint.
- The project's own documentation warns that reports may contain false positives and should be treated as risk signals, not proof of malicious intent.
- The project documents unauthenticated API limits of 500 requests per 10 minutes and 5,000 per day. The classifier caps exit probes at 100, caches IP/network/ASN lookups within each run, spaces requests, and aborts on rate limiting or server errors.

## Admission policy implemented by the current classifier

Every candidate must first pass these gates:

1. Mihomo selects the exact requested proxy node.
2. Two independent HTTPS IP-echo services agree on the same globally routable exit IP.
3. IPWhois successfully resolves that exact exit IP and returns a valid country, ASN and non-empty operator name.
4. O-X-L network lookup must return a valid kind list, reputation `ok` or `info`, and exactly zero reports. Missing network records and other lookup failures are quarantined.
5. O-X-L ASN lookup must return a valid kind list and exactly zero reports. Missing ASN records are quarantined.
6. O-X-L IP lookup must return zero reports, or the endpoint must return `not_reported` after a retry. Its documentation describes IP 404 as “not reported or temporary lookup failure”; this ambiguity is retained in evidence and is not proof of zero abuse.
7. VPN, proxy, Tor, scanner, crawler, education, maybe-hacked, mobile, CGNAT, relay, anycast and conflicting network-kind signals cause quarantine.

### US residential candidate

- The ASN lookup must positively include `isp`.
- The network lookup must positively include `isp` and must not include `hosting`.
- The observed exit country must be `US`.
- No disqualifying or conflicting signal may be present.

### Other-country residential candidate

Same requirements as US residential, except the observed exit country must be a valid country other than `US`.

These are ISP-network residential *candidates*, not proof that the address belongs to a household broadband line. A residential proxy can exit through a real ISP ASN.

### Low-risk datacenter candidate

- The ASN lookup must positively include `hosting`.
- The network lookup must positively include `hosting` and must not include `isp`.
- The network reputation must be `ok` or `info`, with zero reports.
- The ASN and IP risk gates must also pass.
- No VPN, proxy, Tor, scanner, crawler, education or conflicting signal may be present.

“Low-risk” means only that the selected public sources did not return the configured exclusion signals at check time. It is not a safety guarantee.

## Quarantine

Unknown/unlisted network types, mobile or other unsupported types, VPN, proxy, Tor, scanner, crawler, education, CGNAT, relay, anycast, conflicting evidence, missing exit IP, failed echo agreement, invalid lookup responses, API errors, rate limits and unsupported address families are not published.

## Privacy and operational limits

- Only proxy exit IPs and their ASNs are sent to public intelligence services. The evidence file retains node names and observed exit IPs for troubleshooting; no user account credentials or personal browsing history are sent.
- Raw evidence records the observed exit IP, country, ASN, operator, risk status, pool verdict and reason.
- The workflow writes new classified subscriptions only after classification completes and validates each generated profile with Mihomo. A failed classification run does not publish partially generated pools.
