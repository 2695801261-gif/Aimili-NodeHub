# Classification data sources and evidence

This document records the source selection for the three output pools. Classification is performed on the **proxy's observed exit IP**, never on the node endpoint or its remark.

## Sources selected for the first classifier

### IPWhois (`ipwho.is`)

- Documentation: https://ipwhois.io/documentation
- Endpoint: `https://ipwho.is/{exit-ip}`
- Free tier: no API key, 1,000 lookups/day per runner egress IP.
- Role: independent exit-IP country, ASN, ISP and organization observation. The free tier does **not** provide VPN/proxy/Tor security flags; those must come from other sources.

### O-X-L Risk Database

- Main project: https://github.com/O-X-L/risk-db
- Lists: https://github.com/O-X-L/risk-db-lists
- API documentation: https://risk.oxl.app/api/docs
- Data license: BSD-3-Clause for the published databases.
- Role: live ASN kind lists (ISP, hosting, VPN, proxy, Tor, scanner, crawler and education), plus per-IP, per-network and per-ASN lookups. Network reputation and kind are checked against the observed exit IP; conflicting kinds and nonzero report counts are quarantined.
- The project's own documentation warns that reports can be false positives and that the data is an early-stage risk signal. A match is a reason to quarantine/review, not proof of malicious intent.
- API limits documented by the project: unauthenticated 500 requests / 10 minutes and 5,000 / day. The classifier must cache lookups per run and stop safely on 429/5xx.

### OpenASN (secondary reference, not a sole verdict)

- Data project: https://github.com/openasn/openasn
- License: MIT for code and CC0 for the core dataset.
- It provides explainable categories such as `residential_isp`, `hosting`, `vpn`, `mobile`, `business`, and `unknown`.
- Its documentation explicitly says `residential_isp` is not proof of a home user and cannot detect residential-proxy abuse by itself.
- The rolling `latest` release must pass a freshness check before use. A stale release is ignored; no stale classification data is silently treated as current.

## Admission policy

### US residential candidate

All of the following are required:

1. Mihomo successfully selects the node and two independent HTTPS IP-echo services agree on the same public exit IP.
2. IPtoASN resolves a routable public address and reports country `US`.
3. Network intelligence supports an access ISP classification; no hosting, VPN, proxy, Tor, mobile-carrier, enterprise-gateway, education, government, or conflicting signal is present.
4. O-X-L IP/network/ASN checks do not return a positive disqualifying or high-risk signal.
5. All source lookups are successful or explicitly documented as non-reporting; timeouts, schema changes, rate limits, and contradictory results cause quarantine.

### Other-country residential candidate

Same requirements as US residential, except the exit country must be known and not `US`.

### Low-risk datacenter candidate

All of the following are required:

1. Actual exit IP is independently observed and ASN/country are resolved by IPWhois; O-X-L independently classifies the ASN.
2. Hosting/datacenter is positively supported by ASN or IP/network classification.
3. The per-network lookup must return hosting classification, reputation of ok/info and zero reports.
4. The per-ASN risk lookup must succeed and report zero abuse reports; a missing ASN risk record is not sufficient for this pool.
5. No VPN, proxy, Tor, relay, mobile, enterprise-gateway, scanner, crawler, or high-risk abuse signal is present.
6. No conflicting or missing evidence at a required gate. Any uncertainty goes to quarantine.

“Low-risk” is relative to the selected public intelligence sources and their freshness. It is not a safety guarantee.

## Quarantine rules

Unknown, mobile, CGNAT, relay, VPN, Tor, business, education, government, conflicting evidence, missing exit IP, failed echo agreement, lookup errors, stale databases, and unsupported address families are not published in any of the three pools.

## Privacy and operational limits

- Only proxy exit IPs are sent to the public intelligence services; no account credentials or user browsing data are sent.
- The project should cache each IP/ASN lookup during a run, cap the number of candidates, and preserve the previous good subscription if any required check fails.
- Raw evidence should record source name, lookup time, database/API version where available, and the exact reason for admission or quarantine.
