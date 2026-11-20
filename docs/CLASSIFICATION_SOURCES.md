# Classification data sources and evidence

All lookups apply to the **proxy's observed exit IP**, never the configured server endpoint or node remark.

## Sources

### Exit-IP identity
- IPWhois: https://ipwho.is/{exit-ip}; primary country, ASN and ISP/organization metadata.
- IPinfo legacy public endpoint: https://ipinfo.io/{exit-ip}/json; fallback only when IPWhois is unavailable or incomplete.
- Both are queried only after two independent HTTPS echo services agree on the exit IP.

### Layer3 Intel Open API
- Documentation: https://docs.layer3intel.com/docs/intel-api/open-api
- Address endpoint: `https://api.layer3intel.com/open/{exit-ip}`
- No API key or credits are required for the Open API. The documentation describes IPv4 address lookups.
- Role: independent address type, risk score/reasons, anonymizer flags, country, ASN, announced prefix and network type.
- The classifier requires exact IP, country, ASN and prefix agreement with the observed exit and the separate IP metadata result.
- Residential admission requires `type=residential`, `network.type=access`, a low risk score below 25, no risk reasons, no anonymizer/proxy/VPN/Tor/relay/hosting flags and no shared-address/crawler/drop-list signal.
- Datacenter admission requires `type=hosting`, `network.type=hosting`, Layer3's ordinary-hosting baseline (`risk.level=medium`, `risk.score=50`, `risk.reasons=["hosting"]`), no anonymizer/proxy/VPN/Tor/relay flags, and no additional risk reason. This is not a numerically low Layer3 risk score; the subscription filename is retained for compatibility.
- The Open API does not include the paid-only live residential-proxy flag. A residential result is an address-type candidate, not proof that the exit is not being resold as a residential proxy.

### O-X-L Risk Database
- Main project: https://github.com/O-X-L/risk-db
- IP lookup: `https://risk.oxl.app/api/ip/{exit-ip}`
- Network lookup: `https://risk.oxl.app/api/net/{exit-ip}`
- ASN lookup: `https://risk.oxl.app/api/asn/{asn}`
- API documentation: https://risk.oxl.app/api/docs/
- Published database license: BSD-3-Clause. The project's separate scripts are GPLv3; this repository does not copy those scripts.
- Role: IP- and ASN-level kind/report checks, plus network reputation and network-kind checks when a network record exists.
- O-X-L documents network 404 as “Network not reported”. This is not treated as a positive clean reputation; independent Layer3 risk and prefix evidence must still pass. If an O-X-L network record exists, it must have zero reports, reputation `ok/info`, a matching ASN/CIDR and compatible network kind.
- O-X-L documents IP 404 as “not reported or temporary lookup failure”. The classifier retries once and retains `not_reported` as an uncertainty signal, not proof of zero abuse.
- If an O-X-L ASN record exists, its ASN kind must positively support the target class and contain no disqualifying kind. The ASN report total is retained as network-level context, not treated as a report against every address in the ASN; exact IP and network records retain zero-report requirements. If O-X-L explicitly reports no ASN record, that absence is not a clean result: the candidate can proceed only when the independent Layer3 response matches the exact exit IP, country, ASN and announced prefix, has the class-specific risk rule, and confirms the target address/network type. O-X-L timeouts, rate limits and server errors are quarantined.
- O-X-L warns that reports can contain false positives; these are risk signals, not proof of malicious intent.
- Unauthenticated API limits documented by O-X-L: 500 requests per 10 minutes and 5,000 per day. The workflow caps the first-pass exit probes at 40 and caches repeated IP/network/ASN lookups within each run.

## Admission policy
Every candidate must pass all of these gates:

1. Mihomo selects the exact requested node.
2. Two independent HTTPS exit-echo services return the same globally routable IP.
3. IPWhois or the IPinfo fallback resolves that exact IP to a valid country, ASN and non-empty operator name.
4. Layer3 returns the exact IP, matching country/ASN and an announced prefix containing the exit IP, plus a low-risk result under the class-specific rules above.
5. If O-X-L ASN lookup returns a record, its ASN kind must positively confirm `isp` or `hosting` as appropriate and contain no disqualifying kind; its aggregate report count is recorded as context, not treated as an IP-level report. An explicit ASN `not_reported` result is not treated as clean; it can proceed only when Layer3 independently confirms the exact exit IP, country, ASN, announced prefix, low risk and target network type. Provider errors and rate limits remain quarantined.
6. O-X-L IP lookup reports zero, or returns 404 after retry with that uncertainty preserved in evidence. Any returned IP kind that conflicts with the class causes quarantine.
7. If O-X-L has a network record, it must pass zero-report, reputation, ASN, prefix and network-kind checks. If it returns 404, the candidate can proceed only on independent Layer3 network/risk evidence and the O-X-L ASN/IP gates.
8. VPN, proxy, Tor, scanner, crawler, education, maybe-hacked, mobile, CGNAT, relay, anycast, drop-listed, shared-address, conflicting or unknown types are quarantined.

### Residential pools
- Layer3 must positively label the observed exit address `residential` and its network `access`.
- Layer3 risk must be `low` with score below 25 and an empty risk-reasons list.
- If an O-X-L ASN record exists, it must positively include `isp` and have no conflicting kind. Aggregate ASN report totals are recorded but do not override exact-IP evidence. If explicitly not reported, Layer3 must independently confirm the exact IP/ASN/country/prefix and residential/access type at low risk.
- The country comes from IPWhois/IPinfo and must agree with Layer3. US goes to the US pool; all other valid countries go to the international pool.
- These are high-confidence residential-address candidates, not proof of a particular household line. Layer3's live residential-proxy detection is paid-only, so the free Open API cannot guarantee an address is not being used by a residential proxy service.

### Low-risk datacenter pool
- Layer3 must label both address and network `hosting`.
- Layer3 must return the ordinary hosting baseline exactly: `risk.level=medium`, `risk.score=50`, and `risk.reasons=["hosting"]`. Anonymizer/proxy/VPN/Tor/relay flags must be false; any extra reason (including `nearby_vpn` or `recent_reassignment`) is rejected.
- If an O-X-L ASN record exists, it must positively include `hosting` and have no conflicting kind. Aggregate ASN report totals are recorded but do not override exact-IP evidence. If explicitly not reported, Layer3 must independently confirm the exact IP/ASN/country/prefix and hosting/hosting type at the exact ordinary-hosting baseline.
- Any O-X-L network record must also confirm hosting, have zero reports and reputation `ok/info`. If no O-X-L network record exists, Layer3's independent exact-IP, prefix and ordinary-hosting-baseline evidence is required.
- “Low-risk” means only that the selected public sources did not return the configured exclusion signals at check time. It is not a safety guarantee.

## Quarantine and publication
Unknown or unsupported address/network types, IPv6 addresses not covered by the Layer3 Open address endpoint, missing exit IP, echo disagreement, metadata disagreement, API errors, rate limits, missing required ASN confirmation, risk signals or conflicting sources are not published.

The workflow writes all three profiles and the evidence report only after classification completes and Mihomo validates every generated profile. A failed run leaves the last committed subscriptions untouched. Public nodes and evidence are readable by anyone; do not use the subscriptions for sensitive traffic.
