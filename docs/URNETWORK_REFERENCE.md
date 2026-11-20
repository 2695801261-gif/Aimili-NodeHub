# URnetwork architecture reference and NodeHub boundaries

This note records design patterns reviewed from the public URnetwork documentation and source code. It is an architectural reference, not a claim that NodeHub implements URnetwork's protocol or security guarantees.

## What URnetwork actually is

URnetwork is not simply an aggregator of public VPN subscriptions. It is a member-operated network with two separate roles:

- A client consumes bandwidth through currently online member devices.
- A provider explicitly opts in to share spare bandwidth. Providing is off by default; documented modes include Auto, Always, Network (own devices only), and Never.
- Provider presence is tied to an observed live connection. Locations are offered only while member devices are online there; a claimed country or a source label is not sufficient.
- Provider selection is continuously ranked using measured reliability and speed. The client maintains a small provider window and replaces slow or disconnected providers rather than trusting a static list.
- The relayed path separates client identity from the provider. The optional sealed session encrypts client-to-provider traffic; the published overview says the seal is off by default, so it must not be assumed active.
- Provider-side egress safety is a first-class data-plane feature. The open-source `connect` IP-security layer applies cheap destination/reputation and port rules first, then stateful flow inspection for BitTorrent and suspicious encrypted egress.

Primary references:
- [URnetwork architecture overview](https://ur.io/docs/overview)
- [URnetwork FAQ: providing and safety](https://ur.io/docs/faq)
- [URnetwork Linux provider setup](https://ur.io/docs/getting-started-linux)
- [URnetwork connect IP security specification](https://github.com/urnetwork/connect/blob/main/docs/IP_SECURITY.md)
- [URnetwork Android provide modes](https://ur.io/docs/tour-android)

## What NodeHub can adopt now

1. **Presence and freshness, not just discovery.** Keep source discovery, syntax validation, real-exit verification, intelligence checks, and publication as separate stages. Attach timestamps and source provenance to every candidate and every decision.
2. **Continuous quality scoring.** Track latency, successful echo rate, recent failure rate, and last-seen time. Use those only to order the probe queue; never let a speed score override the IP-risk gate.
3. **Small rotating samples.** Continue rotating across independent sources so one large feed cannot monopolize every exit probe. Preserve deterministic run-number rotation for reproducible diagnostics.
4. **Failover-safe subscriptions.** Keep last-known-good profiles when a new cycle has no replacement nodes. A failed run must never publish unverified candidates or erase a previously valid pool.
5. **Explicit provider safety boundary.** If NodeHub ever grows a provider-sharing mode, it must be opt-in, isolated from ordinary client use, and enforce abuse controls at the provider's egress. Merely collecting residential-looking public proxies does not create a safe residential network.

## What must not be copied or claimed

- A VPNGate/VPNBook endpoint is a third-party VPN relay, not an opt-in household provider. Its source country, server IP, ASN label, and latency do not prove a residential exit.
- A public proxy aggregator cannot honestly promise URnetwork-style provider identity separation, provider-side packet filtering, or sealed client-to-provider sessions unless those mechanisms are actually implemented and independently tested.
- Do not weaken ASN/IP/network/Layer3 checks to make the three subscription files non-empty. An empty pool is preferable to a falsely labelled residential or low-risk pool.
- Do not expose dynamic credentials, private source URLs, or provider metadata in diagnostics. Public subscription credentials are still public once published.

## Video and project references

The reviewed YouTube tutorial [Pangolin: self-hosted Cloudflare and VPN replacement](https://www.youtube.com/watch?v=c8f-YPiUBZM) is useful for understanding a self-hosted ZTNA/reverse-proxy control plane, but Pangolin is not a free public-node collector and should not be transplanted as one.

For the actual collection/testing workflow, compare:
- [ProxyCollector](https://github.com/Mahdi0024/ProxyCollector): multi-source collection with sing-box testing.
- [V2ray-Tester](https://github.com/lblwb/V2ray-Tester): staged static rejection, TCP precheck, core-based connection tests, active security probes, and bounded speed tests.
- [ProxyHarvest](https://github.com/ombluetuneAI/ProxyHarvest): source collection, deduplication, Mihomo validation, and separate speed-ranking stages.

## Additional project and video comparisons

Further review suggests keeping the collector and the local validation engine as separate concerns:

- [wzdnzd/aggregator](https://github.com/wzdnzd/aggregator) demonstrates broad Telegram/GitHub/search discovery, configurable source groups, and multiple output formats. NodeHub can borrow its source-adapter inventory and quota management, but should keep its stricter observed-exit and risk gates.
- [V2RayDAR](https://github.com/411A/V2RayDAR) demonstrates concurrent subscription fetching, real-network sing-box validation, ranking, and serving a continuously refreshed local pool. Its live quality ranking is a useful reference; NodeHub's server-side classification must remain separate from simple reachability.
- [Residential Proxy Filter](https://github.com/cravinos/residential-proxy-filter) demonstrates concurrent exit-IP enrichment. Its single-provider hosting flag is not strong enough to certify residential status for NodeHub, so it is a comparison point rather than a replacement for independent Layer3 and ASN evidence.

Related YouTube walkthroughs reviewed:
- [GitHub one-click free-node collection and subscription workflow](https://www.youtube.com/watch?v=0Q8zher0x7Q) — useful for understanding public-source discovery and client import flow; promotional speed claims are not verification evidence.
- [Build a self-hosted sing-box proxy with VLESS and Hysteria2](https://www.youtube.com/watch?v=5_67h-HjwfA) — useful for the future opt-in, self-operated provider path; it does not provide public node discovery.
- [Generate sing-box configuration in the browser](https://www.youtube.com/watch?v=9CnqlpCn4pw) — useful for configuration conversion and client compatibility, not exit-IP trust.

The main practical takeaway is to improve candidate diversity, evidence freshness, and probe throughput without conflating availability with trust.
