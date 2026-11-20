# Discovery source coverage

## Active compatible sources

The collection workflow uses the complete source list from the pinned FreeNodes revision. It must not filter the list down to `github_file` entries: the pinned engine also supports `web`, `password_page`, and `youtube_resources` adapters. Each source is bounded by the engine's per-source artifact/byte budgets, per-run byte budget, request timeout, concurrency, parser admission, freshness checks, and Mihomo capability checks.

At the pinned revision, the configured web discovery sources include ClashMeta, NodeV2Ray, FreeClashNode, ClashNode, OneClash, CFmem, JichangX, ClashStair, and Datiya. The active GitHub-file sources include maintained Mihomo/Clash/V2Ray subscription repositories. Password-page and YouTube-resource adapters are also configured with bounded password-candidate policies. The exact list is version-pinned in the upstream `config.yaml`; this repository's workflow prints the active adapter counts in the Actions log.

The reserve-only `audit_sources` remain inactive in the normal publication run. They are not silently promoted into production sources.

## VPN Gate compatibility

[VPN Gate](https://www.vpngate.net/en/) is a useful public VPN relay directory, but it is not a direct Mihomo/Clash subscription source. Its official documentation lists SoftEther VPN, L2TP/IPsec, OpenVPN, and MS-SSTP connection methods; its OpenVPN instructions require downloading and importing a `.ovpn` profile. The pinned FreeNodes parser and Mihomo publication pipeline accept typed Clash proxies and supported proxy URIs, not arbitrary OpenVPN profiles.

Therefore VPN Gate must not be represented as a Mihomo node by copying its server IP, port, country, or CSV metadata into a proxy record. That would create a fake/unusable node and would also confuse server location with the observed proxy exit. A future VPN Gate adapter would need a separate OpenVPN runtime test and a supported portable client format before any record could enter a FlClash/Mihomo subscription. Until then, VPN Gate is explicitly documented as an unsupported source format rather than silently counted as discovered nodes.

## End-to-end admission remains mandatory

All compatible-source candidates are deduplicated and syntax-checked by FreeNodes, measured through Mihomo, then capped to 500 published candidates. The classification module samples at most 25 across the complete Mihomo-ranked pool and tests the real exit IP through two independent echo services. IPWhois/IPinfo, Layer3 Intel, and O-X-L evidence gates remain unchanged. A node's source label, advertised country, server address, or upstream ping score is never used as proof of exit country, residential status, or low risk.

Source discovery success is not the same as a publishable classified node. If a source yields no compatible nodes or a candidate fails the exit/risk checks, it is recorded as unavailable/rejected and is not inserted into any of the three subscription pools.
