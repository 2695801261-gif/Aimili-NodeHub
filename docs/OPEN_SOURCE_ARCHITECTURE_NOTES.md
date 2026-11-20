# 开源项目架构对照与本模块采用项

本项目只借鉴公开项目中可验证的工程模式，不复制实现代码，也不把不同项目的产品定位混为一谈。

## 参考项目

- [XEHN Android 分支](https://github.com/hezhanleiok/xehn/tree/xehn-android)：确实包含 VPNGate 采集器，通过 WARP underlay 获取同一个官方 API，随后做 TCP 预检、OpenVPN 握手/流量测速，并用 ip-api + ipwho.is 丰富 ISP/ASN 证据。代码中的分类细节需要谨慎看：`enrichClassify` 对没有强住宅或机房信号的节点会调用 `heuristicClass`，其规则是“非硬机房 ASN、非机房关键词即住宅”；这能显著扩大住宅标签数量，但不是严格的家庭宽带证明。其 README 所称“分类家宽/机房”不能等同于每个住宅标签都有双源住宅证据。NodeHub 借鉴 WARP underlay、TCP 预检、握手测速、ISP 品牌名单和 ipwho 第二意见；不照搬默认住宅回退，仍要求真实出口 IP、国家、ASN、Layer3 网络类型和风险信息交叉通过。
- [ProxyCollector](https://github.com/Mahdi0024/ProxyCollector)：多来源代理收集，使用 sing-box 进行真实代理连通性测试，并导出不同客户端订阅。可参考协议覆盖、引擎验证和多格式输出。
- [VLESS Collector](https://github.com/mehrtat/vless-collector)：按来源读取配置、去重、启动 xray 对单节点执行真实 HTTP 探测、按延迟排序后发布。可参考“小批验证成功才发布”的简单闭环。
- [Vair Collector](https://github.com/lm705/vair-collector)：Fetch → Stage 1 Ping → Stage 2 Speed → Publish，按配置身份去重，并对 Xray 与 sing-box 协议分配不同测试引擎。可借鉴分阶段筛选、身份去重与运行快照。
- [V2ray-Tester](https://github.com/lblwb/V2ray-Tester)：将静态配置硬拒绝、TCP 预检、核心实时连接和主动网络探测分层。可借鉴“廉价预检先行、昂贵核心测试后置”的顺序。
- [AimiliVPN](https://github.com/hankinsus/AimiliVPN)：VPS 版多协议节点管理项目，README 描述 Master Pool、pending queue、后台周期复检，以及 OpenVPN、SoftEther、SSTP、L2TP/IPsec 等协议；核心管理器以编译扩展模块提供，无法从公开包装层复现演示视频里的节点数量。可检查的 [AimiliVPN 多出口增强版](https://github.com/Guli-Joy/aimili-vpngate) 将单轮 VPNGate 扫描上限设为 300 行，TCP 预筛并发默认 100，OpenVPN 完整测试并发默认 8。它的 IP 丰富化调用 `ip-api.com/batch`（每批最多 100 个 IP），并把没有 `mobile`、`hosting` 或 `proxy` 标记的结果默认标为 `residential`；这能产生较大的“非机房住宅候选”集合，但不等于已验证家庭宽带。该免费批量 API 仅支持 HTTP、每分钟 15 次请求且限非商业用途，因此 NodeHub 不将它作为最终住宅证明。NodeHub 借鉴其“主池＋待检队列＋周期健康复检”和分层并发预筛思路，但保持独立出口验证与更严格的住宅证据门槛。
- [AimiliVPN 多出口增强版](https://github.com/Guli-Joy/aimili-vpngate)：在上游基础上增加分层并发测速，默认 TCP 预筛并发 100、OpenVPN 完整测试并发 8；只对 TCP 节点做快速端口粗筛，UDP 节点不因 TCP 检测失败而误删。NodeHub 将这一模式用于 VPNGate 滚动历史候选，失败只从本轮候选中排除，后续新快照仍可重新纳入。该仓库当前默认扫描上限为 300，不能仅凭默认配置验证演示视频的 2,000 数字。
- [CFNext](https://github.com/PAICNI/CFNext)：Cloudflare Workers/Pages 订阅管理器，3.x README 说明支持 Worker、MASQUE 与 VPN Gate OpenVPN「家宽」模式；其早期家宽链路通过自有 CF 节点作为隧道前置，解决大陆到 VPN Gate 的直连失败。源码进一步确认：Home WAN 路径实际直接请求同一个 `https://www.vpngate.net/api/iphone/` 官方接口，解析 OpenVPN 配置并按上游速度字段排序，内存缓存 30 分钟，最多取 100 个；它不是一个独立于 VPNGate 的额外家宽节点数据库。其 CF 前置只改变到 VPNGate 的传输路径，最终出口仍是 VPNGate 志愿者中继。NodeHub 已使用官方 API、滚动镜像和可选 VLESS 前置，但仍把实际出口 IP 作为唯一分类对象。
- [byJoey/cfnew](https://github.com/byJoey/cfnew)：Cloudflare Worker 家宽链式方案，使用 Mihomo `dialer-proxy` 让 VPNGate OpenVPN 节点经 VLESS/CF 前置出站，再由 VPNGate 节点提供最终出口。NodeHub 的可选 `NODEHUB_CF_FRONT_URI` 探测前置采用相同的链式思路；但前置 URI 只保存在 GitHub Actions Secret，不进入公开订阅或诊断文件。cfnew 的节点筛选规则不等同于多源住宅证明，因此 NodeHub 仍独立验证出口属性。
- [apachecn/edgetunnel21](https://github.com/apachecn/edgetunnel21)：Cloudflare Worker 隧道/代理前置，可作为链路组件参考；它本身不是 VPNGate 节点源，也不能单独证明出口是家宽。
- [hezhanleiok/gate](https://github.com/hezhanleiok/gate)：Cloudflare Worker 远端检查 VPNGate TCP/SSTP 候选并返回出口 IP、ASN、机房标记，输出面向 EdgeTunnel 的专用节点格式。它适合参考远端验证与定时更新，但不能直接当成 Mihomo YAML 源；其单次官方 API 快照规模也远小于演示中声称的数千美国节点。
- [VPNGate rolling pool mirror](https://github.com/GeorgeXie2333/vpngate-list-mirror)：把官方 API 的多次快照合并为 7 天滚动池，以 Cloudflare Workers 进行周期性 TCP 可达性检查，并用内容寻址配置文件和 SHA-256 清单校验。2026-11-20 的公开池快照约 4,948 条，US 标记约 160 条；同一快照中 1,336 条记录通过近期 TCP 检查，其中 US 只有 25 条。NodeHub 对 TCP 候选要求近期 Cloudflare Workers 精确端点可达证据；对镜像明确标记为 UDP、且 TCP 探测为 not_applicable 的记录，则只作为未验证候选接入，校验配置哈希、远端 IP 和协议后交给 Mihomo 做真实 OpenVPN 隧道/出口检查。两类节点最终都必须通过本项目自己的出口和风险门禁。这个来源能补足全球候选规模，但本身并不能提供 2,000 个美国节点。
- [VPNGate Scraper API](https://github.com/fdciabdul/Vpngate-Scraper-API)、[VpngateAPI](https://github.com/sinspired/VpngateAPI)、[OpenVPNGate4Mihomo](https://github.com/RememberOurPromise/OpenVPNGate4Mihomo) 和 [vpngate-clean-mihomo](https://github.com/ZJH233-tech/vpngate-clean-mihomo)：分别提供定时抓取后的 `.ovpn` 文件、CSV/YAML 快照、Worker 浏览/转换界面或 IP 风险评分订阅；检查其实现后确认底层仍是同一个 VPNGate 官方 API，而非独立运营商节点源。`sinspired/VpngateAPI` 设有最多 10,000 条的历史保留上限，但其实现把历史 UDP 节点默认视为存活，不能直接把该数字当成 10,000 个已验证节点。对其 2026-11-20 07:41（UTC+8）快照实际统计：当前 `servers.csv` 只有 99 行、其中 US 仅 2 行；历史 `vpngate.yaml` 保留 2,325 个节点，其中 US 53 个，但 US 53 个里只有 8 个 TCP、45 个 UDP（该项目对 UDP 历史节点免测保留）。这说明大池主要是长期历史和未验证 UDP，不是 2,000 个同时可用的美国出口。NodeHub 若未来借用其历史记录，只能重新执行自身的 TCP/隧道/出口核验。其他仓库可作为故障时的候选镜像或转换参考，但不能把重复服务器当成新增独立节点，也不能直接采信其住宅标签。

## 对 Aimili-NodeHub 的边界

1. 采集成功不等于节点可用；Mihomo 能解析配置也不等于流量真实通过。
2. 真实出口必须来自节点代理流量，不能用配置里的服务器地址推断。
3. 三个独立 HTTPS 出口回显服务执行严格 2-of-3 一致性核验。临时连接失败可以有限重试；少于两票一致或出现无多数冲突仍然隔离。
4. 出口国家、ASN、前缀和风险信号必须对应同一个观测 IP。ASN 级别举报数不能被误写成 IP 级举报数；本项目目前仍按保守策略处理 ASN 有举报记录的情况，不因样本不足而自动放行。
5. 失败运行只允许提交分类诊断，不得提交新候选快照或更新订阅池；只有分类和发布验证整体成功才提交全部生成物。
6. 缓存只能减少重复情报查询，必须有 TTL、按 IP/ASN 分键，并保留来源和时间戳；缓存过期或数据源失败不能被解释为“无风险”。

## 当前落地

- 三个独立出口回显服务并行查询，采用严格 2-of-3 多数一致；临时连接错误进行一次有界重试，少于两票一致或冲突仍隔离。
- VPNGate 候选在完整 Mihomo 出口检查前，默认对 TCP 协议做 64 路并发端口预筛；UDP 节点跳过 TCP 预筛，短暂超时重试一次。配置 CF VLESS underlay 时跳过直连 TCP 预筛，改由 Mihomo 经前置链路做真实出口验证。预筛失败仅代表当前探测路径不可达，不被当成永久失效证据。
- GitHub Actions 将分类步骤标记为独立成功门槛。失败时只提交 `classification/` 诊断证据，保留仓库中已发布的节点快照和订阅。
- 真实出口风险规则不因样本中住宅节点不足而放宽；出口采样在保持 FreeNodes/VPNGate/VPNBook 来源配额的同时，优先抽取名称标注为 US 的候选，以更快检验美国出口池。名称国家仅是抽样提示，不参与国家或住宅属性判定。
- 自动更新：VPNGate 候选历史每 20 分钟刷新一次，保留 14 天、US 离线窗口候选最多 200 条、其他国家每国最多 40 条、全球总上限 2,000 条；每轮轮换 100 条，最多一半给 US 标签候选，其余保持全球国家覆盖，并对所有入选节点进行 Mihomo 配置复核。完整采集、出口核验、三池发布任务每 6 小时运行一次。FreeNodes 上游每轮目标扩展到 1,000 个可用节点，分类层每轮抽检上限扩展到 160 个，并保持来源分层与美国标签优先轮换。只有分类、Mihomo 配置校验和发布门禁全部通过才自动提交新订阅；失败时只提交诊断，保留上一版订阅。

## 后续验收条件

- 单元测试覆盖重试成功、持续回显不一致、无效重试次数。
- Actions 失败场景验证只提交诊断文件，不改变 `nodes/` 和 `subscriptions/`。
- 成功场景验证三个订阅池均经过 Mihomo 配置检查和原子发布。
- 任何订阅池为空时保持上一版已发布文件，不以空订阅覆盖。
