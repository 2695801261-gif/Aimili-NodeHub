# 开源项目架构对照与本模块采用项

本项目只借鉴公开项目中可验证的工程模式，不复制实现代码，也不把不同项目的产品定位混为一谈。

## 参考项目

- [XEHN](https://github.com/hezhanleiok/xehn/tree/xehn-android)：该分支包含 VPNGate 采集器，通过 WARP underlay 获取官方 API 数据，再做 TCP 预检、OpenVPN 隧道握手和真实流量验证；同时使用 ISP 品牌提示和缓存。NodeHub 借鉴“underlay 负责可达性、出口验证负责最终结论”的链路，以及固定宽带 ISP 品牌提示；但不照搬其“没有机房信号就倾向住宅”的宽松回退，品牌只作为辅助证据，仍必须通过独立出口、ASN、Layer3 和风险门禁。
- [ProxyCollector](https://github.com/Mahdi0024/ProxyCollector)：多来源代理收集，使用 sing-box 进行真实代理连通性测试，并导出不同客户端订阅。可参考协议覆盖、引擎验证和多格式输出。
- [VLESS Collector](https://github.com/mehrtat/vless-collector)：按来源读取配置、去重、启动 xray 对单节点执行真实 HTTP 探测、按延迟排序后发布。可参考“小批验证成功才发布”的简单闭环。
- [Vair Collector](https://github.com/lm705/vair-collector)：Fetch → Stage 1 Ping → Stage 2 Speed → Publish，按配置身份去重，并对 Xray 与 sing-box 协议分配不同测试引擎。可借鉴分阶段筛选、身份去重与运行快照。
- [V2ray-Tester](https://github.com/lblwb/V2ray-Tester)：将静态配置硬拒绝、TCP 预检、核心实时连接和主动网络探测分层。可借鉴“廉价预检先行、昂贵核心测试后置”的顺序。
- [AimiliVPN](https://github.com/hankinsus/AimiliVPN)：你此前发来的 VPS 版多协议节点管理项目，README 描述了 Master Pool、pending queue、后台周期复检，以及 OpenVPN、SoftEther、SSTP、L2TP/IPsec 等协议。其核心管理器以编译后的扩展模块提供，无法仅从公开 Python 包装层验证演示视频里的具体节点数量或完整采集逻辑。NodeHub 借鉴其“主池＋待检队列＋周期健康复检”的工程思路，但独立实现采集与风控，不复制二进制实现。
- [AimiliVPN 多出口增强版](https://github.com/Guli-Joy/aimili-vpngate)：在上游基础上增加分层并发测速，默认 TCP 预筛并发 100、OpenVPN 完整测试并发 8；只对 TCP 节点做快速端口粗筛，UDP 节点不因 TCP 检测失败而误删。NodeHub 将这一模式用于 VPNGate 滚动历史候选，失败只从本轮候选中排除，后续新快照仍可重新纳入。该仓库当前默认扫描上限为 300，不能仅凭默认配置验证演示视频的 2,000 数字。
- [X-MILI](https://github.com/Aimilibot/X-MILI)：VPS 面板集成 VPNGate 出站，采用 30 路并发 TCP 检查和批量 IP-API 元数据查询。其公开 `Validate()` 路径对 TCP 节点执行端口检查，而 UDP 节点主要以配置存在作为初始可用标记；另有独立 OpenVPN 测试函数，但不能把它等同于每个候选都完成了真实隧道验证。其 IP 类型辅助函数把非 hosting 直接归为住宅，NodeHub 不采用这一宽松规则。
- [F0rc3Run/F0rc3Run](https://github.com/F0rc3Run/F0rc3Run)：自动更新的多协议免费节点集合。公开统计快照为 291 个节点，其中美国 60 个；美国列表中可见 OVH、Datacamp、GTHost、DigitalOcean 等托管网络，因此可作为待验证的补充机房来源，不应视为大规模美国家宽来源。
- [byJoey/cfnew](https://github.com/byJoey/cfnew)：Cloudflare Worker 家宽链式方案，使用 Mihomo `dialer-proxy` 让 VPNGate OpenVPN 节点经 VLESS/CF 前置出站，再由 VPNGate 节点提供最终出口。NodeHub 的可选 `NODEHUB_CF_FRONT_URI` 探测前置采用相同的链式思路；但前置 URI 只保存在 GitHub Actions Secret，不进入公开订阅或诊断文件。cfnew 的节点筛选规则不等同于多源住宅证明，因此 NodeHub 仍独立验证出口属性。
- [apachecn/edgetunnel21](https://github.com/apachecn/edgetunnel21)：Cloudflare Worker 隧道/代理前置，可作为链路组件参考；它本身不是 VPNGate 节点源，也不能单独证明出口是家宽。
- [hezhanleiok/gate](https://github.com/hezhanleiok/gate)：Cloudflare Worker 远端检查 VPNGate TCP/SSTP 候选并返回出口 IP、ASN、机房标记，输出面向 EdgeTunnel 的专用节点格式。它适合参考远端验证与定时更新，但不能直接当成 Mihomo YAML 源；其单次官方 API 快照规模也远小于演示中声称的数千美国节点。
- [VPNGate rolling pool mirror](https://github.com/GeorgeXie2333/vpngate-list-mirror)：把官方 API 的多次快照合并为 7 天滚动池，以 Cloudflare Workers 进行周期性 TCP 可达性检查，并用内容寻址配置文件和 SHA-256 清单校验。2026-11-20 的公开池快照约 4,948 条，US 标记约 160 条。NodeHub 只接收近期 TCP 检查通过的候选，下载配置后再校验配置哈希；最终仍必须通过本项目自己的 Mihomo 出口和风险门禁。这个来源能补足全球候选规模，但本身并不能提供 2,000 个美国节点。

## 对 Aimili-NodeHub 的边界

1. 采集成功不等于节点可用；Mihomo 能解析配置也不等于流量真实通过。
2. 真实出口必须来自节点代理流量，不能用配置里的服务器地址推断。
3. 出口 IP 必须获得独立回显共识：两家服务先并行查询；如有超时或不一致，再调用第三家，至少两家返回同一 IP 才通过。临时连接失败可以有限重试；不足两票或三家结果互相冲突仍然隔离。
4. 出口国家、ASN、前缀和风险信号必须对应同一个观测 IP。ASN 级别举报数不能被误写成 IP 级举报数；本项目目前仍按保守策略处理 ASN 有举报记录的情况，不因样本不足而自动放行。
5. 失败运行只允许提交分类诊断，不得提交新候选快照或更新订阅池；只有分类和发布验证整体成功才提交全部生成物。
6. 缓存只能减少重复情报查询，必须有 TTL、按 IP/ASN 分键，并保留来源和时间戳；缓存过期或数据源失败不能被解释为“无风险”。

## 当前落地

- 出口回显由 ipify 与 AWS CheckIP 并行核验；任一超时或两家不一致时，再调用 icanhazip，以两票一致为准。各服务只做一次有界重试；没有两票共识仍隔离。
- VPNGate 候选在完整 Mihomo 出口检查前，默认对 TCP 协议做 64 路并发端口预筛；UDP 节点跳过 TCP 预筛，短暂超时重试一次。配置 CF VLESS underlay 时跳过直连 TCP 预筛，改由 Mihomo 经前置链路做真实出口验证。预筛失败仅代表当前探测路径不可达，不被当成永久失效证据。
- GitHub Actions 将分类步骤标记为独立成功门槛。失败时只提交 `classification/` 诊断证据，保留仓库中已发布的节点快照和订阅。
- 真实出口风险规则不因样本中住宅节点不足而放宽；出口采样在保持 FreeNodes/VPNGate/VPNBook 来源配额的同时，优先抽取名称标注为 US 的候选，以更快检验美国出口池。名称国家仅是抽样提示，不参与国家或住宅属性判定。
- 自动更新：VPNGate 候选历史每 20 分钟刷新一次；完整采集、出口核验、三池发布任务每 6 小时运行一次。FreeNodes 上游每轮目标扩展到 1,000 个可用节点，分类层每轮抽检上限扩展到 160 个，并保持来源分层与美国标签优先轮换。只有分类、Mihomo 配置校验和发布门禁全部通过才自动提交新订阅；失败时只提交诊断，保留上一版订阅。

## 后续验收条件

- 单元测试覆盖双服务一致、单服务超时后的第三方回退、第三方多数票解决分歧、三家均不一致、单票不足、重试和无效重试次数。
- Actions 失败场景验证只提交诊断文件，不改变 `nodes/` 和 `subscriptions/`。
- 成功场景验证三个订阅池均经过 Mihomo 配置检查和原子发布。
- 任何订阅池为空时保持上一版已发布文件，不以空订阅覆盖。
