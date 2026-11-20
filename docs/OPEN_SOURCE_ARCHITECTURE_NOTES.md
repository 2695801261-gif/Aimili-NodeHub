# 开源项目架构对照与本模块采用项

本项目只借鉴公开项目中可验证的工程模式，不复制实现代码，也不把不同项目的产品定位混为一谈。

## 参考项目

- [XEHN](https://github.com/hezhanleiok/xehn)：WARP 端点扫描与客户端。其公开说明强调复用 warpscout 扫描引擎、两阶段端点探测与隧道验证、mihomo 实际流量路由，以及扫描结果 TTL 缓存。它不是通用免费节点聚合器，因此主要参考验证链路和缓存/核心解耦，而不是照搬其 WARP 账户与桌面客户端逻辑。
- [ProxyCollector](https://github.com/Mahdi0024/ProxyCollector)：多来源代理收集，使用 sing-box 进行真实代理连通性测试，并导出不同客户端订阅。可参考协议覆盖、引擎验证和多格式输出。
- [VLESS Collector](https://github.com/mehrtat/vless-collector)：按来源读取配置、去重、启动 xray 对单节点执行真实 HTTP 探测、按延迟排序后发布。可参考“小批验证成功才发布”的简单闭环。
- [Vair Collector](https://github.com/lm705/vair-collector)：Fetch → Stage 1 Ping → Stage 2 Speed → Publish，按配置身份去重，并对 Xray 与 sing-box 协议分配不同测试引擎。可借鉴分阶段筛选、身份去重与运行快照。
- [V2ray-Tester](https://github.com/lblwb/V2ray-Tester)：将静态配置硬拒绝、TCP 预检、核心实时连接和主动网络探测分层。可借鉴“廉价预检先行、昂贵核心测试后置”的顺序。
- [AimiliVPN](https://github.com/baoweise-bot/aimili-vpngate)：面向 Linux VPS 的 VPNGate 管理器；当前代码采用最多 300 条候选、5 个并发 OpenVPN 测试 worker，先做 ICMP/TCP 延迟探测，再以 OpenVPN 初始化确认连通；IP 元数据使用批量 100 条查询和 7 天缓存。NodeHub 借鉴其分阶段筛选、并发测试和批量情报思路，但保留 GitHub Actions 无 VPS 部署方式，并以真实出口 IP、独立回显及多源风险证据作为最终发布门槛。
- [AimiliVPN 多出口增强版](https://github.com/Guli-Joy/aimili-vpngate)：在上游基础上增加分层并发测速，默认 TCP 预筛并发 100、OpenVPN 完整测试并发 8；只对 TCP 节点做快速端口粗筛，UDP 节点不因 TCP 检测失败而误删。NodeHub 将这一模式用于 VPNGate 滚动历史候选，失败只从本轮候选中排除，后续新快照仍可重新纳入。该仓库当前默认扫描上限为 300，不能仅凭默认配置验证演示视频的 2,000 数字。

## 对 Aimili-NodeHub 的边界

1. 采集成功不等于节点可用；Mihomo 能解析配置也不等于流量真实通过。
2. 真实出口必须来自节点代理流量，不能用配置里的服务器地址推断。
3. 两个独立出口回显必须一致。临时连接失败可以有限重试；持续失败或回显冲突仍然隔离。
4. 出口国家、ASN、前缀和风险信号必须对应同一个观测 IP。ASN 级别举报数不能被误写成 IP 级举报数；本项目目前仍按保守策略处理 ASN 有举报记录的情况，不因样本不足而自动放行。
5. 失败运行只允许提交分类诊断，不得提交新候选快照或更新订阅池；只有分类和发布验证整体成功才提交全部生成物。
6. 缓存只能减少重复情报查询，必须有 TTL、按 IP/ASN 分键，并保留来源和时间戳；缓存过期或数据源失败不能被解释为“无风险”。

## 当前落地

- 出口回显在临时连接错误时进行一次有界重试；两个服务最终不一致仍隔离。
- VPNGate 候选在完整 Mihomo 出口检查前，先对 TCP 协议做 64 路并发端口预筛；UDP 节点跳过 TCP 预筛，短暂超时重试一次。预筛失败仅代表 GitHub Actions 运行环境当前不可达，不被当成永久失效证据。
- GitHub Actions 将分类步骤标记为独立成功门槛。失败时只提交 `classification/` 诊断证据，保留仓库中已发布的节点快照和订阅。
- 真实出口风险规则不因样本中住宅节点不足而放宽；出口采样在保持 FreeNodes/VPNGate/VPNBook 来源配额的同时，优先抽取名称标注为 US 的候选，以更快检验美国出口池。名称国家仅是抽样提示，不参与国家或住宅属性判定。
- 自动更新：VPNGate 候选历史每 20 分钟刷新一次；完整采集、出口核验、三池发布任务每 6 小时运行一次。只有分类、Mihomo 配置校验和发布门禁全部通过才自动提交新订阅；失败时只提交诊断，保留上一版订阅。

## 后续验收条件

- 单元测试覆盖重试成功、持续回显不一致、无效重试次数。
- Actions 失败场景验证只提交诊断文件，不改变 `nodes/` 和 `subscriptions/`。
- 成功场景验证三个订阅池均经过 Mihomo 配置检查和原子发布。
- 任何订阅池为空时保持上一版已发布文件，不以空订阅覆盖。
