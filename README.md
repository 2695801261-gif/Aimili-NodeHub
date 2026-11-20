# Aimili NodeHub

个人免费代理节点采集、验证与分级项目，面向 Mihomo / FlClash。

## 工作方式

- GitHub Actions 每 6 小时运行；也可在 Actions 页面手动运行。
- 不需要 VPS、Cloudflare Worker、KV、域名或自建服务器。
- 使用固定提交版本的 [FreeNodes](https://github.com/nostalume/FreeNodes) 发现订阅源、去重、运行 Mihomo 实际连通性验证并生成通用节点池。
- 再由本项目启动 Mihomo，逐个选择节点，通过两个独立 HTTPS 出口查询核实代理实际出口 IP。
- 对出口 IP 查询国家/ASN/ISP 信息，并用 O-X-L Risk Database 检查 ASN、IP 风险信号。
- 证据不足、来源冲突、API 限流或检测失败时隔离节点；情报服务故障不会覆盖上一次已生成的分类订阅。

## 三类目标订阅

分类成功后输出到：

- `subscriptions/us-residential.yaml`
- `subscriptions/other-residential.yaml`
- `subscriptions/low-risk-datacenter.yaml`

每次最多进行 100 个出口 IP 的分类检测，以控制免费 API 配额和运行时间。上游通用节点池最多保留 500 个通过 Mihomo 能力验证的节点。

**分类边界：** “住宅”订阅代表多项证据支持的 ISP 网络候选，不等于已证明是某个家庭用户的宽带线路，也不能完全识别使用真实家宽出口的住宅代理。“低风险机房”只代表当前公开情报源没有发现本项目设定的排除信号，不是安全保证。未确认节点不会被硬塞进任何一个分类池。

## 情报来源与限制

- [IPWhois / ipwho.is](https://ipwhois.io/documentation)：免费出口 IP 国家、ASN、ISP 查询，免费接口每日有请求额度；不提供免费 VPN/Tor 风险判断。
- [O-X-L Risk Database](https://github.com/O-X-L/risk-db)：公开 ASN/IP 风险分类及举报信号；项目文档说明数据可能有误报，因此只作筛除和隔离依据。
- 具体字段、许可、限额和分类门槛见 [分类证据规则](docs/CLASSIFICATION_SOURCES.md) 与 [分类策略](docs/CLASSIFICATION_POLICY.md)。

## 安全

免费公开节点由未知第三方运营。不要用于银行、支付、主邮箱、账号恢复或其他敏感流量。公开仓库中的订阅和出口 IP 任何人都能读取。

## 开源基础

- [FreeNodes](https://github.com/nostalume/FreeNodes) — MIT；作为运行时采集、验证和订阅生成底座，固定到 `5a4f4ecf8c06b49b503046179d10933a6a63ef69`。
- [O-X-L Risk Database](https://github.com/O-X-L/risk-db) — BSD-3-Clause 数据库；只使用其公开查询信号，不复制其 GPLv3 构建脚本。
- 本仓库自己的分类规则和测试位于 `scripts/` 与 `tests/`。
