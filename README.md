# Aimili NodeHub

个人免费代理节点采集、验证与分级项目，面向 Mihomo / FlClash。

## 工作方式

- GitHub Actions 每 6 小时运行；也可在 Actions 页面手动运行。
- 不需要 VPS、Cloudflare Worker、KV、域名或自建服务器。
- 使用固定提交版本的 [FreeNodes](https://github.com/nostalume/FreeNodes) 发现订阅源、去重、运行 Mihomo 实际连通性验证并生成通用节点池。
- 再由本项目启动 Mihomo，逐个选择节点，通过两个独立 HTTPS 出口查询核实代理实际出口 IP。
- 对出口 IP 查询国家/ASN/ISP 信息（IPWhois 主源，IPinfo 无密钥接口作回退），并用 Layer3 Intel Open API 核对地址类型、网络类型、风险分数和公告前缀；再用 O-X-L Risk Database 检查 IP/ASN 风险及可用的网络记录。
- 证据不足、来源冲突、API 限流或检测失败时隔离节点；情报服务故障不会覆盖上一次已生成的分类订阅。

## 三类目标订阅

分类成功后输出到以下订阅地址（FlClash / Mihomo 可直接添加远程配置）：

- 美国 ISP 住宅候选：[订阅 YAML](https://raw.githubusercontent.com/2695801261-gif/Aimili-NodeHub/main/subscriptions/us-residential.yaml)
- 其他国家 ISP 住宅候选：[订阅 YAML](https://raw.githubusercontent.com/2695801261-gif/Aimili-NodeHub/main/subscriptions/other-residential.yaml)
- 低风险机房候选：[订阅 YAML](https://raw.githubusercontent.com/2695801261-gif/Aimili-NodeHub/main/subscriptions/low-risk-datacenter.yaml)

仓库内对应文件：`subscriptions/us-residential.yaml`、`subscriptions/other-residential.yaml`、`subscriptions/low-risk-datacenter.yaml`

每次最多进行 25 个出口 IP 的分类检测，以控制免费 API 配额和运行时间。上游通用节点池最多保留 500 个通过 Mihomo 能力验证的节点。

**分类边界：** “住宅”订阅代表多项证据支持的 ISP 网络候选，不等于已证明是某个家庭用户的宽带线路，也不能完全识别使用真实家宽出口的住宅代理。“低风险机房”只代表当前公开情报源没有发现本项目设定的排除信号，不是安全保证。未确认节点不会被硬塞进任何一个分类池。

## 情报来源与限制

- [IPWhois / ipwho.is](https://ipwhois.io/documentation)：主出口 IP 国家、ASN、ISP 查询。
- [IPinfo](https://ipinfo.io/developers)：IPWhois 不可用时使用无密钥备用接口；公开接口有共享日请求额度。
- [Layer3 Intel Open API](https://docs.layer3intel.com/docs/intel-api/open-api)：免费免密钥的地址类型、网络、风险与前缀信息；实时住宅代理检测属于付费数据，不在本项目免费版能力范围内。
- [O-X-L Risk Database](https://github.com/O-X-L/risk-db)：公开 ASN/IP 风险分类及举报信号；项目文档说明数据可能有误报，因此只作筛除和隔离依据。
- 具体字段、许可、限额和分类门槛见 [分类证据规则](docs/CLASSIFICATION_SOURCES.md) 与 [分类策略](docs/CLASSIFICATION_POLICY.md)。

## 安全

免费公开节点由未知第三方运营。不要用于银行、支付、主邮箱、账号恢复或其他敏感流量。公开仓库中的订阅和出口 IP 任何人都能读取。

## 开源基础

- [FreeNodes](https://github.com/nostalume/FreeNodes) — MIT；作为运行时采集、验证和订阅生成底座，固定到 `5a4f4ecf8c06b49b503046179d10933a6a63ef69`。
- [O-X-L Risk Database](https://github.com/O-X-L/risk-db) — BSD-3-Clause 数据库；只使用其公开查询信号，不复制其 GPLv3 构建脚本。
- 本仓库自己的分类规则和测试位于 `scripts/` 与 `tests/`。
