# 节点分类与证据规则

目标输出为三类 Mihomo 订阅：

1. `us-residential`：代理实际出口位于美国，ASN 被 O-X-L 标记为 ISP，且未发现本项目设定的排除信号。
2. `other-residential`：代理实际出口位于美国以外，ASN 被 O-X-L 标记为 ISP，且未发现本项目设定的排除信号。
3. `low-risk-datacenter`：代理实际出口 ASN 被 O-X-L 标记为 hosting，且 IP/ASN 风险检查未发现本项目设定的排除信号。

## 必须遵守

- 必须通过代理本身连接两个独立 HTTPS 出口检测端点，并要求两者返回相同的全球可路由 IP；不能用节点配置中的 server 地址代替出口 IP。
- 国家、ASN、ISP/组织名称由 IPWhois 对已观测出口 IP 解析。
- 网络类型必须在 O-X-L ASN kind 列表中得到正向 ISP 或 hosting 证据；未知/未列出的 ASN 不分类。
- O-X-L ASN 报告数必须为零；IP 报告数必须为零或 API 明确返回 not-reported（IP 404 存在临时失败歧义，证据文件会保留此状态）。
- VPN、proxy、Tor、scanner、crawler、education、maybe_hacked 及 ISP/hosting 冲突信号全部隔离。
- 禁止根据节点名称中的 US、Residential、Home、ISP 等字样直接分类。
- 保存检测时间、出口 IP、国家、ASN、运营商、风险状态及判断理由，便于复核。
- 所有分类输出先在临时文件中生成，并由 Mihomo 配置检查通过后再原子写入。
- 分类步骤失败时，工作流必须停止，不提交新一轮节点池或半成品订阅；仓库里上一版已提交订阅保持不变。

## 重要边界

O-X-L 的 ISP ASN 标签只证明出口归属 ISP 网络，不能证明它是家庭宽带，也不能识别所有真实家宽代理。住宅池因此是“ISP 网络住宅候选”，不是经过物理地址或用户线路验证的家庭宽带清单。

“低风险机房”只表示当前选定公开情报源未返回已配置的排除信号，不等于安全、匿名或绝对无滥用记录。公开免费代理不应用于银行、支付、主邮箱或其他敏感流量。

## 当前实现范围

当前实现使用 FreeNodes 固定版本完成源发现、去重、Mihomo 能力检测和通用节点池生成；本项目再对最多 100 个低延迟候选逐个验证出口 IP 并分类。数据源、API 限制和字段解释见 [CLASSIFICATION_SOURCES.md](CLASSIFICATION_SOURCES.md)。
