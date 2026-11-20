# 节点分类与证据规则

目标输出为三类 Mihomo 订阅：

1. `us-residential`：代理实际出口地址被独立情报源标记为 residential，所在网络为 access，且 精确 IP/网络风险门槛通过。
2. `other-residential`：与美国住宅候选相同，但出口国家不是美国。
3. `low-risk-datacenter`：历史兼容池名；出口地址和网络均被独立情报源标记为 hosting，Layer3 风险仅为普通 hosting 基线（medium/50，原因仅为 hosting），且精确 IP/网络风险门槛通过。

## 必须遵守

- 必须通过代理本身连接两个独立 HTTPS 出口检测端点，并要求两者返回相同的全球可路由 IP；不能用节点配置中的 server 地址代替出口 IP。
- IPWhois 主源（IPinfo 备用）解析出口 IP 的国家、ASN 和运营商；Layer3 Intel 必须返回相同 IP、国家、ASN 和包含该 IP 的实际公告前缀。
- 住宅候选要求 Layer3 地址风险等级为 low、分数低于 25，地址类型 residential、网络类型 access、风险原因为空。普通 hosting 在 Layer3 的风险模型中基线为 medium/50、原因为 [hosting]；机房候选只接受这个精确基线，任何额外风险原因（如 nearby_vpn、recent_reassignment、proxy）或更高分数均隔离。该池名为 low-risk-datacenter 是历史兼容名，不代表 Layer3 数值等级为 low。
- Layer3 的 anonymizer、proxy、VPN、Tor、relay、共享地址、crawler、drop-list 等信号全部隔离。未知、business、mobile、education、government、isp（无法区分家庭/企业的泛 ISP 地址）等类型不进入住宅池。
- O-X-L ASN 查询若有记录，必须明确支持 ISP 或 hosting 类型且无冲突种类；ASN 报告总数作为网络级上下文记录，不直接等同于当前出口 IP 的举报数；若明确返回 not-reported，不视为安全，只有 Layer3 对同一出口 IP、ASN、国家、前缀、对应类别的风险规则和目标网络类型全部独立确认时才允许继续。查询超时、限流或服务错误仍隔离。O-X-L IP 查询要求零举报；其 404 语义存在不确定性，重试后仍为 404 时只记录为 not-reported，不声称已证明无风险。
- O-X-L 网络记录如果存在，必须通过零举报、`ok/info` 信誉、ASN、CIDR 和网络类型核验。若 O-X-L 网络 API 返回 404，只允许在 Layer3 已提供匹配的网络类型、前缀和类别对应的风险证据，且 O-X-L IP 检查通过时继续。若 O-X-L ASN 明确 not-reported，也只能由 Layer3 独立确认精确 IP、ASN、国家、前缀、类别对应风险条件和目标网络类型后继续。
- VPN、proxy、Tor、scanner、crawler、education、maybe_hacked、mobile、CGNAT、relay、anycast 及 ISP/hosting 冲突信号全部隔离。
- 保存检测时间、出口 IP、国家、ASN、运营商、Layer3 风险分数/原因、网络前缀、O-X-L 状态及判断理由，便于复核。
- 所有分类输出先在临时文件中生成，并由 Mihomo 配置检查通过后再原子写入。某一池本轮没有新合格节点时，保留该池上一版已验证配置；首次运行该池仍为空时，明确标记为空池并允许其他池正常发布，不会伪造节点或清空其他池。
- 分类步骤失败时，工作流必须停止，不提交新一轮节点池或半成品订阅；仓库里上一版已提交订阅保持不变。

## 重要边界

Layer3 Open API 不包含付费版的实时 residential-proxy 标记，因此 residential 仅代表出口地址类型和网络证据支持住宅属性，不保证它没有被住宅代理服务商转售。它也不等于已证明某个物理家庭用户的宽带线路。

“低风险机房”是历史兼容名称；Layer3 对普通 hosting 的基线为 medium/50，本池只接受风险原因恰为 hosting、没有额外风险信号的机房。它只表示 Layer3 与 O-X-L 当前公开情报源没有返回本项目设定的额外排除信号，不等于安全、匿名或绝对无滥用记录。公开免费代理不应用于银行、支付、主邮箱或其他敏感流量。

## 当前实现范围

FreeNodes 固定版本负责完整启用配置来源的发现（GitHub 订阅、网页、受限密码页和 YouTube 资源适配器）、去重、Mihomo 能力检测和通用节点池生成；工作流不得把 sources 过滤成仅 github_file。VPN Gate 官方 CSV 的 OpenVPN_ConfigData_Base64 经独立适配器转换为 Mihomo 原生 openvpn outbound，并通过 Mihomo 配置检查后与其他来源一起接受相同的真实出口与风险核验。来源覆盖和格式边界见 [DISCOVERY_SOURCES.md](DISCOVERY_SOURCES.md)。本项目将 FreeNodes 与 VPN Gate 候选合并为最多 500 个节点，并按来源比例从完整排序池分配最多 40 个真实出口探测名额，逐个验证出口 IP；两个独立 HTTPS 回显端点的临时连接失败会进行一次有界重试，但两端不一致仍隔离；使用 IPWhois/IPinfo、Layer3 Intel 和 O-X-L IP/ASN/可用网络记录进行交叉分类。字段、许可、限额和分类门槛见 [CLASSIFICATION_SOURCES.md](CLASSIFICATION_SOURCES.md)。
