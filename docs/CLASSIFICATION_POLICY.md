# 节点分类与证据规则

目标输出为三类 Mihomo 订阅：

1. `us-residential`：实际出口国家为美国，且通过普通 residential/access 规则，或通过下述严格限定的 VPNGate 固定 ISP access 例外。
2. `other-residential`：同一组住宅证据规则，但实际出口国家不是美国。
3. `low-risk-datacenter`：历史兼容池名；出口地址和网络均被独立情报源标记为 hosting，Layer3 风险仅为普通 hosting 基线（medium/50，原因仅为 hosting），且精确 IP/网络风险门槛通过。

## 必须遵守

- 必须通过代理本身并行查询三个独立 HTTPS 出口检测端点，至少两者返回相同的全球可路由 IP（严格 2-of-3）；少于两票一致或结果无多数时隔离。不能用节点配置中的 server 地址代替出口 IP。
- IPWhois 主源（IPinfo 备用）解析出口 IP 的国家、ASN 和运营商；Layer3 Intel 必须返回相同 IP、国家、ASN 和包含该 IP 的实际公告前缀。IPWHO 顶层 `type` 是地址族（如 `ipv4`），不是 ISP 类型；不能把它当成住宅证明。若配置 `IPAPI_IS_API_KEY`，VPNGate 特殊候选还必须通过 IPAPI.is HTTPS 独立核验。可选的 `NODEHUB_CF_FRONT_URI` GitHub Actions secret 可将 VPNGate CI 探测通过 TLS WebSocket VLESS `dialer-proxy` 前置；该 URI/UUID 仅用于探测，不写入公开订阅、证据或日志，客户端订阅仍为直连节点。
- 住宅候选要求 Layer3 地址风险等级为 low、分数低于 25，地址类型 residential、网络类型 access、风险原因为空。普通 hosting 在 Layer3 的风险模型中基线为 medium/50、原因为 [hosting]；机房候选只接受这个精确基线，任何额外风险原因（如 nearby_vpn、recent_reassignment、proxy）或更高分数均隔离。该池名为 low-risk-datacenter 是历史兼容名，不代表 Layer3 数值等级为 low。
- Layer3 的 anonymizer、proxy、VPN、Tor、relay、共享地址、crawler、drop-list 等信号默认不会进入任何订阅池。**唯一的来源专属例外是 VPNGate 的固定 ISP access 出口**：必须是准确的 VPNGate `type=vpn`、`network_type=access`、风险 high/75/`[vpn]` 签名，anonymizer/vpn 两个标志为 true 且 proxy/Tor/relay/hosting 均为 false；实际出口 IP、国家、ASN、前缀必须由 Layer3 精确匹配；IPWHO 运营商必须命中固定线路 ISP 名单；Layer3/O-X-L 网络分类必须为 ISP 且 ASN/前缀一致；O-X-L ASN 若有记录必须确认 ISP、不得有 hosting 冲突，若无记录则必须由同一 Layer3 IP/ASN/前缀和 ISP access 网络证据补足；任何可用的精确 IP 或网络举报记录若报告数非零即拒绝。若配置 `IPAPI_IS_API_KEY`，还必须由 IPAPI.is 返回 `company.type=isp`、`asn.type=isp`、相同 ASN/国家，并明确确认 datacenter/proxy/Tor/abuser/mobile/satellite/anycast/crawler 标记全部为 false；其 `is_vpn` 标记在这个 VPNGate 传输例外中记录但不单独拒绝。移动/无线运营商不进入固定住宅池。这个例外识别的是固定 ISP 接入网络，不证明具体物理家庭线路，也不应用于其他来源。未知、business、mobile、education、government、泛 ISP 或证据冲突类型仍隔离。
- O-X-L ASN 查询若有记录，必须明确支持 ISP 或 hosting 类型且无冲突种类；ASN 报告总数作为网络级上下文记录，不直接等同于当前出口 IP 的举报数；若明确返回 not-reported，不视为安全，只有 Layer3 对同一出口 IP、ASN、国家、前缀、对应类别的风险规则和目标网络类型全部独立确认时才允许继续。查询超时、限流或服务错误仍隔离。O-X-L IP 查询若有记录要求零举报；其 404 语义存在不确定性，重试后仍为 404 时只记录为 not-reported，不声称已证明零风险。住宅规则（包括 VPNGate 特例）可在该字段为 not-reported 时继续，但必须保留这个未知状态，并依靠其他精确 IP/ASN/网络证据通过门槛。
- O-X-L 网络记录如果存在，必须通过零举报、`ok/info` 信誉、ASN、CIDR 和网络类型核验。若 O-X-L 网络 API 返回 404，只允许在 Layer3 已提供匹配的网络类型、前缀和类别对应的风险证据，且 O-X-L IP 检查通过时继续。若 O-X-L ASN 明确 not-reported，也只能由 Layer3 独立确认精确 IP、ASN、国家、前缀、类别对应风险条件和目标网络类型后继续。
- VPN、proxy、Tor、scanner、crawler、education、maybe_hacked、mobile、CGNAT、relay、anycast 及 ISP/hosting 冲突信号默认隔离；仅上文定义的 VPNGate 固定 ISP access 专属例外可以容忍其传输层 `vpn/anonymizer` 标记，其余风险标记仍必须为 false。
- 保存检测时间、出口 IP、国家、ASN、运营商、Layer3 风险分数/原因、网络前缀、O-X-L 状态及判断理由，便于复核。
- 所有分类输出先在临时文件中生成，并由 Mihomo 配置检查通过后再原子写入。某一池本轮没有新合格节点时，保留该池上一版已验证配置；首次运行该池仍为空时，明确标记为空池并允许其他池正常发布，不会伪造节点或清空其他池。保留的上一版节点并非本轮重新验证结果，可能已失效，证据文件会标注保留数量。
- 分类步骤失败时，工作流必须停止，不提交新一轮节点池或半成品订阅；仓库里上一版已提交订阅保持不变。

## 重要边界

Layer3 Open API 不包含付费版的实时 residential-proxy 标记，因此 residential 仅代表出口地址类型和网络证据支持住宅属性，不保证它没有被住宅代理服务商转售。它也不等于已证明某个物理家庭用户的宽带线路。

“低风险机房”是历史兼容名称；Layer3 对普通 hosting 的基线为 medium/50，本池只接受风险原因恰为 hosting、没有额外风险信号的机房。它只表示 Layer3 与 O-X-L 当前公开情报源没有返回本项目设定的额外排除信号，不等于安全、匿名或绝对无滥用记录。公开免费代理不应用于银行、支付、主邮箱或其他敏感流量。

## 当前实现范围

FreeNodes 固定版本负责完整启用配置来源的发现（GitHub 订阅、网页、受限密码页和 YouTube 资源适配器）、去重、Mihomo 能力检测和通用节点池生成；工作流不得把 sources 过滤成仅 github_file。VPN Gate 官方 CSV 的 OpenVPN_ConfigData_Base64 经独立适配器转换为 Mihomo 原生 openvpn outbound，并通过 Mihomo 配置检查后接受真实出口核验。VPNGate 的 Layer3 VPN-on-access 固定 ISP 例外按本文件的专属门槛验证；可选 IPAPI.is 通过 GitHub Actions secret `IPAPI_IS_API_KEY` 启用，密钥只通过 HTTPS POST JSON body 发送，不写入仓库。VPNGate 候选历史保留 14 天并轮换采样，每次正式采集后保存缓存。来源覆盖和格式边界见 [DISCOVERY_SOURCES.md](DISCOVERY_SOURCES.md)。本项目将 FreeNodes 配置为 1,000 个通用节点目标，与最多 310 个 VPN Gate/VPNBook 补充候选合并，分类前候选硬上限为 1,500；每轮按来源比例从完整排序池分配最多 160 个真实出口探测名额，逐个验证出口 IP；三个独立 HTTPS 回显服务执行严格 2-of-3 一致性核验，临时连接失败会进行有界重试，回显冲突仍隔离；使用 IPWhois/IPinfo、Layer3 Intel、O-X-L 和可选 IPAPI.is 进行交叉分类。字段、许可、限额和分类门槛见 [CLASSIFICATION_SOURCES.md](CLASSIFICATION_SOURCES.md)。
