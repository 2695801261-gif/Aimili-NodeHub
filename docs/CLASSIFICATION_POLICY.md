# 节点分类与证据规则

目标输出为三类 Mihomo 订阅：

1. `us-residential`：代理实际出口地址被独立情报源标记为 residential，所在网络为 access，且 ASN/IP 风险门槛通过。
2. `other-residential`：与美国住宅候选相同，但出口国家不是美国。
3. `low-risk-datacenter`：出口地址和网络均被独立情报源标记为 hosting，风险分数低，且 ASN/IP 风险门槛通过。

## 必须遵守

- 必须通过代理本身连接两个独立 HTTPS 出口检测端点，并要求两者返回相同的全球可路由 IP；不能用节点配置中的 server 地址代替出口 IP。
- IPWhois 主源（IPinfo 备用）解析出口 IP 的国家、ASN 和运营商；Layer3 Intel 必须返回相同 IP、国家、ASN 和包含该 IP 的实际公告前缀。
- Layer3 Intel 免费 Open API 的地址风险等级必须为 low、分数低于 25。住宅候选要求地址类型 residential、网络类型 access、风险原因为空；机房候选要求地址和网络均为 hosting，风险原因只能包含普通 hosting 标签。
- Layer3 的 anonymizer、proxy、VPN、Tor、relay、共享地址、crawler、drop-list 等信号全部隔离。未知、business、mobile、education、government、isp（无法区分家庭/企业的泛 ISP 地址）等类型不进入住宅池。
- O-X-L ASN 查询必须存在、举报数为零，并明确支持 ISP 或 hosting 类型。O-X-L IP 查询要求零举报；其 404 语义存在不确定性，重试后仍为 404 时只记录为 not-reported，不声称已证明无风险。
- O-X-L 网络记录如果存在，必须通过零举报、`ok/info` 信誉、ASN、CIDR 和网络类型核验。若 O-X-L 网络 API 返回 404（该项目文档定义为 Network not reported），只允许在 Layer3 已提供匹配的网络类型、前缀和低风险证据，且 O-X-L ASN/IP 检查通过时继续。
- VPN、proxy、Tor、scanner、crawler、education、maybe_hacked、mobile、CGNAT、relay、anycast 及 ISP/hosting 冲突信号全部隔离。
- 保存检测时间、出口 IP、国家、ASN、运营商、Layer3 风险分数/原因、网络前缀、O-X-L 状态及判断理由，便于复核。
- 所有分类输出先在临时文件中生成，并由 Mihomo 配置检查通过后再原子写入。
- 分类步骤失败时，工作流必须停止，不提交新一轮节点池或半成品订阅；仓库里上一版已提交订阅保持不变。

## 重要边界

Layer3 Open API 不包含付费版的实时 residential-proxy 标记，因此 residential 仅代表出口地址类型和网络证据支持住宅属性，不保证它没有被住宅代理服务商转售。它也不等于已证明某个物理家庭用户的宽带线路。

“低风险机房”只表示 Layer3 与 O-X-L 当前公开情报源没有返回本项目设定的排除信号，不等于安全、匿名或绝对无滥用记录。公开免费代理不应用于银行、支付、主邮箱或其他敏感流量。

## 当前实现范围

FreeNodes 固定版本负责源发现、去重、Mihomo 能力检测和通用节点池生成；本项目再对最多 25 个低延迟候选逐个验证出口 IP，使用 IPWhois/IPinfo、Layer3 Intel 和 O-X-L IP/ASN/可用网络记录进行交叉分类。字段、许可、限额和分类门槛见 [CLASSIFICATION_SOURCES.md](CLASSIFICATION_SOURCES.md)。
