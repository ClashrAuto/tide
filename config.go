package tide

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"
)

// 默认值集中在这里，方便一眼看全"网络波动下的行为"由哪些常数决定。
const (
	// DefaultProbeInterval：有活跃流时的路径探测间隔。1s 不是为了测 RTT——
	// 是为了**尽早发现路径死了**。探测间隔直接决定故障检测下界，而检测越晚，
	// 用户看到的卡顿越长。空闲时会自动退到 DefaultIdleProbeInterval。
	DefaultProbeInterval     = 1 * time.Second
	DefaultIdleProbeInterval = 15 * time.Second
	// DefaultProbeTimeout：单次探测判定丢失的时限。取 max(3×SRTT, 这个值)，
	// 所以高延迟线路不会被误杀。
	DefaultProbeTimeout = 2 * time.Second
	// DefaultPathDeadAfter：连续多久收不到任何字节就判定路径死亡。
	DefaultPathDeadAfter = 8 * time.Second

	// DefaultSessionGrace：会话在**一条路径都没有**的情况下能存活多久。
	// 这是整个协议对网络波动最重要的一个数：Wi-Fi 切换、蜂窝换基站、路由器重启
	// 都在这个窗口内，用户的 TCP 连接一条都不会断。代价是服务端要在这段时间里
	// 替一个已经不在线的客户端持有上游连接与缓冲区。
	DefaultSessionGrace = 120 * time.Second

	// DefaultStreamWindow：单流发送窗口，同时也是重传缓冲上限。
	// 迁移时要重发 [acked, sent) 的全部字节，所以这个数直接决定一次迁移最坏要重传多少。
	// 512 KiB 在 100 Mbps × 40ms 的 BDP（约 500 KiB）附近，既不限速也不会让一次
	// 迁移拖出几秒的重传。
	DefaultStreamWindow = 512 * 1024
	// DefaultSessionWindow：会话级接收缓冲上限，防止大量流各自吃满窗口把内存打爆。
	DefaultSessionWindow = 8 * 1024 * 1024

	DefaultMaxStreams = 1024

	// DefaultMaxSessionsPerUser 单个用户同时能有多少条会话。
	//
	// 正常形态是 **1** 条：TIDE 的整个设计就是一条长命会话跨路径活着。
	// 多设备共用同一份凭据时会多几条，64 已经很宽裕。
	// 上界必须存在，理由见 Server.admitSession：建会话由对端驱动，
	// 而会话在路径全断之后还要活满宽限期。
	DefaultMaxSessionsPerUser = 64

	// DefaultUDPTimeout 是一条 UDP 关联多久没有任何方向的流量就被回收。
	//
	// 5 分钟不是拍脑袋：RFC 4787 REQ-5 规定 NAT 的 UDP 映射定时器 **MUST NOT**
	// 短于 2 分钟，并 RECOMMENDED 默认 5 分钟以上；mihomo 的 sing 系入站用的
	// 也正是 5 分钟。定短了会打断长命 UDP 会话（游戏、静默期长的 QUIC），
	// 而那种失败同样是静默的——只表现为"过一会儿就断"。
	DefaultUDPTimeout = 5 * time.Minute

	// newSessionAfterPathless：会话失去全部路径超过这么久之后，**新连接**改建新会话，
	// 不再排队等这条正在宽限期里重连的会话。已有的流仍然享受完整 grace——
	// 它们的未确认字节还在重传缓冲里，重连上就能续上，那正是 grace 的用途。
	//
	// ★ 没有这一条，grace 会把**新连接**一起罚站。树莓派实测：服务端重启后约每三次
	// 有一次要 123 秒才恢复，而 123s ≈ DefaultSessionGrace；诊断输出里
	// `paths established` 自始至终没涨过——那 120 秒里一条新路径都没建起来，
	// 新请求却全都排在这条发不出字节的会话上等着。
	//
	// 取 3s：路径判死本身就要 ~8s（静默计时器），能走到这里说明是真的断了；
	// 再多等只是让新请求陪着耗到 grace 结束。代价是一次握手（实测约 500ms）。
	newSessionAfterPathless = 3 * time.Second

	// 重连退避。上限 5s 而不是更大：0-RTT 让每次尝试只花一个 RTT，
	// 重试便宜，就该退避得保守一点，别让恢复时间被退避本身拖长。
	reconnectBackoffMin = 100 * time.Millisecond
	reconnectBackoffMax = 5 * time.Second

	// 迁移判据（spec §8）：TCP 路径丢包率持续超过这个值时把批量流迁到 QUIC。
	migrateLossThreshold = 0.02
	// bulkThreshold：单流发够这么多字节就算"批量流"，可以迁；之下算交互流，留在 TCP。
	bulkThreshold = 1 << 20
)

// TimestampTolerance 是 spec §3.1 的 ±120 秒容差。
const TimestampTolerance = 120 * time.Second

// ClientConfig 是出站配置。
type ClientConfig struct {
	// Server 是 host:port。
	Server string
	// PublicKey 是服务端静态公钥（base64，见 PublicKey 文档说明为什么这么长）。
	PublicKey *PublicKey
	// UserID 16 字节用户标识。
	UserID [16]byte
	// ServerName 外层 TLS SNI；空则取 Server 的 host。
	ServerName string
	// TLSConfig 可选，用于自定义外层 TLS（ALPN、指纹、跳过校验等）。
	TLSConfig *tls.Config

	// Bare 请求裸帧模式（内层不加密，安全性完全由外层 TLS 承担）。
	// 服务端只在信道绑定校验通过时才会同意。
	Bare bool

	// EnableQUIC 允许调度器探测并使用 QUIC 路径。
	EnableQUIC bool
	// H3 让 QUIC 路径跑在 HTTP/3 之上（spec §12.6）。
	//
	// 收益是服务端对任何非 TIDE 客户端都表现为一个**货真价实的 h3 服务器**
	// （非 TIDE 请求反代到掩护源站），而不是一个沉默的 QUIC 端点——后者对一台
	// 在 TCP/443 上服务 HTTPS 的主机来说是说不通的异常。
	// 需要服务端用 ServeH3 而不是 ServeQUIC 监听，且**两端必须一致**——
	// 不一致时 QUIC 通道会静默失效（两边 ALPN 都是 "h3"，握手照样成功，
	// 之后服务端把 h3 的 HEADERS 帧当 TIDE 的 HELLO 解，路径悄悄死掉，
	// 客户端按 §8 静默回落 TCP）。tide-server 的启动横幅会替用户打出这一行。
	//
	// 掩护、数据面、UDP 三块都已跑通并有测试覆盖：UDP 走的是 RFC 9297 的
	// HTTP Datagram，不是可靠有序的控制流（TestUDPOverH3Datagrams 专门断言
	// 数据报没有落到流上——§9.1 要求 UDP MUST NOT 重传，塞进流里照样能通、
	// 测试照样绿，但被代理的 QUIC 会跑在一条替它重传的通道上，两层拥塞控制打架）。
	//
	// ⚠️ 默认仍然关闭，但**不是**因为还缺什么机制——那条理由（"RFC 9297 尚未接入"）
	// 早就不成立了，这段注释一度还留着它。默认关闭现在纯粹是保守：
	// h3 比原生 QUIC 多一层 HTTP/3 帧开销，而它换来的是 §12.6 的主动探测防御，
	// 那对自建服务端的用户是不是划算，取决于部署环境。
	H3 bool
	// QUICPort 为 0 时复用 Server 的端口。
	QUICPort int

	// Redundancy 常驻维持两条路径。
	//
	// ★ 这是对抗网络波动最有效、也最贵的一个开关：路径死亡时不需要重连，
	// 流直接切到另一条已经握好手的路径上，用户侧几乎无感（一个 RTT 内）。
	// 代价是两条连接的保活开销，以及服务端两倍的会话资源。
	// 弱网/移动网络建议开，稳定有线网不需要。
	Redundancy bool

	// SessionGrace 覆盖 DefaultSessionGrace。
	SessionGrace time.Duration
	// ProbeInterval 覆盖 DefaultProbeInterval。
	ProbeInterval time.Duration
	// StreamWindow 覆盖 DefaultStreamWindow。
	StreamWindow uint64

	// Dial 允许注入自定义拨号（clash 侧用来走 dialer 的接口绑定/DNS）。
	Dial DialFunc

	// ListenPacket 允许注入 QUIC/h3 路径用的 UDP 套接字。
	//
	// ★ 不给这个钩子的话，QUIC 路径会用 quic.DialAddr 自己开一个**裸 UDP 套接字**，
	// 于是它绕过了 Dial 所代表的一切：接口绑定、fwmark、以及最要命的——
	// "这是内核自己发出去的流量"这个标记。
	//
	// 后果在开了 TUN 的机器上是致命的：客户端自己发往服务端的 QUIC 包被**自己的 TUN**
	// 捕获，绕回路由器，嗅探器再从 QUIC ClientHello 里读出 SNI（比如 tide.local）
	// 把目的地改写成那个名字，然后解析失败。日志里就是没完没了的
	//   [UDP] dial ... --> tide.local:8443 error: can't resolve ip
	// 这是一个把自己绕进去的环路，且 TCP 路径完全正常，所以特别难往这上面想。
	// 2026-08-07 用户实测截图即此现象（Coast 1.0.974，增强/TUN 开启）。
	//
	// 为空时回退到 quic.DialAddr（库单独使用、没有 TUN 的场景照常工作）。
	ListenPacket ListenPacketFunc

	// Congestion 指定 TCP 路径的拥塞控制算法（Linux 专有，如 "bbr"、"cubic"）。
	// 空 = **不动系统默认**。填 "-" 同义。
	//
	// ⚠️ 别想当然地填 "bbr"：实测双向 5% 丢包下它把 p99 从 125ms 抬到 620ms
	//    （详见 congestion_linux.go）。Linux 的 `bbr` 是 v1，对随机丢包的处理
	//    正是它的弱点；design.md 里说的 BBRv3 内核里并没有。
	// ⚠️ 只作用于 TCP 路径：quic-go v0.61 内置只有 cubic 且不暴露选择接口。
	Congestion string
}

// congestion 返回该配置最终要用的算法名。
func (c *ClientConfig) congestion() string {
	if c.Congestion == "-" {
		return ""
	}
	if c.Congestion != "" {
		return c.Congestion
	}
	return defaultCongestion
}

// DialFunc 与 net.Dialer.DialContext 同形。
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// ListenPacketFunc 交出一个用于 QUIC/h3 的 UDP 套接字。addr 是即将拨的对端地址，
// 供实现方按目的地选网卡/加标记。
type ListenPacketFunc func(ctx context.Context, addr string) (net.PacketConn, error)

func (c *ClientConfig) validate() error {
	if c.Server == "" {
		return errors.New("tide: ClientConfig.Server is empty")
	}
	if c.PublicKey == nil {
		return errors.New("tide: ClientConfig.PublicKey is nil")
	}
	return nil
}

func (c *ClientConfig) sessionGrace() time.Duration {
	if c.SessionGrace > 0 {
		return c.SessionGrace
	}
	return DefaultSessionGrace
}

func (c *ClientConfig) probeInterval() time.Duration {
	if c.ProbeInterval > 0 {
		return c.ProbeInterval
	}
	return DefaultProbeInterval
}

func (c *ClientConfig) streamWindow() uint64 {
	if c.StreamWindow > 0 {
		return c.StreamWindow
	}
	return DefaultStreamWindow
}

// ServerConfig 是入站配置。
type ServerConfig struct {
	// PrivateKey 服务端静态私钥。
	PrivateKey *PrivateKey
	// Users 允许的用户集合。
	//
	// ⚠️ **空表 = 接受任何 user_id = 开放代理**，必须配合 AllowAnyUser 显式声明。
	//
	// 这里原先的注释写的是"只有在 PrivateKey 本身即凭据的部署里才合理"，
	// 那句话是错的：客户端在握手里**从不证明**自己知道私钥——它只需要**公钥**
	// （用来做 KEM 封装），而公钥印在服务端启动横幅上、也贴在每一份客户端配置里。
	// 客户端唯一提供的凭据就是口令派生出来的 user_id。所以空表的真实含义是
	// "任何拿到公钥的人都能用这台代理，口令随便填"。
	// 唯一说得通的部署是把公钥当共享秘密来发，那也该是显式选择，而不是默认。
	Users map[[16]byte]string

	// AllowAnyUser 显式接受"任何 user_id 都放行"。仅在把公钥当共享秘密分发的
	// 部署里才有意义。不设而又不给 Users 时，NewServer 直接报错。
	//
	// ★ 这是**故意做成失败关闭**的。空集合默认放行属于 CWE-1188
	// （Insecure Default Initialization），MITRE 把它的利用可能性评为 High，
	// 现实里"空 token / 空用户表即绕过认证"的 CVE 一抓一把。
	// 而本仓库对同一类问题已经有过两次正确处置：CoverAddr 为空直接拒绝启动
	// （注释写着"静默降级掉的安全属性没人会发现它已经没了"），
	// cmd/tide-server 也拒绝空用户表启动。漏的恰恰是库本身——
	// 于是 clash 那个 listener（Coast 真正在用的入口）从 YAML 里读到一个没有
	// users: 的配置时，会安安静静地起一台开放代理。
	AllowAnyUser bool

	// TLSConfig 外层 TLS。必须提供（bare 模式与信道绑定都依赖它）。
	TLSConfig *tls.Config

	// CoverAddr 是掩护源站地址（host:port）。
	//
	// ★ 认证失败时必须把这条连接的全部字节**真的转发**过去，而不是模拟响应。
	// 时序是这里唯一真正难伪造的东西：失败路径 0.1ms、真实站点 50ms，
	// 探测方量一下响应时间分布就分开了，伪装随即全部作废。
	// 所以掩护站点必须真实可达且延迟合理（同机房或本机）。
	CoverAddr string

	// TicketStore 为空时用 MemTicketStore（**只在单机正确**，见 TicketStore 文档）。
	TicketStore TicketStore
	// TicketCount 单批签发数量，0 取 DefaultTicketCount。
	TicketCount uint16

	// AllowBare 是否允许协商裸帧模式。
	AllowBare bool

	// SessionGrace 覆盖 DefaultSessionGrace。
	SessionGrace time.Duration
	// StreamWindow 覆盖 DefaultStreamWindow。
	StreamWindow uint64
	// MaxStreams 单会话并发流上限。
	MaxStreams int
	// UDPTimeout 覆盖 DefaultUDPTimeout：UDP 关联的空闲回收期。
	UDPTimeout time.Duration
	// MaxSessionsPerUser 覆盖 DefaultMaxSessionsPerUser。
	MaxSessionsPerUser int

	// Congestion 同 ClientConfig.Congestion。
	Congestion string
}

func (c *ServerConfig) congestion() string {
	if c.Congestion == "-" {
		return ""
	}
	if c.Congestion != "" {
		return c.Congestion
	}
	return defaultCongestion
}

func (c *ServerConfig) validate() error {
	if c.PrivateKey == nil {
		return errors.New("tide: ServerConfig.PrivateKey is nil")
	}
	if c.TLSConfig == nil {
		return errors.New("tide: ServerConfig.TLSConfig is nil")
	}
	if len(c.Users) == 0 && !c.AllowAnyUser {
		return errors.New("tide: ServerConfig.Users is empty, which would accept ANY user_id " +
			"(the client only needs the public key, which is not a secret); " +
			"set Users, or set AllowAnyUser=true to knowingly run an open relay")
	}
	if c.CoverAddr == "" {
		// 不给掩护站点就等于放弃 §6 的抗主动探测。允许，但必须是显式选择，
		// 所以这里报错而不是静默降级——静默降级的安全属性没人会发现已经没了。
		return errors.New("tide: ServerConfig.CoverAddr is empty; " +
			"set it to a real reachable origin, or explicitly use CoverAddr=\"drop\" to accept probe exposure")
	}
	return nil
}

func (c *ServerConfig) sessionGrace() time.Duration {
	if c.SessionGrace > 0 {
		return c.SessionGrace
	}
	return DefaultSessionGrace
}

func (c *ServerConfig) streamWindow() uint64 {
	if c.StreamWindow > 0 {
		return c.StreamWindow
	}
	return DefaultStreamWindow
}

func (c *ServerConfig) maxStreams() int {
	if c.MaxStreams > 0 {
		return c.MaxStreams
	}
	return DefaultMaxStreams
}

func (c *ServerConfig) maxSessionsPerUser() int {
	if c.MaxSessionsPerUser > 0 {
		return c.MaxSessionsPerUser
	}
	return DefaultMaxSessionsPerUser
}

func (c *ServerConfig) udpTimeout() time.Duration {
	if c.UDPTimeout > 0 {
		return c.UDPTimeout
	}
	return DefaultUDPTimeout
}

func (c *ServerConfig) ticketCount() uint16 {
	if c.TicketCount > 0 {
		return c.TicketCount
	}
	return DefaultTicketCount
}
