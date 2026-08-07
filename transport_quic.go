package tide

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// QUIC 路径（spec §8 / design.md 机制 6b）。
//
// ★ 为什么值得做，实测说了算：本仓库在树莓派↔x86 之间量过，5% 丢包下单条 TCP 路径的
// p99 往返是 619ms，两条 TCP 路径 323ms。这几百毫秒里绝大部分不是链路时延，
// 是 **Linux TCP 的最小 RTO（200ms）**——LAN 上 RTT 只有 0.3ms，一次丢包却要等 200ms
// 才重传，而且重传期间这条连接上复用的**所有**流一起卡住（队头阻塞）。
// QUIC 的 PTO 由实测 RTT 驱动、没有 200ms 的地板，正是冲着这一项来的。
//
// 一条 QUIC 路径上，**每条 TIDE 流有自己的 QUIC 流**（见 quicmux.go），
// 控制帧（握手、探测、票据）留在第一条流上。这样一条流的丢包不会卡住其它流——
// 早先的单流版本在 5% 丢包下 p99 比裸 TCP 还差，原因就是把 4 条流全塞进了一条。

const quicALPN = "h3"

// quicConn 把一条 QUIC 流包装成 net.Conn。
// 地址取自连接而不是流——流本身没有地址概念。
type quicConn struct {
	*quic.Stream
	conn *quic.Conn
}

func (q *quicConn) LocalAddr() net.Addr  { return q.conn.LocalAddr() }
func (q *quicConn) RemoteAddr() net.Addr { return q.conn.RemoteAddr() }

// Close 关掉这条 QUIC 路径。**只从路径判死那条路上调**（markDeadReason）。
//
// ★ 这里绝不能用 Stream.Close()。quic-go 的文档是明写的约束：
// "Close() must not be called concurrently with Write()"——而本函数正是从
// markDeadReason 过来的，此刻 path.writeLoop 极可能**正阻塞在 Write 里等流控额度**
// （对端不给窗口、链路拥塞、或者对端已经没了）。
//
// 违反那条约束的后果实测到了：Stream.Close() 自己不返回，于是它**下面**那句
// conn.CloseWithError 根本执行不到，writeLoop 就永远挂着——一条路径连同它的
// 缓冲一起泄漏。第 39 轮那道协程守卫抓到的正是这个，而且是偶发的：
// 只有 writeLoop 恰好卡在流控里时才复现（连跑三遍 verify 才撞出两次）。
//
// 正确的 API 是 CancelWrite——官方原话是 "Write will unblock immediately"，
// 而且"在 Close 之后调用 CancelWrite 是合法的"。这里干脆不再调 Stream.Close()：
// 反正下一句就把整条 QUIC 连接关掉了，给流做一次优雅 FIN 没有任何意义。
func (q *quicConn) Close() error {
	q.Stream.CancelRead(0)
	q.Stream.CancelWrite(0)
	q.conn.CloseWithError(0, "")
	return nil
}

// ExportKeyingMaterial 让 QUIC 路径也能做信道绑定（spec §4）。
// QUIC-TLS 的导出器与 TLS 1.3 的是同一套，crypto/tls 的 QUIC 接口原样提供。
func (q *quicConn) ExportKeyingMaterial(label string, ctx []byte, n int) (out []byte, err error) {
	// ExportKeyingMaterial 是 tls.ConnectionState 上的**方法**，不是字段，
	// 所以没法用 == nil 判断有没有导出器；底层 ekm 为 nil 时它直接 panic。
	// 这里兜住那个 panic 并转成错误：没有信道绑定就没有 MITM 检测、也没有 bare 模式的
	// 安全前提，必须是一个显式失败，而不是一个悄悄少掉的安全属性。
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, errNoExporter
		}
	}()
	cs := q.conn.ConnectionState().TLS
	return cs.ExportKeyingMaterial(label, ctx, n)
}

func quicClientTLS(base *tls.Config) *tls.Config {
	c := base.Clone()
	// QUIC 强制要求 ALPN。用 h3 是因为 QUIC 上的 h3 是当下唯一常见的流量，
	// 换成自定义串等于在握手明文里插一个协议指纹。
	c.NextProtos = []string{quicALPN}
	if c.MinVersion < tls.VersionTLS13 {
		c.MinVersion = tls.VersionTLS13
	}
	return c
}

// h3QUICConfig 是 HTTP/3 模式用的 QUIC 参数。
//
// ★ 与原生模式的关键差别：**必须允许单向流**。HTTP/3 靠单向流承载控制流与
// QPACK 编解码流（RFC 9114 §6.2），而原生模式那份配置把 MaxIncomingUniStreams
// 设成了 -1（禁用）——客户端开不出控制流，握手直接以 H3_INTERNAL_ERROR 告终，
// 而且错误是**客户端本地**产生的，看日志会以为是客户端的问题。
func h3QUICConfig() *quic.Config {
	c := quicConfig()
	c.MaxIncomingUniStreams = 16
	// RFC 9297 的 HTTP Datagram 建在 QUIC 数据报之上，两层都要开。
	c.EnableDatagrams = true
	return c
}

func quicConfig() *quic.Config {
	return &quic.Config{
		// KeepAlivePeriod 让 NAT 表项不过期。移动网络的 UDP NAT 超时经常只有 30 秒，
		// 超时之后回程包直接被丢，表现为"能发不能收"——这是 UDP 代理最常见的一类假死。
		KeepAlivePeriod: 10 * time.Second,
		// MaxIdleTimeout 要比会话宽限期短：路径该死就让它死，
		// 由 TIDE 的重连逻辑接管，而不是让一条僵尸 QUIC 连接吊着。
		MaxIdleTimeout: 30 * time.Second,
		// 分流之后每条 TIDE 流吃一条 QUIC 流，上限必须跟得上会话的并发流数，
		// 否则超出的流会阻塞在 OpenStream 上——现象是"并发一高就有连接卡死"。
		MaxIncomingStreams:    int64(DefaultMaxStreams) + 16,
		MaxIncomingUniStreams: -1,
		// UDP 关联要走 RFC 9221 的数据报（spec §12.8），两端都必须通告支持。
		EnableDatagrams: true,
		// Allow0RTT 关掉：TIDE 自己的单次票据才是 0-RTT 的正确实现，
		// QUIC 的 0-RTT 早期数据**没有重放保护**（TUIC 就吃这个亏），
		// 两层都开等于把内层辛苦建立的重放保护又从外层漏掉。
		Allow0RTT: false,
	}
}

// dialQUICPath 拨一条 QUIC 路径。
func (c *Client) dialQUICPath(ctx context.Context, s *Session, join bool) (*path, error) {
	addr := c.quicAddr()
	base := c.tlsCfg
	conn, err := quic.DialAddr(ctx, addr, quicClientTLS(base), quicConfig())
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, err
	}
	// QUIC 的流是懒创建的：不写一个字节，服务端永远 Accept 不到。
	// 握手的第一帧就是那个字节，所以这里不需要额外的探针。
	qc := &quicConn{Stream: stream, conn: conn}
	p, err := c.handshake(ctx, s, qc, join, "quic")
	if err != nil {
		qc.Close()
		return nil, err
	}
	return p, nil
}

func (c *Client) quicAddr() string {
	host, port, err := net.SplitHostPort(c.cfg.Server)
	if err != nil {
		return c.cfg.Server
	}
	if c.cfg.QUICPort > 0 {
		return net.JoinHostPort(host, itoa(c.cfg.QUICPort))
	}
	return net.JoinHostPort(host, port)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// ServeQUIC 在 addr 上接受 QUIC 路径。与 Serve 并存：同一个 Server 可以同时
// 提供 TCP 与 QUIC 两条数据面，客户端的调度器按实测质量挑。
func (s *Server) ServeQUIC(addr string) error {
	tlsCfg := s.cfg.TLSConfig.Clone()
	tlsCfg.NextProtos = []string{quicALPN}
	ln, err := quic.ListenAddr(addr, tlsCfg, quicConfig())
	if err != nil {
		return err
	}
	defer ln.Close()
	ctx, cancel := s.acceptContext()
	defer cancel()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			select {
			case <-s.stopped:
				return nil
			default:
			}
			return err
		}
		go s.handleQUICConn(conn)
	}
}

// acceptContext 返回一个在 Server.Close() 时被取消的 context，供 Accept 使用。
//
// ★ 只在 Accept **返回之后**去看 s.stopped 是不够的——那个检查根本轮不到执行，
// 因为 Accept 传的是 context.Background()，Close() 不会让它醒。于是：
//
//	Server.Close() 之后 QUIC/h3 的 Accept 循环仍然挂着，UDP 端口一直被占；
//	`defer ln.Close()` 也跑不到——它要等循环退出，而循环在等 Accept，死结。
//
// 这在**配置热重载**下会连成一条完整的故障：旧入站关掉（TCP 端口释放了，
// UDP 没有）→ 新入站绑同一个 UDP 端口失败 → 而调用方往往把这个错误丢掉 →
// 客户端按 §8 静默回落 TCP。净效果是"第一次热重载之后 QUIC 加速就再也不工作了，
// 直到进程重启"，全程零日志。Coast 每次订阅/设置变更都会热重载。
//
// quic-go 官方给的停机做法正是**取消传给 Accept 的那个 context**
// （它的 Listener.Close() 还会一并关掉所有活动连接，语义比 TCP 的更重，
// 所以不适合用来单纯地"停止接受新连接"）。
func (s *Server) acceptContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-s.stopped:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func (s *Server) handleQUICConn(conn *quic.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), handshakeReadTimeout)
	stream, err := conn.AcceptStream(ctx)
	cancel()
	if err != nil {
		conn.CloseWithError(0, "")
		return
	}
	qc := &quicConn{Stream: stream, conn: conn}

	// QUIC 路径上**不做**掩护转发。
	//
	// 不是偷懒：§6 的失败关闭要求把字节原样转给一个真实的掩护源站，而 QUIC 的
	// 掩护对象只能是另一个 QUIC/HTTP-3 服务，字节流也不能直接搬过去（QUIC 有自己的
	// 流语义）。更关键的是，一个对外只开 UDP/443 的主机本来就没有"看起来像普通网站"
	// 这个选项——真正的伪装靠的是 TCP 那条路径。所以 QUIC 路径的定位是
	// **已建立会话的加速通道**，不是首次接入的门面；探测方打到这里只会看到一个沉默的
	// QUIC 端点，和任何一个不响应的 UDP 端口没有区别。
	t := &teeConn{Conn: qc, recording: false}
	p, sess, err := s.serverHandshake(t)
	if err != nil {
		// 认证失败：**不要立刻关**。立刻关是一个可测量的、与"真实 QUIC 服务在等
		// 后续请求"截然不同的行为，等于给探测方一个免费的判据。
		// 这里读到对端自己放弃为止，与 §7.2「掩护源站不可达时」的处理一致。
		// 注意这仍然弱于 TCP 那条路径的真实转发——QUIC 面没有掩护源站，
		// 见 spec §12.6 对这个残留差距的说明。
		go func() {
			buf := make([]byte, 4096)
			qc.SetReadDeadline(time.Now().Add(30 * time.Second))
			for {
				if _, err := qc.Read(buf); err != nil {
					break
				}
			}
			qc.Close()
		}()
		return
	}
	sess.addPath(p)
	<-p.dead
}

// isQUICConn 判断一条传输是不是 QUIC —— **包括跑在 HTTP/3 之上的**。
//
// ★ 漏掉 h3 那一支会产生一个极难查的 bug：服务端据此决定 bare 与否，
// 漏判就会协商成 sealed，而客户端的 h3 分流器写的是 bare 裸帧。
// 握手本身照常成功（它不走记录层），路径建起来之后第一帧数据就解密失败、
// 路径静默判死、重连、再死——现象是"h3 路径永远起不来"，
// 而错误信息指向的是密钥/记录层，跟 bare 协商八竿子打不着。
func isQUICConn(c interface{}) bool {
	switch c.(type) {
	case *quicConn, *h3Conn:
		return true
	}
	return false
}

// errNoExporter：传输层拿不出 TLS 导出器。没有它就没有信道绑定，
// 也就没有 MITM 检测和 bare 模式的安全前提——必须是显式失败。
var errNoExporter = errors.New("tide: transport exposes no TLS exporter; " +
	"channel binding cannot be established")
