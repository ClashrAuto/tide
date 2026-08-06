package tide

import (
	"bytes"
	"context"
	"errors"
	"sync"

	"github.com/quic-go/quic-go"
)

// QUIC 多流复用：把**每条 TIDE 流映射到一条独立的 QUIC 流**，消除路径内部的队头阻塞。
//
// ★ 为什么必须做，实测说了算（树莓派↔x86，netem 5% 丢包，4 条并发流）：
//
//	裸 TCP（4 条独立连接）   p99 279ms   p99.9 1.377s
//	TIDE 单流复用            p99 360ms   p99.9 571ms
//
// TIDE 的 p99.9 已经好 2.4 倍（QUIC 的 PTO 没有 TCP 那个 200ms 的 RTO 地板），
// 但 p99 反而**更差**。差在哪一目了然：对照组是 4 条独立的 TCP 连接，一条丢包只卡它
// 自己；单流复用把 4 条流全塞进一条 QUIC 流，一个丢包把四条一起卡住。
// 复用省下的连接数，是拿队头阻塞换的——并发流越多，这笔交换越亏。
//
// 分流之后每条 TIDE 流有自己的 QUIC 流，丢包只影响它自己，
// 队头阻塞面缩到和"每条流一个连接"一样，同时仍然共享一次握手、一个拥塞控制器、
// 一个会话身份。
//
// ⚠️ 分流强制 bare 内层（不加内层 AEAD）。这不是妥协，是**必须**：
// sealed 记录层的 nonce 是每路径单调的序号，它成立的前提是"一条路径 = 一个有序字节流"。
// 多条 QUIC 流之间没有全局顺序，记录会乱序到达，序号立刻对不上——
// 而 (key, nonce) 一旦错位，AEAD 直接失效。
// 安全性上这也站得住：QUIC-TLS 本身**恒定**提供 AEAD（不像裸 TCP 那样可能没有），
// 且信道绑定（spec §5）已经密码学地证明外层没被中间人替换。
// 这正是 spec §6.2 允许 bare 的两个前提，QUIC 路径天然同时满足。

var errNoQUICStream = errors.New("tide: no QUIC stream bound for this TIDE stream yet")

// qstream 是一条 QUIC 流加它自己的写锁。
// 每条流一把锁，而不是整个 mux 一把——否则分了流却在写入口重新串行化，白分。
// muxStream 是"一条双向字节流"。QUIC 原生流与 h3 流都满足它——
// 抽这一层是为了让 §12.6 的 h3 模式复用整套分流逻辑，而不是复制一份。
type muxStream interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

type qstream struct {
	s  muxStream
	mu sync.Mutex
}

// cancelRead 只对 QUIC 原生流有意义（h3 流由 http3 自己管）。
func (q *qstream) cancelRead() {
	if s, ok := q.s.(*quic.Stream); ok {
		s.CancelRead(0)
	}
}

type quicMux struct {
	conn     *quic.Conn
	isClient bool
	path     *path

	// h3 为真时流由 HTTP/3 handler 交进来，不走 AcceptStream。
	h3 bool
	// open 开一条新的底层流。QUIC 原生模式下是 conn.OpenStream；
	// h3 模式下是"发一个 POST 并把请求体/响应体当成双向流"。
	open func() (muxStream, error)

	mu      sync.Mutex
	streams map[uint64]*qstream
	closed  bool
}

// adoptStream 收养一条对端开来的流（h3 模式下由 handler 交进来）。
// 绑定关系等第一帧里的 stream_id 揭晓，与 acceptLoop 的处理一致。
func (m *quicMux) adoptStream(s muxStream) {
	m.readLoop(&qstream{s: s}, 0)
}

func newQUICMux(conn *quic.Conn, isClient bool, p *path) *quicMux {
	m := &quicMux{conn: conn, isClient: isClient, path: p, streams: map[uint64]*qstream{}}
	m.open = func() (muxStream, error) { return conn.OpenStream() }
	go m.acceptLoop()
	go m.datagramLoop()
	return m
}

// weOpen 决定这条 TIDE 流的 QUIC 流由哪一端开。
//
// 没有这条规则，两端会为同一条 TIDE 流各开一条 QUIC 流，然后各写各的、
// 谁也收不到对方的数据——而且不会报错，表现为连接静默挂死。
// 流号本来就奇偶分家（客户端奇、服务端偶，见 spec §4.1），直接复用这个约定。
func (m *quicMux) weOpen(sid uint64) bool { return m.isClient == (sid%2 == 1) }

// streamFor 取（必要时打开）某条 TIDE 流对应的 QUIC 流。
func (m *quicMux) streamFor(sid uint64, create bool) (*qstream, error) {
	m.mu.Lock()
	if q, ok := m.streams[sid]; ok {
		m.mu.Unlock()
		return q, nil
	}
	if m.closed {
		m.mu.Unlock()
		return nil, ErrClosed
	}
	if !create || !m.weOpen(sid) {
		// 该由对端开的流还没到。调用方据此回退：写失败 → pendOff 回退 →
		// 对端的流一到就重发。这条路径在正常时序下走不到，但重连期间会。
		m.mu.Unlock()
		return nil, errNoQUICStream
	}
	m.mu.Unlock()

	s, err := m.open()
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	if q, ok := m.streams[sid]; ok {
		// 竞态：另一个 goroutine 抢先开了。用它的，把自己这条关掉。
		m.mu.Unlock()
		s.Close()
		return q, nil
	}
	q := &qstream{s: s}
	m.streams[sid] = q
	m.mu.Unlock()

	go m.readLoop(q, sid)
	return q, nil
}

// write 把一帧写到该 TIDE 流自己的 QUIC 流上。
func (m *quicMux) write(t FrameType, flags uint8, sid uint64, payload []byte) error {
	q, err := m.streamFor(sid, true)
	if err != nil {
		return err
	}
	// bare 内层：不加密、不填充，一帧就是一次 Write。quic-go 内部会攒包，
	// 这里再攒一层只会增加延迟。
	buf := AppendFrame(nil, t, flags, sid, payload, 0)
	q.mu.Lock()
	_, err = q.s.Write(buf)
	q.mu.Unlock()
	if err != nil {
		return err
	}
	m.path.txBytes.Add(uint64(len(buf)))
	return nil
}

// acceptLoop 收对端开的 QUIC 流。
func (m *quicMux) acceptLoop() {
	if m.h3 {
		return // h3 模式下流由 handler 交进来，见 adoptStream
	}
	for {
		s, err := m.conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go m.readLoop(&qstream{s: s}, 0) // sid=0：等第一帧告诉我们它是哪条流
	}
}

// readLoop 读一条 QUIC 流上的帧。
//
// knownSID 为 0 表示这是对端开的流，绑定关系要等第一帧里的 stream_id 才知道。
// 绑定之后本端的回写才能找到同一条 QUIC 流——漏了这一步，服务端会试图为一条
// 客户端开的流再开一条自己的，于是双方各说各话。
func (m *quicMux) readLoop(q *qstream, knownSID uint64) {
	fr := newFrameReader(q.s)
	bound := knownSID != 0
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			m.dropStream(q)
			return
		}
		m.path.noteRecv(len(f.Payload))
		if !bound && f.StreamID != 0 {
			m.mu.Lock()
			if _, exists := m.streams[f.StreamID]; !exists {
				m.streams[f.StreamID] = q
			}
			m.mu.Unlock()
			bound = true
		}
		if err := m.path.sess.handleFrame(m.path, f); err != nil {
			m.dropStream(q)
			return
		}
	}
}

func (m *quicMux) dropStream(q *qstream) {
	m.mu.Lock()
	for sid, cur := range m.streams {
		if cur == q {
			delete(m.streams, sid)
		}
	}
	m.mu.Unlock()
	q.cancelRead()
	q.s.Close()
}

// closeStream 在 TIDE 流结束时关掉对应的 QUIC 流，别让它泄漏。
func (m *quicMux) closeStream(sid uint64) {
	m.mu.Lock()
	q := m.streams[sid]
	delete(m.streams, sid)
	m.mu.Unlock()
	if q != nil {
		q.mu.Lock()
		q.s.Close() // 只关写侧，让对端把剩下的读完
		q.mu.Unlock()
	}
}

func (m *quicMux) close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	all := make([]*qstream, 0, len(m.streams))
	for _, q := range m.streams {
		all = append(all, q)
	}
	m.streams = map[uint64]*qstream{}
	m.mu.Unlock()
	for _, q := range all {
		q.cancelRead()
		q.s.Close()
	}
}

// muxable 判断一个帧类型该不该走独立的 QUIC 流。
//
// 只有属于某条 TIDE 流的帧才分流。会话级的控制帧（探测、票据、关闭）留在控制流上：
// 它们本来就该保序，而且分流会让 PATH_PROBE 的 RTT 量到的是"一条新流的建立时间"
// 而不是路径时延。
//
// DATAGRAM 也留在控制流——它带着 assoc 的流号，但 UDP 语义上不该被重传。
// 放在控制流至少不会额外增加队头阻塞面；真正正确的做法是走 QUIC 数据报，
// 见 spec §12.5 的后续项。
func muxable(t FrameType) bool {
	switch t {
	case FrameStreamOpen, FrameStreamData, FrameStreamFin, FrameStreamRst,
		FrameStreamAck, FramePathMigrate:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// UDP 走 QUIC 数据报（spec §12.8）
// ---------------------------------------------------------------------------
//
// ★ 为什么不能让 DATAGRAM 帧走普通的 QUIC 流：那会把它变成**可靠有序**的。
// spec §9.1 明确要求 UDP MUST NOT 重传——重传和保序都会改变上层协议
// （QUIC、DNS、游戏）自己的拥塞与超时行为，通常比丢包更糟。
// 一个被代理的 QUIC 连接如果跑在一条可靠流上，就会出现"两层拥塞控制打架"：
// 内层以为网络没丢包（下层替它重传了），于是一路加速，直到下层缓冲爆掉。
// 这类故障的现象是吞吐周期性崩塌，且两层各自的统计都看不出问题。
//
// RFC 9221 的 QUIC 数据报正是为此存在：不重传、不保序、受拥塞控制约束。

// sendDatagram 把一个 DATAGRAM 帧作为 QUIC 数据报发出。
//
// 超过单个 QUIC 数据报能装下的大小时回退到控制流（可靠有序）。
// 为什么不直接丢：真实世界里超过 MTU 的 UDP 会被 IP 分片，而不是消失；
// 直接丢会让大响应（比如带很多记录的 DNS 应答）静默失败。
// 回退保住了正确性，代价是那一小部分数据报被"意外地可靠了"——
// 这个取舍比静默丢包好，且只影响大包。
func (m *quicMux) sendDatagram(flags uint8, sid uint64, payload []byte) error {
	buf := AppendFrame(nil, FrameDatagram, flags, sid, payload, 0)
	err := m.conn.SendDatagram(buf)
	if err == nil {
		m.path.txBytes.Add(uint64(len(buf)))
		return nil
	}
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return errDatagramTooLarge
	}
	return err
}

var errDatagramTooLarge = errors.New("tide: datagram exceeds the QUIC datagram limit")

// datagramLoop 收 QUIC 数据报并按普通帧分发。
func (m *quicMux) datagramLoop() {
	for {
		b, err := m.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		f, err := readFrameExact(bytes.NewReader(b))
		if err != nil {
			continue // 坏数据报丢掉即可，不值得断路径
		}
		m.path.noteRecv(len(f.Payload))
		if err := m.path.sess.handleFrame(m.path, f); err != nil {
			return
		}
	}
}

// newQUICMuxH3 建一个跑在 HTTP/3 之上的分流器（spec §12.6）。
//
// 与原生 QUIC 模式的两点不同：
//   - 新流不是 conn.OpenStream()，而是"发一个 POST，把请求体/响应体当双向流"。
//   - 对端开的流由 h3 handler 交进来（adoptStream），不走 AcceptStream。
//
// ⚠️ h3 模式下**不用 QUIC 数据报**。RFC 9297 的 HTTP Datagram 要求带 Quarter Stream ID
// 前缀，直接发裸 QUIC 数据报会违反 h3 的帧结构，被规范的 h3 实现视为协议错误。
// 所以这里 DATAGRAM 回落到控制流——UDP 因此暂时是可靠有序的，与 §9.1 的意图相悖，
// 这是 h3 模式当前的已知代价，记在 spec §12.6。
func newQUICMuxH3(conn *quic.Conn, p *path, open func() (muxStream, error)) *quicMux {
	m := &quicMux{conn: conn, isClient: true, path: p, streams: map[uint64]*qstream{}, h3: true}
	m.open = open
	return m
}

// newQUICMuxH3Server 是服务端侧的 h3 分流器。
//
// 服务端**从不主动开**数据流：TIDE 的流号奇偶分家，客户端开奇数，而服务端在本设计里
// 不开流。它只负责收养 h3 handler 交进来的流（adoptStream）。
// 没有这个分流器，serveData 会因为 p.qmux == nil 把每条数据流直接丢掉——
// 现象是控制流好好的、路径活着，但数据一个字节都过不去。
func newQUICMuxH3Server(conn *quic.Conn, p *path) *quicMux {
	m := &quicMux{conn: conn, isClient: false, path: p, streams: map[uint64]*qstream{}, h3: true}
	m.open = func() (muxStream, error) { return nil, errNoQUICStream }
	return m
}
