package tide

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// UDP（spec §5）。
//
// ★ 身份信息挂在**会话**上，而不是每个数据报上。这一条值得停下来看清楚：
// SOCKS5 的 UDP 中继是共享 socket，数据报本身不携带任何认证，所以客户端不得不在
// ASSOCIATE 请求里申报自己的真实来源地址，让服务端做 addr→user 的归属
// （Coast 在 Windows 侧就是这么干的，见仓库根 CLAUDE.md）。那条链路上任何一环
// 申报错了都不会报错——只是 IN-USER 规则对 UDP 静默失配，某台设备的 QUIC 流量
// 被记到「本机」头上。TIDE 里这个问题在架构上不存在：数据报走在已认证的会话内，
// 归属是结构决定的，不需要申报。

// Datagram 是一个收到的 UDP 数据报。
type Datagram struct {
	Assoc uint64 // 关联标识 = 开这条 UDP 关联时用的流号
	Addr  string // 对端地址
	Data  []byte
}

// PacketStream 是一条 UDP 关联，实现 net.PacketConn 的常用子集。
type PacketStream struct {
	st   *Stream
	sess *Session

	mu     sync.Mutex
	cond   *sync.Cond
	queue  []*Datagram
	queued int // queue 里的载荷字节数，与 sess.dgramBytes 同步增减
	closed bool
	rdl    time.Time

	// lastActive 是这条关联**任一方向**最后一次有流量的时刻（UnixNano）。
	// 空闲回收看的是它，见 watchUDPIdle。
	lastActive atomic.Int64
	// done 在关联结束时关闭，让空闲看门狗立刻退出而不是睡到下一个 tick。
	done chan struct{}
}

// OpenPacket 开一条 UDP 关联。dst 是"默认目标"，实际每个数据报都自带地址。
func (s *Session) OpenPacket(ctx context.Context, dst string) (*PacketStream, error) {
	if dst == "" {
		dst = "0.0.0.0:0"
	}
	select {
	case <-s.closed:
		return nil, ErrClosed
	default:
	}
	// ★ UDP 关联也是流，也要占流数上限。
	// OpenStream 与 onStreamOpen 两条路都查了，唯独这里漏了——于是"最多 1024 条流"
	// 这个上限可以用 UDP 绕开。在 Coast 里这条路的调用方是局域网设备发来的
	// SOCKS UDP ASSOCIATE，属于不可信输入；而每条关联自己还带着一个收队列，
	// 两个无界相乘就没有上界可言了。
	if int(s.streamCount.Load()) >= s.maxStream {
		return nil, ErrTooManyStreams
	}
	s.mu.Lock()
	id := s.nextSID
	s.nextSID += 2
	st := newStream(s, id, dst, s.window)
	st.initiator = true
	st.udp = true
	s.streams[id] = st
	s.mu.Unlock()
	s.streamCount.Add(1)

	payload := make([]byte, 0, 32+len(dst))
	payload = append(payload, 1) // kind: 1 = udp assoc
	payload = AppendVarint(payload, s.window)
	var err error
	payload, err = appendSocksAddr(payload, dst)
	if err != nil {
		s.removeStream(id)
		return nil, err
	}
	st.openPayload = payload
	if err := s.sendOnStream(st, FrameStreamOpen, FlagPush, payload); err != nil {
		if err := s.waitPath(ctx); err != nil {
			s.removeStream(id)
			return nil, err
		}
		s.sendOnStream(st, FrameStreamOpen, FlagPush, payload)
	}
	ps := newPacketStream(s, st)
	st.pkt = ps
	return ps, nil
}

func newPacketStream(s *Session, st *Stream) *PacketStream {
	ps := &PacketStream{st: st, sess: s, done: make(chan struct{})}
	ps.cond = sync.NewCond(&ps.mu)
	ps.lastActive.Store(time.Now().UnixNano())
	return ps
}

// WriteTo 发一个数据报。
//
// UDP **不做重传也不进重传缓冲**：它本来就是不可靠的，硬给它加可靠性会改变
// 上层协议（QUIC、DNS、游戏）自己的拥塞与超时行为，通常比丢包更糟。
// 路径切换期间丢掉的数据报就是丢了——这与在真实网络上丢包没有区别，
// 上层应用早就为此做好了准备。
// User 返回这条包流所属会话认证到的用户 ID。见 `Stream.User`。
//
// ★ UDP 那一路同样要能归属：手机上的 QUIC（YouTube 之类）全走这里，
//   缺了它「这台设备跑了多少流量」会只算 TCP，看起来像用得很少。
func (ps *PacketStream) User() [16]byte { return ps.sess.User() }

func (ps *PacketStream) WriteTo(b []byte, addr string) (int, error) {
	if len(b) > MaxFrameBody-300 {
		return 0, ErrFrameTooLarge
	}
	payload := make([]byte, 0, len(b)+300)
	var err error
	payload, err = appendSocksAddr(payload, addr)
	if err != nil {
		return 0, err
	}
	payload = append(payload, b...)
	if err := ps.sess.sendOnStream(ps.st, FrameDatagram, FlagPush, payload); err != nil {
		return 0, err
	}
	// 出向也算"活着"。只按入向计时的话，一条纯下载的关联（本端一直在发、
	// 对端偶尔才回）会在传输中途被当成空闲收掉。
	ps.lastActive.Store(time.Now().UnixNano())
	return len(b), nil
}

// ReadFrom 收一个数据报。
func (ps *PacketStream) ReadFrom() (*Datagram, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for len(ps.queue) == 0 {
		if ps.closed {
			return nil, ErrStreamClosed
		}
		if !ps.rdl.IsZero() {
			if time.Now().After(ps.rdl) {
				return nil, os_ErrDeadline
			}
			t := time.AfterFunc(time.Until(ps.rdl), func() {
				ps.mu.Lock()
				ps.cond.Broadcast()
				ps.mu.Unlock()
			})
			ps.cond.Wait()
			t.Stop()
			continue
		}
		ps.cond.Wait()
	}
	d := ps.queue[0]
	ps.queue[0] = nil // 见 evictOldestLocked 上面那段说明：不置 nil 就回收不掉
	ps.queue = ps.queue[1:]
	ps.queued -= len(d.Data)
	ps.sess.dgramBytes.Add(-int64(len(d.Data)))
	return d, nil
}

func (ps *PacketStream) SetReadDeadline(t time.Time) error {
	ps.mu.Lock()
	ps.rdl = t
	ps.cond.Broadcast()
	ps.mu.Unlock()
	return nil
}

func (ps *PacketStream) Close() error {
	ps.closeQueue()
	return ps.st.Close()
}

// closeQueue 关掉收队列、唤醒读者并归还预算。
//
// 和 Close 分开是因为 removeStream 也要调它，而 Close 会回头去关流——
// 从 removeStream 调 Close 就绕回来了。两处都必须调：
//   - 应用自己关（Close）；
//   - 对端 RST 或流被摘掉（removeStream）。少了后者有两个后果，
//     且都只在跑久了之后才显形：没读走的字节永久占着会话的数据报预算，
//     于是所有关联慢慢开始丢包而查不出原因；DefaultPacketHandler 的读循环
//     没有超时，会永远阻塞在 ReadFrom 上，连同它的 UDP socket 一起泄漏。
func (ps *PacketStream) closeQueue() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.closed {
		return
	}
	ps.closed = true
	if ps.queued > 0 {
		ps.sess.dgramBytes.Add(-int64(ps.queued))
		ps.queued = 0
	}
	ps.queue = nil
	// 叫醒空闲看门狗。少了这一句它会一直睡到下一个 tick（默认 75 秒）才发现
	// 关联已经没了——一条 goroutine 白挂 75 秒，而并发关联上限是 1024。
	close(ps.done)
	ps.cond.Broadcast()
}

func (ps *PacketStream) LocalAddr() net.Addr { return ps.sess.LocalAddr() }

// Assoc 返回关联标识。
func (ps *PacketStream) Assoc() uint64 { return ps.st.id }

// 已建关联的收队列上界。满了就丢最老的——UDP 的语义下，一个陈旧的数据报比一个
// 新的更没价值（mvfst 的入向数据报缓冲也是这个策略），而无上界排队会在应用
// 读得慢时把内存吃光。
//
// ★ 三个上界缺一不可，理由和下面抢跑暂存区那三个是同一套，只是这里晚发现了一轮。
//
//  1. **条数**。每条排队记录除了载荷还有 slice 表项与 Datagram 结构，
//     合计上百字节且**与载荷长度无关**。LSQUIC 的 QUIC-LEAK（CVE-2025-54939）
//     就栽在这个量上：每个包 ~96 字节的结构体，一条 UDP 数据报换 ~960 字节 RAM，
//     内存以带宽 70% 的速度线性增长。只限字节挡不住"小数据报刷条数"。
//
//  2. **单关联字节**。这一条原先没有，而它才是这里真正会涨的量：
//     单条数据报的载荷上限是 MaxFrameBody-300 ≈ 56 KiB，512 条就是 28 MiB。
//     参考实现在这一点上分成两派，分歧的根源正是单条上限：quic-go 只限条数
//     （maxDatagramRcvQueueLen = 128），因为 QUIC 的 max_datagram_frame_size
//     把单条压在 ~1200 字节，条数与字节是同一个量；.NET / MsQuic 的
//     DatagramReceiveQueueLength 则明确是"缓冲入向数据报所用的**字节**数"。
//     TIDE 的单条上限属于后者，却抄了前者的形状。
//     256 KiB 按 1500 字节的真实数据报算约 175 条，够吸收一次调度抖动了。
//
//  3. **全会话字节**。前两条只约束一条关联；关联数虽然被 maxStream 封顶
//     （OpenPacket 漏查那一处已一并补上），1024 × 256 KiB 仍是 256 MiB。
//     "每条都有界"和"条数有界"这两个各自正确的决定，乘起来仍然是个大数——
//     这是本项目反复踩的同一类坑，所以再加一道硬顶。
const (
	maxDatagramQueue        = 512
	maxDatagramQueueBytes   = 256 << 10
	maxSessionDatagramBytes = 4 << 20
)

func (ps *PacketStream) deliver(d *Datagram) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.closed {
		return
	}
	n := len(d.Data)
	if n > maxDatagramQueueBytes {
		return // 单条就超预算：留着也只会把别人挤光
	}

	// 先按本关联的两个上界腾地方，丢最老的。
	for len(ps.queue) >= maxDatagramQueue || ps.queued+n > maxDatagramQueueBytes {
		ps.evictOldestLocked()
	}
	// 再看全会话预算。★ 腾的仍然是**自己**的最老那条，不去动别的关联：
	// 一来跨关联驱逐要跨锁，二来"谁在发谁就能回收自己的额度"意味着一条正在
	// 收数据的关联永远不会被别人饿死。全会话预算被别的关联占满时才丢新的——
	// 那时丢谁都是丢，而丢新的至少不会把已经排好的顺序打乱。
	for !ps.sess.reserveDatagram(n) {
		if len(ps.queue) == 0 {
			return
		}
		ps.evictOldestLocked()
	}

	ps.queue = append(ps.queue, d)
	ps.queued += n
	ps.lastActive.Store(time.Now().UnixNano())
	ps.cond.Signal()
}

// evictOldestLocked 丢掉队首并归还两级预算。调用方必须持有 ps.mu 且队列非空。
//
// ★ 摘掉队首之前必须把那个槽位置 nil。
//
// `q = q[1:]` 只是把视窗右移，被摘掉的那个 *Datagram **仍然被底层数组引用着**，
// 于是它连同它的载荷都无法被回收——而记账（dgramBytes / queued）已经把它减掉了。
// 结果是"账上是 0、内存还占着"，正是本仓库反复踩的那一类
// （乱序缓冲、抢跑暂存区都栽在"上界限的量不是真正涨的那个量"上）。
// Go 官方在 1.22 里把 slices.Delete 等改成 clear the tail，就是为了这件事。
func (ps *PacketStream) evictOldestLocked() {
	old := ps.queue[0]
	ps.queue[0] = nil
	ps.queue = ps.queue[1:]
	ps.queued -= len(old.Data)
	ps.sess.dgramBytes.Add(-int64(len(old.Data)))
}

// reserveDatagram 从全会话预算里划走 n 字节；不够就不划，返回 false。
// CAS 循环而不是先加后判：先加会让预算短暂越界，而越界的那一瞬间正是
// 攻击者要的——多条关联同时抢，"短暂"就变成"持续"。
func (s *Session) reserveDatagram(n int) bool {
	for {
		cur := s.dgramBytes.Load()
		if cur+int64(n) > maxSessionDatagramBytes {
			return false
		}
		if s.dgramBytes.CompareAndSwap(cur, cur+int64(n)) {
			return true
		}
	}
}

func (s *Session) onDatagram(f Frame) error {
	addr, n, err := parseSocksAddr(f.Payload)
	if err != nil {
		return nil // 坏数据报丢掉即可，不值得断会话
	}
	data := make([]byte, len(f.Payload)-n)
	copy(data, f.Payload[n:])
	d := &Datagram{Assoc: f.StreamID, Addr: addr, Data: data}

	st := s.stream(f.StreamID)
	if st != nil && st.pkt != nil {
		st.markOpenAcked()
		st.pkt.deliver(d)
		return nil
	}
	// 关联还没建好：**短暂**留住，等 STREAM_OPEN 追上来（见 holdEarlyDatagram）。
	s.holdEarlyDatagram(d)
	return nil
}

// ---------------------------------------------------------------------------
// 抢跑的数据报
// ---------------------------------------------------------------------------
//
// ★ 一条 UDP 关联的第一个数据报**理应**跑在它自己的 STREAM_OPEN 前面。
//
// 这不是竞态、也不是实现瑕疵，而是把不可靠数据面（RFC 9221 的 QUIC 数据报 /
// RFC 9297 的 HTTP Datagram）和可靠控制面（STREAM_OPEN 走流）混在一起的必然结果：
// 两者之间**没有任何顺序关系**。数据报不排队、不等流控、不等重传，
// 于是在任何有 RTT 的链路上，"先发的 STREAM_OPEN 后到"是常态而不是例外。
//
// 丢掉它的代价是隐形的：DNS 的第一个查询消失，应用要等自己的重传超时（通常 1 秒）；
// 被代理的 QUIC 第一个 Initial 消失，握手退避一轮。两者都**不报错**，
// 只表现为"每开一个新连接就卡一下"。
//
// RFC 9297 §5.2 对完全同构的问题（收到的 HTTP Datagram 其 Quarter Stream ID
// 指向一条尚未创建的流）给的处置就是两选一：静默丢弃，**或者**在一个 RTT 量级的
// 时间内暂存等待流建立。这里选后者，并且给足三重上界，避免它变成新的内存坑：
// 总字节、每关联条数、存活时长。
const (
	// earlyDatagramTTL 是"一个 RTT 量级"的具体取值。宁短勿长：
	// 留久了不会更正确（应用早就自己重传了），只会让攻击面变大。
	earlyDatagramTTL = time.Second
	// earlyDatagramPerAssoc 是单个关联最多暂存几个。一次 DNS 查询是 1 个，
	// 一个 QUIC Initial 突发也就几个，超过说明对端在乱发。
	earlyDatagramPerAssoc = 8
	// earlyDatagramAssocs 是同时能有几个关联处于"数据报已到、STREAM_OPEN 未到"。
	// ★ 光有字节上界不够：每条暂存记录除了载荷还有 map 表项、slice、
	//   Datagram 结构与地址字符串，合计一两百字节且**与载荷长度无关**。
	//   只限字节的话，对端拿 1 字节的数据报配上不同的流号，就能用 256 KiB 的
	//   记账额度换到几十 MB 的真实占用——和 stream.go 里 reorderSegOverhead
	//   记的是同一类错误：上界限的量不是真正涨的那个量。
	earlyDatagramAssocs = 64
	// earlyDatagramBytes 是整个会话暂存区的字节上界。限条数不够，单帧可以有 56 KiB，
	// 所以两个上界缺一不可。
	earlyDatagramBytes = 256 << 10
)

type earlyDatagrams struct {
	expires time.Time
	dgrams  []*Datagram
}

// holdEarlyDatagram 暂存一个还没有归属的数据报。
func (s *Session) holdEarlyDatagram(d *Datagram) {
	s.earlyMu.Lock()
	defer s.earlyMu.Unlock()

	now := time.Now()
	s.sweepEarlyLocked(now)

	if s.earlyBytes+len(d.Data) > earlyDatagramBytes {
		return // 暂存区满：按 UDP 的规矩丢掉，不扩容
	}
	e := s.early[d.Assoc]
	if e == nil {
		if len(s.early) >= earlyDatagramAssocs {
			return // 待建关联太多：丢，不扩容
		}
		if s.early == nil {
			s.early = make(map[uint64]*earlyDatagrams)
		}
		e = &earlyDatagrams{}
		s.early[d.Assoc] = e
	}
	// 每次续期：同一个关联持续抢跑说明它确实还在等 STREAM_OPEN。
	e.expires = now.Add(earlyDatagramTTL)
	if len(e.dgrams) >= earlyDatagramPerAssoc {
		s.earlyBytes -= len(e.dgrams[0].Data)
		e.dgrams[0] = nil       // 不置 nil 的话底层数组还引用着它，回收不掉
		e.dgrams = e.dgrams[1:] // 丢最老的：陈旧的 UDP 比新鲜的更没价值
	}
	e.dgrams = append(e.dgrams, d)
	s.earlyBytes += len(d.Data)
}

// releaseEarlyDatagrams 在关联建好后把暂存的数据报按原序交付。
// 由 onStreamOpen 在 st.pkt 装好、流已入表之后调用。
func (s *Session) releaseEarlyDatagrams(st *Stream) {
	s.earlyMu.Lock()
	e := s.early[st.id]
	if e != nil {
		delete(s.early, st.id)
		for _, d := range e.dgrams {
			s.earlyBytes -= len(d.Data)
		}
	}
	s.sweepEarlyLocked(time.Now())
	s.earlyMu.Unlock()

	if e == nil || st.pkt == nil {
		return
	}
	for _, d := range e.dgrams {
		st.pkt.deliver(d)
	}
}

// earlyHeld 返回暂存区里的数据报条数，供自检与测试。
func (s *Session) earlyHeld() int {
	s.earlyMu.Lock()
	defer s.earlyMu.Unlock()
	n := 0
	for _, e := range s.early {
		n += len(e.dgrams)
	}
	return n
}

// sweepEarlyLocked 清掉过期条目。惰性清理，不额外起 timer——
// 暂存区只在有数据报抢跑时才被碰，没人碰就没有需要清的东西。
func (s *Session) sweepEarlyLocked(now time.Time) {
	for id, e := range s.early {
		if now.After(e.expires) {
			for _, d := range e.dgrams {
				s.earlyBytes -= len(d.Data)
			}
			delete(s.early, id)
		}
	}
}
