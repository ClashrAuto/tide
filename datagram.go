package tide

import (
	"context"
	"net"
	"sync"
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
	closed bool
	rdl    time.Time
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
	ps := &PacketStream{st: st, sess: s}
	ps.cond = sync.NewCond(&ps.mu)
	return ps
}

// WriteTo 发一个数据报。
//
// UDP **不做重传也不进重传缓冲**：它本来就是不可靠的，硬给它加可靠性会改变
// 上层协议（QUIC、DNS、游戏）自己的拥塞与超时行为，通常比丢包更糟。
// 路径切换期间丢掉的数据报就是丢了——这与在真实网络上丢包没有区别，
// 上层应用早就为此做好了准备。
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
	ps.queue = ps.queue[1:]
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
	ps.mu.Lock()
	if ps.closed {
		ps.mu.Unlock()
		return nil
	}
	ps.closed = true
	ps.cond.Broadcast()
	ps.mu.Unlock()
	return ps.st.Close()
}

func (ps *PacketStream) LocalAddr() net.Addr { return ps.sess.LocalAddr() }

// Assoc 返回关联标识。
func (ps *PacketStream) Assoc() uint64 { return ps.st.id }

// maxDatagramQueue：单个关联最多排多少个未读数据报。
// 满了就丢最老的——UDP 的语义下，一个陈旧的数据报比一个新的更没价值，
// 而无上界排队会在应用读得慢时把内存吃光。
const maxDatagramQueue = 512

func (ps *PacketStream) deliver(d *Datagram) {
	ps.mu.Lock()
	if ps.closed {
		ps.mu.Unlock()
		return
	}
	if len(ps.queue) >= maxDatagramQueue {
		ps.queue = ps.queue[1:]
	}
	ps.queue = append(ps.queue, d)
	ps.cond.Signal()
	ps.mu.Unlock()
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
