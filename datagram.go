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
	// 服务端侧：关联由 STREAM_OPEN(kind=1) 建立，PacketStream 挂在流上。
	// 走到这里说明关联还没建好或已经关了，丢弃。
	select {
	case s.dgramCh <- d:
	default:
	}
	return nil
}
