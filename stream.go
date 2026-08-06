package tide

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Stream 是会话内的一条应用层字节流，对应一个被代理的 TCP 连接。实现 net.Conn。
//
// ★ 为什么这里要重新实现一遍可靠传输（绝对偏移 + 累积 ACK + 重传缓冲），
// 明明底下的 TCP/QUIC 已经是可靠的了？
//
// 因为"可靠"是**每条路径**的属性，而会话要活得比路径长。路径死掉的那一刻，
// 内核发送队列里已经被 TCP ACK 过、但还没到达对端应用层的字节全部消失，
// 且本端无从知道丢了哪些——TCP 的 ACK 只保证到达内核，不保证到达对端应用。
// 没有会话级的偏移与 ACK，一次 Wi-Fi 切换就会让每条流的中间凭空少掉一段字节，
// 表现为"网页加载到一半卡住"或"下载文件校验和不对"，而且不会有任何报错。
//
// 代价是发送方要缓存 [ackedOff, sendOff) 这段未确认字节（上限 = 流窗口），
// 以及每 ackThreshold 字节一个小 ACK 帧。这是无缝迁移的真实价格。
type Stream struct {
	id   uint64
	sess *Session
	dst  string // 目标地址，仅日志用

	// ---- 发送侧 ----
	wmu     sync.Mutex
	wcond   *sync.Cond
	sendOff uint64 // 已交付给协议栈的下一个偏移
	ackOff  uint64 // 对端已连续确认到的偏移
	// retx 保存 [ackOff, sendOff) 的字节。迁移时从 ackOff 起整段重发。
	retx []byte
	// pendOff 是"下一个待发送到线上的偏移"。正常等于 sendOff；
	// 路径切换时被回退到 ackOff，于是 pump() 会自动把这段重发一遍。
	pendOff    uint64
	peerMaxOff uint64 // 对端通告的可接收上界（流控）
	sentFin    bool
	wErr       error

	// ---- 接收侧 ----
	rmu      sync.Mutex
	rcond    *sync.Cond
	recvOff  uint64 // 已连续收到的偏移
	recvBuf  []byte // 连续、待 Read 走的数据
	reorder  map[uint64][]byte
	reorderN int
	gotFin   bool
	finOff   uint64
	rErr     error
	ackedAdv uint64 // 上次通告出去的 ackOff
	window   uint64

	// ---- 路径亲和 ----
	pathID    atomic.Uint32
	bytesSent atomic.Uint64

	// ---- 重连/重传所需的状态 ----
	// initiator: 本端开的流。只有开流方需要在重连后补发 STREAM_OPEN——
	// 被动方的流本来就是对端告知才存在的。
	initiator   bool
	udp         bool
	pkt         *PacketStream
	openPayload []byte
	openAcked   atomic.Bool
	// lastProgress: 最后一次 ackOff 前进的时刻。RTO 判据看的是它，
	// 而不是"最后一次发送时间"——发得再多，对端没确认就等于没进展。
	lastProgress atomic.Int64
	lastRewind   atomic.Int64
	// migrateVotes 由 Session.rebalance 在 s.mu 下读写（和 streams map 同一把锁），
	// 所以是普通字段而不是 atomic。
	migrateVotes int
	created      time.Time

	readDL, writeDL atomic.Int64 // UnixNano，0 = 无
	closeOnce       sync.Once
	closed          atomic.Bool
	// ackBusy：这条流当前是否已有一个协程在写 ACK。见 scheduleAck。
	ackBusy atomic.Bool
}

func newStream(s *Session, id uint64, dst string, window uint64) *Stream {
	st := &Stream{
		id:      id,
		sess:    s,
		dst:     dst,
		reorder: make(map[uint64][]byte),
		window:  window,
		created: time.Now(),
		// 对端窗口的初值：在收到对方第一个 STREAM_ACK 之前只敢发这么多。
		// 64 KiB 足以覆盖绝大多数请求的首包，又不会在对端窗口其实更小时溢出。
		peerMaxOff: 64 * 1024,
	}
	st.wcond = sync.NewCond(&st.wmu)
	st.rcond = sync.NewCond(&st.rmu)
	st.lastProgress.Store(st.created.UnixNano())
	return st
}

// markOpenAcked 记下"对端确实知道这条流存在"。任何一个针对本流的帧都算证据——
// 不需要专门的 OPEN_ACK 帧。
func (st *Stream) markOpenAcked() { st.openAcked.Store(true) }

func (st *Stream) needsOpenResend() bool {
	return st.initiator && !st.openAcked.Load() && st.openPayload != nil
}

func (st *Stream) finPending() bool {
	st.wmu.Lock()
	defer st.wmu.Unlock()
	return st.sentFin
}

// stalledFor 判断这条流是不是卡住了：有未确认字节（或开流帧还没被认），
// 且超过一个 RTO 没有任何进展。
func (st *Stream) stalledFor(now time.Time, rto time.Duration) bool {
	st.rmu.Lock()
	failed := st.rErr != nil
	st.rmu.Unlock()
	if failed {
		return false
	}
	last := time.Unix(0, st.lastProgress.Load())
	if now.Sub(last) < rto {
		return false
	}
	// 刚回退过就先等等，别把重发变成风暴。
	if lr := st.lastRewind.Load(); lr != 0 && now.Sub(time.Unix(0, lr)) < rto {
		return false
	}
	if st.needsOpenResend() {
		return true
	}
	st.wmu.Lock()
	inflight := st.sendOff > st.ackOff
	st.wmu.Unlock()
	return inflight
}

func (st *Stream) noteRewind(now time.Time) { st.lastRewind.Store(now.UnixNano()) }

// ackThreshold：累积多少字节就回一个 ACK。
// 32 KiB 在"ACK 帧开销"与"发送方重传缓冲占用"之间取平衡：太大则发送方缓冲长期打满、
// 迁移时要重发更多；太小则小包泛滥，反而给分类器提供节奏特征。
const ackThreshold = 32 * 1024

// ---------------------------------------------------------------------------
// net.Conn
// ---------------------------------------------------------------------------

func (st *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	st.rmu.Lock()
	defer st.rmu.Unlock()

	for len(st.recvBuf) == 0 {
		if st.rErr != nil {
			return 0, st.rErr
		}
		if st.gotFin && st.recvOff >= st.finOff {
			return 0, io.EOF
		}
		if dl := st.readDL.Load(); dl != 0 {
			if time.Now().UnixNano() >= dl {
				return 0, os_ErrDeadline
			}
			st.armDeadline(&st.rmu, st.rcond, dl)
		}
		st.rcond.Wait()
	}
	n := copy(p, st.recvBuf)
	st.recvBuf = st.recvBuf[n:]
	if len(st.recvBuf) == 0 {
		st.recvBuf = nil
	}
	st.maybeAckLocked(false)
	return n, nil
}

func (st *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := st.writeChunk(p)
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (st *Stream) writeChunk(p []byte) (int, error) {
	st.wmu.Lock()
	for {
		if st.wErr != nil {
			err := st.wErr
			st.wmu.Unlock()
			return 0, err
		}
		if st.sentFin {
			st.wmu.Unlock()
			return 0, ErrStreamClosed
		}
		// 两道闸：对端通告的接收上界，以及本端重传缓冲的容量。
		// 后者是内存的硬约束——没有它，一条卡住的路径能让重传缓冲无限增长。
		avail := int64(st.peerMaxOff) - int64(st.sendOff)
		if cap := int64(st.window) - int64(st.sendOff-st.ackOff); cap < avail {
			avail = cap
		}
		if avail > 0 {
			n := len(p)
			if int64(n) > avail {
				n = int(avail)
			}
			if n > MaxPayload {
				n = MaxPayload
			}
			st.retx = append(st.retx, p[:n]...)
			st.sendOff += uint64(n)
			st.wmu.Unlock()
			st.bytesSent.Add(uint64(n))
			st.pump()
			return n, nil
		}
		if dl := st.writeDL.Load(); dl != 0 {
			if time.Now().UnixNano() >= dl {
				st.wmu.Unlock()
				return 0, os_ErrDeadline
			}
			st.armDeadline(&st.wmu, st.wcond, dl)
		}
		st.wcond.Wait()
	}
}

// armDeadline 起一个一次性定时器在 deadline 时唤醒 cond，避免 Wait 永久挂住。
func (st *Stream) armDeadline(mu *sync.Mutex, c *sync.Cond, deadlineNano int64) {
	d := time.Until(time.Unix(0, deadlineNano))
	if d <= 0 {
		d = time.Millisecond
	}
	time.AfterFunc(d, func() {
		mu.Lock()
		c.Broadcast()
		mu.Unlock()
	})
}

func (st *Stream) Close() error {
	st.closeOnce.Do(func() {
		st.closed.Store(true)
		st.wmu.Lock()
		fin := !st.sentFin
		st.sentFin = true
		finOff := st.sendOff
		st.wmu.Unlock()
		if fin {
			var buf []byte
			buf = AppendVarint(buf, finOff)
			st.sess.sendOnStream(st, FrameStreamFin, 0, buf)
		}
		st.failWrite(ErrStreamClosed)
		st.sess.removeStream(st.id)
	})
	return nil
}

// CloseWrite 只关半边（对应 TCP 的 shutdown(SHUT_WR)）。
func (st *Stream) CloseWrite() error {
	st.wmu.Lock()
	if st.sentFin {
		st.wmu.Unlock()
		return nil
	}
	st.sentFin = true
	finOff := st.sendOff
	st.wmu.Unlock()
	var buf []byte
	buf = AppendVarint(buf, finOff)
	return st.sess.sendOnStream(st, FrameStreamFin, 0, buf)
}

func (st *Stream) LocalAddr() net.Addr  { return st.sess.LocalAddr() }
func (st *Stream) RemoteAddr() net.Addr { return streamAddr(st.dst) }

func (st *Stream) SetDeadline(t time.Time) error {
	st.SetReadDeadline(t)
	return st.SetWriteDeadline(t)
}

func (st *Stream) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		st.readDL.Store(0)
	} else {
		st.readDL.Store(t.UnixNano())
	}
	st.rmu.Lock()
	st.rcond.Broadcast()
	st.rmu.Unlock()
	return nil
}

func (st *Stream) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		st.writeDL.Store(0)
	} else {
		st.writeDL.Store(t.UnixNano())
	}
	st.wmu.Lock()
	st.wcond.Broadcast()
	st.wmu.Unlock()
	return nil
}

// ID 返回流号（自检与日志用）。
func (st *Stream) ID() uint64 { return st.id }

type streamAddr string

func (a streamAddr) Network() string { return "tide" }
func (a streamAddr) String() string  { return string(a) }

// deadlineError 实现 net.Error，让上层的 `if ne, ok := err.(net.Error); ok && ne.Timeout()`
// 这类惯用判断照常工作——代理链路上到处都是这种判断，返回一个普通 error 会让
// 超时被当成永久失败处理。
type deadlineError struct{}

func (deadlineError) Error() string   { return "tide: i/o deadline exceeded" }
func (deadlineError) Timeout() bool   { return true }
func (deadlineError) Temporary() bool { return true }

var os_ErrDeadline net.Error = deadlineError{}

var _ = errors.Is

// ---------------------------------------------------------------------------
// 发送泵
// ---------------------------------------------------------------------------

// pump 把 [pendOff, sendOff) 这段还没上线的字节切成帧交给当前路径。
// 迁移后 pendOff 被回退，于是同一段字节会在新路径上重发一遍——
// 接收方按绝对偏移去重，重复部分直接丢弃。
func (st *Stream) pump() {
	for {
		st.wmu.Lock()
		if st.wErr != nil || st.pendOff >= st.sendOff {
			st.wmu.Unlock()
			return
		}
		base := st.pendOff - st.ackOff
		end := st.sendOff - st.ackOff
		n := end - base
		if n > MaxPayload {
			n = MaxPayload
		}
		off := st.pendOff
		chunk := make([]byte, n)
		copy(chunk, st.retx[base:base+n])
		st.pendOff += n
		st.wmu.Unlock()

		payload := make([]byte, 0, VarintLen(off)+len(chunk))
		payload = AppendVarint(payload, off)
		payload = append(payload, chunk...)
		if err := st.sess.sendOnStream(st, FrameStreamData, 0, payload); err != nil {
			// 发送失败意味着当前路径没了。把 pendOff 退回去，等新路径接管后重发。
			// 这一步是"路径死亡对上层不可见"的全部秘密。
			st.wmu.Lock()
			if st.pendOff > off {
				st.pendOff = off
			}
			st.wmu.Unlock()
			return
		}
	}
}

// rewind 由路径切换/重连触发：把待发指针退回到最后一个被确认的偏移。
func (st *Stream) rewind() {
	st.wmu.Lock()
	st.pendOff = st.ackOff
	st.wmu.Unlock()
	go st.pump()
}

// ---------------------------------------------------------------------------
// 接收处理
// ---------------------------------------------------------------------------

// reorderSegOverhead 是一个乱序段除了自身字节之外的固定占用：
// map 表项 + slice 头 + 一次独立的小块堆分配。**与段长无关**。
//
// ★ 这个数不是估的，是量的（TestReorderBufferFootprint 每次跑都在重量）：
// 1 / 8 / 64 / 1024 字节的段，每段实际占用减去载荷都落在 ~80 字节。
//
// 为什么必须把它算进窗口：窗口的意思是"这条流的乱序缓冲最多吃多少内存"。
// 只累加载荷字节的话，这句话在段很小的时候就是假的——实测 1 字节段能让
// reorderN 报 512 KiB 而真实堆占用 42.5 MB（**81 倍**），乘上 MaxStreams=1024
// 就是几十 GB。对端只要把 STREAM_DATA 拆成 1 字节一段、段间留空洞永远接不上，
// 就能在完全合法的流控之内把接收方撑爆。
//
// 代价可以忽略：真实的乱序段是 MTU 量级（~1400 字节），80 字节的记账开销是 5.7%。
const reorderSegOverhead = 80

func reorderCost(n int) int { return n + reorderSegOverhead }

func (st *Stream) onData(off uint64, data []byte) error {
	st.rmu.Lock()
	defer st.rmu.Unlock()

	end := off + uint64(len(data))
	if end <= st.recvOff {
		return nil // 迁移后的重复段，正常现象
	}
	if off > st.recvOff {
		// 乱序：只可能发生在跨路径迁移的窗口期，正常路径内 TCP/QUIC 已经保序。
		if uint64(st.reorderN)+uint64(reorderCost(len(data))) > st.window {
			// 超出窗口的乱序段直接丢弃，让发送方重传。缓冲无上界是内存炸弹，
			// 而重传的代价有界。
			return nil
		}
		if _, dup := st.reorder[off]; !dup {
			cp := make([]byte, len(data))
			copy(cp, data)
			st.reorder[off] = cp
			st.reorderN += reorderCost(len(data))
		}
		return nil
	}
	// off <= recvOff < end：取尾部有用的一段
	st.appendLocked(data[st.recvOff-off:])
	st.drainReorderLocked()
	st.maybeAckLocked(false)
	st.rcond.Broadcast()
	return nil
}

func (st *Stream) appendLocked(b []byte) {
	if uint64(len(st.recvBuf))+uint64(len(b)) > st.window*2 {
		// 只可能是对端无视流控。断流比无限吃内存好。
		st.rErr = ErrFlowControl
		return
	}
	st.recvBuf = append(st.recvBuf, b...)
	st.recvOff += uint64(len(b))
}

func (st *Stream) drainReorderLocked() {
	for {
		seg, ok := st.reorder[st.recvOff]
		if !ok {
			return
		}
		delete(st.reorder, st.recvOff)
		st.reorderN -= reorderCost(len(seg))
		st.appendLocked(seg)
	}
}

// maybeAckLocked 在累计到阈值或被强制时回一个 STREAM_ACK。
// 必须在 rmu 持有时调用。
//
// ★ 这里**只登记，不发送**。发送交给 scheduleAck 起的那个临时协程。
//
// 原先是在这里直接 sendOnStream 的，旁边还留着一句"在 rmu 内直接发是安全的：
// sendOnStream 不会回调进接收侧"——那句话本身没错，但它防的是**重入**，
// 而真正的危险是**阻塞**，两者毫无关系。这条路径是从 readLoop 里下来的
// （handleFrame → onData/onFin → forceAck），于是：
//
//	pump 拿着这条流的写锁，堵在 quic-go 的流控里等对端开窗；
//	readLoop 想发 ACK，去抢同一把写锁，堵住；
//	而对端要开窗，恰恰得靠这个 readLoop 继续把数据读走。
//
// 两端对称，于是整条会话彻底卡死——实测在一次 -race 全量跑里卡了 9 分 33 秒，
// 直到测试框架超时才被发现。
//
// ★ 根因是两条数据面的形状不一致。TCP 路径的 writeFrame 只把帧追加进 p.wbuf
// 再 Signal 一下，真正的 conn.Write 在独立的 writeLoop 协程里，所以它**从不阻塞**；
// quicMux.write 却是在持锁的情况下直接调 quic-go 的 Stream.Write。
// 同一个 writeFrame 入口，一条路径上不阻塞、另一条阻塞——调用方（这里）
// 按前者的直觉写，就踩中了后者。
//
// 处置照 Go 官方 net/http2 服务端的做法：**serve/read 协程绝不阻塞在写上**。
// 那边的原话是 writeFrame"排一帧、不施加反压——阻塞的是 handler，不是 serve 协程"；
// 控制帧一律经通道交给别的协程写。这里同构：readLoop 只做一次原子置位，
// 真正的写留给别的协程，它堵住也不影响读侧继续排空。
func (st *Stream) maybeAckLocked(force bool) {
	if !force && st.recvOff-st.ackedAdv < ackThreshold {
		return
	}
	st.scheduleAck()
}

// forceAck 供 FIN、迁移完成等需要立刻同步状态的时机。
func (st *Stream) forceAck() { st.scheduleAck() }

// scheduleAck 交代"这条流该发 ACK 了"，然后立刻返回。
//
// ★ 每条流各自一个临时协程，而**不是**全会话共用一个发送协程。
// 共用的话，一条卡在流控里的流会把其它所有流的 ACK 一起压住——
// 那正是"每条 TIDE 流一条独立 QUIC 流"要消除的队头阻塞（spec §12.5），
// 在发送侧原样重建一遍就白分了。
//
// ackBusy 保证一条流同时最多一个协程在写，所以协程数有界（≤ 并发流上限），
// 且 ACK 是累积量，同一条流并发发两个也无害。
func (st *Stream) scheduleAck() {
	if st.ackBusy.Swap(true) {
		return // 已经有协程在写这条流的 ACK，它写完会自己再看一眼
	}
	go st.ackFlushLoop()
}

func (st *Stream) ackFlushLoop() {
	for {
		st.flushAck()
		st.ackBusy.Store(false)
		// 写的这段时间里又来了新数据？自己接着发，别指望下一帧来触发——
		// 对端可能正等着这个 ACK 才敢继续发，没有"下一帧"。
		st.rmu.Lock()
		more := st.recvOff != st.ackedAdv
		st.rmu.Unlock()
		if !more {
			return
		}
		if st.ackBusy.Swap(true) {
			return // 别人接手了
		}
	}
}

// flushAck 现算一个 STREAM_ACK 并发出去。只由 ackFlushLoop 调用。
//
// ⚠️ 算完就把 rmu 放掉，**绝不能带着 rmu 去写**：onData 也要 rmu，
// 带着锁写就等于把刚从 readLoop 挪走的那个死锁原样挪到 rmu 上。
func (st *Stream) flushAck() {
	st.rmu.Lock()
	ack := st.recvOff
	// 通告上界 = 已连续接收 + 剩余缓冲空间。读得慢的应用会自然把窗口压小，
	// 反压一路传回发送端，而不是让中间缓冲无限膨胀。
	free := int64(st.window) - int64(len(st.recvBuf)) - int64(st.reorderN)
	if free < 0 {
		free = 0
	}
	maxOff := ack + uint64(free)
	st.ackedAdv = ack
	st.rmu.Unlock()

	payload := make([]byte, 0, 16)
	payload = AppendVarint(payload, ack)
	payload = AppendVarint(payload, maxOff)
	st.sess.sendOnStream(st, FrameStreamAck, 0, payload)
}

func (st *Stream) onAck(ack, maxOff uint64) {
	st.wmu.Lock()
	if ack > st.sendOff {
		st.wmu.Unlock()
		return // 对端确认了没发过的字节：协议违规，忽略
	}
	if ack > st.ackOff {
		st.retx = st.retx[ack-st.ackOff:]
		st.ackOff = ack
		if st.pendOff < st.ackOff {
			st.pendOff = st.ackOff
		}
		st.lastProgress.Store(time.Now().UnixNano())
	}
	if maxOff > st.peerMaxOff {
		st.peerMaxOff = maxOff
	}
	st.wcond.Broadcast()
	st.wmu.Unlock()
}

func (st *Stream) onFin(finOff uint64) {
	st.rmu.Lock()
	st.gotFin = true
	if finOff > st.finOff {
		st.finOff = finOff
	}
	st.rcond.Broadcast()
	st.rmu.Unlock()
	st.endAssoc()
	st.forceAck()
}

func (st *Stream) onReset(code StreamError) {
	st.fail(code)
}

func (st *Stream) fail(err error) {
	st.rmu.Lock()
	if st.rErr == nil {
		st.rErr = err
	}
	st.rcond.Broadcast()
	st.rmu.Unlock()
	st.failWrite(err)
	st.endAssoc()
}

// endAssoc 结束这条流承载的 UDP 关联（如果它是一条关联的话）。
//
// ★ RFC 1928 早就把这件事定死了：UDP 关联在承载 ASSOCIATE 请求的那条 TCP 连接
// 终止时终止。TIDE 里关联本来就**是**一条流，那就该是"流结束 = 关联结束"。
//
// 少了这一步，对端关掉关联时本端只收到一个 STREAM_FIN，而 onFin 从前只置了个
// gotFin 标志——PacketStream.ReadFrom 根本不看它。于是 DefaultPacketHandler
// 永远堵在 ReadFrom 上，连同它的 UDP socket 和那条流的计数一起留着。
// TCP 流没这个问题只是因为它的 handler 走 io.Copy，读到 EOF 自己就 Close 了；
// UDP 这条路上根本没有 EOF 这个概念。
//
// 后果是累积的，而且现象与原因毫无关联：一条长命会话每做一次 DNS 查询漏一条，
// 攒够并发流上限之后**连 TCP 流都开不出来**（上限是共用的），
// 用户看到的只是"用着用着就连不上了"。
func (st *Stream) endAssoc() {
	if st.pkt != nil {
		st.pkt.closeQueue()
	}
}

func (st *Stream) failWrite(err error) {
	st.wmu.Lock()
	if st.wErr == nil {
		st.wErr = err
	}
	st.wcond.Broadcast()
	st.wmu.Unlock()
}

// isBulk 判断这条流该不该被迁到 QUIC 路径（spec §8：批量流迁走，交互流留在 TCP）。
func (st *Stream) isBulk() bool { return st.bytesSent.Load() >= bulkThreshold }
