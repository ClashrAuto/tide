package tide

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Session 是由 Session ID 标识的逻辑连接，**独立于任何一条路径存在**。
//
// 这一条是整个设计的地基：会话密钥、流状态、身份都不绑定到某条 TCP/QUIC 连接，
// 于是多路径、无缝迁移、0-RTT 全都从这里派生。反过来说，网络波动下的稳定性
// 也全都落在这个结构体上——路径来来去去，Session 得一直在。
type Session struct {
	id       [16]byte
	isClient bool
	user     [16]byte

	bare   bool
	useAES bool
	c2sKey []byte
	s2cKey []byte

	window    uint64
	grace     time.Duration
	probeIvl  time.Duration
	maxStream int

	mu       sync.Mutex
	paths    []*path
	nextPath uint32
	streams  map[uint64]*Stream
	nextSID  uint64
	pathCond *sync.Cond

	acceptCh chan *Stream

	// early 暂存"比自己的 STREAM_OPEN 先到"的数据报，见 datagram.go 的 holdEarlyDatagram。
	earlyMu    sync.Mutex
	early      map[uint64]*earlyDatagrams
	earlyBytes int

	// redial 由客户端注入：在所有路径都死掉后重新拨一条并加入本会话。
	// 服务端为 nil——服务端不能主动连客户端，只能在宽限期里等对方回来。
	redial func(ctx context.Context, s *Session) (*path, error)

	// onOpen 由服务端注入：收到 STREAM_OPEN 时去连目标。
	localAddr net.Addr

	noPathSince atomic.Int64 // 最后一条路径消失的时刻（UnixNano），0 = 当前有路径
	reconnBusy  atomic.Bool
	streamCount atomic.Int64
	// pathsAdded 是累计接入过多少条路径。测试靠它确认"恢复机制真的被触发了"——
	// 环回网络上重连快到看不见，一个只测了 happy path 的稳定性测试比没有更糟。
	pathsAdded atomic.Uint64
	// deadLog 留着最近几条路径的死因。路径死了就从 paths 里摘掉，
	// 死因也跟着消失——而"反复建起来又死"恰恰只能靠死因序列来查。
	deadLog deathLog

	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error

	// 客户端票据钱包，重连时用来做 0-RTT。
	wallet *ticketWallet
	// ticketNeed 由 handleFrame 置位，重连循环消费。
	ticketLow atomic.Bool
	// onTicketReq 由服务端注入：客户端票据见底时补发一批。
	onTicketReq func()
}

func newSession(id [16]byte, isClient bool, window uint64, grace, probeIvl time.Duration, maxStreams int) *Session {
	s := &Session{
		id:        id,
		isClient:  isClient,
		window:    window,
		grace:     grace,
		probeIvl:  probeIvl,
		maxStream: maxStreams,
		streams:   make(map[uint64]*Stream),
		acceptCh:  make(chan *Stream, 64),
		closed:    make(chan struct{}),
	}
	s.pathCond = sync.NewCond(&s.mu)
	// 流号奇偶分家（同 HTTP/2）：客户端用奇数、服务端用偶数，
	// 双方可以同时开流而不需要任何协商。
	if isClient {
		s.nextSID = 1
	} else {
		s.nextSID = 2
	}
	return s
}

// ID 返回会话标识。
func (s *Session) ID() [16]byte { return s.id }

// LocalAddr 返回当前主路径的本地地址；无路径时返回一个占位值。
func (s *Session) LocalAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.paths) > 0 {
		return s.paths[0].conn.LocalAddr()
	}
	if s.localAddr != nil {
		return s.localAddr
	}
	return streamAddr("tide")
}

func (s *Session) activeStreams() int { return int(s.streamCount.Load()) }

// Done 在会话彻底结束后关闭。
func (s *Session) Done() <-chan struct{} { return s.closed }

// ---------------------------------------------------------------------------
// 路径集合
// ---------------------------------------------------------------------------

func (s *Session) addPath(p *path) {
	s.mu.Lock()
	s.paths = append(s.paths, p)
	s.mu.Unlock()
	s.noPathSince.Store(0)
	s.pathsAdded.Add(1)

	go p.readLoop()
	go p.writeLoop()
	go p.probeLoop(s.probeIvl, DefaultIdleProbeInterval)

	// 新路径到位：把所有流的待发指针退回最后确认点，未确认的字节在新路径上重来一遍。
	// 接收方按绝对偏移去重，所以重发是幂等的。
	s.rewindAll()

	s.mu.Lock()
	s.pathCond.Broadcast()
	s.mu.Unlock()
}

func (s *Session) onPathDead(p *path) {
	s.deadLog.add(p.kind + "#" + itoa(int(p.id)) + " " + p.DeadReason())
	s.mu.Lock()
	for i, q := range s.paths {
		if q == p {
			s.paths = append(s.paths[:i], s.paths[i+1:]...)
			break
		}
	}
	left := len(s.paths)
	s.mu.Unlock()

	if left > 0 {
		// 还有别的路径：把钉在这条上的流全部重新指派并重发未确认段。
		// 用户看到的只是一个 RTT 的停顿。
		s.reassignFrom(p.id)
		return
	}
	if s.noPathSince.CompareAndSwap(0, time.Now().UnixNano()) {
		go s.recoverLoop()
	}
}

func (s *Session) onPathState(p *path, from, to pathState) {
	if to == pathDegraded || to == pathSuspect {
		// 这条路径变差了：批量流迁到更好的路径上去，交互流留着——
		// QUIC 的优势在丢包下的批量吞吐，不在小包延迟，把交互流也迁走反而更糟。
		s.migrateBulkAway(p)
	}
}

// pickPath 为一条流选路径。已有亲和且路径仍可用就不动——
// 跨路径乱序的开销比多几毫秒延迟贵。
func (s *Session) pickPath(st *Stream) *path {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pickPathLocked(st)
}

func (s *Session) pickPathLocked(st *Stream) *path {
	if st != nil {
		if id := st.pathID.Load(); id != 0 {
			for _, p := range s.paths {
				// holdable 而不是 usable：一次探测抖动不该把一条正在传输的流
				// 从好路径上赶到差路径上，见 path.holdable 的说明。
				if p.id == id && p.holdable() {
					return p
				}
			}
		}
	}
	var best *path
	bestScore := 0.0
	for _, p := range s.paths {
		if !p.usable() {
			continue
		}
		sc := p.score()
		if st != nil && st.isBulk() && p.kind == "quic" {
			// 批量流偏好 QUIC：同分时优先，不是无脑覆盖。
			sc *= 0.8
		}
		if st != nil && !st.isBulk() && p.kind == "tcp" {
			sc *= 0.8
		}
		if best == nil || sc < bestScore {
			best, bestScore = p, sc
		}
	}
	if best == nil {
		// 全都不可用时退而求其次：suspect 也比没有强，反正数据能不能到由 ACK 判定。
		for _, p := range s.paths {
			if p.State() != pathDead {
				best = p
				break
			}
		}
	}
	if best != nil && st != nil {
		st.pathID.Store(best.id)
	}
	return best
}

func (s *Session) reassignFrom(deadID uint32) {
	s.mu.Lock()
	sts := make([]*Stream, 0, len(s.streams))
	for _, st := range s.streams {
		if st.pathID.Load() == deadID {
			st.pathID.Store(0)
			sts = append(sts, st)
		}
	}
	s.mu.Unlock()
	for _, st := range sts {
		s.resumeStream(st)
	}
}

func (s *Session) migrateBulkAway(bad *path) {
	s.mu.Lock()
	var alt *path
	for _, p := range s.paths {
		if p != bad && p.State() == pathActive {
			if alt == nil || p.score() < alt.score() {
				alt = p
			}
		}
	}
	if alt == nil {
		s.mu.Unlock()
		return
	}
	var moved []*Stream
	for _, st := range s.streams {
		if st.pathID.Load() == bad.id && st.isBulk() {
			st.pathID.Store(alt.id)
			moved = append(moved, st)
		}
	}
	s.mu.Unlock()

	for _, st := range moved {
		// 显式声明迁移（spec §8）。接收方靠绝对偏移就能正确重组，
		// 这个帧的作用是让对端知道"接下来这条流换路了"，便于日志与它自己的调度。
		var buf []byte
		st.wmu.Lock()
		buf = AppendVarint(buf, st.ackOff)
		st.wmu.Unlock()
		alt.writeFrame(FramePathMigrate, FlagPush, st.id, buf)
		st.rewind()
	}
}

// rebalanceLoop 周期性地把流挪到当下最好的那条路径上。
//
// ★ 为什么不能只靠 onPathState 的事件触发（那是最初的实现，实测被证伪）：
// 事件触发依赖 pathDegraded，而 pathDegraded 依赖丢包估计，而丢包估计在 TCP 路径上
// 恒为 0（原因见 path.score() 的注释）。结果就是 QUIC 路径建起来了、评分好 35 倍，
// 却一个字节都拿不到——实测 tx=0.1MiB vs TCP 的 52.2MiB。
// 迁移判据必须建立在**能观测到的量**上，也就是路径之间的相对评分。
func (s *Session) rebalanceLoop() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-t.C:
		}
		s.rebalance()
	}
}

// migrateAdvantage：目标路径必须好这么多倍才值得迁。
// 迁移不是免费的——未确认的字节要在新路径上重发一遍，而且两条路径的
// 拥塞窗口都要重新长起来。2 倍的门槛保证只有真正显著的差距才会触发。
const migrateAdvantage = 2.0

// migrateDecisive：差距大到这个倍数就不必等滞回票数了。
const migrateDecisive = 5.0

// migrateVotesNeeded：连续几次观测都支持迁移才动手，防止被一次抖动骗到。
const migrateVotesNeeded = 2

func (s *Session) rebalance() {
	s.mu.Lock()
	var best *path
	bestScore := 0.0
	usable := 0
	for _, p := range s.paths {
		if !p.usable() {
			continue
		}
		usable++
		if sc := p.score(); best == nil || sc < bestScore {
			best, bestScore = p, sc
		}
	}
	if usable < 2 || best == nil {
		s.mu.Unlock()
		return
	}
	scoreOf := make(map[uint32]float64, len(s.paths))
	for _, p := range s.paths {
		scoreOf[p.id] = p.score()
	}
	var moved []*Stream
	for _, st := range s.streams {
		cur := st.pathID.Load()
		if cur == best.id {
			st.migrateVotes = 0
			continue
		}
		curScore, ok := scoreOf[cur]
		if !ok || bestScore*migrateAdvantage >= curScore {
			st.migrateVotes = 0
			continue
		}
		st.migrateVotes++
		// 差距悬殊（5 倍以上）时一票就够。滞回是为了防抖动，
		// 而 5 倍的差距不可能是抖动——多等一轮只是让瞬态里更多字节走在差路径上。
		need := migrateVotesNeeded
		if bestScore*migrateDecisive < curScore {
			need = 1
		}
		if st.migrateVotes >= need {
			st.migrateVotes = 0
			st.pathID.Store(best.id)
			moved = append(moved, st)
		}
	}
	s.mu.Unlock()

	for _, st := range moved {
		var buf []byte
		st.wmu.Lock()
		buf = AppendVarint(buf, st.ackOff)
		st.wmu.Unlock()
		best.writeFrame(FramePathMigrate, FlagPush, st.id, buf)
		st.rewind()
	}
}

func (s *Session) rewindAll() {
	s.mu.Lock()
	sts := make([]*Stream, 0, len(s.streams))
	for _, st := range s.streams {
		sts = append(sts, st)
	}
	s.mu.Unlock()
	for _, st := range sts {
		s.resumeStream(st)
	}
}

// resumeStream 在换路/重连后把一条流恢复到可发送状态。
// 顺序很重要：先补 STREAM_OPEN（对端可能压根没收到过），再重发数据，最后补 FIN。
func (s *Session) resumeStream(st *Stream) {
	if st.needsOpenResend() {
		s.sendOnStream(st, FrameStreamOpen, 0, st.openPayload)
	}
	st.rewind()
	if st.finPending() {
		var buf []byte
		st.wmu.Lock()
		fin := st.sendOff
		st.wmu.Unlock()
		buf = AppendVarint(buf, fin)
		s.sendOnStream(st, FrameStreamFin, 0, buf)
	}
	st.forceAck()
}

// ---------------------------------------------------------------------------
// 重连（客户端）/ 宽限期（服务端）
// ---------------------------------------------------------------------------

// recoverLoop 在一条路径都不剩时运行。
//
// ★ 这是"网络波动不断线"的最后一道，也是最重要的一道防线。
// 客户端会带着**同一个 session_id** 用 0-RTT 票据重拨；服务端那边会话还在宽限期里，
// 于是流状态、未确认字节、上游连接全都原封不动，用户的 TCP 连接一条都不会断。
// 拨不通就退避重试，直到宽限期耗尽才真的放弃。
func (s *Session) recoverLoop() {
	if !s.reconnBusy.CompareAndSwap(false, true) {
		return
	}
	defer s.reconnBusy.Store(false)

	deadline := time.Now().Add(s.grace)
	backoff := reconnectBackoffMin

	for {
		select {
		case <-s.closed:
			return
		default:
		}
		if time.Now().After(deadline) {
			s.closeWith(ErrSessionGone)
			return
		}
		s.mu.Lock()
		have := len(s.paths)
		s.mu.Unlock()
		if have > 0 {
			return // 别的地方（比如冗余路径）已经补上了
		}
		if s.redial == nil {
			// 服务端：只能等客户端带着 session_id 回来。
			select {
			case <-s.closed:
				return
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		p, err := s.redial(ctx, s)
		cancel()
		if err == nil && p != nil {
			s.addPath(p)
			return
		}

		// 退避带抖动：波动往往是整片网络的，几十个客户端同时重连会把刚恢复的
		// 链路再打垮一次。抖动把重连打散开。
		jit := time.Duration(fastRand()%uint32(backoff/time.Millisecond+1)) * time.Millisecond
		select {
		case <-s.closed:
			return
		case <-time.After(backoff/2 + jit):
		}
		backoff *= 2
		if backoff > reconnectBackoffMax {
			backoff = reconnectBackoffMax
		}
	}
}

// ---------------------------------------------------------------------------
// 发送
// ---------------------------------------------------------------------------

func (s *Session) sendOnStream(st *Stream, t FrameType, flags uint8, payload []byte) error {
	p := s.pickPath(st)
	if p == nil {
		return ErrNoPath
	}
	if err := p.writeFrame(t, flags, st.id, payload); err != nil {
		return err
	}
	if flags&FlagPush != 0 {
		p.flush()
	}
	return nil
}

func (s *Session) sendControl(t FrameType, payload []byte) error {
	p := s.pickPath(nil)
	if p == nil {
		return ErrNoPath
	}
	if err := p.writeFrame(t, FlagPush, 0, payload); err != nil {
		return err
	}
	p.flush()
	return nil
}

// ---------------------------------------------------------------------------
// 流管理
// ---------------------------------------------------------------------------

// OpenStream 开一条流并把目标地址告诉对端。
func (s *Session) OpenStream(ctx context.Context, dst string) (*Stream, error) {
	select {
	case <-s.closed:
		return nil, ErrClosed
	default:
	}
	if int(s.streamCount.Load()) >= s.maxStream {
		return nil, ErrTooManyStreams
	}

	s.mu.Lock()
	id := s.nextSID
	s.nextSID += 2
	st := newStream(s, id, dst, s.window)
	st.initiator = true
	s.streams[id] = st
	s.mu.Unlock()
	s.streamCount.Add(1)

	payload := make([]byte, 0, 32+len(dst))
	payload = append(payload, 0) // kind: 0=tcp
	payload = AppendVarint(payload, s.window)
	var err error
	payload, err = appendSocksAddr(payload, dst)
	if err != nil {
		s.removeStream(id)
		return nil, err
	}
	st.openPayload = payload

	// 开流帧带 PUSH：首包延迟直接决定用户看到的"点开网页多久有反应"。
	if err := s.sendOnStream(st, FrameStreamOpen, FlagPush, payload); err != nil {
		// 没路径也不算失败——重连后 resumeStream 会补发。这里只在会话已死时报错。
		if !errors.Is(err, ErrNoPath) {
			s.removeStream(id)
			return nil, err
		}
		if err := s.waitPath(ctx); err != nil {
			s.removeStream(id)
			return nil, err
		}
		s.sendOnStream(st, FrameStreamOpen, FlagPush, payload)
	}
	return st, nil
}

// waitPath 阻塞到至少有一条可用路径，或 ctx/会话结束。
func (s *Session) waitPath(ctx context.Context) error {
	done := make(chan struct{})
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
		case <-s.closed:
		case <-stop:
			return
		}
		s.mu.Lock()
		s.pathCond.Broadcast()
		s.mu.Unlock()
	}()
	go func() {
		s.mu.Lock()
		for len(s.paths) == 0 {
			select {
			case <-ctx.Done():
				s.mu.Unlock()
				close(done)
				return
			case <-s.closed:
				s.mu.Unlock()
				close(done)
				return
			default:
			}
			s.pathCond.Wait()
		}
		s.mu.Unlock()
		close(done)
	}()
	<-done
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.closed:
		return ErrClosed
	default:
	}
	return nil
}

// AcceptStream 取一条对端开的流（服务端侧）。
func (s *Session) AcceptStream(ctx context.Context) (*Stream, error) {
	select {
	case st := <-s.acceptCh:
		return st, nil
	case <-s.closed:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Session) removeStream(id uint64) {
	s.mu.Lock()
	_, ok := s.streams[id]
	delete(s.streams, id)
	paths := append([]*path(nil), s.paths...)
	s.mu.Unlock()
	if ok {
		s.streamCount.Add(-1)
	}
	// 顺手关掉这条流占的 QUIC 流。不关就是纯泄漏——quic-go 的流上限
	// （MaxIncomingStreams）用满之后，新流会阻塞在 OpenStream 上，
	// 表现为"跑一段时间后新连接全部卡住"，而且看不出跟流没回收有关系。
	for _, p := range paths {
		if p.qmux != nil {
			p.qmux.closeStream(id)
		}
	}
}

func (s *Session) stream(id uint64) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

// ---------------------------------------------------------------------------
// 帧分发
// ---------------------------------------------------------------------------

func (s *Session) handleFrame(p *path, f Frame) error {
	switch f.Type {
	case FramePathProbe:
		p.onProbe(f.Payload)
	case FramePathAck:
		p.onProbeAck(f.Payload)
	case FramePadding:
		// MUST 丢弃
	case FrameStreamOpen:
		return s.onStreamOpen(p, f)
	case FrameStreamData:
		off, n := ReadVarint(f.Payload)
		if n == 0 {
			return ErrProtocol
		}
		st := s.stream(f.StreamID)
		if st == nil {
			// 未知流：可能是刚被本端关掉，也可能是 STREAM_OPEN 在旧路径上丢了。
			// 不回错——回错会给主动探测方一个可测的差异；不 ACK 就够了，
			// 对端的 RTO 会把 STREAM_OPEN 一起重发。
			return nil
		}
		st.markOpenAcked()
		if err := st.onData(off, f.Payload[n:]); err != nil {
			return err
		}
		if f.Flags&FlagEnd != 0 {
			st.onFin(off + uint64(len(f.Payload)-n))
		}
	case FrameStreamAck:
		ack, n := ReadVarint(f.Payload)
		if n == 0 {
			return ErrProtocol
		}
		maxOff, m := ReadVarint(f.Payload[n:])
		if m == 0 {
			return ErrProtocol
		}
		if st := s.stream(f.StreamID); st != nil {
			st.markOpenAcked()
			st.onAck(ack, maxOff)
		}
	case FrameStreamFin:
		finOff, n := ReadVarint(f.Payload)
		if n == 0 {
			return ErrProtocol
		}
		if st := s.stream(f.StreamID); st != nil {
			st.markOpenAcked()
			st.onFin(finOff)
		}
	case FrameStreamRst:
		if len(f.Payload) < 4 {
			return ErrProtocol
		}
		code := StreamError(binary.BigEndian.Uint32(f.Payload[:4]))
		if st := s.stream(f.StreamID); st != nil {
			st.onReset(code)
			s.removeStream(st.id)
		}
	case FramePathMigrate:
		// 纯声明。绝对偏移已经让重组自洽，这里只更新亲和记录。
		if st := s.stream(f.StreamID); st != nil {
			st.pathID.Store(p.id)
		}
	case FrameDatagram:
		return s.onDatagram(f)
	case FrameTicketRepl:
		if s.wallet != nil {
			if base, count, seed, ok := parseTicketGrant(f.Payload); ok {
				s.wallet.add(base, count, seed, time.Now())
			}
		}
	case FrameTicketReq:
		s.ticketLow.Store(true)
		if s.onTicketReq != nil {
			go s.onTicketReq()
		}
	case FrameClose:
		s.closeWith(ErrClosed)
		return ErrClosed
	default:
		// 未知类型 MUST 忽略并按 length 跳过——frameReader 已经跳过了。
	}
	return nil
}

func (s *Session) onStreamOpen(p *path, f Frame) error {
	if s.stream(f.StreamID) != nil {
		return nil // 重连后的补发，幂等
	}
	if len(f.Payload) < 2 {
		return ErrProtocol
	}
	kind := f.Payload[0]
	rest := f.Payload[1:]
	peerWin, n := ReadVarint(rest)
	if n == 0 {
		return ErrProtocol
	}
	rest = rest[n:]
	dst, _, err := parseSocksAddr(rest)
	if err != nil {
		return ErrProtocol
	}
	if int(s.streamCount.Load()) >= s.maxStream {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], uint32(StreamErrRefused))
		p.writeFrame(FrameStreamRst, FlagPush, f.StreamID, buf[:])
		return nil
	}

	st := newStream(s, f.StreamID, dst, s.window)
	st.peerMaxOff = peerWin
	st.pathID.Store(p.id)
	st.udp = kind == 1
	if st.udp {
		st.pkt = newPacketStream(s, st)
	}
	st.markOpenAcked()

	s.mu.Lock()
	if _, dup := s.streams[f.StreamID]; dup {
		s.mu.Unlock()
		return nil
	}
	s.streams[f.StreamID] = st
	s.mu.Unlock()
	s.streamCount.Add(1)

	// 立刻回一个 ACK 通告本端真实窗口——对端在此之前只敢用 64 KiB 的保守初值。
	st.forceAck()

	// 关联建好了，把抢跑到前面的数据报按原序补交。必须在流入表之后做，
	// 否则补交与新到的数据报会乱序。
	if st.udp {
		s.releaseEarlyDatagrams(st)
	}

	select {
	case s.acceptCh <- st:
	case <-s.closed:
	default:
		// accept 队列满：拒绝而不是无限排队，否则上游一慢就把内存吃光。
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], uint32(StreamErrRefused))
		p.writeFrame(FrameStreamRst, FlagPush, f.StreamID, buf[:])
		s.removeStream(f.StreamID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// RTO：最后的安全网
// ---------------------------------------------------------------------------

// retransmitLoop 定期检查"有未确认字节但一直没有进展"的流，把它们回退重发。
//
// 为什么在已经有路径健康检查之后还需要这个：健康检查看的是路径，
// 而丢帧可以在路径完全健康时发生——比如 STREAM_OPEN 恰好落在路径断掉的那一刻，
// 或者对端因为流表满而丢弃了帧。没有 RTO，这类情况表现为一条永远卡住的连接，
// 且两端都认为自己没问题。这是弱网下最难查的一类故障，必须有兜底。
func (s *Session) retransmitLoop() {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-t.C:
		}
		now := time.Now()
		rto := s.currentRTO()

		s.mu.Lock()
		var stuck []*Stream
		for _, st := range s.streams {
			if st.stalledFor(now, rto) {
				stuck = append(stuck, st)
			}
		}
		s.mu.Unlock()

		for _, st := range stuck {
			st.noteRewind(now)
			s.resumeStream(st)
		}
	}
}

func (s *Session) currentRTO() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	best := time.Duration(0)
	for _, p := range s.paths {
		if r := p.RTT(); r > 0 && (best == 0 || r < best) {
			best = r
		}
	}
	rto := 2*best + 200*time.Millisecond
	if rto < 500*time.Millisecond {
		rto = 500 * time.Millisecond
	}
	if rto > 4*time.Second {
		rto = 4 * time.Second
	}
	return rto
}

// ticketLoop（客户端）在票据不足时向服务端要一批。
func (s *Session) ticketLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-t.C:
		}
		if s.wallet == nil {
			continue
		}
		now := time.Now()
		s.wallet.sweep(now)
		if float64(s.wallet.remaining(now)) < float64(DefaultTicketCount)*ticketLowWater {
			s.sendControl(FrameTicketReq, nil)
		}
	}
}

// ---------------------------------------------------------------------------
// 关闭
// ---------------------------------------------------------------------------

// Close 关闭会话与其上全部流。
func (s *Session) Close() error {
	s.sendControl(FrameClose, nil)
	s.closeWith(ErrClosed)
	return nil
}

func (s *Session) closeWith(err error) {
	s.closeOnce.Do(func() {
		s.closeErr = err
		close(s.closed)

		s.mu.Lock()
		ps := s.paths
		s.paths = nil
		sts := make([]*Stream, 0, len(s.streams))
		for _, st := range s.streams {
			sts = append(sts, st)
		}
		s.streams = map[uint64]*Stream{}
		s.pathCond.Broadcast()
		s.mu.Unlock()

		for _, p := range ps {
			p.markDead()
		}
		for _, st := range sts {
			st.fail(err)
		}
		// ★ 这里**不能**关 acceptCh，也不能关任何"别人还在往里发"的通道。
		// 关闭会话是**接收侧**的动作，而每条路径的收帧协程都是发送侧——
		// Go 里向已关闭通道发送必定 panic，`select`+`default` 也挡不住。
		// 曾经这里关过一个 dgramCh，于是"会话关闭的同时对端还在发 DATAGRAM"
		// 就是一次远端可触发的进程崩溃。发送侧一律以 s.closed 为准，通道交给 GC。
	})
}

// pathsSnapshot 供自检与诊断。
func (s *Session) pathsSnapshot() []*path {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]*path(nil), s.paths...)
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

// fastRand 用于退避抖动，不需要密码学强度。
var randState atomic.Uint64

func fastRand() uint32 {
	// xorshift64*，够用且无锁。
	for {
		old := randState.Load()
		x := old
		if x == 0 {
			x = uint64(time.Now().UnixNano()) | 1
		}
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		if randState.CompareAndSwap(old, x) {
			return uint32(x >> 33)
		}
	}
}

// deathLog 是一个很小的环形缓冲，记最近 16 条路径的死因。
//
// 只留 16 条是因为它的用途很窄：查"路径反复重建"时，前几条就足以看出模式
// （是全都"lost N consecutive probes"，还是全都"read loop: ..."）。
// 无上界地留着反而会在长跑会话里悄悄吃内存。
type deathLog struct {
	mu   sync.Mutex
	ring [16]string
	n    int
}

func (d *deathLog) add(s string) {
	d.mu.Lock()
	d.ring[d.n%len(d.ring)] = s
	d.n++
	d.mu.Unlock()
}

func (d *deathLog) snapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := d.n
	if n > len(d.ring) {
		n = len(d.ring)
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		idx := (d.n - n + i) % len(d.ring)
		out = append(out, d.ring[idx])
	}
	return out
}
