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
	// resumes 是累计有多少次"把一条流退回最后确认点重发"。
	// 每一次都意味着一段已经发过的字节要再上一次线，所以它是虚假重传的直接度量：
	// 正常爬坡（TCP 起来后再加 QUIC）**不该**让它涨，涨了就是在白烧带宽。
	resumes atomic.Uint64
	// dgramBytes 是全会话所有 UDP 关联收队列里的载荷字节数（见 maxSessionDatagramBytes）。
	dgramBytes atomic.Int64

	// ctrlOut 是不能在读协程里写的**一次性**控制帧（目前只有拒绝流的 RST）。
	// 满了就丢：丢一个 RST 只是让对端多等一个超时，而为了发它把读侧堵住，
	// 代价是整条会话。理由见 stream.go 的 maybeAckLocked。
	ctrlOut chan pendingCtrl
	// deadLog 留着最近几条路径的死因。路径死了就从 paths 里摘掉，
	// 死因也跟着消失——而"反复建起来又死"恰恰只能靠死因序列来查。
	deadLog deathLog

	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error

	// 客户端票据钱包，重连时用来做 0-RTT。
	wallet *ticketWallet
	// onTicketReq 由服务端注入：客户端票据见底时补发一批。
	onTicketReq func()
	// ticketReq 是 TICKET_REQUEST 的**合并**信号，容量 1。
	// 见 ticketServeLoop：一条会话只有一个补票协程，且有最小间隔。
	ticketReq chan struct{}
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
		ticketReq: make(chan struct{}, 1),
		ctrlOut:   make(chan pendingCtrl, 64),
		closed:    make(chan struct{}),
	}
	go s.ctrlLoop()
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

// maxPathsPerSession 是一条会话最多能挂几条路径。
//
// 正常形态是 2 条（TCP + QUIC/h3），多网口部署每个上行各一条，8 是宽裕的余量。
// 上界必须存在，因为**加路径这件事由对端驱动**：任何拿着有效 session_id 的对端
// 都可以不断握手加入同一条会话，而每条路径要付 3 个协程（读/写/探测）
// 加一个 32 KiB 的解帧缓冲，还会让 pickPath 的每次发送变成 O(路径数)。
const maxPathsPerSession = 8

// addPath 把一条新路径挂进会话。返回 false 表示已达上限、这条路径没有被接纳。
func (s *Session) addPath(p *path) bool {
	s.mu.Lock()
	if len(s.paths) >= maxPathsPerSession {
		s.mu.Unlock()
		p.markDeadReason("too many paths on this session")
		return false
	}
	// ★ path_id 在一条会话内 MUST 唯一，而且这是**安全**要求，不是整洁要求。
	//
	// 记录层的密钥是 pathKey(方向密钥, path_id)——纯粹由 path_id 决定；
	// 而每条路径的 recordSealer 序号都从 0 起。两条路径若拿到同一个 path_id，
	// 就是同一把密钥配同一串 nonce，AEAD 当场失效：两段密文异或即泄露明文，
	// Poly1305 的认证密钥也跟着复用，伪造随之成立。
	//
	// 这里是**唯一**的插入点，也是唯一能和 s.paths 原子地一起判的地方。
	// 握手里那次判（见 server.go）只是尽早给对端换一个号，挡不住并发加入的竞态。
	// 多路径 QUIC 给出的是同一条要求，理由也一模一样：
	// "为保证 nonce 唯一，path ID 不得在同一条连接内被另一条路径复用"
	// （draft-ietf-quic-multipath）。
	for _, q := range s.paths {
		if q.id == p.id {
			s.mu.Unlock()
			p.markDeadReason("duplicate path id on this session")
			return false
		}
	}
	s.paths = append(s.paths, p)
	first := len(s.paths) == 1
	s.mu.Unlock()
	s.noPathSince.Store(0)
	s.pathsAdded.Add(1)

	go p.readLoop()
	go p.writeLoop()
	go p.probeLoop(s.probeIvl, DefaultIdleProbeInterval)
	// 判决窗口内把静默间隔也填掉——填充的长度那一半早就上线了，时序这一半到此才接上。
	go p.heartbeatLoop()

	// ★ 只有"会话此刻一条路径都没有"才需要全量退回重发。
	//
	// 这里曾经是无条件 rewindAll()，那是错的，而且错得很贵：
	//  · 正常多路径爬坡（TCP 起来后再加 QUIC）会把**所有流**已发未确认的字节
	//    全部重发一遍——数据明明还在一条健康的路径上飞，接收方按绝对偏移去重，
	//    于是这些字节纯属浪费带宽。
	//  · 更糟的是它由对端驱动：任何一次 join 都能触发一次全量重发，
	//    最坏是 maxStreams × window = 1024 × 512 KiB ≈ 512 MB 的出向流量，
	//    外加每条流一个 pump 协程。对端只要反复加路径就能把服务端的出口打满。
	//
	// 路径死了但还有别的活着，走的是 onPathDead → reassignFrom(deadID)，
	// 那里只恢复钉在死路径上的那些流，是精确的。真正需要全量重发的只有
	// "路径全死光之后重连回来"，而那一刻 len(s.paths) 正好是 1。
	//
	// 多路径 QUIC 的原则是一样的：在确认丢失或路径被判死之前不重传，
	// 就是为了避免这种虚假重传（draft-ietf-quic-multipath）。
	if first {
		s.rewindAll()
	}

	s.mu.Lock()
	s.pathCond.Broadcast()
	s.mu.Unlock()
	return true
}

// pathIDInUse 报告这条会话此刻是否已经有路径用着这个 path_id。
func (s *Session) pathIDInUse(id uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.paths {
		if p.id == id {
			return true
		}
	}
	return false
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
	best, _ := s.bestPathForLocked(st)
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

// scoreFor 是路径 p 对**这条流**的有效评分（越小越好）。
//
// ★ 偏好只有一个来源。从前它只写在 pickPathLocked 里，而每 2 秒跑一次的 rebalance
// 用的是**裸** score()，于是三处调度各说各话：
//
//	migrateBulkAway  只迁批量流，注释写明"交互流留着——QUIC 的优势在丢包下的批量
//	                 吞吐，不在小包延迟，把交互流也迁走反而更糟"；
//	pickPathLocked   建流时给批量流偏 QUIC、交互流偏 TCP；
//	rebalance        取一个**全局**最优路径，把**所有**流都迁过去，两种偏好都不看。
//
// 而 rebalance 是周期性的，所以它赢：前两处的判断活不过 2 秒就被覆盖掉。
//
// ★ 影响要说准，别夸大：偏好只有 ±20%，而迁移门槛 migrateAdvantage 是 2 倍，
// 所以偏好挪的是**触发点**而不是结论——交互流迁往 QUIC 的条件从"TCP 差 2 倍"
// 变成"TCP 差 2.5 倍"。也就是说交互流并不会被随便赶走，只是比设计意图早了 25%
// 被赶走；而每迁一条都要 rewind() 重发未确认字节（resumes 计数器量的就是它）。
//
// 这里把偏好收成一个函数，三处共用，矛盾从结构上消失。
func (s *Session) scoreFor(p *path, st *Stream) float64 {
	sc := p.score()
	if st == nil {
		return sc
	}
	if st.isBulk() && p.kind == "quic" {
		// 批量流偏好 QUIC：同分时优先，不是无脑覆盖。
		sc *= 0.8
	}
	if !st.isBulk() && p.kind == "tcp" {
		sc *= 0.8
	}
	return sc
}

// bestPathForLocked 给出对 st 最好的可用路径及其有效评分。st 为 nil 时就是全局最优。
func (s *Session) bestPathForLocked(st *Stream) (*path, float64) {
	var best *path
	bestScore := 0.0
	for _, p := range s.paths {
		if !p.usable() {
			continue
		}
		if sc := s.scoreFor(p, st); best == nil || sc < bestScore {
			best, bestScore = p, sc
		}
	}
	return best, bestScore
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
	usable := 0
	for _, p := range s.paths {
		if p.usable() {
			usable++
		}
	}
	if usable < 2 {
		s.mu.Unlock()
		return
	}
	type move struct {
		st *Stream
		to *path
	}
	var moved []move
	for _, st := range s.streams {
		// ★ 为**这条流**挑最好的路径，不是挑一条全局最优再把所有流都塞过去。
		// 全局最优那种写法会把交互流也迁到 QUIC 上——而 migrateBulkAway 与
		// pickPathLocked 两处都明确不这么做（见 scoreFor 的说明）。
		best, bestScore := s.bestPathForLocked(st)
		if best == nil {
			st.migrateVotes = 0
			continue
		}
		cur := st.pathID.Load()
		if cur == best.id {
			st.migrateVotes = 0
			continue
		}
		var curScore float64
		found := false
		for _, p := range s.paths {
			if p.id == cur {
				curScore, found = s.scoreFor(p, st), true
				break
			}
		}
		if !found || bestScore*migrateAdvantage >= curScore {
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
			moved = append(moved, move{st: st, to: best})
		}
	}
	s.mu.Unlock()

	for _, m := range moved {
		var buf []byte
		m.st.wmu.Lock()
		buf = AppendVarint(buf, m.st.ackOff)
		m.st.wmu.Unlock()
		m.to.writeFrame(FramePathMigrate, FlagPush, m.st.id, buf)
		m.st.rewind()
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
	s.resumes.Add(1)
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
			if !s.addPath(p) {
				// 会话已经挂满：这条重连的路径被顶回来了，别当成"恢复成功"，
				// 否则 recoverLoop 就此退出，而会话其实一条可用路径都没有。
				continue
			}
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
	st, ok := s.streams[id]
	delete(s.streams, id)
	paths := append([]*path(nil), s.paths...)
	s.mu.Unlock()
	if ok {
		s.streamCount.Add(-1)
		// UDP 关联的收队列跟着走：不关就是两处泄漏，见 closeQueue 的说明。
		if st != nil && st.pkt != nil {
			st.pkt.closeQueue()
		}
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

// ---------------------------------------------------------------------------
// 读协程里产生的出向帧：一律不在读协程上写
// ---------------------------------------------------------------------------

// ctrlLoop 发那些**一次性**的控制帧。
//
// 它堵住不要紧——读协程照常排空对端的数据，对端的窗口照常打开，这条写迟早通过。
// 反过来（读协程自己去写）才是死锁：见 stream.go 的 maybeAckLocked。
//
// ★ 它和 ACK **不共用**协程。共用的话，一条卡住的流会把整条会话所有流的 ACK
// 一起压住——那正是每条 TIDE 流一条独立 QUIC 流要消除的队头阻塞，
// 在发送侧原样重建一遍就白分了。
func (s *Session) ctrlLoop() {
	for {
		select {
		case <-s.closed:
			return
		case pc := <-s.ctrlOut:
			pc.p.writeFrame(pc.t, pc.flags, pc.sid, pc.payload)
		}
	}
}

// pendingCtrl 是一帧待发的一次性控制帧。
type pendingCtrl struct {
	p       *path
	t       FrameType
	flags   uint8
	sid     uint64
	payload []byte
}

// deferCtrl 把一帧控制帧交给 ackLoop 去写。★ 不阻塞：队列满就丢。
// 调用点全在 handleFrame 里，也就是读协程上——在那里直接 writeFrame
// 就是 stream.go maybeAckLocked 里描述的那个死锁。
func (s *Session) deferCtrl(p *path, t FrameType, flags uint8, sid uint64, payload []byte) {
	select {
	case s.ctrlOut <- pendingCtrl{p: p, t: t, flags: flags, sid: sid, payload: payload}:
	default:
	}
}

func refusedPayload() []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(StreamErrRefused))
	return buf[:]
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
		// ★ 这里**绝不能**是 `go s.onTicketReq()`。
		//
		// TICKET_REQUEST 是全协议里最便宜的一个帧：type+flags+len(0)+sid(0) = 4 字节。
		// 而它让服务端做的事是：起一个协程、读一次 crypto/rand、在票据库里新建一批
		// （1024 张的位图 + 索引项，约 330 字节，**留存 24 小时**）、再回一个 42 字节的
		// TICKET_REPLENISH。4 字节换 330 字节留存 24 小时是 80 倍放大，
		// 换 42 字节回程是 10 倍反射，换一个协程是无上界并发。
		// 一个已认证的对端只要在循环里发这个帧，服务端就会在几十秒内被自己的票据库撑死，
		// 而且全程没有任何错误路径被触发（RFC 9000 §21.9 说的正是这一类：
		// "处理开销相对带宽与状态变化不成比例"）。
		//
		// 改成往一个容量 1 的通道里投**非阻塞**信号：满了就丢，因为"请补票"这件事
		// 是幂等的，投 1 次和投 1 万次要做的事一模一样。真正的补票在 ticketServeLoop
		// 里排队执行，一条会话一个协程、且有最小间隔。
		select {
		case s.ticketReq <- struct{}{}:
		default:
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
		s.deferCtrl(p, FrameStreamRst, FlagPush, f.StreamID, refusedPayload())
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
		s.deferCtrl(p, FrameStreamRst, FlagPush, f.StreamID, refusedPayload())
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

// minReplenishInterval 是服务端两次补票之间的最小间隔。
//
// 客户端那边 ticketLoop 每 5 秒才检查一次、且要低于 25% 才发请求，所以对正常客户端
// 这个下限从来不会碰到；它只对"在循环里刷 TICKET_REQUEST"的对端生效，
// 把攻击成本从"每帧一批票据"压到"每秒一批"。
const minReplenishInterval = time.Second

// ticketServeLoop（服务端）串行地响应补票请求。
//
// 一条会话**一个**协程，且两次补票之间至少隔 minReplenishInterval。
// 冷却期内到达的请求全部被合并成一次——补票是幂等的，对端要 1 次和要 1 万次
// 需要做的事一模一样，所以合并不丢任何语义。
func (s *Session) ticketServeLoop() {
	var last time.Time
	for {
		select {
		case <-s.closed:
			return
		case <-s.ticketReq:
		}
		if wait := minReplenishInterval - time.Since(last); wait > 0 && !last.IsZero() {
			t := time.NewTimer(wait)
			select {
			case <-s.closed:
				t.Stop()
				return
			case <-t.C:
			}
		}
		last = time.Now()
		if s.onTicketReq != nil {
			s.onTicketReq()
		}
	}
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
