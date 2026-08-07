package tide

import (
	"encoding/binary"
	"encoding/hex"

	"errors"
	"github.com/quic-go/quic-go/http3"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// path 是承载会话的一条具体传输连接（TCP+TLS 或 QUIC）。
//
// 路径的健康状态机是整个"网络波动不断线"的探测端：它必须**快到能在用户察觉前切走**，
// 又**稳到不会被一次抖动骗到**。这两个要求方向相反，所以状态迁移全部带滞回——
// 降级要连续 N 次坏样本，恢复要连续 M 次好样本。没有滞回的实现会在丢包率 2% 附近
// 每秒来回迁移几十次，比不迁移还糟。

type pathState uint32

const (
	pathActive   pathState = iota // 正常
	pathDegraded                  // 丢包超阈值：仍可用，但批量流该迁走
	pathSuspect                   // 连续探测丢失：新流不再选它
	pathDead                      // 判死：流全部撤离
)

func (s pathState) String() string {
	switch s {
	case pathActive:
		return "active"
	case pathDegraded:
		return "degraded"
	case pathSuspect:
		return "suspect"
	}
	return "dead"
}

// 滞回参数。
const (
	suspectAfterLostProbes = 2 // 连续丢 2 个探测 → suspect
	deadAfterLostProbes    = 4 // 连续丢 4 个 → dead
	recoverAfterGoodProbes = 3 // 连续 3 个好探测才回 active

	// maxProbeBackoffShift 是探测超时的指数退避上限（2^6 = 64 倍）。
	maxProbeBackoffShift = 6
	// maxProbeTimeout 是退避后的硬上界，免得一条真死的路径拖到天荒地老。
	maxProbeTimeout = 30 * time.Second
	// probeRetainHorizon 是**已判丢**的探测记录再保留多久。
	// 保留是为了让迟到的应答仍能贡献 RTT 样本（见 probeRec）。
	probeRetainHorizon = 2 * maxProbeTimeout
)

// probeRec 是一条探测的发送记录。
//
// ★ reaped 表示"已经按超时记为丢失"，但记录**不删**——迟到的应答仍然是
// 一个完全无歧义的 RTT 样本。Karn 算法之所以禁止用超时段的样本，是因为
// TCP 会重传，应答归属哪一次发送无从分辨（RFC 6298 §5）；而 TIDE 的探测
// 带唯一 seq 且**从不重传**，那个歧义根本不存在。
//
// 这条不是优化，是**估计器唯一的学习通道**：判丢就删记录的话，srtt 只能
// 收到"比当前超时更快"的样本，于是链路一旦变慢到超过下界，估计器就再也
// 看不到任何真实 RTT——超时永远停在 2s，而每个探测都超过 2s，路径必死。
// 2026-08-07 跨洲实链（空载 166ms、满载 4~14s）上就是这么每 20s 死 5 次的。
type probeRec struct {
	sent   time.Time
	reaped bool
}

type path struct {
	id   uint32
	kind string // "tcp" / "quic"
	sess *Session
	conn net.Conn

	fr     *frameReader
	sealer *recordSealer // nil = bare 模式
	pad    *paddingScheduler

	// 写侧：帧先攒进 wbuf，由 writer goroutine 批量封装下发。
	// 攒批不只是为了少几次 syscall——它让判决窗口里的多个小帧合成一个
	// 长度落在 HTTPS 分布内的记录，单帧一记录反而会暴露帧边界。
	wmu     sync.Mutex
	wcond   *sync.Cond
	wbuf    []byte
	wclosed bool

	// 健康
	hmu     sync.Mutex
	srtt    time.Duration
	rttvar  time.Duration
	minRTT  time.Duration
	loss    float64 // EWMA
	probeSq uint64
	pending map[uint64]probeRec
	goodRun int
	badRun  int

	state    atomic.Uint32
	lastRecv atomic.Int64 // UnixNano
	// lastSent 是最后一次真正把字节写上线的时刻，供 heartbeatLoop 判断"现在是不是静默"。
	lastSent atomic.Int64 // UnixNano
	created  time.Time
	// 收发字节数。调度器的决策（哪条流走哪条路）除了看这个没有别的办法验证——
	// "QUIC 路径建起来了"和"数据真的走了 QUIC"是两件事。
	//
	// tx/rxBytes 是**这条路径上的全部**字节；tx/rxDgram 是其中走不可靠数据面
	// （RFC 9221 的 QUIC 数据报 / RFC 9297 的 HTTP Datagram）的那部分。
	// ★ 拆开不是为了好看：判断"UDP 有没有被偷偷塞进可靠流"唯一能用的证据就是
	// 「总量 − 数据报量 = 流字节」这个差。只有一个总数时，"没走流"和"没发出去"
	// 长得一模一样，而这两件事一个是对的、一个是彻底坏了。
	txBytes atomic.Uint64
	rxBytes atomic.Uint64
	txDgram atomic.Uint64
	rxDgram atomic.Uint64

	// qmux 非空 = QUIC 多流模式：每条 TIDE 流一条独立的 QUIC 流（见 quicmux.go）。
	// 单流模式下为 nil，所有帧走 conn 那一条字节流。
	qmux *quicMux
	// h3 非空 = 这条路径跑在 HTTP/3 之上的**客户端**侧（spec §12.6）。
	h3 *h3Client
	// h3srv 是服务端侧承载 RFC 9297 数据报的那条流。
	h3srv *http3.Stream

	dead     chan struct{}
	deadOnce sync.Once
	peek     *peekReader
	// deadReason 记下这条路径是被谁判死的。
	//
	// ★ 没有它就查不动"路径反复建起来又死"这类问题：markDead 有四个调用点
	// （写循环退出、读循环出错、连丢探测、静默超时），四者的现象一模一样——
	// 路径消失、重连、再消失。实网上 h3 模式 40 秒内建了 9 次路径，
	// 而日志里一个字都没有，等于只能靠猜。
	deadReason atomic.Value // string
}

func newPath(s *Session, id uint32, kind string, conn net.Conn, sealKey, openKey []byte, useAES bool, bare bool) (*path, error) {
	p := &path{
		id:      id,
		kind:    kind,
		sess:    s,
		conn:    conn,
		pad:     newPaddingScheduler(),
		pending: make(map[uint64]probeRec),
		created: time.Now(),
		dead:    make(chan struct{}),
	}
	p.wcond = sync.NewCond(&p.wmu)
	p.lastRecv.Store(time.Now().UnixNano())

	var src io.Reader = conn
	if !bare {
		sl, err := newRecordSealer(sealKey, useAES)
		if err != nil {
			return nil, err
		}
		op, err := newRecordOpener(conn, openKey, useAES)
		if err != nil {
			return nil, err
		}
		p.sealer = sl
		src = op
	}
	// ★ bare **只**表示"用户态不做 AEAD"（外层信道已经提供了），它与要不要填充无关。
	//
	// 这里曾经在 bare 分支里 p.pad.disable()，理由写的是"要插填充就得在用户态碰载荷，
	// 那 splice 就没了"。那个理由已经**不存在**：§12.3 定稿说 kTLS + splice 在本协议里
	// 根本做不到（多路复用必须解帧，解帧就必须把数据读进用户态），与 kTLS 能不能用无关。
	// 一个为已被否决的优化让路的开关，就这么一直开着。
	//
	// 后果不小：QUIC/h3 路径**恒为 bare**（服务端对每条 QUIC 连接都置 acceptModeBare），
	// 于是这些路径既没有长度填充、也没有时序心跳（Phase() 返回 PhaseOff，
	// heartbeatLoop 一进去就退出）。而 §8.1 恰恰把**批量**流往 QUIC 上偏——
	// 承载字节最多的那条路，防护是零。
	//
	// 代价可以忽略：填充预算本来就只花在判决窗口（前 64 KiB / 100 帧），之后自动归零。
	// 留一份开头字节，解帧失败时能看清到底收到了什么（见 peekReader）。
	pk := newPeekReader(src, 48)
	p.peek = pk
	p.fr = newFrameReader(pk)
	return p, nil
}

func (p *path) State() pathState { return pathState(p.state.Load()) }

// usable 表示"新流可以选它"。suspect 不在其列（spec §8.2）。
func (p *path) usable() bool {
	s := p.State()
	return s == pathActive || s == pathDegraded
}

// holdable 表示"已经钉在它上面的流可以继续留着"。
//
// ★ 这两个判据必须分开，spec §8.2 写的就是 suspect = "**新流**不再选它"。
// 早先只有 usable() 一个判据，suspect 会把已有的流也一起赶走——而赶到哪去？
// 赶到当时唯一还 active 的那条路径上，哪怕它慢 8 倍。
// 5% 丢包下探测本身也会丢，连丢 2 个就进 suspect，于是这事**反复发生**：
// 实测 90 秒里有 24.3 MiB（14%）被赶回 RTT 高一个数量级的 TCP 路径，
// 而且是稳态泄漏、不是启动瞬态——把测试时长从 25s 拉到 90s，这个量成比例增长。
// 判死（连丢 4 个探测或静默 8 秒）仍然会撤离所有流，所以留在 suspect 上的代价有上界。
func (p *path) holdable() bool { return p.State() != pathDead }

// RTT 返回平滑后的往返时延（自检/调度用）。
func (p *path) RTT() time.Duration {
	p.hmu.Lock()
	defer p.hmu.Unlock()
	return p.srtt
}

// Loss 返回 EWMA 丢包率估计。
func (p *path) Loss() float64 {
	p.hmu.Lock()
	defer p.hmu.Unlock()
	return p.loss
}

// ---------------------------------------------------------------------------
// 写
// ---------------------------------------------------------------------------

// writeFrame 把一帧序列化进发送缓冲。填充在这一层加，因为只有这里同时知道
// 帧的真实长度与该路径的填充阶段。
func (p *path) writeFrame(t FrameType, flags uint8, streamID uint64, payload []byte) error {
	if len(payload) > MaxFrameBody {
		return ErrFrameTooLarge
	}
	// 属于某条 TIDE 流的帧走它自己的 QUIC 流，避免一条流的丢包卡住其它流。
	if p.qmux != nil && streamID != 0 && muxable(t) {
		return p.qmux.write(t, flags, streamID, payload)
	}
	// UDP 走数据报：不重传、不保序，才是 UDP 该有的语义（spec §9.1）。
	// 原生 QUIC 路径用 RFC 9221 的 QUIC 数据报；h3 路径用 RFC 9297 的 HTTP Datagram
	// （绑在控制流上，Quarter Stream ID 前缀由 quic-go 自己加）。
	// 两者都装不下时回退到可靠流——真实世界超 MTU 的 UDP 是被分片而不是消失，
	// 静默丢会让大 DNS 响应无声失败。
	if t == FrameDatagram {
		if buf, ok := p.h3DatagramFrame(flags, streamID, payload); ok {
			if err := p.sendH3Datagram(buf); err == nil {
				return nil
			}
		} else if p.qmux != nil && !p.qmux.h3 {
			if err := p.qmux.sendDatagram(flags, streamID, payload); err == nil {
				return nil
			} else if !errors.Is(err, errDatagramTooLarge) {
				return err
			}
		}
	}
	pad := p.pad.padFor(streamID, len(payload))

	p.wmu.Lock()
	if p.wclosed {
		p.wmu.Unlock()
		return ErrClosed
	}
	p.wbuf = AppendFrame(p.wbuf, t, flags, streamID, payload, pad)
	p.wcond.Signal()
	p.wmu.Unlock()
	return nil
}

func (p *path) writeLoop() {
	defer p.markDeadReason("write loop exited")
	var out []byte
	for {
		p.wmu.Lock()
		for len(p.wbuf) == 0 && !p.wclosed {
			p.wcond.Wait()
		}
		if p.wclosed && len(p.wbuf) == 0 {
			p.wmu.Unlock()
			return
		}
		batch := p.wbuf
		p.wbuf = nil
		p.wmu.Unlock()

		out = out[:0]
		if p.sealer == nil {
			out = append(out, batch...)
		} else {
			// 一批可能超过一条记录的明文上限，按上限切开。帧可以跨记录边界——
			// 接收侧的 recordOpener 吐的是连续字节流，frameReader 自己会拼。
			for len(batch) > 0 {
				n := len(batch)
				if n > maxRecordPlain {
					n = maxRecordPlain
				}
				var err error
				out, err = p.sealer.Seal(out, batch[:n])
				if err != nil {
					return
				}
				batch = batch[n:]
			}
		}
		if _, err := p.conn.Write(out); err != nil {
			return
		}
		p.txBytes.Add(uint64(len(out)))
		p.lastSent.Store(time.Now().UnixNano())
	}
}

// ---------------------------------------------------------------------------
// 读
// ---------------------------------------------------------------------------

func (p *path) readLoop() {
	var rerr error
	defer func() {
		reason := "read loop: " + errText(rerr)
		// 解帧类错误一定要带上原始字节，否则只知道"对不齐"，不知道对不齐成什么样。
		if rerr == ErrFrameTooLarge || rerr == ErrProtocol {
			reason += " head=" + hex.EncodeToString(p.peek.Head())
		}
		p.markDeadReason(reason)
	}()
	for {
		f, err := p.fr.ReadFrame()
		if err != nil {
			rerr = err
			return
		}
		p.noteRecv(len(f.Payload))
		if err := p.sess.handleFrame(p, f); err != nil {
			rerr = err
			return
		}
	}
}

func errText(err error) string {
	if err == nil {
		return "EOF"
	}
	return err.Error()
}

// ---------------------------------------------------------------------------
// 探测与健康
// ---------------------------------------------------------------------------

// jitter 给一个标称间隔加上 ±40% 的均匀抖动。
//
// ★ 固定周期的心跳是**最容易被认出来的时序特征**，而且根本不需要机器学习。
// 实测未加抖动时，一条应用层完全静默的连接，线上包的到达间隔是
// **均值 1000.2ms、标准差 0.15ms、变异系数 0.00015**——一个精确到 0.15 毫秒的节拍器。
// 对到达间隔做个直方图，或者一次自相关，就一眼看穿；而真实 HTTPS 浏览的到达间隔
// 是重尾且高度不规则的。填充把**长度**修得再像也没用，长度和时序是两个独立的维度。
//
// 抖动保持均值不变，所以路径死亡的检测时延基本不受影响（最坏晚 0.4 个间隔）。
func jitter(d time.Duration) time.Duration {
	span := int64(d) * 8 / 10 // ±40%
	if span <= 0 {
		return d
	}
	return d - time.Duration(span/2) + time.Duration(int64(fastRand())%span)
}

// heartbeatLoop 在判决窗口内把**静默间隔**填掉。
//
// ★ 这是 design.md 机制 6a 的另一半，padding.go 里 maybeHeartbeat 那段注释写得很清楚：
// 只填"有数据要发的帧"是不够的，交互流量的静默间隔本身就是特征
// （请求-等待-响应的节奏在包到达时间上一览无余）。
// 但那个函数写完之后**从来没有被任何地方调用过**——长度那一半上线了，时序这一半没有。
//
// 学术上这套叫 adaptive padding（WTF-PAD 及 Tor 的 circuit padding 框架都基于它）：
// 往包间隔里注入假流量，而不是恒定速率发送——后者能根治但会毁掉低延迟。
func (p *path) heartbeatLoop() {
	const nominal = 150 * time.Millisecond
	for {
		d := jitter(nominal)
		select {
		case <-p.dead:
			return
		case <-p.sess.closed:
			return
		case <-time.After(d):
		}
		if p.pad.Phase() != PhaseDecision {
			return // 判决窗口过了、或填充被关了（bare），之后不再需要
		}
		// 链路本来就在发东西时不插：那时没有静默间隔可填，
		// 硬插只是白花判决窗口那点预算。
		if time.Since(time.Unix(0, p.lastSent.Load())) < d {
			continue
		}
		if !p.pad.maybeHeartbeat() {
			continue
		}
		// 空 PADDING 帧，长度由 padFor 从同一张 HTTPS 分布表里采样。
		// 接收方 MUST 丢弃（spec §2.2），所以它对上层完全透明。
		p.writeFrame(FramePadding, FlagPush, 0, nil)
	}
}

func (p *path) probeLoop(interval, idleInterval time.Duration) {
	// ★ 立刻探一次，不要先等一个周期。
	// score() 在没有 RTT 样本时返回中性值 50（毫秒当量），而一条正常的 TCP 路径
	// 只有 3 左右——于是新建的 QUIC 路径在拿到第一个样本之前**看起来比 TCP 差**，
	// 调度器不会往它上面迁。实测这段窗口让每次会话开头有几秒钟的流量白白走在
	// 慢一个数量级的路径上（单流 40 秒的测试里是 8.1MiB / 10%）。
	p.sendProbe()
	t := time.NewTimer(jitter(interval))
	defer t.Stop()
	for {
		select {
		case <-p.dead:
			return
		case <-p.sess.closed:
			return
		case <-t.C:
		}

		p.reapProbes()
		p.checkSilence()
		if p.State() == pathDead {
			return
		}
		p.sendProbe()

		d := interval
		if p.sess.activeStreams() == 0 {
			d = idleInterval
		}
		t.Reset(jitter(d))
	}
}

func (p *path) sendProbe() {
	p.hmu.Lock()
	p.probeSq++
	seq := p.probeSq
	p.pending[seq] = probeRec{sent: time.Now()}
	p.hmu.Unlock()

	var buf [16]byte
	binary.BigEndian.PutUint64(buf[:8], seq)
	binary.BigEndian.PutUint64(buf[8:], uint64(time.Now().UnixNano()))
	// 探测帧走 PUSH：它的价值全在时效性上，被攒批攒掉就失去意义了。
	p.writeFrame(FramePathProbe, FlagPush, 0, buf[:])
	p.flush()
}

func (p *path) onProbe(payload []byte) {
	if len(payload) < 16 {
		return
	}
	// 原样回显对方的 seq 与时间戳：接收方不需要时钟同步，只用自己的两次读数算差值。
	p.writeFrame(FramePathAck, FlagPush, 0, payload[:16])
	p.flush()
}

func (p *path) onProbeAck(payload []byte) {
	if len(payload) < 16 {
		return
	}
	seq := binary.BigEndian.Uint64(payload[:8])
	p.hmu.Lock()
	rec, ok := p.pending[seq]
	if !ok {
		p.hmu.Unlock()
		return
	}
	delete(p.pending, seq)
	rtt := time.Since(rec.sent)
	// rec.reaped 的样本照收不误——这正是"链路变慢了"唯一能传进估计器的路径。
	// 见 probeRec 的说明：探测 seq 唯一且不重传，没有 Karn 歧义。
	p.updateRTTLocked(rtt)
	p.loss = p.loss * 0.85 // 一个成功样本把丢包估计往下拉
	p.goodRun++
	p.badRun = 0
	promote := p.goodRun >= recoverAfterGoodProbes
	loss := p.loss
	p.hmu.Unlock()

	if promote {
		cur := p.State()
		switch {
		case cur == pathDead:
			// 已判死不复活：会话侧的流已经撤离，复活会造成两条路径同时认领同一批流。
		case loss > migrateLossThreshold:
			p.setState(pathDegraded)
		default:
			p.setState(pathActive)
		}
	}
}

func (p *path) updateRTTLocked(rtt time.Duration) {
	if p.srtt == 0 {
		p.srtt = rtt
		p.rttvar = rtt / 2
		p.minRTT = rtt
		return
	}
	// RFC 6298 的平滑参数。
	diff := p.srtt - rtt
	if diff < 0 {
		diff = -diff
	}
	p.rttvar = (3*p.rttvar + diff) / 4
	p.srtt = (7*p.srtt + rtt) / 8
	if rtt < p.minRTT || p.minRTT == 0 {
		p.minRTT = rtt
	}
}

// probeTimeout 取 max(3×SRTT + 4×RTTVAR, DefaultProbeTimeout)。
// 下界是为了不误杀高延迟线路——卫星/跨洲链路 RTT 600ms 是正常的，
// 用固定 2s 判丢会让它一直处于"丢包 100%"的假象里。
func (p *path) probeTimeout() time.Duration {
	p.hmu.Lock()
	defer p.hmu.Unlock()
	return p.probeTimeoutLocked()
}

// probeTimeoutLocked 在 3×SRTT+4×RTTVAR 的基础上按连续丢失次数**指数退避**。
//
// 退避不是可选的调优：RFC 6298 §5.5（"the host MUST set RTO <- RTO * 2"）和
// RFC 9002 §6.2 的 PTO（duration × 2^pto_count）都要求它，理由一样——
// 连续超时最可能的解释是"链路真的变慢/拥塞了"，而不是"对端没了"。
// 少了这一项，尺子就是死的：链路一旦慢过下界，每个探测都判丢，谁也救不回来。
func (p *path) probeTimeoutLocked() time.Duration {
	t := 3*p.srtt + 4*p.rttvar
	if t < DefaultProbeTimeout {
		t = DefaultProbeTimeout
	}
	if n := p.badRun; n > 0 {
		if n > maxProbeBackoffShift {
			n = maxProbeBackoffShift
		}
		t <<= uint(n)
	}
	if t > maxProbeTimeout {
		t = maxProbeTimeout
	}
	return t
}

func (p *path) reapProbes() {
	now := time.Now()
	p.hmu.Lock()
	// 逐个判、每判丢一个就重算尺子：退避必须在这一轮内生效。
	// 否则一次 reap 会拿同一把（最短的）尺子把所有在途探测一次性判死，
	// 指数退避还没来得及张开，badRun 就已经越过 deadAfterLostProbes 了。
	for seq, rec := range p.pending {
		switch {
		case rec.reaped:
			// 已判丢的记录只留一段时间，供迟到的应答贡献样本，之后回收。
			if now.Sub(rec.sent) > probeRetainHorizon {
				delete(p.pending, seq)
			}
		case now.Sub(rec.sent) > p.probeTimeoutLocked():
			rec.reaped = true
			p.pending[seq] = rec
			p.loss = p.loss*0.85 + 0.15
			p.badRun++
			p.goodRun = 0
		}
	}
	bad := p.badRun
	loss := p.loss
	p.hmu.Unlock()

	// ★ 收到过字节的路径不能凭探测判死。
	//
	// 探测超时只说明"这一来一回超过了尺子"，不说明对端没了——RFC 9002 §6.2
	// 把这点写得很直白："a PTO timer expiration event does not indicate packet loss"。
	// 本文件对 checkSilence 早就是这么讲的（noteRecv 的注释：满速传输的路径
	// 不能被静默计时器判死），只是这条推理没有走到探测这一侧来。
	//
	// 判死交给 checkSilence——它看的是物理证据（多久没收到一个字节），
	// 那是比"探测慢了"硬得多的判据。这里最多降级，让调度器把流挪走。
	if bad >= deadAfterLostProbes {
		if idle := time.Since(time.Unix(0, p.lastRecv.Load())); idle < p.probeTimeout() {
			p.setState(pathDegraded)
			return
		}
	}

	switch {
	case bad >= deadAfterLostProbes:
		p.markDeadReason("lost " + itoa(bad) + " consecutive probes")
	case bad >= suspectAfterLostProbes:
		p.setState(pathSuspect)
	case loss > migrateLossThreshold && p.State() == pathActive:
		p.setState(pathDegraded)
	}
}

// checkSilence 是探测机制之外的第二个死亡判据：一段时间内**一个字节都没收到**。
//
// 为什么需要第二个来源：探测的往返依赖对端还在响应；如果对端进程还活着但会话状态
// 已经丢了（比如服务端重启后 session_id 不认识了），探测可能仍然被回复，
// 而流数据永远不会来。静默计时器不看语义，只看物理层面有没有字节，是更硬的证据。
func (p *path) checkSilence() {
	last := time.Unix(0, p.lastRecv.Load())
	if d := time.Since(last); d > DefaultPathDeadAfter {
		p.markDeadReason("silent for " + d.Round(time.Millisecond).String())
	}
}

func (p *path) setState(s pathState) {
	old := pathState(p.state.Swap(uint32(s)))
	if old != s {
		p.sess.onPathState(p, old, s)
	}
}

// noteRecv 记一次收到数据。
//
// ★ QUIC 多流模式下这条**必须**被每条数据流调用：静默计时器（checkSilence）
// 是路径死亡的第二个判据，它只看"多久没收到字节"。分流之后控制流上可能长时间
// 只有稀疏的探测，真正的数据全在别的 QUIC 流上——不在那里打点，
// 一条正在满速传输的路径会被静默计时器判死。
func (p *path) noteRecv(n int) {
	p.lastRecv.Store(time.Now().UnixNano())
	p.rxBytes.Add(uint64(n))
}

// noteRecvDatagram 同 noteRecv，外加记下"这些字节走的是不可靠数据面"。
func (p *path) noteRecvDatagram(n int) {
	p.noteRecv(n)
	p.rxDgram.Add(uint64(n))
}

// noteSentDatagram 记一次从不可靠数据面发出的字节。
func (p *path) noteSentDatagram(n int) {
	p.txBytes.Add(uint64(n))
	p.txDgram.Add(uint64(n))
}

func (p *path) markDead() { p.markDeadReason("unspecified") }

func (p *path) markDeadReason(reason string) {
	p.deadOnce.Do(func() {
		p.deadReason.Store(reason)
		p.state.Store(uint32(pathDead))
		close(p.dead)
		p.wmu.Lock()
		p.wclosed = true
		p.wcond.Broadcast()
		p.wmu.Unlock()
		if p.qmux != nil {
			p.qmux.close()
		}
		if p.h3 != nil {
			p.h3.close()
		}
		p.conn.Close()
		p.sess.onPathDead(p)
	})
}

// flush 触发写 goroutine 立刻处理缓冲（PUSH 语义）。
func (p *path) flush() {
	p.wmu.Lock()
	p.wcond.Signal()
	p.wmu.Unlock()
}

// score 给调度器排序用：越小越好。
//
// ★ 这里有一条实测才发现、而且相当反直觉的事实：**TCP 路径的丢包率从上层看恒等于 0。**
//
// PATH_PROBE 走在 TCP 连接里，丢了的段由内核重传，探测最终总会到达——只是变慢。
// 所以 p.loss 这个字段在 TCP 路径上永远接近 0，spec §8 那条"TCP 路径丢包率持续超过
// 2% 时迁移"的判据，按字面实现是**永远不会触发**的。
// 树莓派↔x86 实测（netem 5% 丢包）：TCP 路径 loss=0.00% 而 srtt=44.69ms，
// 同一时刻并存的 QUIC 路径 srtt=1.26ms。丢包在 TCP 上不表现为丢包，表现为 **RTT 膨胀**。
//
// 因此评分以 RTT 为主、抖动为辅，丢包只作为 QUIC 这类能真实观测到丢包的路径的补充信号。
// rttvar 单独计权，是因为同样的平均延迟下抖动大的链路交互体验明显更差。
func (p *path) score() float64 {
	p.hmu.Lock()
	defer p.hmu.Unlock()
	rtt := float64(p.srtt) / float64(time.Millisecond)
	if rtt == 0 {
		rtt = 50 // 还没有样本，给个中性值
	}
	jit := float64(p.rttvar) / float64(time.Millisecond)
	sc := rtt + 2*jit
	if !math.IsNaN(p.loss) {
		sc += p.loss * 2000
	}
	return sc
}

// h3DatagramFrame 在 h3 路径上把一帧序列化成 HTTP Datagram 的载荷。
// 非 h3 路径返回 ok=false，调用方转而走 RFC 9221 的 QUIC 数据报。
func (p *path) h3DatagramFrame(flags uint8, streamID uint64, payload []byte) ([]byte, bool) {
	if p.h3 == nil && p.h3srv == nil {
		return nil, false
	}
	return AppendFrame(nil, FrameDatagram, flags, streamID, payload, 0), true
}

// sendH3Datagram 走 RFC 9297。客户端侧与服务端侧各持有同一条控制流的一端。
func (p *path) sendH3Datagram(buf []byte) error {
	var err error
	switch {
	case p.h3 != nil:
		err = p.h3.sendDatagram(buf)
	case p.h3srv != nil:
		err = p.h3srv.SendDatagram(buf)
	default:
		return errNoQUICStream
	}
	if err == nil {
		p.noteSentDatagram(len(buf))
	}
	return err
}

// MinRTT 返回观测到的最小往返，即链路的传播时延（不含排队）。
//
// ★ 算 BDP 必须用它而不是 SRTT。SRTT 在拥塞时已经被排队时延撑大了，
// 拿它算出来的 BDP 会把"队列里积压的字节"也算成"链路容量"，
// 于是窗口越算越大、队列越排越长——正是要避免的那个正反馈。
// BBR 用 min_rtt × delivery_rate 估 BDP，也是同一个道理。
func (p *path) MinRTT() time.Duration {
	p.hmu.Lock()
	defer p.hmu.Unlock()
	return p.minRTT
}
