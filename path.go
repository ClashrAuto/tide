package tide

import (
	"encoding/binary"
	"errors"
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
)

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
	pending map[uint64]time.Time
	goodRun int
	badRun  int

	state    atomic.Uint32
	lastRecv atomic.Int64 // UnixNano
	created  time.Time
	// 收发字节数。调度器的决策（哪条流走哪条路）除了看这个没有别的办法验证——
	// "QUIC 路径建起来了"和"数据真的走了 QUIC"是两件事。
	txBytes atomic.Uint64
	rxBytes atomic.Uint64

	// qmux 非空 = QUIC 多流模式：每条 TIDE 流一条独立的 QUIC 流（见 quicmux.go）。
	// 单流模式下为 nil，所有帧走 conn 那一条字节流。
	qmux *quicMux
	// h3 非空 = 这条路径跑在 HTTP/3 之上（spec §12.6）。
	h3 *h3Client

	dead     chan struct{}
	deadOnce sync.Once
}

func newPath(s *Session, id uint32, kind string, conn net.Conn, sealKey, openKey []byte, useAES bool, bare bool) (*path, error) {
	p := &path{
		id:      id,
		kind:    kind,
		sess:    s,
		conn:    conn,
		pad:     newPaddingScheduler(),
		pending: make(map[uint64]time.Time),
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
	} else {
		// bare 模式下用户态不做任何 AEAD，这正是 kTLS/splice 能生效的前提；
		// 填充也随之关闭——要插填充就得在用户态碰载荷，那 splice 就没了。
		p.pad.disable()
	}
	p.fr = newFrameReader(src)
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
	// UDP 走 RFC 9221 的 QUIC 数据报：不重传、不保序，才是 UDP 该有的语义。
	// 太大装不下时下面会回退到控制流（可靠），见 quicMux.sendDatagram。
	if p.qmux != nil && !p.qmux.h3 && t == FrameDatagram {
		if err := p.qmux.sendDatagram(flags, streamID, payload); err == nil {
			return nil
		} else if !errors.Is(err, errDatagramTooLarge) {
			return err
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
	defer p.markDead()
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
	}
}

// ---------------------------------------------------------------------------
// 读
// ---------------------------------------------------------------------------

func (p *path) readLoop() {
	defer p.markDead()
	for {
		f, err := p.fr.ReadFrame()
		if err != nil {
			return
		}
		p.noteRecv(len(f.Payload))
		if err := p.sess.handleFrame(p, f); err != nil {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// 探测与健康
// ---------------------------------------------------------------------------

func (p *path) probeLoop(interval, idleInterval time.Duration) {
	// ★ 立刻探一次，不要先等一个周期。
	// score() 在没有 RTT 样本时返回中性值 50（毫秒当量），而一条正常的 TCP 路径
	// 只有 3 左右——于是新建的 QUIC 路径在拿到第一个样本之前**看起来比 TCP 差**，
	// 调度器不会往它上面迁。实测这段窗口让每次会话开头有几秒钟的流量白白走在
	// 慢一个数量级的路径上（单流 40 秒的测试里是 8.1MiB / 10%）。
	p.sendProbe()
	t := time.NewTimer(interval)
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
		t.Reset(d)
	}
}

func (p *path) sendProbe() {
	p.hmu.Lock()
	p.probeSq++
	seq := p.probeSq
	p.pending[seq] = time.Now()
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
	sent, ok := p.pending[seq]
	if !ok {
		p.hmu.Unlock()
		return
	}
	delete(p.pending, seq)
	rtt := time.Since(sent)
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
	t := 3*p.srtt + 4*p.rttvar
	if t < DefaultProbeTimeout {
		t = DefaultProbeTimeout
	}
	return t
}

func (p *path) reapProbes() {
	to := p.probeTimeout()
	now := time.Now()
	lost := 0
	p.hmu.Lock()
	for seq, sent := range p.pending {
		if now.Sub(sent) > to {
			delete(p.pending, seq)
			lost++
		}
	}
	if lost > 0 {
		for i := 0; i < lost; i++ {
			p.loss = p.loss*0.85 + 0.15
		}
		p.badRun += lost
		p.goodRun = 0
	}
	bad := p.badRun
	loss := p.loss
	p.hmu.Unlock()

	switch {
	case bad >= deadAfterLostProbes:
		p.markDead()
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
	if time.Since(last) > DefaultPathDeadAfter {
		p.markDead()
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

func (p *path) markDead() {
	p.deadOnce.Do(func() {
		p.state.Store(uint32(pathDead))
		close(p.dead)
		p.wmu.Lock()
		p.wclosed = true
		p.wcond.Broadcast()
		p.wmu.Unlock()
		if p.qmux != nil {
			p.qmux.close()
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
