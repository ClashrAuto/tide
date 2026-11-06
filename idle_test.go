package tide

// 空闲时不留定时器的回归测试（2026-11-06 真机账，见 idle.go）。
//
// 现场：iPhone 上挂着空闲 tide 会话 184~283 唤醒/秒，超过内核 150 次/秒的限额；
// iMac 上量到单边 130 次/秒（新路径头 15 秒，判决窗口心跳）、之后 30 次/秒
// （250ms 重传扫描 + 500ms 宽限看门狗 + 2s rebalance / 补路），服务端孤儿会话 53 次/秒
// （再加 200ms 恢复轮询）。Go 在 Darwin 上每个定时器触发约 3.3 次唤醒，所以
// 这里钉的是「循环确实停下来了」，以及更要紧的另一面：**停下来之后该醒还得醒**。
// 后者错了不会有任何征兆，只是某一次丢包、断网之后流永远卡住。

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func waitFor(t *testing.T, what string, within time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("等了 %v：%s", within, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func echoOnce(t *testing.T, c net.Conn, n int) {
	t.Helper()
	payload := bytes.Repeat([]byte("E"), n)
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, make([]byte, n)); err != nil {
		t.Fatalf("回声没回来：%v", err)
	}
	c.SetReadDeadline(time.Time{})
}

func onlyServerSession(t *testing.T, h *harness) *Session {
	t.Helper()
	var s *Session
	waitFor(t, "服务端上没有会话", 5*time.Second, func() bool {
		h.srv.mu.Lock()
		defer h.srv.mu.Unlock()
		for _, ss := range h.srv.sessions {
			s = ss.sess
			return true
		}
		return false
	})
	return s
}

// 没有载荷的路径上一帧心跳都不跳：线上是静的，判决预算原样留给真流量。
func TestIdlePathSendsNoHeartbeat(t *testing.T) {
	var mu sync.Mutex
	var at []time.Time
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		cc.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := net.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			return &tsConn{Conn: c, mu: &mu, at: &at}, nil
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 握手、首探和第二探都落地。第二探按快档的 1s±40% 排（probeLoop 还不知道这条路径空闲），
	// 再往后就是 15s 慢档，下面这个窗口里线上不该有东西。
	time.Sleep(1500 * time.Millisecond)
	mu.Lock()
	at = at[:0]
	mu.Unlock()

	// 旧行为这段里有 2s×6.7拍×0.35 ≈ 5 帧，一帧都没有的概率 0.4%。
	time.Sleep(2 * time.Second)

	mu.Lock()
	n := len(at)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("空闲路径上写了 %d 次：心跳在没有载荷时还在跳，判决预算被白烧", n)
	}
	p := sess.pathsSnapshot()[0]
	if !p.hbGate.parked.Load() {
		t.Fatal("心跳循环没有停下来，定时器还在转")
	}
	if ph := p.pad.Phase(); ph != PhaseDecision {
		t.Fatalf("真流量还没来，判决窗口就过了：%v", ph)
	}
}

// 载荷来了心跳要跳起来（这才是它的本职），载荷停了跟着停，再来再跳。
func TestHeartbeatFollowsPayload(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p := sess.pathsSnapshot()[0]
	srvp := onlyServerPath(t, h)
	// 先看它们停下：路径刚建好时协程可能还没走到 park，下面的「醒了」会白白成立。
	waitFor(t, "客户端的心跳没有停下", time.Second, p.hbGate.parked.Load)
	waitFor(t, "服务端的心跳没有停下", time.Second, srvp.hbGate.parked.Load)

	echoOnce(t, c, 512)
	for name, q := range map[string]*path{"客户端": p, "服务端": srvp} {
		q := q
		waitFor(t, name+"的心跳没有被载荷叫醒", 2*time.Second, func() bool { return !q.hbGate.parked.Load() })
	}
	// 窗口过后两边都停。假帧的长度是重尾的，偶尔这几秒就把 64 KiB 花完了，
	// 那时循环是退出而不是停车，同样算停。
	stopped := func(q *path) bool { return q.hbGate.parked.Load() || q.pad.Phase() != PhaseDecision }
	for name, q := range map[string]*path{"客户端": p, "服务端": srvp} {
		q := q
		waitFor(t, name+"的心跳过了窗口还没停", heartbeatActivityWindow+2*time.Second, func() bool { return stopped(q) })
	}
	if p.pad.Phase() != PhaseDecision {
		return
	}
	echoOnce(t, c, 512)
	waitFor(t, "心跳第二次没有被叫醒", 2*time.Second, func() bool { return !p.hbGate.parked.Load() })
}

// 只有一个方向有载荷时，两端的路径都算活跃：发的一端和收的一端是两处记账，
// 漏掉一处的话单向下载时服务端（或客户端）那头的静默就没人填了。
func TestHeartbeatCountsBothDirections(t *testing.T) {
	payload := make([]byte, 512)
	for _, tc := range []struct {
		name    string
		clientW bool
	}{{"客户端只发", true}, {"服务端只发", false}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			release := make(chan struct{})
			h.srv.Handler = func(_ context.Context, st *Stream) {
				defer st.Close()
				if !tc.clientW {
					<-release
					st.Write(payload)
				}
				io.Copy(io.Discard, st)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			sess, err := h.client.Session(ctx)
			if err != nil {
				t.Fatal(err)
			}
			p := sess.pathsSnapshot()[0]
			srvp := onlyServerPath(t, h)
			waitFor(t, "客户端的心跳没有停下", time.Second, p.hbGate.parked.Load)
			waitFor(t, "服务端的心跳没有停下", time.Second, srvp.hbGate.parked.Load)
			if tc.clientW {
				if _, err := c.Write(payload); err != nil {
					t.Fatal(err)
				}
			} else {
				close(release)
			}
			waitFor(t, "客户端的心跳没醒", 2*time.Second, func() bool { return !p.hbGate.parked.Load() })
			waitFor(t, "服务端的心跳没醒", 2*time.Second, func() bool { return !srvp.hbGate.parked.Load() })
		})
	}
}

// 判决窗口的预算要花在真流量上：空闲一段之后第一笔真数据仍然要被填充。
func TestDecisionBudgetSurvivesIdle(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p := sess.pathsSnapshot()[0]
	time.Sleep(1500 * time.Millisecond) // 让头两个探测过去，它们走填充是对的
	p.pad.mu.Lock()
	before := p.pad.bytes
	p.pad.mu.Unlock()
	time.Sleep(1500 * time.Millisecond)
	p.pad.mu.Lock()
	after := p.pad.bytes
	p.pad.mu.Unlock()
	if after != before {
		t.Fatalf("空闲 1.5 秒花掉了 %d 字节判决预算", after-before)
	}
}

// 冗余路径没有载荷，不能因为会话活跃就跟着跳：对观察者那是一条无缘无故发随机包的连接。
func TestHeartbeatStaysOffTheSparePath(t *testing.T) {
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) { cc.Redundancy = true })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "第二条路径没建起来", 10*time.Second, func() bool { return len(sess.pathsSnapshot()) >= 2 })
	c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	echoOnce(t, c, 512)

	var carrying, spare *path
	waitFor(t, "没有哪条路径在跳心跳", 2*time.Second, func() bool {
		carrying, spare = nil, nil
		for _, p := range sess.pathsSnapshot() {
			if p.hbGate.parked.Load() {
				spare = p
			} else {
				carrying = p
			}
		}
		return carrying != nil
	})
	if spare == nil {
		t.Fatal("两条路径都在跳心跳：空着的那条也被算成了活跃")
	}
}

// 重传扫描：开着不说话的流（推送长连接）不留定时器，客户端、服务端都是。
//
// ★ 写之前先等一下，别删：建流时服务端会回一个 ACK，那个 ackFlushLoop 跑尾的时候要是
// 数据正好到了，会被它顺手确认掉，这条用例就碰巧绿了。真实的长连接是「开了一阵才写一点」，
// 那时候没有人带它，只能靠延迟确认（见 ackDelay）。
func TestRetransmitLoopParksWithOpenStream(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	srvs := onlyServerSession(t, h)
	time.Sleep(300 * time.Millisecond)
	echoOnce(t, c, 64)
	waitFor(t, "客户端的重传扫描没停", 2*time.Second, sess.rtoGate.parked.Load)
	waitFor(t, "服务端的重传扫描没停", 2*time.Second, srvs.rtoGate.parked.Load)
}

// 小写操作要被确认，不能靠 RTO 把尾巴再发一遍。
//
// 这是 2026-11-06 真正把手机钉在 200 次/秒上的那个缺陷：确认只看 32 KiB 阈值，
// 长连接上的小写操作永远等不到确认，RTO 就退避着一直重发，而重发算真实载荷，
// 探测被顶回 1 秒快档、心跳也停不下来（见 ackDelay）。
func TestSmallWriteIsAckedNotRetransmitted(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	srvs := onlyServerSession(t, h)
	time.Sleep(300 * time.Millisecond)
	echoOnce(t, c, 64)
	last, srvLast := sess.lastPayload.Load(), srvs.lastPayload.Load()

	// 第一次 RTO 在 500ms 上下，这段时间足够旧行为重发两三轮。
	time.Sleep(2 * time.Second)

	if n := sess.resumes.Load() + srvs.resumes.Load(); n != 0 {
		t.Fatalf("没有丢任何东西，却重发了 %d 次：小写操作没有被确认", n)
	}
	if sess.lastPayload.Load() != last || srvs.lastPayload.Load() != srvLast {
		t.Fatal("没有新数据，lastPayload 却在涨：重发被算成了真实载荷，探测会被钉回快档")
	}
}

// 上一条的实网形状。环回上确认几乎不花时间，RTO 的钟走没走对根本看不出来；
// 单向时延一上来，确认要 ackDelay + 时延才回得来，晚于重传扫描的第一拍。
func TestSmallWriteOnLaggyLinkIsNotRetransmitted(t *testing.T) {
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		cc.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := net.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			return newLaggyConn(c, 100*time.Millisecond), nil
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 空闲够久，让 lastProgress 旧过 RTO。
	time.Sleep(time.Second)
	echoOnce(t, c, 64)
	time.Sleep(1500 * time.Millisecond)
	if n := sess.resumes.Load(); n != 0 {
		t.Fatalf("链路只是慢，字节却被重发了 %d 次", n)
	}
}

// 空闲之后第一次写，RTO 要从这一刻算，不能从上一次 ACK 算。
func TestFirstWriteAfterIdleRestartsRTOClock(t *testing.T) {
	s := newSession([16]byte{1}, true, DefaultStreamWindow, time.Minute, time.Second, 16)
	defer s.closeWith(ErrClosed)
	st := newStream(s, 1, "x", DefaultStreamWindow)
	st.lastProgress.Store(time.Now().Add(-time.Hour).UnixNano())
	if _, err := st.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if st.stalledFor(time.Now(), 500*time.Millisecond) {
		t.Fatal("刚写的字节被判成卡住了")
	}
	if !st.stalledFor(time.Now().Add(time.Second), 500*time.Millisecond) {
		t.Fatal("过了 RTO 还没确认，应该算卡住")
	}
}

// 两个确认挨着到达时不能算出一个天文数字的速率，否则在途上限被撑到整个窗口。
func TestCloseAcksDoNotInflateDeliveredRate(t *testing.T) {
	st := &Stream{window: DefaultStreamWindow}
	st.pathMinRTT.Store(int64(40 * time.Millisecond))
	now := time.Now()
	st.noteDeliveredLocked(0, now)
	// 真实速率 64 KiB/s：每 200ms 确认 13 KiB，其中每一轮都紧跟着一个 0.1ms 之后的小确认。
	for i := 0; i < 50; i++ {
		now = now.Add(ackDelay)
		st.noteDeliveredLocked(13*1024, now)
		now = now.Add(100 * time.Microsecond)
		st.noteDeliveredLocked(4*1024, now)
	}
	const real = (13 + 4) * 1024 * 5
	if st.deliveredRate > real*2 {
		t.Fatalf("速率估计 %.0f B/s，真实约 %d", st.deliveredRate, real)
	}
	if c := st.inflightCapLocked(); c != minInflightCap {
		t.Fatalf("在途上限被撑到 %d，这条链路只该有下界 %d", c, minInflightCap)
	}
}

// 一条路径都没有时，在途上限要停在断网前的值。RTT 缓存被冲成 0 的话，上限放到整个窗口，
// 被路径背压挡住的写侧在路径判死的那一刻全放开，断网期间白灌几百 KiB 进重传缓冲。
func TestNoPathKeepsCachedRTT(t *testing.T) {
	s := newSession([16]byte{1}, true, DefaultStreamWindow, time.Minute, time.Second, 16)
	defer s.closeWith(ErrClosed)
	st := newStream(s, 1, "x", DefaultStreamWindow)
	s.mu.Lock()
	s.streams[st.id] = st
	s.mu.Unlock()
	st.pathMinRTT.Store(int64(40 * time.Millisecond))
	st.pathRTT.Store(int64(40 * time.Millisecond))
	st.wmu.Lock()
	st.deliveredRate = 65 * 1024
	st.wmu.Unlock()
	if _, err := st.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	go s.retransmitLoop()
	time.Sleep(400 * time.Millisecond) // 够它扫一遍

	st.wmu.Lock()
	c := st.inflightCapLocked()
	st.wmu.Unlock()
	if c != minInflightCap {
		t.Fatalf("没有路径时在途上限变成了 %d，应该停在 %d", c, minInflightCap)
	}
}

type laggyWrite struct {
	at time.Time
	b  []byte
}

// laggyConn 给写方向加固定时延，保序。
type laggyConn struct {
	net.Conn
	d    time.Duration
	q    chan laggyWrite
	done chan struct{}
	once sync.Once
}

func newLaggyConn(c net.Conn, d time.Duration) *laggyConn {
	l := &laggyConn{Conn: c, d: d, q: make(chan laggyWrite, 4096), done: make(chan struct{})}
	go func() {
		for {
			select {
			case <-l.done:
				return
			case w := <-l.q:
				time.Sleep(time.Until(w.at))
				if _, err := c.Write(w.b); err != nil {
					return
				}
			}
		}
	}()
	return l
}

func (l *laggyConn) Write(p []byte) (int, error) {
	select {
	case l.q <- laggyWrite{time.Now().Add(l.d), append([]byte(nil), p...)}:
		return len(p), nil
	case <-l.done:
		return 0, net.ErrClosed
	}
}

func (l *laggyConn) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Conn.Close()
}

// 确认丢了（死在路径上）时，发送方重发的是对端早收齐的字节，对端必须回话，
// 否则发送方永远不知道可以收手。TCP 的 dup ACK 同理。
func TestDuplicateSegmentGetsAnAck(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	echoOnce(t, c, 64)
	sess.mu.Lock()
	var st *Stream
	for _, x := range sess.streams {
		st = x
	}
	sess.mu.Unlock()
	acked := func() bool {
		st.wmu.Lock()
		defer st.wmu.Unlock()
		return st.ackOff == st.sendOff
	}
	waitFor(t, "第一次确认没到", 2*time.Second, acked)

	// 让发送方回到「确认没收到」的状态：把最后 16 字节退回未确认再重发一遍。
	const n = 16
	st.wmu.Lock()
	st.ackOff = st.sendOff - n
	st.pendOff = st.ackOff
	st.retx = append(st.retx[:0], make([]byte, n)...)
	st.wmu.Unlock()
	st.rewind()

	waitFor(t, "重复段没有换回确认，发送方收不了手", 150*time.Millisecond, acked)
}

// ★ 这条是最要紧的：扫描停下来之后，丢掉的字节仍然要能重发回来。
//
// TCP 路径上没法真的丢一帧（记录层的序号一乱路径就死了），所以这里做的是「内核收了但
// 对端没收到」的等价形态：字节记进重传缓冲、pendOff 推过去，当作已经上过线；然后走
// **生产路径**发一帧给对端不认识的流，它被静默丢弃，唯一的作用是踩一次 sendOnStream
// 里的叫醒。叫醒漏掉的话这条流就永远卡着——零报错，这正是 RTO 存在要防的那种故障。
func TestRetransmitWakesFromParkAndRecoversLoss(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	echoOnce(t, c, 512)
	waitFor(t, "重传扫描没停", 2*time.Second, sess.rtoGate.parked.Load)

	sess.mu.Lock()
	var st *Stream
	for _, x := range sess.streams {
		st = x
	}
	sess.mu.Unlock()
	lost := bytes.Repeat([]byte("L"), 2048)
	st.wmu.Lock()
	st.retx = append(st.retx, lost...)
	st.sendOff += uint64(len(lost))
	st.pendOff = st.sendOff
	st.wmu.Unlock()

	ghost := &Stream{id: 1 << 40, sess: sess}
	if err := sess.sendOnStream(ghost, FrameStreamData, 0, AppendVarint(nil, 0)); err != nil {
		t.Fatal(err)
	}

	got := make([]byte, len(lost))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("丢掉的字节没有被重发：%v（重传扫描停下之后没有被叫醒）", err)
	}
	if !bytes.Equal(got, lost) {
		t.Fatal("重发的内容不对")
	}
}

// rebalance 同理：停下来之后载荷一来要醒。
func TestRebalanceLoopParksAndWakes(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "rebalance 没停", 3*time.Second, sess.rebalGate.parked.Load)
	sess.notePayload()
	waitFor(t, "rebalance 没有被载荷叫醒", time.Second, func() bool { return !sess.rebalGate.parked.Load() })
}

// 补路循环睡在路径事件上：路径死了、或者只是变差了，都要在一个短拍之内补上，
// 不能等 30 秒的兜底。这条挡的是「切网时第二条路径迟迟不回来」。
func TestRedundancyRedialsFromParkedWait(t *testing.T) {
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) { cc.Redundancy = true })
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "第二条路径没建起来", 10*time.Second, func() bool { return len(sess.pathsSnapshot()) >= 2 })
	// 等它数过一遍、睡到路径事件上。
	time.Sleep(redundancyCheckInterval * 3 / 2)

	added := sess.pathsAdded.Load()
	sess.pathsSnapshot()[0].conn.Close()
	waitFor(t, "路径死了之后没有补上", 5*time.Second, func() bool { return sess.pathsAdded.Load() > added })

	waitFor(t, "补回两条", 5*time.Second, func() bool {
		n := 0
		for _, p := range sess.pathsSnapshot() {
			if p.usable() {
				n++
			}
		}
		return n >= 2
	})
	time.Sleep(redundancyCheckInterval * 3 / 2)
	added = sess.pathsAdded.Load()
	// 这条路径其实是好的，碰上一个探测应答就会被升回 active，这里要的是「它一直差」。
	p := sess.pathsSnapshot()[0]
	p.hmu.Lock()
	p.goodRun = -1 << 20
	p.hmu.Unlock()
	p.setState(pathSuspect)
	waitFor(t, "路径变差之后没有补路", 5*time.Second, func() bool { return sess.pathsAdded.Load() > added })
}

// 宽限看门狗不再轮询，三件事都要靠路径事件：丢路径开始计时、回来取消、再丢重新计时。
//
// ★ 这条要**单独**测：服务端的 recoverLoop 也会在同一时刻到期，两个一起跑的话看门狗坏了
// 也看不出来。而它正是 recoverLoop 没起来时唯一的兜底（路径恰好在旧循环退出的瞬间又死掉，
// reconnBusy 还没放下，新的 recoverLoop 直接返回）。
func TestGraceWatcherFollowsPathEvents(t *testing.T) {
	const grace = 300 * time.Millisecond
	s := newSession([16]byte{1}, false, DefaultStreamWindow, grace, time.Second, 16)
	defer s.closeWith(ErrClosed)
	srv := &Server{cfg: &ServerConfig{SessionGrace: grace}, stopped: make(chan struct{})}
	defer close(srv.stopped)
	go srv.graceWatcher(s, [16]byte{1})

	lose := func() {
		s.noPathSince.Store(time.Now().UnixNano())
		s.firePathEvent()
	}
	back := func() {
		s.noPathSince.Store(0)
		s.firePathEvent()
	}
	gone := func() bool {
		select {
		case <-s.closed:
			return true
		default:
			return false
		}
	}

	time.Sleep(grace * 3 / 2)
	if gone() {
		t.Fatal("有路径的会话被收掉了")
	}
	lose()
	time.Sleep(grace / 3)
	back()
	time.Sleep(grace * 3 / 2)
	if gone() {
		t.Fatal("客户端回来之后计时没有取消")
	}
	lose()
	waitFor(t, "第二次丢路径之后宽限到期没有收", grace*3, gone)
}

// 服务端等重连不再轮询：路径回来时要当场退出，否则到期会把已经接上的会话关掉。
func TestServerRecoverLoopWakesOnPathEvent(t *testing.T) {
	const grace = 300 * time.Millisecond
	s := newSession([16]byte{1}, false, DefaultStreamWindow, grace, time.Second, 16)
	defer s.closeWith(ErrClosed)
	// 下面塞进去的是个裸夹具，拆毁流程碰不得它。
	defer func() {
		s.mu.Lock()
		s.paths = nil
		s.mu.Unlock()
	}()
	go s.recoverLoop()
	waitFor(t, "recoverLoop 没起来", time.Second, s.reconnBusy.Load)

	s.mu.Lock()
	s.paths = append(s.paths, &path{id: 1, sess: s, dead: make(chan struct{})})
	s.firePathEventLocked()
	s.mu.Unlock()
	waitFor(t, "路径回来之后 recoverLoop 没有退出", grace/2, func() bool { return !s.reconnBusy.Load() })

	time.Sleep(grace * 3 / 2)
	select {
	case <-s.closed:
		t.Fatal("路径已经回来了，会话还是在到期时被关了")
	default:
	}
}

// 上一条的端到端版本，走真的 addPath：路径断了又接回来，过了宽限期会话还要活着、流还能用。
// addPath 忘了发事件的话，服务端的恢复循环睡到期就把已经接上的会话关了，
// 表现是「切网成功了，一两分钟之后所有连接一起断」。
func TestServerSessionOutlivesGraceAfterReconnect(t *testing.T) {
	const grace = 800 * time.Millisecond
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) { sc.SessionGrace = grace })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	srvs := onlyServerSession(t, h)
	echoOnce(t, c, 128)

	killAllPaths(sess)
	waitFor(t, "服务端没有等到路径回来", grace/2, func() bool {
		return srvs.pathsAdded.Load() >= 2 && srvs.noPathSince.Load() == 0
	})
	time.Sleep(grace * 3 / 2)
	select {
	case <-srvs.closed:
		t.Fatal("路径已经接回来了，服务端会话还是到期关了")
	default:
	}
	echoOnce(t, c, 128)
}

// idleGate 不能丢唤醒：生产者先改状态再 kick，消费者怎么交错都要看得到。
// 丢一次的后果是循环永远停着，所以这里拿最紧的节奏撞那个窗口。
func TestIdleGateNeverLosesAWakeup(t *testing.T) {
	var g idleGate
	g.init()
	var pending atomic.Bool
	done := make(chan struct{})
	defer close(done)
	served := make(chan struct{})
	go func() {
		for {
			if !g.park(done, nil, pending.Load) {
				return
			}
			if pending.CompareAndSwap(true, false) {
				served <- struct{}{}
			}
		}
	}()
	for i := 0; i < 200000; i++ {
		pending.Store(true)
		g.kick()
		select {
		case <-served:
		case <-time.After(2 * time.Second):
			t.Fatalf("第 %d 次唤醒丢了", i)
		}
	}
}

// 服务端孤儿会话到期要退干净，在线会话不留看门狗定时器之后这条最容易漏。
func TestOrphanServerSessionExpires(t *testing.T) {
	var gone atomic.Bool
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		sc.SessionGrace = 500 * time.Millisecond
		cc.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if gone.Load() {
				return nil, errors.New("手机进隧道了")
			}
			return net.Dial(network, addr)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	srvs := onlyServerSession(t, h)
	// 客户端不说再见就走：不发 CLOSE，只掐路径，之后也拨不回来。
	gone.Store(true)
	sess.pathsSnapshot()[0].conn.Close()
	select {
	case <-srvs.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("孤儿会话过了宽限期还没收")
	}
}

// onlyServerPath 取服务端会话上的路径。客户端看到 ACCEPT 时服务端可能还没 addPath，要等。
func onlyServerPath(t *testing.T, h *harness) *path {
	t.Helper()
	s := onlyServerSession(t, h)
	var p *path
	waitFor(t, "服务端会话上没有路径", 5*time.Second, func() bool {
		ps := s.pathsSnapshot()
		if len(ps) == 0 {
			return false
		}
		p = ps[0]
		return true
	})
	return p
}
