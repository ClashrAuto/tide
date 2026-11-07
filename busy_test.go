package tide

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

const sec = int64(time.Second)

// 2026-11-07 真机形状：静态时 tide 上每 10 秒两三百字节，偶尔一个 27 KB 的毛刺。
// 这些都不算忙，否则路径会被钉在 1 秒快档上。
func TestBusyMeterIgnoresHeartbeat(t *testing.T) {
	var m busyMeter
	now := 1000 * sec
	for i := 0; i < 600; i++ {
		n := 222 / 3
		if i%60 == 30 {
			for j := 0; j < 20; j++ {
				if m.note(now, 27<<10/20) {
					t.Fatalf("第 %d 拍的毛刺被判成忙", i)
				}
			}
		}
		if m.note(now, n) {
			t.Fatalf("第 %d 拍的心跳被判成忙", i)
		}
		if m.active(now) {
			t.Fatalf("第 %d 拍判成了活跃", i)
		}
		now += 3 * sec
	}
}

func TestBusyMeterBulkFiresOneEdgeThenDecays(t *testing.T) {
	var m busyMeter
	now := 1000 * sec
	edges := 0
	for i := 0; i < 64; i++ {
		if m.note(now, 8<<10) {
			edges++
		}
		now += sec / 100
	}
	if edges != 1 {
		t.Fatalf("一段连续的流量应该只有一个边沿，实际 %d", edges)
	}
	if !m.active(now + int64(probeActivityWindow) - sec) {
		t.Fatal("窗口内不该退回空闲：读网页的停顿不能丢掉快档")
	}
	if m.active(now + int64(probeActivityWindow) + sec) {
		t.Fatal("窗口过了还算忙")
	}
	if m.note(now+int64(probeActivityWindow)+sec, 64<<10) != true {
		t.Fatal("退回空闲之后再忙起来要有新的边沿")
	}
}

// 语音：字节不多，但帧多，而且用户在等它。数据报没有确认，RTO 那条路帮不上忙，
// 所以它必须靠这里切快档。
func TestBusyMeterCountsSmallFrames(t *testing.T) {
	var m busyMeter
	now := 1000 * sec
	for i := 0; i < 30*5; i++ {
		m.note(now, 60)
		now += sec / 30
	}
	if !m.active(now) {
		t.Fatal("30 帧/秒的小包流没有判成忙")
	}
}

func TestBusyMeterMarkIsAnEdgeOnce(t *testing.T) {
	var m busyMeter
	if !m.mark(1000 * sec) {
		t.Fatal("第一次 mark 应该是边沿")
	}
	if m.mark(1001 * sec) {
		t.Fatal("已经忙了不该再有边沿")
	}
}

// settledPath 建一条流、一条路径，等探测落到慢档。
func settledPath(t *testing.T, h *harness) (net.Conn, *Session, *path) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p := sess.pathsSnapshot()[0]
	waitFor(t, "探测没有落到慢档", 3*time.Second, func() bool {
		return time.Duration(p.probeGap.Load()) == DefaultIdleProbeInterval
	})
	return c, sess, p
}

func probesSent(p *path) uint64 {
	p.hmu.Lock()
	defer p.hmu.Unlock()
	return p.probeSq
}

// 这是这一轮的主角：流上一直有零星的载荷，探测也不许回到 1 秒快档。
func TestTrickleStaysOnSlowProbes(t *testing.T) {
	h := newHarness(t, nil)
	c, _, p := settledPath(t, h)
	before := probesSent(p)
	for i := 0; i < 15; i++ {
		echoOnce(t, c, 64)
		time.Sleep(200 * time.Millisecond)
	}
	if n := probesSent(p) - before; n != 0 {
		t.Fatalf("3 秒的心跳流量发了 %d 个探测：心跳把探测顶回了快档", n)
	}
	if got := time.Duration(p.probeGap.Load()); got != DefaultIdleProbeInterval {
		t.Fatalf("探测档位变成了 %v", got)
	}
}

// 真流量一来不等慢档那一拍，当场探一次、切快档。
func TestBulkSwitchesToFastProbesAtOnce(t *testing.T) {
	h := newHarness(t, nil)
	c, _, p := settledPath(t, h)
	before := probesSent(p)
	echoOnce(t, c, probeBusyWeight)
	waitFor(t, "成量的流量没有叫醒探测", 500*time.Millisecond, func() bool {
		return probesSent(p) > before
	})
	waitFor(t, "没有切到快档", 500*time.Millisecond, func() bool {
		return time.Duration(p.probeGap.Load()) == DefaultProbeInterval
	})
}

// dropConn 打开之后两个方向都静默丢弃，路径看上去就是黑洞。
type dropConn struct {
	net.Conn
	drop *atomic.Bool
}

func (c *dropConn) Write(b []byte) (int, error) {
	if c.drop.Load() {
		return len(b), nil
	}
	return c.Conn.Write(b)
}

// 慢档上路径黑洞了：判死窗口是 32 秒，但只要有人写了数据，RTO 一到就切快档，
// 判死回到 8 秒。少了这一条，心跳形状的流量会多卡 24 秒。
func TestStallPullsDeadPathBackToFastDetection(t *testing.T) {
	var drop atomic.Bool
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		cc.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := net.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			return &dropConn{Conn: c, drop: &drop}, nil
		}
	})
	c, _, p := settledPath(t, h)
	drop.Store(true)
	start := time.Now()
	if _, err := c.Write(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "卡住的写操作没有把探测切回快档", 3*time.Second, func() bool {
		return time.Duration(p.probeGap.Load()) == DefaultProbeInterval
	})
	waitFor(t, "切回快档之后 12 秒内没有判死", 12*time.Second, func() bool {
		return p.State() == pathDead
	})
	t.Logf("写入之后 %v 判死", time.Since(start).Round(time.Millisecond))
}

// 切快档的那一拍不能拿 8 秒窗口去量慢档留下的空白，否则活路径会被判死。
func TestSwitchToFastHoldsSilenceCheck(t *testing.T) {
	h := newHarness(t, nil)
	_, sess, p := settledPath(t, h)
	sess.notePayload(probeBusyWeight)
	waitFor(t, "切档时没有留出宽限", 500*time.Millisecond, func() bool {
		return p.silenceHold.Load() > time.Now().UnixNano()
	})
	p.probeGap.Store(int64(DefaultProbeInterval))
	p.lastRecv.Store(time.Now().Add(-time.Minute).UnixNano())
	p.checkSilence()
	if p.State() == pathDead {
		t.Fatal("宽限内被判死了")
	}
	p.silenceHold.Store(0)
	p.checkSilence()
	if p.State() != pathDead {
		t.Fatal("宽限过后静默判据不工作了")
	}
}
