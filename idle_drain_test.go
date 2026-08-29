package tide

// 空闲探测分档与排水模式的回归测试（2026-08-29 真机事故的钉子）。
//
// 现场：Android 日用机 ↔ macOS 配对电脑，tun 近乎零流量时 tide 链路仍有
// 133 包/秒、66 KB/s 纯协议流量、手机核心 1300 唤醒/秒。三个叠加缺陷：
//   ① 探测快/慢档按「有流开着」判——推送长连接把它永远钉成真；
//   ② mihomo 重载漏下的旧会话被推送流攥着不死，各自带着补路/探测永动；
//   ③ 泄漏会话路径攒到上限后，冗余补路每轮白做一套握手再吃 FIN（~8 SYN/分钟）。
// 修复分别是 probeDelay 的载荷判据、Session.Drain、redundancyShouldDial 的满员守卫。

import (
	"errors"
	"testing"
	"time"
)

// ① 快档必须同时要求「有流」和「窗口内有真实载荷」；排水无条件慢档。
func TestProbeDelayJudgesPayloadNotStreamCount(t *testing.T) {
	const fast, idle = time.Second, 15 * time.Second
	cases := []struct {
		name          string
		streams       int
		payloadRecent bool
		draining      bool
		want          time.Duration
	}{
		// 事故形态：推送长连接开着、没有一个真实字节——必须慢档。
		{"open-but-quiet streams idle", 11, false, false, idle},
		{"active traffic fast", 3, true, false, fast},
		{"no streams idle", 0, true, false, idle},
		{"no streams no payload idle", 0, false, false, idle},
		// 排水中的会话即使还有活跃流量也不配快档——它只等善终。
		{"draining always idle", 3, true, true, idle},
	}
	for _, c := range cases {
		if got := probeDelay(fast, idle, c.streams, c.payloadRecent, c.draining); got != c.want {
			t.Fatalf("%s: probeDelay=%v want %v", c.name, got, c.want)
		}
	}
}

// payloadRecent 的边界：零值（从没有过载荷）恒 false；刚记过恒 true。
func TestPayloadRecentZeroValueIsIdle(t *testing.T) {
	s := newSession([16]byte{1}, true, 1<<20, time.Minute, time.Second, 64)
	defer s.closeWith(ErrClosed)
	if s.payloadRecent(time.Hour) {
		t.Fatal("从没有过载荷的会话不该被判成活跃")
	}
	s.notePayload()
	if !s.payloadRecent(time.Second) {
		t.Fatal("刚记过载荷却判成空闲")
	}
}

// ③ 满员时绝不再拨：拨了也会被 addPath 顶回，只产出握手垃圾。
func TestRedundancyShouldDialStopsAtPathCap(t *testing.T) {
	cases := []struct {
		usable, total int
		want          bool
	}{
		{0, 0, true},                      // 一条都没有：拨
		{1, 1, true},                      // 只有一条：拨
		{2, 2, false},                     // 冗余已够：不拨
		{1, maxPathsPerSession, false},    // 事故形态：可用不足但已满员——不拨
		{0, maxPathsPerSession, false},    // 全不可用且满员：等 onPathDead 腾位置
		{1, maxPathsPerSession - 1, true}, // 差一条到上限：还能拨
	}
	for _, c := range cases {
		if got := redundancyShouldDial(c.usable, c.total); got != c.want {
			t.Fatalf("redundancyShouldDial(%d,%d)=%v want %v", c.usable, c.total, got, c.want)
		}
	}
}

// ② 排水：没有存量流的会话在下一个检查拍就该关掉，错误是 ErrSuperseded。
func TestDrainClosesIdleSession(t *testing.T) {
	s := newSession([16]byte{2}, true, 1<<20, time.Minute, time.Second, 64)
	s.Drain(time.Minute)
	if !s.Draining() {
		t.Fatal("Drain 之后 Draining() 应为真")
	}
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second): // 检查拍 2s 一次，5s 兜底余量
		t.Fatal("零流会话排水后没有在检查拍内关闭")
	}
	if !errors.Is(s.closeErr, ErrSuperseded) {
		t.Fatalf("关闭原因是 %v，应为 ErrSuperseded", s.closeErr)
	}
}

// ② 排水：存量流攥着时不提前杀，硬期限到点强关兜底。
func TestDrainHardDeadlineWithLiveStreams(t *testing.T) {
	s := newSession([16]byte{3}, true, 1<<20, time.Minute, time.Second, 64)
	s.streamCount.Add(1) // 模拟一条不肯走的推送长连接
	start := time.Now()
	s.Drain(300 * time.Millisecond)
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("硬期限没有兜住攥着流的排水会话")
	}
	if time.Since(start) < 250*time.Millisecond {
		t.Fatal("攥着流的会话被提前杀了——排水该等到硬期限")
	}
	if !errors.Is(s.closeErr, ErrSuperseded) {
		t.Fatalf("关闭原因是 %v，应为 ErrSuperseded", s.closeErr)
	}
}

// Drain 幂等：重复调不 panic、不重置硬期限语义。
func TestDrainIdempotent(t *testing.T) {
	s := newSession([16]byte{4}, true, 1<<20, time.Minute, time.Second, 64)
	defer s.closeWith(ErrClosed)
	s.Drain(time.Hour)
	s.Drain(time.Hour) // 第二次是 no-op
	if !s.Draining() {
		t.Fatal("Draining 应保持为真")
	}
}

// 静默判死窗口必须跟着探测档位走:空闲档两拍之间本来就没有字节,
// 固定 8s 窗口会把每条空闲路径误判死(churn 引擎,真机实锤)。
func TestSilenceDeadlineScalesWithProbeGap(t *testing.T) {
	// 快档(1s):窗口 = 8s 原语义,行为不变。
	if got := silenceDeadline(DefaultProbeInterval); got != DefaultPathDeadAfter {
		t.Fatalf("快档窗口 %v,应保持 %v", got, DefaultPathDeadAfter)
	}
	// 未初始化(0):同快档。
	if got := silenceDeadline(0); got != DefaultPathDeadAfter {
		t.Fatalf("零值窗口 %v,应为 %v", got, DefaultPathDeadAfter)
	}
	// 空闲档(15s):窗口必须容得下两拍探测 + 超时,否则空闲路径必被误判死。
	idle := silenceDeadline(DefaultIdleProbeInterval)
	if idle <= DefaultIdleProbeInterval {
		t.Fatalf("空闲档窗口 %v 连一拍探测间隔都容不下——每条空闲路径活不过两拍", idle)
	}
	if want := DefaultIdleProbeInterval*2 + DefaultProbeTimeout; idle != want {
		t.Fatalf("空闲档窗口 %v,应为 %v", idle, want)
	}
}
