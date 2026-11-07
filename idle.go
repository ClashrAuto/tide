package tide

import "sync/atomic"

// 空闲时把定时器停掉（2026-11-06 真机账）。
//
// ★★ 定时器不是「反正就几次/秒」：Go 在 Darwin 上每触发一次定时器，线程要被唤醒
//   约 3.3 次（等定时器的 M、到点一起醒的 sysmon、sysmon 随后那拍 20µs 的短睡）。
//   一个什么都不做的 Ticker 实测 4Hz → 13.2 次/秒、10Hz → 31.8 次/秒。
//   一条空闲会话上 250ms 的重传扫描 + 500ms 的宽限看门狗 + 2s 的 rebalance，
//   单边就是 20 多次/秒，服务端孤儿会话再加 200ms 的恢复轮询到 50 次/秒。
//   手机内核的限额是 300 秒 45000 次（150 次/秒），超了系统直接记违规。
//
// 所以这里的原则是：**循环只在有活的时候才有定时器**，没活就睡在 idleGate 上。
// 判死、切网走的是路径探测（probeLoop），那条定时器一直在，不受这里影响。

// busyMeter 判「真有成量的流量在走」。**不加锁**：note 在发送热路径上，
// 窗口切换时的竞争最多让一次判定差几帧，门槛本来就是个量级。
type busyMeter struct {
	start  atomic.Int64 // 当前采样窗的起点（UnixNano）
	weight atomic.Int64 // 窗内累计重量
	last   atomic.Int64 // 最近一次判忙的时刻（UnixNano）
}

// note 记一帧载荷。返回 true 表示这一帧让会话从不忙变成忙。
func (m *busyMeter) note(now int64, n int) bool {
	if now-m.start.Load() > int64(probeBusySample) {
		m.start.Store(now)
		m.weight.Store(0)
	}
	if m.weight.Add(int64(n)+probeFrameWeight) < probeBusyWeight {
		return false
	}
	return m.mark(now)
}

// mark 无条件判忙，返回 true 表示这是从不忙到忙的边沿。
func (m *busyMeter) mark(now int64) bool {
	was := m.active(now)
	m.last.Store(now)
	return !was
}

// active 报告 probeActivityWindow 内判过忙没有。零值恒 false。
func (m *busyMeter) active(now int64) bool {
	t := m.last.Load()
	return t != 0 && now-t < int64(probeActivityWindow)
}

// idleGate 给**单个**消费者用：循环发现没活就 park，生产者有活就 kick。
//
// 生产方在发送热路径上（每帧一次），所以 kick 在循环醒着时只有一次原子读。
//
// ★ 不会丢唤醒：park 先亮牌子再复查 busy，kick 方先改状态再看牌子，
// 两边都是顺序一致的原子操作，「它没看到牌子」和「我们没看到状态」不可能同时成立。
//
// ⚠️ 所以调用方必须**先改状态、后 kick**，反过来就是一个偶发的永久停摆。
type idleGate struct {
	parked atomic.Bool
	ch     chan struct{}
}

func (g *idleGate) init() { g.ch = make(chan struct{}, 1) }

// kick 叫醒停着的循环。ch 为 nil（测试里手搓的 &path{}）时是空操作。
func (g *idleGate) kick() {
	if g.parked.Load() {
		select {
		case g.ch <- struct{}{}:
		default:
		}
	}
}

// park 在 busy 为假时一直睡到 kick。返回 false 表示 done 关了，循环该退了。
//
// 醒来时 ch 里偶尔留着一个旧令牌（kick 落在亮牌子和复查之间），代价只是多转一圈。
func (g *idleGate) park(done1, done2 <-chan struct{}, busy func() bool) bool {
	g.parked.Store(true)
	defer g.parked.Store(false)
	if busy() {
		return true
	}
	select {
	case <-g.ch:
		return true
	case <-done1:
		return false
	case <-done2:
		return false
	}
}
