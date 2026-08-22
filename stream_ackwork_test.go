package tide

import (
	"sync"
	"testing"
)

// ACK 冲刷循环的「还有事吗」判据必须认「应用读走了数据」，不能只认「又收到了新数据」。
//
// 这一条钉的是一个真实死锁（2026-08-22）：
//
//	发送方把窗口用光停在 writeChunk；接收侧应用 Read 走一批 → 条件③命中 →
//	scheduleAck，但 ackBusy 已被上一个 ackFlushLoop 占着，于是**直接返回**；
//	那个 loop 写完的是读走之前的上界，接着判「还有事吗」——
//	旧判据 `recvOff != ackedAdv` 只看新数据，这一幕里没有新数据，于是判无事退出。
//	新腾出来的空间永远没人说出去，双方各等各的。
//
// ⚠️ 端到端那条（TestClosedWindowReopensWithoutWaitingForRTO）能复现它，但只有
// 约五成概率——要撞上「scheduleAck 恰好落在 ackBusy 窗口里」。所以这里直接对判据
// 断言，让它变成确定性的、毫秒级的门禁。
func TestAckWorkSeesReaderDrainingBuffer(t *testing.T) {
	const win = 32 * 1024
	st := &Stream{window: win}
	st.rcond = sync.NewCond(&st.rmu)

	// 收满一窗，缓冲还没被应用读走。
	st.recvOff = win
	st.recvBuf = make([]byte, win)

	// 模拟 flushAck 刚发过一个 ACK：把两个"已通告"游标对齐到当前值。
	st.ackedAdv = st.recvOff
	st.ackedMaxOff = st.advertisableLocked()

	if st.hasAckWorkLocked() {
		t.Fatalf("刚发完 ACK、什么都没变，却判成有事要说——这会让 ackFlushLoop 空转")
	}

	// 应用把缓冲读空。没有一个新字节到达，变的只是"可通告的上界"。
	st.recvBuf = nil

	if !st.hasAckWorkLocked() {
		t.Fatalf("应用读空了缓冲（可通告上界 %d → %d），判据却说无事可做——"+
			"发送方还停在窗口用光的 wcond.Wait 上，这就是那个死锁",
			st.ackedMaxOff, st.advertisableLocked())
	}
}

// 反向：只有新数据到达、上界没动（缓冲仍是满的）时也要判有事。
// 两个条件各自独立，任何一个被"简化"掉都会漏掉一类唤醒。
func TestAckWorkSeesNewDataWithoutWindowChange(t *testing.T) {
	const win = 32 * 1024
	st := &Stream{window: win}
	st.rcond = sync.NewCond(&st.rmu)

	st.recvOff = win / 2
	st.recvBuf = make([]byte, win/2)
	st.ackedAdv = st.recvOff
	st.ackedMaxOff = st.advertisableLocked()
	if st.hasAckWorkLocked() {
		t.Fatal("对齐之后不该有事")
	}

	// 又收到一批：recvOff 前进，但缓冲也跟着涨，可通告上界原地不动。
	st.recvOff += 1024
	st.recvBuf = make([]byte, win/2+1024)
	if st.advertisableLocked() != st.ackedMaxOff {
		t.Fatalf("这一步应当让上界保持不变（%d vs %d），否则测的就不是这一条了",
			st.advertisableLocked(), st.ackedMaxOff)
	}
	if !st.hasAckWorkLocked() {
		t.Fatal("收到了新数据却判无事——对端在等这个 ACK 才敢继续发")
	}
}
