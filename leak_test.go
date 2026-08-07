package tide

import (
	"context"
	"net"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// residualTideGoroutines 返回当前还活着、且栈里出现本包的 goroutine。
//
// ★ 判据是"**有没有本包的协程还在**"，不是"协程总数有没有回到某个数"。
// 数量阈值这个东西两头不讨好：放宽了漏（第 34 轮我自己引入的看门狗泄漏只多 1 条，
// 任何 +1 的容差都会把它放过去），收紧了又会被运行时的临时协程弄成偶发红。
// 而"本包不该再有协程"是个精确、且与运行时噪音无关的不变量。
func residualTideGoroutines(skip string) []string {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	var out []string
	for _, g := range strings.Split(string(buf), "\n\n") {
		if !strings.Contains(g, "ClashrAuto/tide.") {
			continue
		}
		if skip != "" && strings.Contains(g, skip) {
			continue // 用例自己那条
		}
		lines := strings.Split(strings.TrimSpace(g), "\n")
		if len(lines) > 14 {
			lines = lines[:14]
		}
		out = append(out, strings.Join(lines, " | "))
	}
	return out
}

// 关掉客户端与服务端之后，本包不该再留下任何协程。
//
// ★ 这是一道**通用**守卫，针对本项目最近反复出现的那一类问题：生命周期没收干净。
// 第 34~36 轮连着三个都是这一类（UDP 关联寿命、空闲回收放错层、停机不释放 QUIC
// 端口），而它们各自的用例都只盯自己那一处。残留协程是这一类的**共同可观测量**：
// 任何一处没退的循环都会在这里留下痕迹，连同它的栈。
//
// 已验证它能抓住两个**真实**的历史问题：
//   - 把 ServeQUIC 的 Accept 退回 context.Background()（第 36 轮那个 bug）→
//     quic-go 的 Listener.Accept 永远挂着，正是当时 UDP 端口不释放的原因；
//   - 把 watchUDPIdle 退回 `for range t.C`（第 34 轮我自己引入的）→
//     关联结束后它还要睡到下一个 tick（默认 75 秒）才发现，而并发关联上限是 1024。
//
// 覆盖面要够宽才有意义：一条 TCP 流、一条 UDP 关联、一条 QUIC 路径都得真的建起来，
// 否则"没有泄漏"只是因为压根没创建过东西。
func TestNoGoroutineLeakAfterClose(t *testing.T) {
	func() {
		port := freeUDPPort(t)
		h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
			cc.EnableQUIC = true
			cc.QUICPort = port
			cc.ProbeInterval = 200 * time.Millisecond
		})
		serveQUICOn(t, h, port)
		ctx := context.Background()

		c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("hello"))
		buf := make([]byte, 5)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		c.Read(buf)
		c.Close()

		// UDP 关联也走一遍：它自带收队列、空闲看门狗和 handler 协程。
		ps, err := h.client.DialPacket(ctx, "10.0.0.1:53")
		if err == nil {
			ps.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			ps.WriteTo([]byte("q"), "10.0.0.1:53")
			ps.ReadFrom()
			ps.Close()
		}

		// 等 QUIC 路径真的建起来，否则这一轮等于没测 QUIC。
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			sess, _ := h.client.Session(ctx)
			if sess != nil {
				for _, p := range sess.pathsSnapshot() {
					if p.kind == "quic" {
						deadline = time.Now()
						break
					}
				}
			}
			time.Sleep(100 * time.Millisecond)
		}

		h.client.Close()
		h.srv.Close()
		h.ln.Close()
		h.cover.Close()
	}()

	// 收尾不是瞬时的（协程要被唤醒、要跑完 defer），给足时间再判。
	var left []string
	for i := 0; i < 80; i++ {
		time.Sleep(100 * time.Millisecond)
		left = residualTideGoroutines("TestNoGoroutineLeakAfterClose")
		if len(left) == 0 {
			return
		}
	}
	for _, g := range left {
		t.Logf("残留协程: %s", g)
	}
	t.Fatalf("客户端与服务端都关掉之后，本包还留着 %d 条协程", len(left))
}

// h3 数据面也不能漏协程。
//
// ★ 它有自己的一整套长命协程（ServeH3 的 Accept 循环、每条 QUIC 连接一个
// http3.Server、h3Binding、recvH3Datagrams 的收数据报循环、每条流一个 readLoop），
// 与原生 QUIC 那条路**不共用**代码。第 36 轮那个 bug 正是 Accept 传了
// context.Background()，而 recvH3Datagrams 里也有一个同样形状的
// `ReceiveDatagram(context.Background())` —— 同一个坑值得单独踩一遍。
//
// 而且这条路刚刚才对 Coast 可用（此前 clash 的入站没有 h3 开关，
// ServeH3 根本调不到），所以它是"新上线、没被真正跑过"的那一类。
func TestNoGoroutineLeakAfterCloseH3(t *testing.T) {
	func() {
		port := freeUDPPort(t)
		h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
			cc.EnableQUIC = true
			cc.H3 = true
			cc.QUICPort = port
			cc.ProbeInterval = 200 * time.Millisecond
		})
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		go func() { _ = h.srv.ServeH3(addr) }()
		time.Sleep(400 * time.Millisecond)

		ctx := context.Background()
		c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("hello"))
		buf := make([]byte, 5)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		c.Read(buf)
		c.Close()

		// UDP 走 RFC 9297 的 HTTP Datagram，那是 h3 专有的一条路。
		ps, err := h.client.DialPacket(ctx, "10.0.0.1:53")
		if err == nil {
			ps.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			ps.WriteTo([]byte("q"), "10.0.0.1:53")
			ps.ReadFrom()
			ps.Close()
		}

		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			sess, _ := h.client.Session(ctx)
			if sess != nil {
				for _, p := range sess.pathsSnapshot() {
					if p.kind == "quic" {
						deadline = time.Now()
						break
					}
				}
			}
			time.Sleep(100 * time.Millisecond)
		}

		h.client.Close()
		h.srv.Close()
		h.ln.Close()
		h.cover.Close()
	}()

	var left []string
	for i := 0; i < 80; i++ {
		time.Sleep(100 * time.Millisecond)
		left = residualTideGoroutines("TestNoGoroutineLeakAfterCloseH3")
		if len(left) == 0 {
			return
		}
	}
	for _, g := range left {
		t.Logf("残留协程: %s", g)
	}
	t.Fatalf("h3 模式下关掉之后，本包还留着 %d 条协程", len(left))
}

// 客户端**不告而别**时，服务端也必须把自己收干净。
//
// ★ 这是真实世界里最常见的收尾路径，却是测试覆盖最薄的一条：
// 网络断了、进程被杀、手机切后台——客户端根本没机会调 Close()。
// 服务端这一侧走的是完全不同的代码：路径读循环出错 → onPathDead →
// recoverLoop（服务端没有 redial，只能空转等）→ graceWatcher 到点 →
// closeWith(ErrSessionGone)。上面两条用例走的都是"两边都优雅关闭"，
// 一行都覆盖不到这条路。
//
// 断言的是**服务端**关干净了：客户端这边故意不 Close，模拟它已经消失。
func TestNoGoroutineLeakAfterClientVanishes(t *testing.T) {
	func() {
		h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
			// 宽限期压短，否则用例要等两分钟。
			sc.SessionGrace = 800 * time.Millisecond
			cc.SessionGrace = 800 * time.Millisecond
			cc.ProbeInterval = 100 * time.Millisecond
		})
		ctx := context.Background()
		c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("hello"))
		buf := make([]byte, 5)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		c.Read(buf)

		// ★ 模拟"客户端凭空消失"。
		//
		// ⚠️ 光把连接掐断是不够的——那只是一次网络抖动，而客户端的 recoverLoop
		// 会**正常地**重连回来、把宽限期计时清零。第一版就是这么写的，
		// 结果会话十秒都没被回收，我差点当成 bug；其实那是协议在按设计工作
		// （§9 的整个存在意义就是让抖动不断线）。
		//
		// 要让"客户端消失"成立，必须让它**回不来**：先把监听关掉，
		// 再掐断连接。这才是服务端视角下的"对端不告而别"。
		h.ln.Close()
		sess, _ := h.client.Session(ctx)
		if sess != nil {
			killAllPaths(sess)
		}

		// 等服务端的宽限期走完并把会话收掉。
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			h.srv.mu.Lock()
			n := len(h.srv.sessions)
			h.srv.mu.Unlock()
			if n == 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		h.srv.mu.Lock()
		left := len(h.srv.sessions)
		h.srv.mu.Unlock()
		if left != 0 {
			t.Fatalf("宽限期过后服务端还挂着 %d 条会话", left)
		}

		// 到此为止服务端**没有**被 Close：要测的正是"会话自然消亡"之后
		// 服务端不该留下与这条会话有关的协程。
		h.srv.Close()
		h.client.Close()
		h.cover.Close()
	}()

	var left []string
	for i := 0; i < 80; i++ {
		time.Sleep(100 * time.Millisecond)
		left = residualTideGoroutines("TestNoGoroutineLeakAfterClientVanishes")
		if len(left) == 0 {
			return
		}
	}
	for _, g := range left {
		t.Logf("残留协程: %s", g)
	}
	t.Fatalf("客户端不告而别、宽限期到点之后，本包还留着 %d 条协程", len(left))
}

// 会话死掉之后客户端会**另建一条**（Client.Session 里那段替换逻辑）。
// 旧会话上那些长命协程（ctrlLoop / maintainQUIC / maintainRedundancy /
// retransmitLoop / rebalanceLoop / ticketServeLoop）必须跟着旧会话一起退，
// 否则每换一次会话就漏一批——而换会话在移动网络下是常态。
func TestNoGoroutineLeakAcrossSessionReplacement(t *testing.T) {
	func() {
		port := freeUDPPort(t)
		h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
			cc.EnableQUIC = true
			cc.QUICPort = port
			cc.Redundancy = true
			cc.ProbeInterval = 100 * time.Millisecond
		})
		serveQUICOn(t, h, port)
		ctx := context.Background()

		for round := 0; round < 3; round++ {
			c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
			if err != nil {
				t.Fatalf("第 %d 轮拨号失败：%v", round, err)
			}
			c.Write([]byte("hello"))
			buf := make([]byte, 5)
			c.SetReadDeadline(time.Now().Add(3 * time.Second))
			c.Read(buf)
			c.Close()

			// 直接把会话判死，模拟宽限期耗尽。下一次 DialContext 会另建一条。
			sess, _ := h.client.Session(ctx)
			if sess != nil {
				sess.closeWith(ErrSessionGone)
			}
			time.Sleep(200 * time.Millisecond)
		}

		h.client.Close()
		h.srv.Close()
		h.ln.Close()
		h.cover.Close()
	}()

	var left []string
	for i := 0; i < 80; i++ {
		time.Sleep(100 * time.Millisecond)
		left = residualTideGoroutines("TestNoGoroutineLeakAcrossSessionReplacement")
		if len(left) == 0 {
			return
		}
	}
	for _, g := range left {
		t.Logf("残留协程: %s", g)
	}
	t.Fatalf("反复换会话之后，本包还留着 %d 条协程", len(left))
}
