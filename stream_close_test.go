package tide

import (
	"context"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

// 本端 Close 必须叫醒卡在 Read 里的协程（net.Conn 的约定）。
//
// 原来 Close 只 failWrite，再把流从会话里摘掉——之后对端的 FIN/RST、会话关闭时的 fail
// 都再也到不了这条流，读方永远醒不过来，连同它攥着的缓冲一起漏掉。真机上两条路天天走：
// HTTP 健康检查结束时 CloseIdleConnections 关掉长连接（persistConn.readLoop 卡在
// Stream.Read），Relay 一侧出错时关掉 tide 那头（回程拷贝卡在 Stream.Read）。
// 2026-10-04：六天攒了 1.7 万个协程、400 MB 堆，顶穿 512 MiB 上限后 GC 连轴转。
func TestStreamCloseUnblocksRead(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := h.client.DialContext(ctx, "tcp", "idle.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 64)) // 回声服务收不到东西就不回，这里会一直等
		done <- err
	}()
	time.Sleep(100 * time.Millisecond) // 让读方真的进入 Wait
	select {
	case err := <-done:
		t.Fatalf("还没 Close 读方就返回了: %v", err)
	default:
	}
	c.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Close 之后 Read 应返回错误")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("本端 Close 之后卡在 Read 里的协程没有醒来")
	}
}

func countGoroutines(substr string) int {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	n := 0
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, substr) {
			n++
		}
	}
	return n
}

// 第一条路径拨不通时，已经建好（并起了 ctrlLoop）的会话要关掉，否则每失败一次漏一个会话。
// 2026-10-04 真机：548 个 ctrlLoop 活着，而正常只该有当前那一两个会话。
func TestNewSessionDialFailureClosesSession(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // 端口立刻拒绝连接

	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cl, err := NewClient(&ClientConfig{Server: addr, PublicKey: priv.Public()})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	before := countGoroutines("tide.(*Session).ctrlLoop")
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if _, err := cl.DialContext(ctx, "tcp", "x.invalid:80"); err == nil {
			cancel()
			t.Fatal("服务端端口是关着的，拨号不该成功")
		}
		cancel()
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		n := countGoroutines("tide.(*Session).ctrlLoop")
		if n <= before {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("拨号失败 5 次后多出 %d 个 ctrlLoop：失败的会话没关", n-before)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
