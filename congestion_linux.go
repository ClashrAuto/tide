//go:build linux

package tide

import (
	"net"
	"syscall"
)

// 拥塞控制（spec §12.7 / design.md 机制 6b）。
//
// design.md 明确选了 BBR 而不是 Brutal：Brutal 的收益部分是幻觉——它靠无视丢包信号
// 制造缓冲区膨胀与重传来"看起来"占住带宽，同时挤压同链路其他流量，
// 让自己成为 QoS 的显眼目标。
//
// 但**只有 TCP 路径能真的换**：
//
//   - TCP：Linux 允许按 socket 设 `TCP_CONGESTION`，这里在拨号/接受时设一次。
//     BBR 对本协议的意义在于它不把丢包当拥塞——而 TIDE 要跑的恰恰是丢包链路，
//     Cubic 在 5% 丢包下会把窗口压到地板上。
//   - QUIC：**做不到**。quic-go v0.61 的 internal/congestion 里只有 cubic，
//     且 Config 不暴露任何选择拥塞控制的接口。想换只能 fork quic-go。
//     所以 design.md 里"拥塞控制明确用 BBRv3"这句，当前只在 TCP 路径上成立。
//
// 设置失败一律**静默忽略**：内核没编 BBR、或没加载 tcp_bbr 模块都很常见，
// 而这只是优化，不该让连接建不起来。

// defaultCongestion 空 = **不动系统默认**。
//
// ★ 这里原本默认设成 "bbr"，因为 design.md 写着"拥塞控制明确用 BBRv3"。
// 实测把这个默认值否掉了（树莓派↔x86，双向 5% 丢包，40 秒，同一份测量代码）：
//
//	bbr    p90 76.2ms  p99 620ms  p99.9 811ms   （TCP 路径 srtt 21.71ms）
//	cubic  p90 22.7ms  p99 125ms  p99.9 203ms   （TCP 路径 srtt  1.29ms）
//
// **BBR 让尾部差了 5 倍。** 原因是 design.md 说的是 BBR**v3**，而 Linux 内核里
// `bbr` 是 **v1**——v1 对随机丢包（不是拥塞造成的丢包）的处理正是它的已知弱点：
// 它会持续探测带宽、把队列撑起来，在 netem 这种浅队列上反而制造突发丢包，
// RTT 直接膨胀一个数量级。BBRv3 改了这块，但内核里没有。
//
// 所以默认改成"不动"：一个只在特定内核+特定链路上才可能有收益、
// 而在实测链路上明确有害的优化，不该是默认值。想用的人显式配。
var defaultCongestion = ""

// setCongestion 尽力把一条 TCP 连接切到指定的拥塞控制算法。
func setCongestion(c net.Conn, algo string) {
	if algo == "" {
		return
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return
	}
	// 失败不报错：内核没有这个算法是常态，而它只是优化。
	_ = raw.Control(func(fd uintptr) {
		_ = syscall.SetsockoptString(int(fd), syscall.IPPROTO_TCP, tcpCongestion, algo)
	})
}

// controlCongestion 供 net.Dialer.Control 使用，在**连接建立前**就把算法设好。
// 比连上之后再设更可靠：慢启动的头几个 RTT 也就用上了新算法。
func controlCongestion(algo string) func(network, address string, c syscall.RawConn) error {
	if algo == "" {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		_ = c.Control(func(fd uintptr) {
			_ = syscall.SetsockoptString(int(fd), syscall.IPPROTO_TCP, tcpCongestion, algo)
		})
		return nil
	}
}

// TCP_CONGESTION 在 syscall 包里没有常量，值取自 Linux 的 <netinet/tcp.h>。
const tcpCongestion = 13
