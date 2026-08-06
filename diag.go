package tide

import "time"

// 诊断与故障注入接口。
//
// 这些方法是导出的，因为「网络波动下还稳不稳」只能靠**制造波动**来验证，
// 而制造波动的钩子必须在包外可用（cmd/tide-selftest、clash 侧的自检、CI）。
// 一个只能在包内测的稳定性机制，等于只在开发者的环回网卡上被验过。

// PathsEstablished 返回本会话累计接入过多少条路径。
//
// 初始值 1；每一次重连或新增冗余路径 +1。它是判断"恢复逻辑到底跑没跑"的唯一硬证据——
// 在环回或低延迟链路上，重连快到几毫秒，光看传输成功与否完全分辨不出来。
func (s *Session) PathsEstablished() uint64 { return s.pathsAdded.Load() }

// PathCount 返回当前还活着的路径数。
func (s *Session) PathCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.paths)
}

// PathInfo 是一条路径的可观测状态。
type PathInfo struct {
	ID    uint32
	Kind  string // "tcp" / "quic"
	State string // active / degraded / suspect / dead
	RTT   time.Duration
	Loss  float64
	Age   time.Duration
	Pad   string // 当前填充阶段
	TX    uint64
	RX    uint64
	// TXDgram/RXDgram 是 TX/RX 里走不可靠数据面（RFC 9221 / RFC 9297）的那部分。
	// 「TX − TXDgram」才是流字节，也是判断"UDP 有没有被偷偷塞进可靠流"的唯一证据。
	TXDgram uint64
	RXDgram uint64
	// Dead 非空时说明这条路径已经死了，内容是**谁**判的死。
	Dead string
}

// Paths 返回当前路径快照，供日志、UI 与自检展示。
func (s *Session) Paths() []PathInfo {
	ps := s.pathsSnapshot()
	out := make([]PathInfo, 0, len(ps))
	for _, p := range ps {
		out = append(out, PathInfo{
			ID:    p.id,
			Kind:  p.kind,
			State: p.State().String(),
			RTT:   p.RTT(),
			Loss:  p.Loss(),
			Age:   time.Since(p.created),
			Pad:   p.pad.Phase().String(),
			TX:    p.txBytes.Load(),
			RX:    p.rxBytes.Load(),

			TXDgram: p.txDgram.Load(),
			RXDgram: p.rxDgram.Load(),
			Dead:    p.DeadReason(),
		})
	}
	return out
}

// KillAllPaths 立刻打死本会话的全部路径，不走任何优雅关闭。
//
// 这是**故障注入**，模拟"网线被拔了 / Wi-Fi 切走了 / 运营商掐了连接"。
// 与 Close() 的区别很重要：Close 会发 CLOSE 帧、对端知道该收摊了；
// 这里对端什么都收不到，只能靠自己的探测与静默计时器发现——
// 而那正是真实网络波动的样子，也正是要验的东西。
func (s *Session) KillAllPaths() int {
	ps := s.pathsSnapshot()
	for _, p := range ps {
		p.conn.Close()
	}
	return len(ps)
}

// CloseSession 关掉当前会话但保留客户端（票据钱包留着）。
// 下一次拨号会用 0-RTT 重新起一个会话——这是验证 0-RTT 复用最直接的办法。
func (c *Client) CloseSession() {
	c.mu.Lock()
	s := c.sess
	c.sess = nil
	c.mu.Unlock()
	if s != nil {
		s.closeWith(ErrClosed)
	}
}

// CurrentSession 返回当前会话（可能为 nil）。
func (c *Client) CurrentSession() *Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sess
}

// TicketsTaken 返回累计用掉多少张票据。等于"有多少次握手是 0-RTT"。
func (c *Client) TicketsTaken() uint64 { return c.wallet.taken.Load() }

// TicketsRemaining 返回钱包里还剩多少张可用票据。
func (c *Client) TicketsRemaining() int { return c.wallet.remaining(time.Now()) }

// DeadReason 返回这条路径被判死的原因，还活着时为空。
func (p *path) DeadReason() string {
	if v, ok := p.deadReason.Load().(string); ok {
		return v
	}
	return ""
}

// PathDeaths 返回本会话里已经死掉的路径及其死因，供排查"路径反复重建"用。
// 活着的路径不在其中。
func (s *Session) PathDeaths() []string { return s.deadLog.snapshot() }
