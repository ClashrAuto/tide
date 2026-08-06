package tide

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Client 是一个 TIDE 出站。它维持**一个**会话并在其上复用所有流——
// 这正是 0-RTT 与无缝迁移能生效的前提：会话越长寿，一次握手摊得越薄，
// 路径切换对上层就越是不可见。

type Client struct {
	cfg    *ClientConfig
	tlsCfg *tls.Config

	mu     sync.Mutex
	sess   *Session
	closed bool

	// wallet 跨会话保留：会话可能因为宽限期耗尽而彻底死掉，
	// 但票据还没过期，下一个会话仍然能 0-RTT 起步。
	wallet   *ticketWallet
	nextPath atomic.Uint32
}

func NewClient(cfg *ClientConfig) (*Client, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	sni := cfg.ServerName
	if sni == "" {
		if h, _, err := net.SplitHostPort(cfg.Server); err == nil {
			sni = h
		} else {
			sni = cfg.Server
		}
	}
	var tc *tls.Config
	if cfg.TLSConfig != nil {
		tc = cfg.TLSConfig.Clone()
	} else {
		tc = &tls.Config{}
	}
	if tc.ServerName == "" {
		tc.ServerName = sni
	}
	// TLS 1.3 是硬要求：信道绑定用的 Exporter、以及 bare 模式的安全前提都建立在它上面。
	if tc.MinVersion < tls.VersionTLS13 {
		tc.MinVersion = tls.VersionTLS13
	}
	if len(tc.NextProtos) == 0 {
		// 伪装成 HTTP/2 —— 一个只谈 TLS 却不谈任何 ALPN 的连接本身就是特征。
		tc.NextProtos = []string{"h2", "http/1.1"}
	}
	c := &Client{cfg: cfg, tlsCfg: tc, wallet: newTicketWallet()}
	c.nextPath.Store(1)
	return c, nil
}

// DialContext 开一条代理 TCP 流。签名与 net.Dialer.DialContext 兼容，
// 方便直接塞进 clash 的 dialer 链。
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	s, err := c.Session(ctx)
	if err != nil {
		return nil, err
	}
	return s.OpenStream(ctx, addr)
}

// DialPacket 开一条 UDP 关联。
func (c *Client) DialPacket(ctx context.Context, addr string) (*PacketStream, error) {
	s, err := c.Session(ctx)
	if err != nil {
		return nil, err
	}
	return s.OpenPacket(ctx, addr)
}

// Session 返回当前会话，必要时新建。
func (c *Client) Session(ctx context.Context) (*Session, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	if s := c.sess; s != nil {
		select {
		case <-s.closed:
			c.sess = nil
		default:
			c.mu.Unlock()
			return s, nil
		}
	}
	c.mu.Unlock()

	// 建会话不持锁：TLS 握手可能要几百毫秒，持锁会把所有并发拨号串起来。
	// 用第二次检查解决竞态——多建一个会话只是浪费一次握手，不会出错。
	s, err := c.newSession(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		s.Close()
		return nil, ErrClosed
	}
	if c.sess != nil {
		select {
		case <-c.sess.closed:
		default:
			existing := c.sess
			c.mu.Unlock()
			s.Close()
			return existing, nil
		}
	}
	c.sess = s
	c.mu.Unlock()
	return s, nil
}

func (c *Client) newSession(ctx context.Context) (*Session, error) {
	s := newSession([16]byte{}, true, c.cfg.streamWindow(),
		c.cfg.sessionGrace(), c.cfg.probeInterval(), DefaultMaxStreams)
	s.wallet = c.wallet
	s.redial = func(ctx context.Context, sess *Session) (*path, error) {
		return c.dialPath(ctx, sess, true)
	}

	p, err := c.dialPath(ctx, s, false)
	if err != nil {
		return nil, err
	}
	s.addPath(p)
	go s.retransmitLoop()
	go s.rebalanceLoop()
	go s.ticketLoop()

	if c.cfg.Redundancy {
		// 常驻第二条路径：路径死掉时不需要重连，流直接切过去，
		// 用户侧只有一个 RTT 的抖动。移动网络下这是最有效的一个开关。
		go c.maintainRedundancy(s)
	}
	if c.cfg.EnableQUIC {
		go c.maintainQUIC(s)
	}
	return s, nil
}

// maintainQUIC 在后台挂一条 QUIC 路径上去（spec §8：默认从 TCP 起步，
// 后台低频探测 QUIC）。
//
// ★ 探测失败 MUST 静默全量回落 TCP，不得向用户暴露错误。UDP 被封是极常见的部署现实，
// 一个因为"QUIC 连不上"就弹错误的客户端等于在告诉用户一件他无能为力的事。
// 重试间隔故意拉得很长（30s）：UDP 被封通常是长期状态，密集重试只是浪费电和流量，
// 而且一串规律的 UDP 探测本身就是个特征。
func (c *Client) maintainQUIC(s *Session) {
	const (
		quicIdleCheck  = 2 * time.Second
		quicBackoffMax = 30 * time.Second
	)
	// 首次**不等待**：QUIC 越早可用，启动瞬态里被迫走 TCP 的字节越少。
	backoff := time.Duration(0)
	for {
		if backoff > 0 {
			select {
			case <-s.closed:
				return
			case <-time.After(backoff):
			}
		} else {
			select {
			case <-s.closed:
				return
			default:
			}
		}
		s.mu.Lock()
		hasQUIC, hasAny := false, false
		for _, p := range s.paths {
			if !p.usable() {
				continue
			}
			hasAny = true
			if p.kind == "quic" {
				hasQUIC = true
			}
		}
		full := len(s.paths) >= maxPathsPerSession
		s.mu.Unlock()

		// ★ 会话已经挂满路径：拨了也会被 addPath 顶回来。
		//
		// 没有这一条就是个自伤的握手风暴：hasQUIC 永远为 false（新路径根本挂不上），
		// 于是每 5 秒拨一次全新的 QUIC 路径，每次都做完整的 KEM 握手、
		// 服务端也陪着做一遍，然后被拒、判死、重来。会话活多久就刷多久。
		// 退避拉到最大，等别的路径死掉腾出位置再说。
		if full {
			backoff = quicBackoffMax
			continue
		}

		if hasQUIC {
			backoff = 5 * time.Second
			continue
		}
		if !hasAny {
			// ★ 一条路径都没有 = **整个网络**断了，不是 UDP 被封。
			// 这里绝不能加大退避：断网恢复后所有路径会同时回来，而一个已经涨到 30 秒的
			// QUIC 退避会让加速路径在恢复后再缺席半分钟。实测就栽在这上面——
			// 一次 10 秒黑洞之后 QUIC 迟迟没接回来，全部流量挤在 RTT 414ms 的 TCP 上。
			// 退避只该在"别的路径好好的、唯独 QUIC 连不上"时增长，那才是 UDP 被封的证据。
			backoff = quicIdleCheck
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		var p *path
		var err error
		if c.cfg.H3 {
			p, err = c.dialH3Path(ctx, s, true)
		} else {
			p, err = c.dialQUICPath(ctx, s, true)
		}
		cancel()
		if err == nil && p != nil {
			if !s.addPath(p) {
				// 被路径上界顶回来了。上面的 full 检查通常已经拦住，
				// 这里是并发下的兜底：拨号期间别的协程刚把位置占满。
				backoff = quicBackoffMax
				continue
			}
			backoff = 5 * time.Second
			continue
		}
		// 别的路径是通的却拨不通 QUIC —— 这才是 UDP 被封的证据，可以放心退避。
		backoff *= 2
		if backoff > quicBackoffMax {
			backoff = quicBackoffMax
		}
	}
}

const (
	redundancyCheckInterval = 2 * time.Second
	redundancyBackoffMax    = 30 * time.Second
)

// nextRedundancyDelay 给出下一次检查/补路之前要等的**基准**间隔（真正睡的时候还要过
// jitter）。ok = 这一轮不需要补路，或者补上了。
//
// ★ 补不上时必须退避，而且必须抖动——这两件事这里原本一件都没有，是**固定 2 秒**。
//
// 两条独立的理由，各自都足够：
//
//  1. **它违反 spec §8.5**。那一条要求"任何周期性发送的间隔 MUST 加入随机抖动"，
//     而补不上第二条路径时，这个循环每 2.000 秒发起一次完整的 TCP+TLS 拨号——
//     比 §8.5 当初治的那个 PATH_PROBE 节拍器更显眼，因为每一拍都是一次新连接，
//     链路上任何观察者都看得见。识别它连机器学习都不用，对到达间隔做个直方图就够了。
//
//  2. **惊群**。波动往往是整片网络的，几十上百个客户端会在同一时刻失去第二条路径，
//     然后以完全相同的 2 秒节奏一起重拨，把刚要恢复的链路再打垮一次。
//     这正是 AWS 那篇 Exponential Backoff And Jitter 讲的：退避降的是总量，
//     抖动断的是同步，两者缺一不可。
//
// 讽刺的是这两条道理在本仓库里各写过一遍：recoverLoop 的退避注释写的就是惊群，
// maintainQUIC 的注释写的就是"一串规律的探测本身就是个特征"。
// 唯独 Redundancy 这条漏了——而它恰恰是文档里**专门推荐给移动网络**的那个开关，
// 也就是最容易反复补不上第二条路径的场景。
func nextRedundancyDelay(cur time.Duration, ok bool) time.Duration {
	if ok {
		return redundancyCheckInterval
	}
	next := cur * 2
	if next < redundancyCheckInterval {
		next = redundancyCheckInterval
	}
	if next > redundancyBackoffMax {
		next = redundancyBackoffMax
	}
	return next
}

// maintainRedundancy 保证会话上始终有两条路径。
func (c *Client) maintainRedundancy(s *Session) {
	base := redundancyCheckInterval
	for {
		select {
		case <-s.closed:
			return
		case <-time.After(jitter(base)):
		}
		s.mu.Lock()
		n := 0
		for _, p := range s.paths {
			if p.usable() {
				n++
			}
		}
		s.mu.Unlock()
		if n >= 2 {
			base = nextRedundancyDelay(base, true)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		p, err := c.dialPath(ctx, s, true)
		cancel()
		// addPath 的返回值不能丢：会话的路径数有上界（maxPathsPerSession），
		// 顶回来的那条已经被 markDead 关掉了，这一轮等于没补上。
		ok := err == nil && p != nil && s.addPath(p)
		base = nextRedundancyDelay(base, ok)
	}
}

// Close 关闭客户端与其会话。
func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	s := c.sess
	c.sess = nil
	c.mu.Unlock()
	if s != nil {
		return s.Close()
	}
	return nil
}

// ---------------------------------------------------------------------------
// 路径拨号 + 握手
// ---------------------------------------------------------------------------

func (c *Client) dialPath(ctx context.Context, s *Session, join bool) (*path, error) {
	raw, err := c.dialTCP(ctx, c.cfg.Server)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, c.tlsCfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	p, err := c.handshake(ctx, s, tc, join, "tcp")
	if err != nil {
		tc.Close()
		return nil, err
	}
	return p, nil
}

func (c *Client) dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	if c.cfg.Dial != nil {
		// 注入的 dialer（clash 侧）自己管 socket 选项；连上之后再补设一次。
		conn, err := c.cfg.Dial(ctx, "tcp", addr)
		if err == nil {
			setCongestion(conn, c.cfg.congestion())
		}
		return conn, err
	}
	// 在 Control 里设：连接建立**之前**就生效，慢启动的头几个 RTT 也用上新算法。
	d := net.Dialer{Control: controlCongestion(c.cfg.congestion())}
	return d.DialContext(ctx, "tcp", addr)
}

// exporter 抽象出"从外层信道导出信道绑定值"，TCP+TLS 与 QUIC 各有一份。
type exporter interface {
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
}

func channelBinding(e exporter) ([cbHashLen]byte, error) {
	var cb [cbHashLen]byte
	b, err := e.ExportKeyingMaterial(ChannelBindingLabel, nil, cbHashLen)
	if err != nil {
		return cb, err
	}
	copy(cb[:], b)
	return cb, nil
}

// exporterFor 找出这条传输的信道绑定导出器。TCP 走 *tls.Conn，
// QUIC 走 quicConn 自己实现的那份——两者用的是同一套 TLS 1.3 导出器。
func exporterFor(conn net.Conn) (exporter, error) {
	switch t := conn.(type) {
	case *tls.Conn:
		return tlsExporter{t}, nil
	case exporter:
		return t, nil
	}
	return nil, errors.New("tide: transport does not support channel binding")
}

type tlsExporter struct{ c *tls.Conn }

func (t tlsExporter) ExportKeyingMaterial(label string, ctx []byte, n int) ([]byte, error) {
	cs := t.c.ConnectionState()
	return cs.ExportKeyingMaterial(label, ctx, n)
}

// handshake 在一条已完成外层握手的连接上跑 TIDE 握手。
func (c *Client) handshake(ctx context.Context, s *Session, conn net.Conn, join bool, kind string) (*path, error) {
	exp, err := exporterFor(conn)
	if err != nil {
		return nil, err
	}
	cb, err := channelBinding(exp)
	if err != nil {
		return nil, err
	}

	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
		defer conn.SetDeadline(time.Time{})
	} else {
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		defer conn.SetDeadline(time.Time{})
	}

	pathID := c.nextPath.Add(1)
	flags := uint8(0)
	if c.cfg.Bare {
		flags |= flagRequestBare
	}
	if preferAES {
		flags |= flagHasAESNI
	}
	sid := s.ID()
	if join && sid != ([16]byte{}) {
		flags |= flagJoinSession
	}

	// 有票据就 0-RTT，没有就 1-RTT。**绝不阻塞等待补充**——
	// 弱网下补充帧本身就可能丢，阻塞会把一次丢包放大成所有新连接挂死。
	if id, key, ok := c.wallet.take(time.Now()); ok {
		p, err := c.zeroRTT(s, conn, cb, id, key, flags, pathID, sid, kind)
		if err == nil {
			return p, nil
		}
		// 0-RTT 被拒（票据过期/服务端重启/位图不同步）时连接已经不可用了——
		// 服务端按 §6 把它转给掩护站点了，不能在同一条连接上重试。
		// 这里返回错误，由上层退避后重拨；那次重拨会因为钱包里没有可用票据而走 1-RTT。
		return nil, err
	}
	return c.oneRTT(s, conn, cb, flags, pathID, sid, kind)
}

func (c *Client) oneRTT(s *Session, conn net.Conn, cb [cbHashLen]byte, flags uint8, pathID uint32, sid [16]byte, kind string) (*path, error) {
	kemShare, ikm, eph, err := encapsulate(c.cfg.PublicKey)
	if err != nil {
		return nil, err
	}
	var cr [32]byte
	if _, err := io.ReadFull(rand.Reader, cr[:]); err != nil {
		return nil, err
	}
	transcript := transcriptHash(ProtocolVersion, kemShare, cr[:])
	kHS, err := handshakeKey(cr[:], ikm, transcript)
	if err != nil {
		return nil, err
	}

	ap := &authPlain{
		user: c.cfg.UserID, timestamp: time.Now().Unix(),
		cbHash: cb, flags: flags, sessionID: sid, pathID: pathID,
	}
	// 握手封装**恒用 ChaCha20-Poly1305**，与两端有没有 AES-NI 无关。
	// 理由：接收方在解开这条消息之前根本不知道对方用了什么（flags 就在密文里），
	// 试两种算法会引入一个可测的时间差，而握手就那么几帧，AES 快不快无关紧要。
	// AES/ChaCha 的选择只作用于记录层（批量数据），由 ACCEPT 里的 mode 位敲定。
	sealed, err := sealFixed(kHS, zeroNonce, ap.marshal(), transcript, false)
	if err != nil {
		return nil, err
	}
	h := &helloMsg{version: ProtocolVersion, kemShare: kemShare, clientRandom: cr, sealed: sealed}
	// ★ 握手帧必须填充。不填的话，每条 TIDE 连接的第一条应用记录长度是个常量
	// （全由协议结构决定），DPI 看一个包就能认出来。见 handshakePad。
	helloBody := h.marshal()
	if err := writeFrameExact(conn, FrameHello, FlagPush, 0, helloBody, handshakePad(len(helloBody))); err != nil {
		return nil, err
	}
	return c.readAccept(s, conn, kHS, transcript, pathID, kind, eph)
}

func (c *Client) zeroRTT(s *Session, conn net.Conn, cb [cbHashLen]byte, ticketID uint64, tkey []byte, flags uint8, pathID uint32, sid [16]byte, kind string) (*path, error) {
	var nonce [12]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	// 0-RTT 路径上没有 kem_share，服务端拿不到客户端的临时公开材料就做不了 ee，
	// 这条会话就会没有前向保密。所以这里另生成一对（X25519 + ML-KEM），
	// 把公开的那一半带在 zero_seal 里。
	ephPub, eph, err := newEphSecrets()
	if err != nil {
		return nil, err
	}
	zs := &zeroSeal{
		cbHash: cb, timestamp: time.Now().Unix(), user: c.cfg.UserID,
		sessionID: sid, flags: flags, pathID: pathID,
	}
	copy(zs.eph[:], ephPub)
	ad := make([]byte, 0, 1+8+12)
	ad = append(ad, ProtocolVersion)
	ad = appendU64(ad, ticketID)
	ad = append(ad, nonce[:]...)

	sealed, err2 := sealFixed(tkey, nonce[:], zs.marshal(nil), ad, false)
	err = err2
	if err != nil {
		return nil, err
	}
	z := &zeroRTTMsg{version: ProtocolVersion, ticketID: ticketID, nonce: nonce, sealed: sealed}
	zBody := z.marshal()
	if err := writeFrameExact(conn, FrameZeroRTT, FlagPush, 0, zBody, handshakePad(len(zBody))); err != nil {
		return nil, err
	}
	// 0-RTT 的 ACCEPT 用票据密钥派生的握手密钥保护。
	kHS, err := zeroRTTHandshakeKey(tkey, cb[:])
	if err != nil {
		return nil, err
	}
	return c.readAccept(s, conn, kHS, cb[:], pathID, kind, eph)
}

func zeroRTTHandshakeKey(ticketKey, cb []byte) ([]byte, error) {
	return hkdfKey(ticketKey, cb, labelZeroRTT)
}

// eph 是本次连接的 X25519 临时私钥：ACCEPT 里带回服务端的临时公钥，两者做 ee，
// 会话密钥因此获得前向保密（见 crypto.go）。
func (c *Client) readAccept(s *Session, conn net.Conn, kHS, ad []byte, pathID uint32, kind string, eph *ephSecrets) (*path, error) {
	f, err := readFrameExact(conn)
	if err != nil {
		return nil, err
	}
	if f.Type != FrameAccept {
		return nil, ErrProtocol
	}
	plain, err := openFixed(kHS, acceptNonce, f.Payload, ad, false)
	if err != nil {
		return nil, ErrProtocol
	}
	am, ok := parseAccept(plain)
	if !ok {
		return nil, ErrProtocol
	}
	if am.ticketCount > 0 {
		c.wallet.add(am.ticketBase, am.ticketCount, am.ticketSeed, time.Now())
	}

	first := s.ID() == [16]byte{}
	if first {
		s.mu.Lock()
		s.id = am.sessionID
		s.mu.Unlock()
		ee, err := clientEphemeralShared(eph, am.srvEph[:])
		if err != nil {
			return nil, err
		}
		secret, err := sessionSecret(kHS, ee, am.sessionID[:])
		if err != nil {
			return nil, err
		}
		c2s, s2c, err := directionKeys(secret)
		if err != nil {
			return nil, err
		}
		s.c2sKey, s.s2cKey = c2s, s2c
		s.bare = am.mode&acceptModeBare != 0
		s.useAES = am.mode&acceptModeAES != 0
	} else if am.sessionID != s.ID() {
		// 服务端不认这个会话（宽限期已过或它重启了）：这条路径没意义，
		// 而会话的密钥又不能改——只能放弃，让上层建新会话。
		return nil, ErrSessionGone
	}

	// 服务端可能给了不同的 path_id（比如本端选的号已被占用）。
	usePath := am.pathID
	if usePath == 0 {
		usePath = pathID
	}
	sealKey, err := pathKey(s.c2sKey, usePath)
	if err != nil {
		return nil, err
	}
	openKey, err := pathKey(s.s2cKey, usePath)
	if err != nil {
		return nil, err
	}
	// ★ bare 是**每路径**的属性，不是每会话的。同一个会话可以同时挂着一条 sealed 的
	// TCP 路径和一条 bare 的 QUIC 路径——QUIC 多流分流强制 bare（见 quicmux.go）。
	// 早先这里读的是 s.bare（会话级），那会让 QUIC 路径按 TCP 那条的模式建记录层，
	// 两端立刻对不上，且错误长得像"解密失败"，查起来会指向密钥调度。
	pathBare := am.mode&acceptModeBare != 0
	p, err := newPath(s, usePath, kind, conn, sealKey, openKey, s.useAES, pathBare)
	if err != nil {
		return nil, err
	}
	if qc, ok := conn.(*quicConn); ok && pathBare {
		p.qmux = newQUICMux(qc.conn, true, p)
	}
	return p, nil
}

// acceptNonce 与握手 seal 的全零 nonce 区分开——同一把 k_hs 下用了两次同一个 nonce
// 就是灾难，这里显式用 1 而不是 0。
var acceptNonce = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

func appendU64(b []byte, v uint64) []byte {
	return append(b, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
