package tide

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Server 是 TIDE 入站。
//
// 它有两件事和普通的服务端不一样，且两件都不能省：
//
//  1. **失败关闭必须真的转发**（§6）。认证失败时把这条连接的全部字节原样代理到
//     掩护源站，直到任一端关闭，全程不做特殊超时/限速/日志分支。不能"模拟"响应——
//     失败路径 0.1ms、真实站点 50ms，探测方量一下响应时间分布就分开了。
//     时序是这里唯一真正难伪造的东西。
//  2. **会话要活得比连接长**（宽限期）。客户端的路径全断了之后，会话连同它的流、
//     未确认字节、上游连接都得留着，等对方带着同一个 session_id 回来。
//     这是"网络波动不断线"在服务端的那一半。

type Server struct {
	cfg   *ServerConfig
	store TicketStore

	mu       sync.Mutex
	sessions map[[16]byte]*serverSession
	closed   bool

	// Handler 处理一条被代理的流。为空时用 DefaultHandler（直连目标）。
	Handler func(ctx context.Context, st *Stream)
	// PacketHandler 处理一条 UDP 关联。
	PacketHandler func(ctx context.Context, ps *PacketStream)

	nextPath atomic.Uint32
	stopped  chan struct{}
	stopOnce sync.Once
}

type serverSession struct {
	sess       *Session
	user       [16]byte
	graceTimer *time.Timer
}

func NewServer(cfg *ServerConfig) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	store := cfg.TicketStore
	if store == nil {
		store = NewMemTicketStore()
	}
	s := &Server{
		cfg:      cfg,
		store:    store,
		sessions: make(map[[16]byte]*serverSession),
		stopped:  make(chan struct{}),
	}
	s.nextPath.Store(1 << 20) // 服务端分配的 path_id 与客户端选的不撞
	go s.sweepLoop()
	return s, nil
}

// Serve 在 l 上接受连接。l 应当已经是**明文** listener：
// TLS 由本函数套上，因为信道绑定要拿到 tls.Conn 本身。
func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			select {
			case <-s.stopped:
				return nil
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		setCongestion(c, s.cfg.congestion())
		go s.handleConn(c)
	}
}

// Close 停止服务端。
func (s *Server) Close() error {
	s.stopOnce.Do(func() { close(s.stopped) })
	s.mu.Lock()
	s.closed = true
	sess := make([]*serverSession, 0, len(s.sessions))
	for _, ss := range s.sessions {
		sess = append(sess, ss)
	}
	s.sessions = map[[16]byte]*serverSession{}
	s.mu.Unlock()
	for _, ss := range sess {
		ss.sess.Close()
	}
	return nil
}

func (s *Server) sweepLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.stopped:
			return
		case now := <-t.C:
			s.store.Sweep(now)
		}
	}
}

// ---------------------------------------------------------------------------
// 连接处理
// ---------------------------------------------------------------------------

func (s *Server) handleConn(raw net.Conn) {
	tc := tls.Server(raw, s.cfg.TLSConfig)
	// 外层 TLS 握手失败：不是 TIDE 的事，直接丢。这里不转发掩护站点，
	// 因为连 TLS 都没建起来的对端本来就看不到任何 TIDE 特有的行为。
	hctx, hcancel := context.WithTimeout(context.Background(), 10*time.Second)
	err := tc.HandshakeContext(hctx)
	hcancel()
	if err != nil {
		raw.Close()
		return
	}

	// tee 记录握手期间读到的所有字节。认证失败时这些字节要原样喂给掩护源站——
	// 不能只转发"之后"的字节，否则掩护源站收到的是一个被砍掉头部的请求，
	// 它的响应会和真实访问不一样，探测方照样能分辨。
	t := &teeConn{Conn: tc, rec: make([]byte, 0, 4096), recording: true}

	p, sess, err := s.serverHandshake(t)
	if err != nil {
		s.failClosed(t)
		return
	}
	t.stopRecording()

	sess.addPath(p)
	<-p.dead
}

// failClosed 执行 §6。
func (s *Server) failClosed(t *teeConn) {
	defer t.Conn.Close()
	// ⚠️ 必须先把握手期间设的读超时清掉。忘了这一步，下面的 io.Copy 会在
	// 已经过期的 deadline 上立刻返回，掩护转发变成空操作——而且测不出来：
	// 连接照样在，只是一个字节都不转，探测方看到的是"TLS 握手成功后立刻沉默"，
	// 比不做伪装还显眼。
	t.Conn.SetDeadline(time.Time{})
	if s.cfg.CoverAddr == "drop" {
		// 显式选择了不做伪装。直接读到对端放弃为止——
		// 至少不要出现"立刻 RST"这种明显的区别性行为。
		io.Copy(io.Discard, t.Conn)
		return
	}
	up, err := net.DialTimeout("tcp", s.cfg.CoverAddr, 5*time.Second)
	if err != nil {
		// 掩护源站连不上。这时候唯一不制造差异的做法是把连接晾着直到对端放弃，
		// 而不是马上关——马上关是一个可测量的、与真实站点完全不同的行为。
		io.Copy(io.Discard, t.Conn)
		return
	}
	defer up.Close()

	// 先把握手期间已经读走的字节补给上游，再做双向拷贝。
	if rec := t.recorded(); len(rec) > 0 {
		if _, err := up.Write(rec); err != nil {
			io.Copy(io.Discard, t.Conn)
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, t.Conn); done <- struct{}{} }()
	go func() { io.Copy(t.Conn, up); done <- struct{}{} }()
	<-done
}

// teeConn 在 recording 期间把读到的字节留一份副本。
type teeConn struct {
	net.Conn
	mu        sync.Mutex
	rec       []byte
	recording bool
}

func (t *teeConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		t.mu.Lock()
		if t.recording {
			t.rec = append(t.rec, p[:n]...)
		}
		t.mu.Unlock()
	}
	return n, err
}

func (t *teeConn) stopRecording() {
	t.mu.Lock()
	t.recording = false
	t.rec = nil
	t.mu.Unlock()
}

func (t *teeConn) recorded() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.rec
}

// ---------------------------------------------------------------------------
// 握手
// ---------------------------------------------------------------------------

func (s *Server) serverHandshake(t *teeConn) (*path, *Session, error) {
	exp, err := exporterFor(t.Conn)
	if err != nil {
		return nil, nil, err
	}
	cb, err := channelBinding(exp)
	if err != nil {
		return nil, nil, err
	}
	// 合法客户端在外层 TLS 握手完成后**立刻**把整个 HELLO/ZERO_RTT 写出去，
	// 一个 RTT 都不会等。所以这里给 5 秒就绰绰有余，而超时越短，
	// 一个故意拖着不发的探测方就越早被交给掩护源站。
	t.Conn.SetDeadline(time.Now().Add(handshakeReadTimeout))
	defer t.Conn.SetDeadline(time.Time{})

	var hdr [2]byte
	if _, err := io.ReadFull(t, hdr[:]); err != nil {
		return nil, nil, err
	}
	// ★ 只看 2 个字节就能否掉绝大多数探测：HTTP 请求以 'G'/'P'/'H' 开头，
	// TLS-in-TLS 以 0x16 开头，端口扫描往往一个字节都不发。
	// 它们全都不等于 0x01/0x03，于是立刻走失败关闭，掩护源站在毫秒级接手。
	typ := FrameType(hdr[0])
	if typ != FrameHello && typ != FrameZeroRTT {
		return nil, nil, ErrProtocol
	}
	// 长度上界也按类型收紧：握手帧的大小是知道的，一个声称自己是 HELLO
	// 却要发 50 KB 的对端不必等它发完。
	f, err := readFrameRest(t, hdr, maxHandshakeBody)
	if err != nil {
		return nil, nil, err
	}
	switch f.Type {
	case FrameHello:
		if len(f.Payload) < minHelloBody {
			return nil, nil, ErrProtocol
		}
		return s.handleHello(t, f, cb)
	case FrameZeroRTT:
		if len(f.Payload) < minZeroRTTBody {
			return nil, nil, ErrProtocol
		}
		return s.handleZeroRTT(t, f, cb)
	}
	return nil, nil, ErrProtocol
}

const (
	handshakeReadTimeout = 5 * time.Second
	// HELLO 的固定部分：version(1) + kem_share(1120) + client_random(32) +
	// sealed 长度前缀(2) + sealed 本身（auth_plain + 16 字节 tag）。
	minHelloBody = 1 + kemShareLen + 32 + 2 + authPlainLen + 16
	// ZERO_RTT：version(1) + ticket_id(8) + nonce(12) + 长度前缀(2) + sealed。
	minZeroRTTBody = 1 + 8 + 12 + 2 + zeroSealLen + 16
	// 上界留出 early_data 的余量，但远小于 MaxFrameBody。
	maxHandshakeBody = 16 * 1024
)

func (s *Server) handleHello(t *teeConn, f Frame, cb [cbHashLen]byte) (*path, *Session, error) {
	h, ok := parseHello(f.Payload)
	if !ok {
		return nil, nil, ErrProtocol
	}
	// 版本不支持 MUST 走失败关闭，MUST NOT 回版本错误——
	// 任何区别性响应都是可探测的指纹（spec §9）。
	if h.version != ProtocolVersion {
		return nil, nil, ErrVersion
	}
	ikm, err := decapsulate(s.cfg.PrivateKey, h.kemShare)
	if err != nil {
		return nil, nil, err
	}
	transcript := transcriptHash(h.version, h.kemShare, h.clientRandom[:])
	kHS, err := handshakeKey(h.clientRandom[:], ikm, transcript)
	if err != nil {
		return nil, nil, err
	}
	// 握手封装恒用 ChaCha20-Poly1305（见 client.go 里同一处的说明）：
	// flags 就在密文里，解开之前无从知道对方用了什么，试两种会引入可测的时间差。
	plain, err := openFixed(kHS, zeroNonce, h.sealed, transcript, false)
	if err != nil {
		return nil, nil, ErrProtocol
	}
	ap, ok := parseAuthPlain(plain)
	if !ok {
		return nil, nil, ErrProtocol
	}
	if !timestampSane(ap.timestamp, time.Now()) {
		return nil, nil, ErrStaleTimestamp
	}
	if ap.cbHash != cb {
		// 中间人终止并重建了外层 TLS。失败关闭，MUST NOT 降级重试。
		return nil, nil, ErrChannelBinding
	}
	if !s.userAllowed(ap.user) {
		return nil, nil, ErrProtocol
	}
	useAES := ap.flags&flagHasAESNI != 0 && preferAES
	return s.finishHandshake(t, kHS, transcript, ap.user, ap.sessionID, ap.pathID, ap.flags, useAES, cb)
}

func (s *Server) handleZeroRTT(t *teeConn, f Frame, cb [cbHashLen]byte) (*path, *Session, error) {
	z, ok := parseZeroRTT(f.Payload)
	if !ok || z.version != ProtocolVersion {
		return nil, nil, ErrProtocol
	}
	// ⚠️ 顺序不能动（spec §3.3）：查位图 → **置位** → 再解密 early_data。
	// 置位必须先于解密，且对同一 ticket_id 的并发必须原子化，否则重放保护失效——
	// 而且不会有任何报错，重放的连接会正常建立。
	//
	// 这里还有一个鸡生蛋：要查位图得先知道 user_id，而 user_id 在密文里。
	// 解法是位图按 (user, id) 存但允许按 id 反查所属用户批次——MemTicketStore 的
	// Issue 用全局单调基址分配，所以 ticket_id 本身就唯一确定了批次。
	seed, uid, okc := s.consumeTicket(z.ticketID)
	if !okc {
		return nil, nil, ErrBadTicket
	}
	tkey, err := ticketKey(seed[:], z.ticketID)
	if err != nil {
		return nil, nil, err
	}
	ad := make([]byte, 0, 1+8+12)
	ad = append(ad, z.version)
	ad = appendU64(ad, z.ticketID)
	ad = append(ad, z.nonce[:]...)

	plain, err := openFixed(tkey, z.nonce[:], z.sealed, ad, false)
	if err != nil {
		return nil, nil, ErrProtocol
	}
	zs, _, ok := parseZeroSeal(plain)
	if !ok {
		return nil, nil, ErrProtocol
	}
	if !timestampSane(zs.timestamp, time.Now()) {
		return nil, nil, ErrStaleTimestamp
	}
	if zs.cbHash != cb {
		return nil, nil, ErrChannelBinding
	}
	if zs.user != uid || !s.userAllowed(zs.user) {
		return nil, nil, ErrProtocol
	}
	kHS, err := zeroRTTHandshakeKey(tkey, cb[:])
	if err != nil {
		return nil, nil, err
	}
	useAES := zs.flags&flagHasAESNI != 0 && preferAES
	return s.finishHandshake(t, kHS, cb[:], zs.user, zs.sessionID, zs.pathID, zs.flags, useAES, cb)
}

func (s *Server) consumeTicket(id uint64) ([32]byte, [16]byte, bool) {
	// MemTicketStore 的 Consume 需要 user；这里用它的反查接口。
	if ms, ok := s.store.(*MemTicketStore); ok {
		return ms.consumeAny(id)
	}
	// 自定义 store（比如 Redis）应实现 anyConsumer。
	if ac, ok := s.store.(anyConsumer); ok {
		return ac.ConsumeAny(id)
	}
	var z1 [32]byte
	var z2 [16]byte
	return z1, z2, false
}

// anyConsumer 让集群 store 也能"按 ticket_id 反查用户并原子消费"。
type anyConsumer interface {
	ConsumeAny(id uint64) (seed [32]byte, user [16]byte, ok bool)
}

func (s *Server) userAllowed(u [16]byte) bool {
	if len(s.cfg.Users) == 0 {
		return true
	}
	_, ok := s.cfg.Users[u]
	return ok
}

func (s *Server) finishHandshake(t *teeConn, kHS, ad []byte, user, wantSession [16]byte,
	wantPath uint32, flags uint8, useAES bool, cb [cbHashLen]byte) (*path, *Session, error) {

	bare := s.cfg.AllowBare && flags&flagRequestBare != 0

	var sess *Session
	joining := false
	if wantSession != ([16]byte{}) {
		s.mu.Lock()
		ss := s.sessions[wantSession]
		s.mu.Unlock()
		if ss != nil && ss.user == user {
			sess = ss.sess
			joining = true
			// 客户端回来了：撤掉宽限期定时器。
			s.cancelGrace(wantSession)
		}
		// 会话不在（宽限期已过或服务端重启）：不报错，当作新会话建。
		// 客户端会发现 ACCEPT 里的 session_id 变了，然后放弃旧会话建新的——
		// 比在这里失败关闭要好，因为这不是攻击，是正常的超时。
	}

	// ★ QUIC 路径**只能加入已有会话，不能新建会话**（spec §12.6）。
	//
	// QUIC 面是加速通道，不是门面：它不做 §7 的掩护转发（掩护对象只能是另一个
	// QUIC/HTTP-3 服务，而字节流也不能直接搬过去——QUIC 有自己的流语义）。
	// 既然它没有伪装，就不该让它成为一个可以独立进入的入口。
	//
	// 强制"必须先有会话"之后，探测方无论怎么打这个 UDP 端口都拿不到任何东西：
	// 它没有会话 ID，而会话 ID 只能通过 TCP 那条**有掩护**的路径认证后取得。
	// 这把"QUIC 是加速通道"从一句部署建议变成了协议强制的性质。
	if isQUICConn(t.Conn) && !joining {
		return nil, nil, ErrProtocol
	}
	sid := wantSession
	if !joining {
		var err error
		sid, err = newSessionID()
		if err != nil {
			return nil, nil, err
		}
	}

	pathID := wantPath
	if pathID == 0 {
		pathID = s.nextPath.Add(1)
	}

	count := s.cfg.ticketCount()
	base, seed, err := s.store.Issue(user, count)
	if err != nil {
		return nil, nil, err
	}

	am := &acceptMsg{
		sessionID: sid, pathID: pathID,
		ticketBase: base, ticketCount: count, ticketSeed: seed,
	}
	if bare || isQUICConn(t.Conn) {
		am.mode |= acceptModeBare
	}
	if useAES {
		am.mode |= acceptModeAES
	}
	sealedAccept, err := sealFixed(kHS, acceptNonce, am.marshal(), ad, false)
	if err != nil {
		return nil, nil, err
	}
	if err := writeFrameExact(t.Conn, FrameAccept, FlagPush, 0, sealedAccept, 0); err != nil {
		return nil, nil, err
	}

	if !joining {
		secret, err := sessionSecret(kHS, sid[:])
		if err != nil {
			return nil, nil, err
		}
		c2s, s2c, err := directionKeys(secret)
		if err != nil {
			return nil, nil, err
		}
		sess = newSession(sid, false, s.cfg.streamWindow(), s.cfg.sessionGrace(),
			DefaultProbeInterval, s.cfg.maxStreams())
		sess.c2sKey, sess.s2cKey = c2s, s2c
		sess.bare = bare
		sess.useAES = useAES
		sess.user = user
		sess.localAddr = t.Conn.LocalAddr()
		sess.onTicketReq = func() { s.replenish(sess, user) }
		go sess.ticketServeLoop()

		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil, nil, ErrClosed
		}
		s.sessions[sid] = &serverSession{sess: sess, user: user}
		s.mu.Unlock()

		go sess.retransmitLoop()
		go sess.rebalanceLoop()
		go s.acceptLoop(sess)
		go func() {
			<-sess.closed
			s.mu.Lock()
			delete(s.sessions, sid)
			s.mu.Unlock()
		}()
		// 会话失去全部路径时启动宽限期。
		go s.graceWatcher(sess, sid)
	}

	// 服务端读客户端 = c2s，写客户端 = s2c。
	openKey, err := pathKey(sess.c2sKey, pathID)
	if err != nil {
		return nil, nil, err
	}
	sealKey, err := pathKey(sess.s2cKey, pathID)
	if err != nil {
		return nil, nil, err
	}
	// ★ 这里必须用 isQUICConn（含 h3），不能再写一次窄的 *quicConn 断言。
	//
	// 曾经就是两处各自回答"这是不是 QUIC"：上面 ACCEPT 的 mode 位用了 isQUICConn
	// （于是**告诉客户端用 bare**），这里用窄断言（于是**服务端建了 sealed 记录层**）。
	// 同一个函数里隔着 70 行的两个答案不一致，结果是服务端发密文、客户端当明文读，
	// 现象是"h3 路径建起来就死"，报错还是 frame exceeds max size ——
	// 指向解帧，跟 bare 协商差着十万八千里。查了整整两轮。
	//
	// nativeQUIC 单独留着，是因为下面装原生多流复用器需要那个**具体类型**；
	// 但凡涉及"要不要 bare"，一律走 isQUICConn。
	qc, nativeQUIC := t.Conn.(*quicConn)
	isQUIC := isQUICConn(t.Conn)
	kind := "tcp"
	if isQUIC {
		kind = "quic"
	}
	// bare 是**每路径**的属性。QUIC 路径无条件 bare，且不受 AllowBare 开关约束——
	// 那个开关防的是"外层可能没有 AEAD"的情况（裸 TCP + 混淆），而 QUIC-TLS
	// **恒定**提供 AEAD，加上信道绑定已经证明外层没被中间人替换，
	// spec §6.2 允许 bare 的两个前提天然满足。分流本身也要求 bare（见 quicmux.go）。
	pathBare := bare || isQUIC
	p, err := newPath(sess, pathID, kind, t.Conn, sealKey, openKey, sess.useAES, pathBare)
	if err != nil {
		return nil, nil, err
	}
	if nativeQUIC {
		p.qmux = newQUICMux(qc.conn, false, p)
	}
	return p, sess, nil
}

// replenish 增量补充票据。
//
// 补充走**普通帧**而不是重新握手，所以它跑在已建立的会话上，成本只有一个小帧。
// 客户端在剩余量跌破 25% 时就会来要，留出的余量足以覆盖一次补充帧在弱网上丢失
// 并等到下一个 5 秒周期重发。
func (s *Server) replenish(sess *Session, user [16]byte) {
	base, seed, err := s.store.Issue(user, s.cfg.ticketCount())
	if err != nil {
		return
	}
	payload := appendTicketGrant(nil, base, s.cfg.ticketCount(), seed)
	sess.sendControl(FrameTicketRepl, payload)
}

// graceWatcher 在会话没有任何路径时开始倒计时，超时才真的关掉会话。
//
// ★ 这是服务端这一半的"网络波动不断线"。客户端 Wi-Fi 切走的那一刻，
// 服务端这边所有上游 TCP 连接都还开着、缓冲还在，等对方带着同一个 session_id 回来。
// 没有它，客户端就算 0-RTT 重连成功也只能拿到一个空会话，用户的连接照样全断。
func (s *Server) graceWatcher(sess *Session, sid [16]byte) {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-sess.closed:
			return
		case <-s.stopped:
			return
		case <-t.C:
		}
		since := sess.noPathSince.Load()
		if since == 0 {
			continue
		}
		if time.Since(time.Unix(0, since)) > s.cfg.sessionGrace() {
			sess.closeWith(ErrSessionGone)
			return
		}
	}
}

func (s *Server) cancelGrace(sid [16]byte) {
	s.mu.Lock()
	ss := s.sessions[sid]
	s.mu.Unlock()
	if ss != nil && ss.graceTimer != nil {
		ss.graceTimer.Stop()
	}
}

// ---------------------------------------------------------------------------
// 流处理
// ---------------------------------------------------------------------------

func (s *Server) acceptLoop(sess *Session) {
	for {
		st, err := sess.AcceptStream(context.Background())
		if err != nil {
			return
		}
		if st.udp {
			ps := st.pkt
			go func() {
				if s.PacketHandler != nil {
					s.PacketHandler(context.Background(), ps)
				} else {
					DefaultPacketHandler(context.Background(), ps)
				}
			}()
			continue
		}
		go func(st *Stream) {
			if s.Handler != nil {
				s.Handler(context.Background(), st)
			} else {
				DefaultHandler(context.Background(), st)
			}
		}(st)
	}
}

// DefaultHandler 直连目标并对拷。
func DefaultHandler(ctx context.Context, st *Stream) {
	defer st.Close()
	var d net.Dialer
	up, err := d.DialContext(ctx, "tcp", st.dst)
	if err != nil {
		var buf [4]byte
		buf[3] = byte(StreamErrRefused)
		st.sess.sendOnStream(st, FrameStreamRst, FlagPush, buf[:])
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, st); done <- struct{}{} }()
	go func() { io.Copy(st, up); done <- struct{}{} }()
	<-done
}

// DefaultPacketHandler 为一条 UDP 关联建一个本地 socket 并转发。
func DefaultPacketHandler(ctx context.Context, ps *PacketStream) {
	defer ps.Close()
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 64*1024)
		for {
			pc.SetReadDeadline(time.Now().Add(2 * time.Minute))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := ps.WriteTo(buf[:n], addr.String()); err != nil {
				return
			}
		}
	}()
	for {
		d, err := ps.ReadFrom()
		if err != nil {
			return
		}
		ua, err := net.ResolveUDPAddr("udp", d.Addr)
		if err != nil {
			continue
		}
		if _, err := pc.WriteTo(d.Data, ua); err != nil {
			return
		}
	}
}
