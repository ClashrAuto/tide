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

	// h3entry 是本部署的 h3 入口路径，见 h3PathFor。算一次存着——
	// 每个请求都重算等于对着 1216 字节的公钥做一次 SHA-256。
	h3entry string
}

// h3Path 返回本部署的 h3 入口路径。
func (s *Server) h3Path() string { return s.h3entry }

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
	s.h3entry = h3PathFor(cfg.PrivateKey.Public())
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

// admitSession 决定能不能再给这个用户建一条会话。
//
// 返回 (victim, true) 表示可以建，且调用方**必须在锁外**关掉 victim（可能为 nil）；
// 返回 (nil, false) 表示这个用户的会话全都在用，只能拒。
//
// ★ 淘汰顺序是这里唯一需要想清楚的事：**只淘汰已经没有路径的会话**。
//
// 一个正常重连的客户端，会在旧会话还停在宽限期里的时候建一条新的——那恰恰是这个
// 协议存在的意义（spec §9）。所以：
//   - 直接拒绝新会话 = 把恢复路径堵死，上界本身变成故障；
//   - 淘汰一条**正在用**的会话 = 谁都能靠反复握手把别人的连接挤掉，
//     上界本身变成针对真实用户的攻击面。
//
// 宽限期里的会话此刻没有在服务任何人，淘汰最老的那条，代价上限是少一次无缝恢复。
// noPathSince 正好同时给出这两个信息：0 表示还有路径（不能动），
// 非 0 则是最后一条路径消失的时刻（越小越老）。
func (s *Server) admitSession(user [16]byte) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	var victim *Session
	var oldest int64
	for _, ss := range s.sessions {
		if ss.user != user {
			continue
		}
		n++
		idleSince := ss.sess.noPathSince.Load()
		if idleSince == 0 {
			continue // 还有路径，正在服务真实用户，不能动
		}
		if victim == nil || idleSince < oldest {
			victim, oldest = ss.sess, idleSince
		}
	}
	if n < s.cfg.maxSessionsPerUser() {
		return nil, true
	}
	if victim == nil {
		return nil, false
	}
	return victim, true
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

	// ★ 掩护连接**在读第一个字节之前**就开始拨，且不管这条连接后来是不是 TIDE。
	//
	// 这不是预取优化，是在堵一个时序侧信道。§7.1 要求"尽早判定"，于是不同的探测
	// 会在不同深度被否掉：一个 HTTP 请求第 2 个字节就出局，而一个长得像 HELLO 的
	// 探测要等服务端做完 X25519 + ML-KEM-768 解封装才在 AEAD 上失败。
	// 那段密码学运算的时间就直接写在"多久之后掩护源站开始回话"里。
	//
	// 实测（掩护源站在本机）：垃圾探测 182µs、像 HELLO 的探测 315µs，
	// 差 133µs / **+73%**，Welch t = 38.7，两个分布几乎不重叠。
	// 而一台真正的 nginx 对这两个输入的响应时间**没有任何差别**——两者都只是畸形请求。
	// 所以这个差值本身就是 TIDE 的签名，而且探测方不需要任何对照基线，
	// 拿同一台机器自己跟自己比就够了。
	//
	// 讽刺的是 §7 建议掩护源站放本机以压低延迟，那反而**抬高了信噪比**、让这个
	// 差值更好测。想靠"两边都慢一点"去抹平是抹不掉的：均值差在那里，多采几次就出来。
	//
	// 提前拨号把这件事从根上去掉：拨号在读任何字节之前就发起，它完成的时刻与
	// 探测方发了什么完全无关。失败关闭时掩护连接**已经在手**，响应时刻由掩护源站
	// 自己决定，密码学运算被并行掉了。代价是每条连接多一次到本机的 TCP 连接，
	// 握手成功时立刻关掉——TIDE 一条路径只握手一次，会话是长寿的，这个代价可以忽略。
	t.cover = s.dialCoverEarly()

	p, sess, err := s.serverHandshake(t)
	if err != nil {
		s.failClosed(t)
		return
	}
	t.stopRecording()
	// 这条是真的 TIDE：掩护连接直接关掉，它的响应一个字节都不会回给客户端。
	if c := t.takeCover(); c != nil {
		c.Close()
	}

	sess.addPath(p)
	<-p.dead
}

// dialCoverEarly 立刻起一个协程去连掩护源站，返回一个只会被写一次的通道。
// 拿不到（没配掩护源站、或连不上）时通道里是 nil。
func (s *Server) dialCoverEarly() <-chan net.Conn {
	ch := make(chan net.Conn, 1)
	if s.cfg.CoverAddr == "" || s.cfg.CoverAddr == "drop" {
		ch <- nil
		return ch
	}
	go func() {
		c, err := net.DialTimeout("tcp", s.cfg.CoverAddr, 5*time.Second)
		if err != nil {
			ch <- nil
			return
		}
		ch <- c
	}()
	return ch
}

// failClosed 执行 §7。掩护连接由 handleConn 在读第一个字节之前就拨好、
// 并可能已经由 serverHandshake 提前把握手帧推过去了（见那两处的说明：
// 这是在堵一个时序侧信道，不是预取优化）。
func (s *Server) failClosed(t *teeConn) {
	defer t.Conn.Close()
	// ⚠️ 必须先把握手期间设的读超时清掉。忘了这一步，下面的 io.Copy 会在
	// 已经过期的 deadline 上立刻返回，掩护转发变成空操作——而且测不出来：
	// 连接照样在，只是一个字节都不转，探测方看到的是"TLS 握手成功后立刻沉默"，
	// 比不做伪装还显眼。
	t.Conn.SetDeadline(time.Time{})
	up := t.takeCover()
	if up == nil {
		// 没配掩护源站，或者连不上。这时候唯一不制造差异的做法是把连接晾着
		// 直到对端放弃，而不是马上关——马上关是一个可测量的、与真实站点
		// 完全不同的行为（§7.2）。
		io.Copy(io.Discard, t.Conn)
		return
	}
	defer up.Close()

	// 把**还没推过**的那段录音补给上游（早推已经送走的部分不会重发）。
	if err := t.flushCover(up); err != nil {
		io.Copy(io.Discard, t.Conn)
		return
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
	sent      int // rec 里已经转给掩护源站的前缀长度
	recording bool

	// cover 是 handleConn 在读第一个字节之前就发起的掩护连接（见 dialCoverEarly）。
	cover     <-chan net.Conn
	coverOnce sync.Once
	up        net.Conn
}

// takeCover 取出提前拨好的掩护连接。多次调用返回同一条；没有掩护源站时返回 nil。
func (t *teeConn) takeCover() net.Conn {
	t.coverOnce.Do(func() {
		if t.cover != nil {
			t.up = <-t.cover
		}
	})
	return t.up
}

// flushCover 把"已经录到、但还没转给掩护源站"的那一段推过去。可重复调用。
//
// 拆出偏移量是必要的：早推（serverHandshake 里）与失败关闭都会调它，
// 不记偏移就会把握手帧发两遍——掩护源站收到的请求于是和真实访问不一样，
// 响应也就不一样，等于把想消除的差异换了个地方留下。
func (t *teeConn) flushCover(up net.Conn) error {
	t.mu.Lock()
	// ⚠️ 必须夹一下：stopRecording 会把 rec 置 nil 而**不动** sent。
	// 今天 stopRecording（握手成功）与 flushCover（失败关闭）互斥，走不到一起，
	// 但早推那个协程是并发的，重排一次代码就可能撞上——那时 t.rec[t.sent:]
	// 就是 nil[2450:]，直接 panic 掉整个进程。夹住比记住这条互斥关系可靠。
	if t.sent > len(t.rec) {
		t.sent = len(t.rec)
	}
	buf := append([]byte(nil), t.rec[t.sent:]...)
	t.sent = len(t.rec)
	t.mu.Unlock()
	if len(buf) == 0 {
		return nil
	}
	_, err := up.Write(buf)
	return err
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
	// ★ 握手帧已经读完，密码学验证还没开始——**就在这里**把已收到的字节推给掩护源站。
	//
	// 这是时序侧信道的第二半（第一半是 handleConn 里的提前拨号）。只提前拨号不够：
	// 本机掩护源站的一次往返大约 150µs，而 X25519 + ML-KEM-768 解封装要 130µs，
	// 后者仍然整个压在关键路径上。实测提前拨号只把差值从 133µs 压到 64µs。
	// 把请求也提前推出去之后，掩护源站的处理与本端的密码学运算**并行**，
	// 响应时刻由两者的较大值决定，而不是相加。
	//
	// 推的是"到目前为止读到的字节"，长度只取决于对端发了多少、与内容无关，
	// 所以这一步本身不引入新的输入相关性。握手成功时这条掩护连接直接关掉，
	// 它的响应一个字节都不会回给客户端。
	// ⚠️ 这里曾经起一个协程"提前把已收到的字节推给掩护源站"，想让掩护源站的处理与
	// 本端的密码学运算并行。**已经删掉**，因为它一无所得、代价却实在：
	//
	//  · 一无所得：实测提前拨号把两类探测的响应时间差从 +73% 压到 +33%，
	//    而再加上提前推请求，差值纹丝不动（64.1µs → 64.1µs，t 从 19.0 到 19.1）。
	//    原因是掩护源站的**响应**在确认握手失败之前本来就不能回给客户端，
	//    请求提前送出去也没法让响应提前到达。
	//  · 代价：它对**每一条合法握手**都会把那 2.4 KB 加密后的 HELLO 推给掩护源站。
	//    掩护源站于是为每次正常连接记一条畸形请求的日志——既是噪音，
	//    也是一个相关性信号：谁能看到掩护源站的日志，就能数出 TIDE 的握手次数。
	//    掩护源站若是第三方站点，这还等于替用户往别人服务器上发垃圾。
	//
	// 既有实践（Xray/Trojan 的 fallback）也是同一条线：**只有认证失败才碰后端**。
	// 合法会话一个字节都不该流到掩护源站。
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
	// ★ 版本必须在 parseHello **之前**查。
	//
	// 版本字节存在的全部意义是让"线格式变了"这件事能被明确地认出来。
	// 而 parseHello 的第一件事是按**当前版本**的 kemShareLen 校验长度——
	// 换句话说，一个旧版本客户端会先在长度上被否掉，返回 ErrProtocol，
	// 版本字节根本没被看过一眼。运维看到的是"协议错误"，
	// 而真相是"这两端版本不一样"，两者的处置完全不同。
	//
	// 版本字节在 payload[0]，不需要任何解析就能读。
	if len(f.Payload) < 1 {
		return nil, nil, ErrProtocol
	}
	if f.Payload[0] != ProtocolVersion {
		// 版本不支持 MUST 走失败关闭，MUST NOT 回版本错误——
		// 任何区别性响应都是可探测的指纹（spec §9）。ErrVersion 只进本端日志。
		return nil, nil, ErrVersion
	}
	h, ok := parseHello(f.Payload)
	if !ok {
		return nil, nil, ErrProtocol
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
	// 1-RTT 的客户端临时公开材料分散在 kem_share 的两头：X25519 公钥在最前面，
	// 临时 ML-KEM 封装密钥在最后（中间那段是发给**静态**密钥的密文，与 ee 无关）。
	// serverEphemeral 要的是"X25519 公钥 || 封装密钥"这个拼接，和 0-RTT 的 zero_seal.eph 同形。
	cliEph := make([]byte, 0, cliEphLen)
	cliEph = append(cliEph, h.kemShare[:x25519PubLen]...)
	cliEph = append(cliEph, h.kemShare[kemStaticLen:kemShareLen]...)
	return s.finishHandshake(t, kHS, transcript, ap.user, ap.sessionID, ap.pathID, ap.flags, useAES, cb, cliEph)
}

func (s *Server) handleZeroRTT(t *teeConn, f Frame, cb [cbHashLen]byte) (*path, *Session, error) {
	z, ok := parseZeroRTT(f.Payload)
	if !ok || z.version != ProtocolVersion {
		return nil, nil, ErrProtocol
	}
	// ⚠️ 顺序（spec §3.3）：**只读**取密钥 → 解密（= 证明持有密钥）→ **原子置位**。
	//
	// 这里有一个鸡生蛋：要查位图得先知道 user_id，而 user_id 在密文里。
	// 解法是位图按 (user, id) 存但允许按 id 反查所属用户批次——MemTicketStore 的
	// Issue 用全局单调基址分配，所以 ticket_id 本身就唯一确定了批次。
	//
	// ★ 曾经这里是"查位图 → 置位 → 再解密"，注释还写着"置位必须先于解密"。那是错的，
	// 而且是个能把 0-RTT 整个废掉的错：ticket_id 是**明文**（不然没法反查密钥），
	// 基址又从全局单调计数器分配，于是 ticket_id 完全可预测——0、1、2……
	// 先置位就意味着**任何人**都能用一个 ~124 字节的伪造帧烧掉任意一张票据，
	// 不需要持有任何密钥。实测 32 张票据被 32 个垃圾帧烧得一张不剩。
	// 攻击者顺着 id 数上去就能让整台服务器上所有用户永久退回 1-RTT，
	// 而服务端回的还是掩护站点，全程没有任何日志或错误。
	//
	// 原子性不需要靠"先置位"来换：它由置位这一步**自己**保证。RFC 8446 §8.2 对
	// TLS 1.3 的 0-RTT 给的正是这个顺序——服务端先验 PSK binder，之后才碰防重放记录。
	seed, uid, burned, okc := s.peekTicket(z.ticketID)
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
	// 解开了 = 对端确实持有这张票据的密钥。现在才动防重放状态。
	// 并发的同一张票据在这里分胜负：consume 是原子的，只会有一个赢，其余判为重放。
	// 之后的检查（时间戳/信道绑定/用户）失败仍然**保持**已消费——那时对端是真的
	// 持有密钥的，这段密文已经上过线，放它回去就等于允许重放。
	if !burned {
		if _, _, ok := s.consumeTicket(z.ticketID); !ok {
			return nil, nil, ErrBadTicket
		}
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
	// 0-RTT 没有 kem_share，客户端临时公钥自己带在 zero_seal 里。
	return s.finishHandshake(t, kHS, cb[:], zs.user, zs.sessionID, zs.pathID, zs.flags, useAES, cb, zs.eph[:])
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

// peekTicket 只读地反查票据密钥。见 handleZeroRTT 里的顺序说明。
//
// 返回的 burned 表示"这次反查已经把票据消费掉了"——只有在 store 没实现 anyPeeker、
// 只能退回旧的合并接口时才为 true。调用方据此跳过第二次消费，否则那次必然失败，
// 0-RTT 会对这类部署彻底不可用。
func (s *Server) peekTicket(id uint64) (seed [32]byte, user [16]byte, burned, ok bool) {
	if ms, isMem := s.store.(*MemTicketStore); isMem {
		seed, user, ok = ms.peekAny(id)
		return seed, user, false, ok
	}
	if ap, has := s.store.(anyPeeker); has {
		seed, user, ok = ap.PeekAny(id)
		return seed, user, false, ok
	}
	// ⚠️ 只实现了 anyConsumer 的旧 store：退回"先消费再认证"。
	// 这条路上伪造帧能烧票据（见 handleZeroRTT），所以集群 store **应当**实现 anyPeeker。
	// 这里不直接失败，是因为失败会让这类部署的 0-RTT 彻底不可用，比弱一点更糟。
	if ac, has := s.store.(anyConsumer); has {
		seed, user, ok = ac.ConsumeAny(id)
		return seed, user, true, ok
	}
	return seed, user, false, false
}

// anyConsumer 让集群 store 也能"按 ticket_id 反查用户并原子消费"。
type anyConsumer interface {
	ConsumeAny(id uint64) (seed [32]byte, user [16]byte, ok bool)
}

// anyPeeker 是 anyConsumer 的只读一半：取出密钥但不置位。
// 集群 store **应当**同时实现它，否则 0-RTT 会退回到"先消费再认证"，
// 而那条路上任何人都能用伪造帧烧掉别人的票据。
type anyPeeker interface {
	PeekAny(id uint64) (seed [32]byte, user [16]byte, ok bool)
}

func (s *Server) userAllowed(u [16]byte) bool {
	if len(s.cfg.Users) == 0 {
		return true
	}
	_, ok := s.cfg.Users[u]
	return ok
}

// clientEph 是对端本次连接的 X25519 临时公钥：1-RTT 取自 kem_share 前 32 字节，
// 0-RTT 取自 zero_seal.eph。服务端拿它做 ee，会话密钥因此获得前向保密（见 crypto.go）。
func (s *Server) finishHandshake(t *teeConn, kHS, ad []byte, user, wantSession [16]byte,
	wantPath uint32, flags uint8, useAES bool, cb [cbHashLen]byte, clientEph []byte) (*path, *Session, error) {

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

	// ★ 会话数也要有上界，而且必须在写 ACCEPT **之前**判。
	//
	// 会话曾经是这个协议里唯一没有上界的一级——路径有 maxPathsPerSession、
	// 流有 maxStreams、票据批次有 maxLiveBatchesPerUser，偏偏会话没有。
	// 而它和那三个是同一个形状：**由对端驱动**。一次握手建一条会话，每条会话要付
	// 7 个协程加流表、路径表、宽限期定时器，并且**在路径全断之后还要活满宽限期**
	// （编排默认 120 秒）。那正是它存在的理由，也正是它可以被拿来堆积的原因：
	// 握手、断开、再握手，一个已认证的对端就能让服务端替它攒下成千上万条
	// "正在等主人回来"的会话，全程不触发任何错误路径
	// （RFC 9000 §21.9 Peer Denial of Service 说的正是这一类）。
	//
	// 判在 ACCEPT 之前，是为了让拒绝走**和其它认证失败完全一样的那条路**
	// （§7 失败关闭 → 掩护源站）。放在 ACCEPT 之后拒，客户端已经拿到 ACCEPT、
	// 以为握手成功了，接着会把掩护源站的字节当 TIDE 帧解——既多一个可测的差异，
	// 又让合法客户端的失败变得莫名其妙。
	if !joining {
		if victim, ok := s.admitSession(user); !ok {
			return nil, nil, ErrProtocol
		} else if victim != nil {
			// 在锁外关：Close 会唤醒那条会话的清理协程，而它要拿 s.mu。
			victim.Close()
		}
	}
	sid := wantSession
	if !joining {
		var err error
		sid, err = newSessionID()
		if err != nil {
			return nil, nil, err
		}
	}

	// path_id 决定记录层密钥（pathKey），而每条路径的 nonce 都从 0 起——
	// 同一会话里两条路径共用一个 path_id 就是 (key, nonce) 复用，AEAD 当场失效。
	// 所以对端报上来的号不能照单全收：已经被占用（或干脆没给）就换一个。
	//
	// ⚠️ 这里只是**尽早**换号，让正常客户端不必白跑一次握手；真正的不变量由
	// Session.addPath 在插入时原子地保证——并发加入能绕过这里的检查，绕不过那里。
	// 客户端本来就按"服务端可能给我换号"写的（它用 ACCEPT 里的 path_id），
	// 只是服务端从前并没有真的换。
	pathID := wantPath
	if pathID == 0 || (sess != nil && sess.pathIDInUse(pathID)) {
		for {
			pathID = s.nextPath.Add(1)
			if sess == nil || !sess.pathIDInUse(pathID) {
				break
			}
		}
	}

	// ★ 只有**新建会话**才签发票据。加入路径（含断线重连）不签。
	//
	// 原先每次握手都签一批 1024 张。配上单用户活跃批次的上界
	// （maxLiveBatchesPerUser，防的是对端刷 TICKET_REQUEST 撑爆票据库），
	// 结果是一条长会话不停地把**自己手里还没用完**的批次挤掉——
	// 而客户端又恰好从最老的批次开始用，两个方向正好相反。
	// 每张这样的票都换来一次完整的失败连接，然后才退回 1-RTT。
	//
	// 加入路径时客户端本来就有票；真不够时它会自己发 TICKET_REQUEST 来要
	// （ticketLoop 每 5 秒检查一次，低于 25% 就请求）。所以这里不签什么也不缺。
	var base uint64
	var seed [32]byte
	var count uint16
	if !joining {
		count = s.cfg.ticketCount()
		var err error
		base, seed, err = s.store.Issue(user, count)
		if err != nil {
			return nil, nil, err
		}
	}

	// 每次握手一对全新的临时密钥。公钥随 ACCEPT 发出去，私钥用完就丢——
	// 前向保密全靠"私钥从不上线"这一点（见 crypto.go 的 serverEphemeral）。
	srvEphPub, ee, err := serverEphemeral(clientEph)
	if err != nil {
		return nil, nil, err
	}
	am := &acceptMsg{
		sessionID: sid, pathID: pathID,
		ticketBase: base, ticketCount: count, ticketSeed: seed,
	}
	copy(am.srvEph[:], srvEphPub)
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
	if err := writeFrameExact(t.Conn, FrameAccept, FlagPush, 0, sealedAccept, handshakePad(len(sealedAccept))); err != nil {
		return nil, nil, err
	}

	if !joining {
		secret, err := sessionSecret(kHS, ee, sid[:])
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
			idle := s.cfg.udpTimeout()
			// ★ 空闲回收由**服务端**保证，而不是塞在默认 handler 里。
			// 见 watchUDPIdle 的说明：接入方换掉 PacketHandler 之后，
			// 从前会连这条保证一起丢掉，且没有任何迹象。
			go watchUDPIdle(ps, idle)
			go func() {
				if s.PacketHandler != nil {
					s.PacketHandler(context.Background(), ps)
				} else {
					packetRelay(context.Background(), ps, idle)
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

// watchUDPIdle 在一条关联**两个方向都**静默超过 idle 之后把它整条收掉。
//
// ★ 这条保证必须由服务端给，不能只写在默认 handler 里。
//
// 空闲回收原先只存在于 packetRelay（也就是 DefaultPacketHandler）内部。
// 于是任何一个提供了自己的 PacketHandler 的接入方——clash 那个 listener 就是——
// **静默地**失去了这条保证：它的 handler 只是阻塞在 ReadFrom 上，没有任何超时，
// 于是"对端开了关联却再也不管"这种情况会一直占着流数配额，直到整条会话过期。
// 而这恰恰是 §9.4 第二条要挡的那一类（对端一声不吭地消失）。
//
// Go 官方 net/http 的取法正相反，也正是该学的：WriteTimeout 覆盖**整个 handler 栈**
// 的生命周期，handler 换成什么都一样——服务端级别的保证不会因为换了 handler 就蒸发。
// 这里照此办理：关联一建起来就挂上看门狗，handler 是谁都不影响。
//
// 计时看的是 PacketStream.lastActive，收发两侧都会刷新它（见 datagram.go），
// 所以纯下载的关联不会在传输中途被误收。
func watchUDPIdle(ps *PacketStream, idle time.Duration) {
	tick := idle / 4
	if tick < time.Second {
		tick = time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ps.done:
			return // 关联已经没了，看门狗立刻跟着退
		case <-t.C:
		}
		if time.Since(time.Unix(0, ps.lastActive.Load())) > idle {
			ps.Close()
			return
		}
	}
}

// DefaultPacketHandler 为一条 UDP 关联建一个本地 socket 并转发。
func DefaultPacketHandler(ctx context.Context, ps *PacketStream) {
	packetRelay(ctx, ps, DefaultUDPTimeout)
}

// packetRelay 是 DefaultPacketHandler 的本体，多一个空闲上限参数供服务端配置与测试。
//
// ★ 空闲回收和"流结束 = 关联结束"（见 stream.go 的 endAssoc）是**两条独立的**
// 回收路径，缺一不可。前者管的是对端一声不吭消失的情况（客户端崩了、路径断了、
// 或者干脆是个恶意实现），后者管的是正常关闭。某家 SOCKS5 服务的事故复盘写得
// 很直白：他们同时依赖"TCP 连接关闭"和"空闲超时"，两条都没配好，
// 于是 node_sockstat_UDP_inuse 爬到两万八，而 CPU/内存/HTTP 健康检查全是绿的。
//
// ⚠️ 从前这里的形状是错的：上行协程给 pc 设 2 分钟读超时，**超时就 return**，
// 但外层还堵在 ps.ReadFrom() 上，于是 pc 不会被关、handler 也不会返回。
// 结果不是"关联被回收"，而是"关联半死"——客户端还能往外发，回包却再也回不来了，
// 而且两端都不报错。比泄漏更难查。
//
// 现在照 mihomo 的做法：任一方向有流量就把读超时**顶回去**（它在 WriteTo 之后
// 直接去重设对端协程的 deadline，Go 里对阻塞中的 Read 调 SetReadDeadline 是安全的
// 且立即生效），真超时了就把**整条关联**收掉，两个方向一起。
func packetRelay(ctx context.Context, ps *PacketStream, idle time.Duration) {
	defer ps.Close()
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return
	}
	defer pc.Close()

	go func() {
		// 上行方向一旦结束，整条关联就结束：关掉 ps 把外层从 ReadFrom 里唤醒。
		// 少了这一句就是上面说的"半死"。
		defer ps.Close()
		defer pc.Close()
		buf := make([]byte, 64*1024)
		for {
			pc.SetReadDeadline(time.Now().Add(idle))
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
		// 下行有流量 = 这条关联还活着，把上行那边的空闲计时顶回去。
		pc.SetReadDeadline(time.Now().Add(idle))
	}
}
