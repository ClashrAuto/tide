package tide

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// TIDE over HTTP/3（spec §12.6）。
//
// ★ 为什么必须是"搬到 h3 之上"，而不是"在旁边加一个 h3 服务器"：
//
// 判别问题无解。h3 的请求流以 HEADERS 帧（类型 0x01）开头，TIDE 的 HELLO 也是 0x01。
// 想先窥探一下再决定交给谁，就必须消费掉第一条双向流——而一旦消费，就再也交还不回给
// h3 服务器，探测方发的那个请求会永远挂着。那比"沉默"更可疑。
//
// 所以这里让服务端**永远是一个货真价实的 h3 服务器**：TIDE 只是它上面的一组请求，
// 认证通过就劫持底层流跑 TIDE，其余一律反向代理到掩护源站。
// 探测方无论怎么打这个 UDP 端口，拿到的都是掩护站点的真实响应。
//
// h3 的行为来自 quic-go 自己的实现（Caddy 用的是同一套），不是手搓的，
// 所以不存在"一个行为古怪的 HTTP/3 服务器"这种新指纹。
//
// 映射关系天然对齐：**一个 h3 请求 = 一条 TIDE 流**，与 §12.5 的每流一条 QUIC 流一致。

const (
	// h3CtlHeader 区分"控制请求"（承载握手，一条路径一个）与"数据请求"（一条流一个）。
	h3CtlHeader  = "X-Request-Id"
	h3CtlValue   = "ctl"
	h3DataPrefix = "s"
)

// h3PathFor 导出这个部署的 TIDE 入口路径。
//
// ★ 它**必须**跟着服务端静态公钥走，不能是个常量。
//
// 这条路径曾经写死成 /api/v1/stream。它落在加密的 h3 请求头里，被动观察者确实
// 看不到——但主动探测方不需要看，猜一次就行，而且它在**每一个** TIDE 部署上
// 逐字节相同：猜中一次等于拿到全网扫描的判据。/api/v1/stream 恰恰是扫描器字典里
// 会有的那种路径。这与 deploy/cover/index.html 那张占位页、以及握手帧的固定长度
// 是同一类错误——**一个到处一样的常量就是指纹**。
//
// 更糟的是打中之后的行为：服务端在认证**之前**就把 200 发出去（客户端要等响应头
// 才敢写，见 serve 里的说明），认证失败之后只是把连接晾着。于是探测方看到的是
// "200 OK 然后无限沉默"——真实站点上不存在的路径会 404，真的流式接口会发点什么，
// 两样都不是。NDSS'20 那篇 Detecting Probe-resistant Proxies 量过这件事：
// 网上超过 94% 的服务器会对某个常见协议回数据，不回数据本身就是异常。
//
// 处置照 Caddy forwardproxy 的 probe_resistance：没有凭据的请求一律当成普通网站
// 伺候（这里就是反代到掩护源站，h3Cover 已经在做），而代理入口藏在一个只有持密者
// 知道的**秘密地址**后面（Caddy 用 secret-link 域名）。这里的"密"现成就有：
// 服务端静态公钥，客户端配置里本来就带着它，不需要任何新配置项。
//
// 猜不中就没有任何区别性行为可测——探测方无论打哪条路径，拿到的都是掩护源站的
// 真实响应。而要猜中就得先有公钥，那已经是共享秘密了。
func h3PathFor(pub *PublicKey) string {
	// 独立的标签，避免这个导出值与任何密钥派生共用输入。
	sum := sha256.Sum256(append([]byte("tide/draft-02 h3-path\x00"), pub.Bytes()...))
	// 形状要像个正常的带 ID 的 API 路径，别像随机串。
	return "/api/v1/" + hex.EncodeToString(sum[:8])
}

// ---------------------------------------------------------------------------
// 服务端
// ---------------------------------------------------------------------------

// ServeH3 在 addr 上提供 HTTP/3：TIDE 请求走 TIDE，其余全部反代到掩护源站。
//
// 与 ServeQUIC 的区别就是这一句——ServeQUIC 对非 TIDE 连接只能沉默，
// 而沉默本身是可测量的异常（一台在 TCP/443 上服务 HTTPS 的主机，
// 在 UDP/443 上跑一个不响应 h3 的 QUIC 端点，说不通）。
func (s *Server) ServeH3(addr string) error {
	tlsCfg := s.cfg.TLSConfig.Clone()
	tlsCfg.NextProtos = []string{quicALPN}
	ln, err := quic.ListenAddr(addr, tlsCfg, h3QUICConfig())
	if err != nil {
		return err
	}
	defer ln.Close()
	ctx, cancel := s.acceptContext()
	defer cancel()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			select {
			case <-s.stopped:
				return nil
			default:
			}
			return err
		}
		go s.serveH3Conn(conn)
	}
}

func (s *Server) serveH3Conn(conn *quic.Conn) {
	// 每条 QUIC 连接一个 h3 服务器实例，好让 handler 闭包拿到这条 *quic.Conn——
	// 信道绑定（spec §5）要从它导出 TLS Exporter，而 http3 的 handler 上下文里没有。
	bind := &h3Binding{srv: s, conn: conn}
	h3 := &http3.Server{
		Handler: http.HandlerFunc(bind.serve),
		// RFC 9297：UDP 关联要走 HTTP Datagram，不能塞进可靠有序的流里
		// （§9.1：UDP MUST NOT 重传）。
		EnableDatagrams: true,
	}
	// ★ 交给 ServeQUICConn 的连接**必须由调用方关**，这是 quic-go 明写的契约：
	// "All connections passed to http3.Server.ServeQUICConn need to be closed by
	// the caller, before calling http3.Server.Close."
	//
	// 从前没人关它。于是 Server.Close() 之后，quic-go 内部的 AcceptStream 一直挂着，
	// ServeQUICConn 永远不返回——这条协程连同整条 QUIC 连接一起泄漏，
	// 每来一条 h3 连接就漏一份。和第 36 轮 ServeQUIC 那个 Accept 是同一类：
	// **停机信号到不了正在阻塞的那一层**。
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-s.stopped:
			conn.CloseWithError(0, "")
			h3.Close()
		case <-done:
		}
	}()
	_ = h3.ServeQUICConn(conn)
	bind.close()
}

// h3Binding 把一条 QUIC 连接上的多个 h3 请求绑到同一条 TIDE 路径上。
type h3Binding struct {
	srv  *Server
	conn *quic.Conn

	mu   sync.Mutex
	path *path
	sess *Session
}

func (b *h3Binding) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != b.srv.h3Path() || r.Method != http.MethodPost {
		b.srv.h3Cover(w, r)
		return
	}
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		b.srv.h3Cover(w, r)
		return
	}
	// 先回 200 **并冲刷**再劫持。
	//
	// ★ Flush 不能省：quic-go 的 responseWriter 会缓冲小响应（maxSmallResponseSize），
	// 不冲刷的话响应头要等 handler 返回才发出去——而 handler 正阻塞在 TIDE 握手上
	// 等客户端发 HELLO，客户端又在等响应头才敢开始写。**双方互等，死锁**。
	// 现象是 h3 路径永远建不起来，而掩护那条路一切正常，看日志完全看不出关联。
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	st := streamer.HTTPStream()

	if r.Header.Get(h3CtlHeader) == h3CtlValue {
		b.serveControl(st)
		return
	}
	b.serveData(st)
}

// serveControl 处理承载握手的那一个请求，成功后这条连接上就有了一条 TIDE 路径。
func (b *h3Binding) serveControl(st *http3.Stream) {
	qc := &h3Conn{Stream: st, conn: b.conn}
	t := &teeConn{Conn: qc, recording: false}
	p, sess, err := b.srv.serverHandshake(t)
	if err != nil {
		// 认证失败：不做任何区别性响应，读到对端放弃为止。
		//
		// ⚠️ 这条路**不**反代到掩护源站，而且做不到——200 在认证之前就发出去了
		// （客户端要等响应头才敢写，见 serve 里的说明），掩护源站的状态码与响应头
		// 已经没地方放了。所以这里能提供的只是"一个开着不说话的长连接"。
		//
		// 它之所以仍然可以接受，是因为**走到这里必须先猜中入口路径**，
		// 而那条路径由服务端静态公钥导出（见 h3PathFor）——猜不中就走 h3Cover，
		// 拿到的是掩护源站的真实响应；能猜中就说明已经持有共享秘密了。
		// 这就是 Caddy forwardproxy 的 probe_resistance 结构：
		// 秘密地址之外一律当普通网站伺候。
		// 别把这条路当成"反正有掩护"——它没有。
		io.Copy(io.Discard, st)
		st.Close()
		return
	}
	// ★ 服务端侧也要装 h3 分流器，否则 serveData 拿不到 qmux，
	// 会把每条数据流原地丢掉——路径活着、控制流通着，数据却一个字节都不过。
	p.qmux = newQUICMuxH3Server(b.conn, p)
	// 控制流同时是数据报流：两端必须用同一条，客户端那边也是控制流。
	p.h3srv = st
	go recvH3Datagrams(p, st)

	b.mu.Lock()
	b.path, b.sess = p, sess
	b.mu.Unlock()

	sess.addPath(p)
	<-p.dead
	st.Close()
}

// serveData 处理一条数据请求 = 一条 TIDE 流。
func (b *h3Binding) serveData(st *http3.Stream) {
	// 控制请求先到是协议约定；没到就说明这是个乱来的客户端。
	deadline := time.Now().Add(5 * time.Second)
	var p *path
	for time.Now().Before(deadline) {
		b.mu.Lock()
		p = b.path
		b.mu.Unlock()
		if p != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if p == nil || p.qmux == nil {
		io.Copy(io.Discard, st)
		st.Close()
		return
	}
	p.qmux.adoptStream(&h3Stream{st: st})
}

func (b *h3Binding) close() {
	b.mu.Lock()
	p := b.path
	b.mu.Unlock()
	if p != nil {
		p.markDead()
	}
}

// recvH3Datagrams 收 RFC 9297 数据报并按普通帧分发（服务端侧）。
func recvH3Datagrams(p *path, st *http3.Stream) {
	// ★ 不能传 context.Background()。路径死掉时 serveControl 会 st.Close()，
	// 但关流**并不会**唤醒一个正挂在 ReceiveDatagram 上的调用（实测如此），
	// 于是这条收数据报的协程会一直挂着。绑到 p.dead 上才是可靠的。
	// 与第 36 轮 ServeQUIC 的 Accept 同一个坑，只是换了个函数。
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-p.dead:
			cancel()
		case <-ctx.Done():
		}
	}()
	for {
		b, err := st.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		f, err := readFrameExact(bytes.NewReader(b))
		if err != nil {
			continue
		}
		p.noteRecvDatagram(len(f.Payload))
		if err := p.sess.handleFrame(p, f); err != nil {
			return
		}
	}
}

// h3Cover 把非 TIDE 的 h3 请求反向代理到掩护源站。
//
// 这一步是 §12.6 的全部意义：探测方拿到的是掩护站点的**真实**响应，
// 而不是一个模拟的、或者干脆沉默的端点。
func (s *Server) h3Cover(w http.ResponseWriter, r *http.Request) {
	if s.cfg.CoverAddr == "" || s.cfg.CoverAddr == "drop" {
		// 没有掩护源站可用。返回一个最普通的 404 —— 比沉默好，
		// 至少看起来像个正常但没有这个资源的网站。
		http.NotFound(w, r)
		return
	}
	up, err := net.DialTimeout("tcp", s.cfg.CoverAddr, 5*time.Second)
	if err != nil {
		http.Error(w, "", http.StatusBadGateway)
		return
	}
	defer up.Close()

	// 用 HTTP/1.1 转给掩护源站，再把它的响应原样搬回 h3。
	outReq := r.Clone(r.Context())
	outReq.URL.Scheme = "http"
	outReq.URL.Host = s.cfg.CoverAddr
	outReq.RequestURI = ""
	if err := outReq.Write(up); err != nil {
		http.Error(w, "", http.StatusBadGateway)
		return
	}
	resp, err := http.ReadResponse(newBufReader(up), outReq)
	if err != nil {
		http.Error(w, "", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		// ★ 逐跳头（hop-by-hop）在 HTTP/2 与 HTTP/3 里是**非法**的，原样搬过去
		// 会让规范的 h3 客户端直接报 H3_INTERNAL_ERROR 断连——而那正好是
		// 我们想消除的"异常端点"信号，等于自己把伪装拆了。
		if isHopByHop(k) {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// ---------------------------------------------------------------------------
// 把 h3 流适配成 TIDE 需要的形状
// ---------------------------------------------------------------------------

// h3Conn 让握手代码把一条 h3 流当普通 net.Conn 用，同时保留信道绑定的能力。
type h3Conn struct {
	*http3.Stream
	conn *quic.Conn
}

func (c *h3Conn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *h3Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *h3Conn) ExportKeyingMaterial(label string, ctx []byte, n int) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, errNoExporter
		}
	}()
	cs := c.conn.ConnectionState().TLS
	return cs.ExportKeyingMaterial(label, ctx, n)
}

// h3Stream 把一条 h3 流包装成 quicMux 能收养的样子。
type h3Stream struct {
	st *http3.Stream
}

func (s *h3Stream) Read(p []byte) (int, error)  { return s.st.Read(p) }
func (s *h3Stream) Write(p []byte) (int, error) { return s.st.Write(p) }
func (s *h3Stream) Close() error                { return s.st.Close() }

// ---------------------------------------------------------------------------
// 客户端
// ---------------------------------------------------------------------------

// dialH3Path 用 HTTP/3 拨一条 TIDE 路径。
func (c *Client) dialH3Path(ctx context.Context, s *Session, join bool) (*path, error) {
	// ★ 自己拨 QUIC，再用 NewClientConn 把 h3 架上去。
	//
	// 不用 Transport.RoundTrip 的原因有两个，缺一不可：
	//  1. 信道绑定（§5）要从这条 *quic.Conn 导出 TLS Exporter，而 RoundTrip 不暴露连接。
	//  2. RFC 9297 的数据报绑在**具体某条请求流**上，只有 OpenRequestStream 拿得到
	//     那个 *RequestStream；RoundTrip 只给 resp.Body，够不着 SendDatagram。
	//
	// ⚠️ 两者不能混用：NewClientConn 会自己开一条 h3 控制流并发 SETTINGS，
	// 同一条 QUIC 连接上再让 RoundTrip 开第二条，就是两条控制流 = h3 协议错误。
	captured, err := quic.DialAddr(ctx, c.quicAddr(), quicClientTLS(c.tlsCfg), h3QUICConfig())
	if err != nil {
		return nil, err
	}
	tr := &http3.Transport{EnableDatagrams: true}
	cc := tr.NewClientConn(captured)

	// ★ 请求的生命周期必须绑到**路径**，不能绑到拨号 ctx。
	//
	// 控制流就是那个 HTTP 请求本身。调用方（maintainQUIC）在拨号返回后立刻
	// cancel() 掉拨号 ctx——若请求挂在它上面，路径**建起来的同一瞬间就被拆掉**，
	// 现象正是"h3 路径起来就死"。原生 QUIC 路径不受影响，因为 DialAddr /
	// OpenStreamSync 的 ctx 只约束等待，不决定流的存活。
	pctx, pcancel := context.WithCancel(context.Background())
	// 拨号超时仍要约束**握手阶段**：ctx 到期而握手还没完成，就撤掉整条路径。
	hsDone := make(chan struct{})
	go func() {
		select {
		case <-hsDone:
		case <-ctx.Done():
			select {
			case <-hsDone:
			default:
				pcancel()
			}
		}
	}()
	fail := func(err error) (*path, error) {
		close(hsDone)
		pcancel()
		tr.Close()
		return nil, err
	}

	ctlStream, err := c.openH3Stream(pctx, cc, true)
	if err != nil {
		return fail(err)
	}
	hc := &h3ClientConn{rw: ctlStream, conn: captured}
	p, err := c.handshake(ctx, s, hc, join, "quic")
	if err != nil {
		ctlStream.Close()
		return fail(err)
	}
	close(hsDone) // 握手完成：拨号 ctx 到期起不再影响这条路径

	// 控制流同时承载 RFC 9297 的数据报：数据报绑在流上，两端必须用**同一条**流，
	// 而控制流是唯一双方都确定存在、且生命周期与路径一致的那条。
	p.h3 = &h3Client{tr: tr, client: c, cancel: pcancel, ctl: ctlStream.rs}
	// 数据流同样用路径级 ctx，路径一死它们跟着回收。
	p.qmux = newQUICMuxH3(captured, p, func() (muxStream, error) {
		return c.openH3Stream(pctx, cc, false)
	})
	go p.h3.recvDatagrams(pctx, p)
	return p, nil
}

// openH3Stream 开一条请求流，并把它当成双向字节流用。
//
// 比先前的 io.Pipe + resp.Body 干净：RequestStream 本身就是双向的，
// 而且它才拿得到 SendDatagram（RFC 9297 的数据报绑在具体请求流上）。
func (c *Client) openH3Stream(ctx context.Context, cc *http3.ClientConn, control bool) (*h3ClientStream, error) {
	rs, err := cc.OpenRequestStream(ctx)
	if err != nil {
		return nil, err
	}
	url := "https://" + c.quicAddr() + h3PathFor(c.cfg.PublicKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}
	if control {
		req.Header.Set(h3CtlHeader, h3CtlValue)
	} else {
		req.Header.Set(h3CtlHeader, h3DataPrefix)
	}
	if err := rs.SendRequestHeader(req); err != nil {
		return nil, err
	}
	// 服务端在劫持前就回了 200 并冲刷，所以这里不会久等。
	resp, err := rs.ReadResponse()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		rs.Close()
		return nil, ErrProtocol
	}
	return &h3ClientStream{rs: rs}, nil
}

type h3ClientStream struct {
	rs *http3.RequestStream
}

func (s *h3ClientStream) Read(p []byte) (int, error)  { return s.rs.Read(p) }
func (s *h3ClientStream) Write(p []byte) (int, error) { return s.rs.Write(p) }
func (s *h3ClientStream) Close() error                { return s.rs.Close() }

// h3ClientConn 是客户端侧的握手载体，同样要能导出信道绑定值。
type h3ClientConn struct {
	rw   *h3ClientStream
	conn *quic.Conn
}

func (c *h3ClientConn) Read(p []byte) (int, error)  { return c.rw.Read(p) }
func (c *h3ClientConn) Write(p []byte) (int, error) { return c.rw.Write(p) }
func (c *h3ClientConn) Close() error                { return c.rw.Close() }
func (c *h3ClientConn) LocalAddr() net.Addr         { return c.conn.LocalAddr() }
func (c *h3ClientConn) RemoteAddr() net.Addr        { return c.conn.RemoteAddr() }
func (c *h3ClientConn) SetDeadline(t time.Time) error {
	return nil // h3 流的超时由 ctx 管，这里是空实现
}
func (c *h3ClientConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *h3ClientConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *h3ClientConn) ExportKeyingMaterial(label string, ctx []byte, n int) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, errNoExporter
		}
	}()
	cs := c.conn.ConnectionState().TLS
	return cs.ExportKeyingMaterial(label, ctx, n)
}

// h3Client 挂在 path 上，供 quicMux 需要新流时回调。
type h3Client struct {
	tr     *http3.Transport
	client *Client
	// cancel 撤掉路径级 ctx，连带回收这条路径上所有 h3 请求。
	cancel context.CancelFunc
	// ctl 是承载 RFC 9297 数据报的那条请求流（= 控制流）。
	ctl *http3.RequestStream
}

// sendDatagram 用 RFC 9297 的 HTTP Datagram 发一帧。
// quic-go 自己加 Quarter Stream ID 前缀，这里不用手写 RFC 9297 的封装。
func (h *h3Client) sendDatagram(b []byte) error {
	if h.ctl == nil {
		return errNoQUICStream
	}
	return h.ctl.SendDatagram(b)
}

func (h *h3Client) recvDatagrams(ctx context.Context, p *path) {
	if h.ctl == nil {
		return
	}
	for {
		b, err := h.ctl.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		f, err := readFrameExact(bytes.NewReader(b))
		if err != nil {
			continue // 坏数据报丢掉即可
		}
		p.noteRecvDatagram(len(f.Payload))
		if err := p.sess.handleFrame(p, f); err != nil {
			return
		}
	}
}

func (h *h3Client) close() {
	if h.cancel != nil {
		h.cancel()
	}
	if h.tr != nil {
		h.tr.Close()
	}
}

func newBufReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }

// hopByHop 是 RFC 9110 §7.6.1 列出的逐跳头，外加 h3 禁止的 Connection 系。
var hopByHop = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-connection": true,
	"proxy-authenticate": true, "proxy-authorization": true,
	"te": true, "trailer": true, "transfer-encoding": true, "upgrade": true,
}

func isHopByHop(k string) bool { return hopByHop[strings.ToLower(k)] }
