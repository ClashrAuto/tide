package tide

import (
	"bufio"
	"context"
	"crypto/tls"
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
	// h3Path 是 TIDE 请求的路径。选一个不起眼、且真实站点上大概率不存在的路径；
	// 它落在**加密的** h3 请求头里，被动观察者看不到，主动探测方也猜不出——
	// 就算猜中了，没有票据/KEM 一样过不了认证，只会被反代到掩护站点。
	h3Path = "/api/v1/stream"
	// h3CtlHeader 区分"控制请求"（承载握手，一条路径一个）与"数据请求"（一条流一个）。
	h3CtlHeader  = "X-Request-Id"
	h3CtlValue   = "ctl"
	h3DataPrefix = "s"
)

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
	for {
		conn, err := ln.Accept(context.Background())
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
	h3 := &http3.Server{Handler: http.HandlerFunc(bind.serve)}
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
	if r.URL.Path != h3Path || r.Method != http.MethodPost {
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
		// 这条请求已经回过 200 了，在探测方看来就是一个开着不说话的长连接——
		// 与真实的流式接口没有区别。
		io.Copy(io.Discard, st)
		st.Close()
		return
	}
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
	var captured *quic.Conn
	var once sync.Once
	tr := &http3.Transport{
		TLSClientConfig: quicClientTLS(c.tlsCfg),
		QUICConfig:      h3QUICConfig(),
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			// ★ 自己拨、自己留一份连接引用：信道绑定要从这条连接导出 TLS Exporter，
			// 而 http3.Transport 不把连接暴露给调用方。没有这个钩子就没法做 §5。
			conn, err := quic.DialAddr(ctx, addr, tlsCfg, cfg)
			if err == nil {
				once.Do(func() { captured = conn })
			}
			return conn, err
		},
	}

	ctlStream, err := c.openH3Stream(ctx, tr, true, 0)
	if err != nil {
		tr.Close()
		return nil, err
	}
	if captured == nil {
		ctlStream.Close()
		tr.Close()
		return nil, errNoExporter
	}

	hc := &h3ClientConn{rw: ctlStream, conn: captured}
	p, err := c.handshake(ctx, s, hc, join, "quic")
	if err != nil {
		ctlStream.Close()
		tr.Close()
		return nil, err
	}
	p.h3 = &h3Client{tr: tr, client: c}
	p.qmux = newQUICMuxH3(captured, p, func() (muxStream, error) {
		return c.openH3Stream(context.Background(), tr, false, 0)
	})
	return p, nil
}

// openH3Stream 发一个 POST 并把它变成一条双向字节流：
// 请求体是上行、响应体是下行。
func (c *Client) openH3Stream(ctx context.Context, tr *http3.Transport, control bool, sid uint64) (*h3ClientStream, error) {
	pr, pw := io.Pipe()
	url := "https://" + c.quicAddr() + h3Path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, pr)
	if err != nil {
		return nil, err
	}
	if control {
		req.Header.Set(h3CtlHeader, h3CtlValue)
	} else {
		req.Header.Set(h3CtlHeader, h3DataPrefix)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		pw.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		pw.Close()
		return nil, ErrProtocol
	}
	return &h3ClientStream{w: pw, r: resp.Body}, nil
}

type h3ClientStream struct {
	w *io.PipeWriter
	r io.ReadCloser
}

func (s *h3ClientStream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *h3ClientStream) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s *h3ClientStream) Close() error {
	s.w.Close()
	return s.r.Close()
}

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
}

func newBufReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }

// hopByHop 是 RFC 9110 §7.6.1 列出的逐跳头，外加 h3 禁止的 Connection 系。
var hopByHop = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-connection": true,
	"proxy-authenticate": true, "proxy-authorization": true,
	"te": true, "trailer": true, "transfer-encoding": true, "upgrade": true,
}

func isHopByHop(k string) bool { return hopByHop[strings.ToLower(k)] }
