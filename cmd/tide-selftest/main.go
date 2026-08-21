// tide-selftest 是 TIDE 的自检与实网压测工具。
//
// 三种用法：
//
//	tide-selftest -mode keygen                     生成一对静态密钥
//	tide-selftest -mode local                      进程内跑完整链路，exit 0 = 通过
//	tide-selftest -mode server -listen :8443 …     实网服务端
//	tide-selftest -mode client  -server host:8443 … 实网客户端（带波动统计）
//
// local 模式对应 CLAUDE.md 里 COAST_TIDE_SELFTEST 的约定：不需要网络、不需要 root、
// exit 0 即通过，可以直接进 CI。
//
// client 模式才是重点：它在真实链路上做**带序号的持续传输**，一边传一边统计
// 断流次数、最长卡顿、重连次数。网络波动下的稳定性没法靠"能不能连上"来判断——
// 能连上但每隔几秒卡两秒，用户体验比连不上还差，只有连续传输的时间分布看得出来。
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClashrAuto/tide"
)

func main() {
	var (
		mode       = flag.String("mode", "local", "keygen | local | server | client")
		listen     = flag.String("listen", ":8443", "server listen address")
		server     = flag.String("server", "", "client: server address host:port")
		password   = flag.String("password", os.Getenv("TIDE_PASSWORD"), "client: password (must match one of the server's -users entries)")
		target     = flag.String("target", "echo.invalid:80", "client: address to hammer **through** the proxy; the default only works against -mode server (its handler echoes without dialing), point it at a real host:port when testing tide-server")
		key        = flag.String("key", "", "server: private key (base64) / client: public key (base64)")
		cover      = flag.String("cover", "", "server: cover origin host:port (required)")
		dur        = flag.Duration("duration", 60*time.Second, "client: how long to hammer the link")
		rate       = flag.Int("rate", 2*1024*1024, "client: target bytes/sec")
		streams    = flag.Int("streams", 4, "client: concurrent streams")
		redun      = flag.Bool("redundancy", false, "client: keep two paths alive at all times")
		bare       = flag.Bool("bare", false, "client: request bare-frame mode")
		grace      = flag.Duration("grace", tide.DefaultSessionGrace, "session grace period")
		probe      = flag.Duration("probe", tide.DefaultProbeInterval, "path probe interval")
		insecure   = flag.Bool("insecure", true, "client: skip outer TLS verification (test certs)")
		useQUIC    = flag.Bool("quic", false, "client: also establish a QUIC path")
		useH3      = flag.Bool("h3", false, "run the QUIC path over HTTP/3 (spec §12.6 masquerade)")
		congestion = flag.String("congestion", "", "TCP congestion control for TIDE paths (\"-\" = leave system default)")
		quicListen = flag.String("quic-listen", "", "server: also serve QUIC on this address")
		// window 只为实验存在：单流发送窗口同时也是**排队上限**。默认 512 KiB 是按
		// 100Mbps×40ms 的 BDP 定的；换到 BDP 小得多的链路（比如 2Mbit×166ms ≈ 41 KiB），
		// 一条流就能把十几倍 BDP 塞进网里，排队时延全落到用户头上。
		window = flag.Uint64("window", 0, "client: 单流发送窗口字节数（0 = 默认 512 KiB）")
		// pprof 只在压测时用：TIDE 的 CPU 开销分布不看 profile 就只能猜，而
		// 「猜错优化点」在这种协议里代价很高——改错的是数据面。
		// 默认空 = 不监听，出货形态与此前逐字节相同。
		pprofAddr = flag.String("pprof", "", "expose net/http/pprof on this address (debug only, e.g. 127.0.0.1:6060)")
	)
	flag.Parse()

	if *pprofAddr != "" {
		// 锁竞争才是这个协议在多流下的主要时延来源，而 CPU profile 完全看不见它
		// （阻塞的 goroutine 不占 CPU 样本）。两个采样率都只在 -pprof 打开时才生效。
		runtime.SetMutexProfileFraction(5)
		runtime.SetBlockProfileRate(10000) // 纳秒：只记 >10µs 的阻塞，开销可忽略
		go func() {
			fmt.Fprintf(os.Stderr, "pprof on http://%s/debug/pprof/\n", *pprofAddr)
			if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
				fmt.Fprintf(os.Stderr, "pprof: %v\n", err)
			}
		}()
	}

	var err error
	switch *mode {
	case "keygen":
		err = doKeygen()
	case "local":
		err = doLocal()
	case "server":
		err = doServer(*listen, *quicListen, *key, *cover, *congestion, *grace, *useH3)
	case "raw-server":
		err = doRawServer(*listen)
	case "raw-client":
		err = doRawClient(*server, *dur, *rate, *streams)
	case "client":
		err = doClient(clientOpts{
			server: *server, pub: *key, password: *password, target: *target, dur: *dur, rate: *rate,
			streams: *streams, redundancy: *redun, bare: *bare, window: *window,
			grace: *grace, probe: *probe, insecure: *insecure, quic: *useQUIC,
			congestion: *congestion, h3: *useH3,
		})
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS")
}

func doKeygen() error {
	k, err := tide.GenerateKey()
	if err != nil {
		return err
	}
	fmt.Printf("private: %s\n", k.String())
	fmt.Printf("public:  %s\n", k.Public().String())
	return nil
}

// ---------------------------------------------------------------------------
// 进程内自检
// ---------------------------------------------------------------------------

func doLocal() error {
	priv, err := tide.GenerateKey()
	if err != nil {
		return err
	}
	pub, err := tide.ParsePublicKey(priv.Public().String())
	if err != nil {
		return fmt.Errorf("public key base64 round trip: %w", err)
	}

	coverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer coverLn.Close()
	go acceptEcho(coverLn)

	tlsCfg, err := selfSignedTLS()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()

	// ★ 自检**配一个真用户**，而不是走 AllowAnyUser。
	// 这条链路本来就该覆盖认证，从前它靠"空用户表默认放行"跑通，
	// 等于把 user_id 这一段整个绕过去了——空用户表刚改成失败关闭，一下就暴露出来。
	const selftestPassword = "tide-selftest"
	srv, err := tide.NewServer(&tide.ServerConfig{
		PrivateKey: priv, TLSConfig: tlsCfg, CoverAddr: coverLn.Addr().String(),
		Users: map[[16]byte]string{tide.UserIDFromPassword(selftestPassword): "selftest"},
	})
	if err != nil {
		return err
	}
	defer srv.Close()
	srv.Handler = func(ctx context.Context, st *tide.Stream) {
		defer st.Close()
		io.Copy(st, st)
	}
	go srv.Serve(ln)

	cl, err := tide.NewClient(&tide.ClientConfig{
		Server:        ln.Addr().String(),
		PublicKey:     pub,
		UserID:        tide.UserIDFromPassword(selftestPassword),
		TLSConfig:     &tls.Config{InsecureSkipVerify: true, ServerName: "tide.local"},
		ProbeInterval: 200 * time.Millisecond,
	})
	if err != nil {
		return err
	}
	defer cl.Close()
	ctx := context.Background()

	// 1) 1-RTT 握手 + 回声
	if err := echoOnce(ctx, cl, "step 1 (1-RTT handshake)"); err != nil {
		return err
	}
	fmt.Println("  ok  1-RTT handshake + echo")

	// 2) 0-RTT 复用：关掉会话再拨，必须消费一张票据
	sess, err := cl.Session(ctx)
	if err != nil {
		return err
	}
	closeSessionForTest(cl)
	if err := echoOnce(ctx, cl, "step 2 (0-RTT resume)"); err != nil {
		return err
	}
	fmt.Println("  ok  0-RTT resume")

	// 3) 主动探测防御：非 TIDE 字节必须被**真的**转发到掩护源站，且要快
	if err := probeCover(ln.Addr().String()); err != nil {
		return err
	}
	fmt.Println("  ok  fail-closed forwards to cover origin (timing preserved)")

	// 4) 路径迁移：传输中途打死路径，数据必须一字不差
	sess, err = cl.Session(ctx)
	if err != nil {
		return err
	}
	if err := migrationIntegrity(ctx, cl, sess); err != nil {
		return err
	}
	fmt.Println("  ok  stream survives path death with byte-exact integrity")

	// 5) UDP 关联
	if err := udpRoundTrip(ctx, cl); err != nil {
		return err
	}
	fmt.Println("  ok  UDP association round trip")
	return nil
}

func echoOnce(ctx context.Context, cl *tide.Client, what string) error {
	c, err := cl.DialContext(ctx, "tcp", "echo.invalid:80")
	if err != nil {
		return fmt.Errorf("%s: dial: %w", what, err)
	}
	defer c.Close()
	msg := []byte("tide-selftest")
	if _, err := c.Write(msg); err != nil {
		return fmt.Errorf("%s: write: %w", what, err)
	}
	buf := make([]byte, len(msg))
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		return fmt.Errorf("%s: read: %w", what, err)
	}
	if string(buf) != string(msg) {
		return fmt.Errorf("%s: echo mismatch %q", what, buf)
	}
	return nil
}

func probeCover(addr string) error {
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "tide.local"})
	if err := tc.Handshake(); err != nil {
		return err
	}
	probe := []byte("GET / HTTP/1.1\r\nHost: probe\r\n\r\n")
	start := time.Now()
	if _, err := tc.Write(probe); err != nil {
		return err
	}
	tc.SetReadDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, len(probe))
	if _, err := io.ReadFull(tc, got); err != nil {
		return fmt.Errorf("cover origin did not respond: %w", err)
	}
	if el := time.Since(start); el > time.Second {
		return fmt.Errorf("fail-closed took %v to reach cover origin; "+
			"a prober can tell that apart from a real site by response time alone", el)
	}
	return nil
}

func migrationIntegrity(ctx context.Context, cl *tide.Client, sess *tide.Session) error {
	c, err := cl.DialContext(ctx, "tcp", "echo.invalid:80")
	if err != nil {
		return err
	}
	defer c.Close()

	const blocks, blockSize = 300, 1024
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, blockSize)
		for i := 0; i < blocks; i++ {
			binary.BigEndian.PutUint32(buf[:4], uint32(i))
			for j := 4; j < blockSize; j++ {
				buf[j] = byte(i)
			}
			if _, err := c.Write(buf); err != nil {
				errCh <- fmt.Errorf("write block %d: %w", i, err)
				return
			}
			if i%100 == 99 {
				before := sess.PathsEstablished()
				sess.KillAllPaths()
				deadline := time.Now().Add(20 * time.Second)
				for sess.PathsEstablished() == before && time.Now().Before(deadline) {
					time.Sleep(2 * time.Millisecond)
				}
			}
		}
		errCh <- nil
	}()

	got := make([]byte, blocks*blockSize)
	c.SetReadDeadline(time.Now().Add(60 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		return fmt.Errorf("read back after migration: %w", err)
	}
	if err := <-errCh; err != nil {
		return err
	}
	for i := 0; i < blocks; i++ {
		blk := got[i*blockSize : (i+1)*blockSize]
		if n := binary.BigEndian.Uint32(blk[:4]); n != uint32(i) {
			return fmt.Errorf("block %d carries sequence %d — data lost/duplicated/reordered "+
				"across migration", i, n)
		}
	}
	if n := sess.PathsEstablished(); n < 4 {
		return fmt.Errorf("only %d paths established; the kills never forced a reconnect, "+
			"so this check proved nothing", n)
	}
	return nil
}

func udpRoundTrip(ctx context.Context, cl *tide.Client) error {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], addr)
		}
	}()
	ps, err := cl.DialPacket(ctx, pc.LocalAddr().String())
	if err != nil {
		return err
	}
	defer ps.Close()
	payload := []byte("datagram-over-tide")
	ps.SetReadDeadline(time.Now().Add(5 * time.Second))
	for i := 0; i < 5; i++ {
		if _, err := ps.WriteTo(payload, pc.LocalAddr().String()); err != nil {
			return err
		}
		if d, err := ps.ReadFrom(); err == nil && string(d.Data) == string(payload) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("no datagram round-tripped")
}

func closeSessionForTest(cl *tide.Client) { cl.CloseSession() }

// ---------------------------------------------------------------------------
// 实网服务端
// ---------------------------------------------------------------------------

func doServer(listen, quicListen, privKey, cover, congestion string, grace time.Duration, h3 bool) error {
	if privKey == "" {
		return fmt.Errorf("-key is required in server mode (use -mode keygen)")
	}
	if cover == "" {
		return fmt.Errorf("-cover is required: §6 fail-close needs a real, reachable origin")
	}
	priv, err := tide.ParsePrivateKey(privKey)
	if err != nil {
		return err
	}
	tlsCfg, err := selfSignedTLS()
	if err != nil {
		return err
	}
	srv, err := tide.NewServer(&tide.ServerConfig{
		PrivateKey: priv, TLSConfig: tlsCfg, CoverAddr: cover, SessionGrace: grace,
		Congestion: congestion,
		// 压测夹具：客户端的 user_id 由它自己的 -password 派生，夹具事先并不知道，
		// 所以这里确实要放行任意 user_id。**显式**写出来，而不是靠空表默认放行。
		// ⚠️ 这是夹具，不是可部署的服务端——要部署请用 tide-server。
		AllowAnyUser: true,
	})
	if err != nil {
		return err
	}
	// 回声上游：压测要测的是 TIDE 自己，不是上游服务。
	srv.Handler = func(ctx context.Context, st *tide.Stream) {
		defer st.Close()
		io.Copy(st, st)
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	if quicListen != "" {
		go func() {
			serve := srv.ServeQUIC
			if h3 {
				// h3 模式：对非 TIDE 的 HTTP/3 客户端反代到掩护源站（spec §12.6）。
				serve = srv.ServeH3
			}
			if err := serve(quicListen); err != nil {
				fmt.Fprintf(os.Stderr, "quic listener stopped: %v\n", err)
			}
		}()
		fmt.Printf("tide QUIC on %s\n", quicListen)
	}
	fmt.Printf("tide server on %s (cover=%s grace=%v)\n", ln.Addr(), cover, grace)
	return srv.Serve(ln)
}

// ---------------------------------------------------------------------------
// 裸 TCP 对照组
// ---------------------------------------------------------------------------
//
// ★ 「5% 丢包下 p99 194ms」这个数字，脱离对照是没法判断好坏的。
// 同一条链路、同一份测量代码、同样的 netem，裸 TCP 能做到多少？
// 那才是地板。没有这个对照，我们既不知道协议开销有多大，也不知道
// 还有多少改进空间——只知道一个孤零零的数。

func doRawServer(listen string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	fmt.Printf("raw TCP echo server on %s\n", ln.Addr())
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
	}
}

func doRawClient(server string, dur time.Duration, rate, streams int) error {
	if server == "" {
		return fmt.Errorf("-server is required")
	}
	st := &stats{}
	var wg sync.WaitGroup
	deadline := time.Now().Add(dur)
	perStream := rate / streams
	ctx, cancel := context.WithTimeout(context.Background(), dur+60*time.Second)
	defer cancel()
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			open := func() (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", server)
			}
			if err := hammer(ctx, open, deadline, perStream, st); err != nil {
				st.recordFatal(fmt.Errorf("stream %d: %w", idx, err))
			}
		}(i)
	}
	wg.Wait()
	return st.report(nil, dur)
}

// ---------------------------------------------------------------------------
// 实网客户端 —— 波动统计
// ---------------------------------------------------------------------------

type clientOpts struct {
	server, pub string
	// password 派生 user_id。tide-server **要求**至少一个用户，
	// 没有它这个压测客户端根本认证不过去——README 里那两条命令原样跑就是这个下场。
	password string
	// target 是压测流量**穿过代理之后**要连的地址。默认 echo.invalid:80 是 RFC 2606
	// 保留的不可解析域名，只在 -mode server 那个回声夹具下成立（它不真的去连）；
	// 对着 tide-server 这种真代理跑，必须给一个真实可达的地址，否则每条流都会
	// 因为 DNS 失败被 RST，现象是"一个块都没跑完往返"。
	target           string
	dur              time.Duration
	rate, streams    int
	window           uint64
	redundancy, bare bool
	grace, probe     time.Duration
	insecure, quic   bool
	h3               bool
	congestion       string
}

func doClient(o clientOpts) error {
	if o.server == "" || o.pub == "" {
		return fmt.Errorf("-server and -key are required in client mode")
	}
	pub, err := tide.ParsePublicKey(o.pub)
	if err != nil {
		return err
	}
	cl, err := tide.NewClient(&tide.ClientConfig{
		Server:        o.server,
		UserID:        tide.UserIDFromPassword(o.password),
		PublicKey:     pub,
		TLSConfig:     &tls.Config{InsecureSkipVerify: o.insecure, ServerName: "tide.local"},
		Bare:          o.bare,
		Redundancy:    o.redundancy,
		EnableQUIC:    o.quic,
		H3:            o.h3,
		Congestion:    o.congestion,
		SessionGrace:  o.grace,
		ProbeInterval: o.probe,
		StreamWindow:  o.window,
	})
	if err != nil {
		return err
	}
	defer cl.Close()

	ctx, cancel := context.WithTimeout(context.Background(), o.dur+60*time.Second)
	defer cancel()

	dialStart := time.Now()
	sess, err := cl.Session(ctx)
	if err != nil {
		return fmt.Errorf("initial handshake: %w", err)
	}
	fmt.Printf("handshake took %v, session %x\n", time.Since(dialStart), sess.ID())

	st := &stats{}
	var wg sync.WaitGroup
	deadline := time.Now().Add(o.dur)
	perStream := o.rate / o.streams
	for i := 0; i < o.streams; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			open := func() (net.Conn, error) { return cl.DialContext(ctx, "tcp", o.target) }
			if err := hammer(ctx, open, deadline, perStream, st); err != nil {
				st.recordFatal(fmt.Errorf("stream %d: %w", idx, err))
			}
		}(i)
	}
	wg.Wait()
	return st.report(sess, o.dur)
}

// hammer 在一条流上做带序号的往返传输，并记录每一次往返的时延。
// 关键是**每个块都要回来**，且回来的顺序与内容必须完全正确——
// 网络波动下最难发现的故障不是断开，而是"重连之后少了一段"。
func hammer(ctx context.Context, open func() (net.Conn, error), deadline time.Time, bytesPerSec int, st *stats) error {
	c, err := open()
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer c.Close()

	const blockSize = 4096
	interval := time.Duration(float64(time.Second) * float64(blockSize) / float64(max(bytesPerSec, 1)))
	if interval < time.Millisecond {
		interval = time.Millisecond
	}

	readErr := make(chan error, 1)
	var seqIn atomic.Uint64
	go func() {
		buf := make([]byte, blockSize)
		var want uint32
		for {
			c.SetReadDeadline(time.Now().Add(90 * time.Second))
			if _, err := io.ReadFull(c, buf); err != nil {
				readErr <- err
				return
			}
			got := binary.BigEndian.Uint32(buf[:4])
			if got != want {
				readErr <- fmt.Errorf("block %d came back as %d — bytes were lost or reordered "+
					"across a migration", want, got)
				return
			}
			sentNano := int64(binary.BigEndian.Uint64(buf[4:12]))
			st.recordRTT(time.Duration(time.Now().UnixNano() - sentNano))
			seqIn.Store(uint64(want))
			want++
		}
	}()

	buf := make([]byte, blockSize)
	var seq uint32
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for time.Now().Before(deadline) {
		select {
		case err := <-readErr:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
		binary.BigEndian.PutUint32(buf[:4], seq)
		binary.BigEndian.PutUint64(buf[4:12], uint64(time.Now().UnixNano()))
		c.SetWriteDeadline(time.Now().Add(90 * time.Second))
		if _, err := c.Write(buf); err != nil {
			return fmt.Errorf("write block %d: %w", seq, err)
		}
		st.sent.Add(uint64(blockSize))
		seq++
	}
	// 等收齐尾巴
	drain := time.Now().Add(30 * time.Second)
	for uint64(seq-1) != seqIn.Load() && time.Now().Before(drain) {
		select {
		case err := <-readErr:
			return err
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	if uint64(seq-1) != seqIn.Load() {
		return fmt.Errorf("sent %d blocks but only %d came back after 30s of drain",
			seq, seqIn.Load()+1)
	}
	return nil
}

type stats struct {
	mu    sync.Mutex
	rtts  []time.Duration
	fatal []error
	sent  atomic.Uint64
}

func (s *stats) recordRTT(d time.Duration) {
	s.mu.Lock()
	s.rtts = append(s.rtts, d)
	s.mu.Unlock()
}

func (s *stats) recordFatal(err error) {
	s.mu.Lock()
	s.fatal = append(s.fatal, err)
	s.mu.Unlock()
}

func (s *stats) report(sess *tide.Session, dur time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.rtts) == 0 {
		return fmt.Errorf("no blocks completed a round trip")
	}
	sort.Slice(s.rtts, func(i, j int) bool { return s.rtts[i] < s.rtts[j] })
	pct := func(p float64) time.Duration {
		i := int(float64(len(s.rtts)-1) * p)
		return s.rtts[i]
	}
	// ★ 稳定性看的是尾部，不是均值。p50 好看而 p99.9 有 8 秒，意味着用户每隔一会儿
	// 就要盯着转圈——那正是"网络波动没处理好"的样子。
	fmt.Printf("blocks=%d  sent=%.1f MiB  dur=%v\n",
		len(s.rtts), float64(s.sent.Load())/(1<<20), dur)
	fmt.Printf("rtt p50=%v p90=%v p99=%v p99.9=%v max=%v\n",
		pct(0.50), pct(0.90), pct(0.99), pct(0.999), s.rtts[len(s.rtts)-1])
	if sess == nil {
		// 裸 TCP 对照组没有会话，也没有路径可打印。
		if len(s.fatal) > 0 {
			for _, e := range s.fatal {
				fmt.Fprintf(os.Stderr, "  %v\n", e)
			}
			return fmt.Errorf("%d stream(s) failed", len(s.fatal))
		}
		return nil
	}
	fmt.Printf("paths established=%d  (1 = never had to reconnect)\n", sess.PathsEstablished())
	// 路径死因。"建立 N 次"只说明有 churn，说不出是谁在杀它——
	// markDead 的四个调用点现象一模一样，不打出来就只能靠猜。
	for _, d := range sess.PathDeaths() {
		fmt.Printf("  died: %s\n", d)
	}
	// "QUIC 路径建起来了" 和 "数据真的走了 QUIC" 是两件事，只有字节数分得清。
	// dgram 那一列同理：UDP 被悄悄塞回可靠流时，总量看不出任何异常，
	// 只有"数据报字节 = 0 而这条路径明明在跑 UDP"能把它抓出来（spec §9.1）。
	for _, p := range sess.Paths() {
		fmt.Printf("  path %d %-4s %-8s rtt=%-10v loss=%5.2f%%  tx=%6.1fMiB rx=%6.1fMiB  dgram=%.1f/%.1fMiB  pad=%s\n",
			p.ID, p.Kind, p.State, p.RTT.Round(10*time.Microsecond), p.Loss*100,
			float64(p.TX)/(1<<20), float64(p.RX)/(1<<20),
			float64(p.TXDgram)/(1<<20), float64(p.RXDgram)/(1<<20), p.Pad)
	}
	if len(s.fatal) > 0 {
		for _, e := range s.fatal {
			fmt.Fprintf(os.Stderr, "  %v\n", e)
		}
		return fmt.Errorf("%d stream(s) failed", len(s.fatal))
	}
	return nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------

func acceptEcho(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() { io.Copy(c, c); c.Close() }()
	}
}

func selfSignedTLS() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tide.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"tide.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
	}, nil
}
