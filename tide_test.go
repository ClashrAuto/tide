package tide

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// ---------------------------------------------------------------------------
// 基础编解码
// ---------------------------------------------------------------------------

func TestVarintRoundTrip(t *testing.T) {
	vals := []uint64{0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, MaxVarint}
	for _, v := range vals {
		b := AppendVarint(nil, v)
		if len(b) != VarintLen(v) {
			t.Fatalf("v=%d: len %d != VarintLen %d", v, len(b), VarintLen(v))
		}
		got, n := ReadVarint(b)
		if got != v || n != len(b) {
			t.Fatalf("v=%d: got %d n=%d", v, got, n)
		}
		// 截断时必须返回 n=0，而不是一个错误的值——解帧循环靠它判断"还要继续收"。
		if len(b) > 1 {
			if _, n := ReadVarint(b[:len(b)-1]); n != 0 {
				t.Fatalf("v=%d: truncated read should return n=0, got %d", v, n)
			}
		}
	}
}

func TestFrameRoundTrip(t *testing.T) {
	cases := []struct {
		typ     FrameType
		flags   uint8
		sid     uint64
		payload []byte
		pad     int
	}{
		{FrameStreamData, 0, 1, []byte("hello"), 0},
		{FrameStreamData, FlagPush, 1 << 20, bytes.Repeat([]byte("x"), 1000), 500},
		{FramePadding, 0, 0, nil, 64},
		{FrameStreamOpen, FlagEnd, 3, []byte{1, 2, 3}, 1},
		{FrameClose, 0, 0, nil, 0},
	}
	var wire []byte
	for _, c := range cases {
		wire = AppendFrame(wire, c.typ, c.flags, c.sid, c.payload, c.pad)
	}
	fr := newFrameReader(bytes.NewReader(wire))
	for i, c := range cases {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if f.Type != c.typ || f.StreamID != c.sid {
			t.Fatalf("case %d: type/sid mismatch: %v/%d", i, f.Type, f.StreamID)
		}
		if !bytes.Equal(f.Payload, c.payload) {
			t.Fatalf("case %d: payload %q != %q", i, f.Payload, c.payload)
		}
	}
}

// 逐字节喂给 frameReader：解帧循环必须能扛住任意的 Read 切分。
// 真实的 TLS 连接就是这样——一次 Read 拿回半个帧头是常态。
func TestFrameReaderByteAtATime(t *testing.T) {
	wire := AppendFrame(nil, FrameStreamData, FlagPush, 12345, bytes.Repeat([]byte("ab"), 5000), 37)
	fr := newFrameReader(&dripReader{b: wire})
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Payload) != 10000 {
		t.Fatalf("payload len %d", len(f.Payload))
	}
}

type dripReader struct {
	b []byte
	i int
}

func (d *dripReader) Read(p []byte) (int, error) {
	if d.i >= len(d.b) {
		return 0, io.EOF
	}
	p[0] = d.b[d.i]
	d.i++
	return 1, nil
}

func TestReadFrameExactConsumesNothingExtra(t *testing.T) {
	wire := AppendFrame(nil, FrameHello, FlagPush, 0, []byte("payload"), 0)
	trailer := []byte("RECORD-LAYER-STARTS-HERE")
	r := bytes.NewReader(append(wire, trailer...))
	f, err := readFrameExact(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(f.Payload) != "payload" {
		t.Fatalf("payload %q", f.Payload)
	}
	rest, _ := io.ReadAll(r)
	if !bytes.Equal(rest, trailer) {
		t.Fatalf("readFrameExact over-read: remaining %q", rest)
	}
}

// ---------------------------------------------------------------------------
// 记录层
// ---------------------------------------------------------------------------

func TestRecordLayerRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	for _, useAES := range []bool{false, true} {
		sealer, err := newRecordSealer(key, useAES)
		if err != nil {
			t.Fatal(err)
		}
		var wire []byte
		msgs := [][]byte{[]byte("first"), bytes.Repeat([]byte("z"), 40000), []byte("last")}
		for _, m := range msgs {
			if wire, err = sealer.Seal(wire, m); err != nil {
				t.Fatal(err)
			}
		}
		op, err := newRecordOpener(bytes.NewReader(wire), key, useAES)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(io.LimitReader(op, 1<<20))
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
		want := bytes.Join(msgs, nil)
		if !bytes.Equal(got, want) {
			t.Fatalf("aes=%v: round trip mismatch (%d vs %d bytes)", useAES, len(got), len(want))
		}
	}
}

func TestRecordLayerRejectsTamper(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	sealer, _ := newRecordSealer(key, false)
	wire, _ := sealer.Seal(nil, []byte("secret payload"))
	wire[len(wire)-1] ^= 0x01
	op, _ := newRecordOpener(bytes.NewReader(wire), key, false)
	if _, err := op.Read(make([]byte, 64)); err == nil {
		t.Fatal("tampered record must not open")
	}
}

// ---------------------------------------------------------------------------
// 票据：0-RTT 与重放保护同时成立，是 TIDE 唯一真正原创的机制之一
// ---------------------------------------------------------------------------

func TestTicketConsumedOnce(t *testing.T) {
	s := NewMemTicketStore()
	var user [16]byte
	user[0] = 42
	base, _, err := s.Issue(user, 16)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.consumeAny(base + 3); !ok {
		t.Fatal("first consume must succeed")
	}
	if _, _, ok := s.consumeAny(base + 3); ok {
		t.Fatal("replay must be rejected — this is the whole point of single-use tickets")
	}
	if _, _, ok := s.consumeAny(base + 999); ok {
		t.Fatal("out-of-range ticket must be rejected")
	}
	if got := s.Remaining(user); got != 15 {
		t.Fatalf("remaining %d, want 15", got)
	}
}

// 并发消费同一张票据：只能有一个赢。这条不过，重放保护就完全失效，
// 而且不会有任何报错——攻击者重放的连接会正常建立。
func TestTicketConsumeIsAtomic(t *testing.T) {
	s := NewMemTicketStore()
	var user [16]byte
	base, _, _ := s.Issue(user, 64)

	const workers = 32
	var wins int32
	var mu sync.Mutex
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, _, ok := s.consumeAny(base + 7); ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d goroutines consumed the same ticket, want exactly 1", wins)
	}
}

func TestTicketWalletFallsBackTo1RTT(t *testing.T) {
	w := newTicketWallet()
	now := time.Now()
	var seed [32]byte
	w.add(100, 2, seed, now)
	for i := 0; i < 2; i++ {
		if _, _, ok := w.take(now); !ok {
			t.Fatalf("take %d should succeed", i)
		}
	}
	// 耗尽后 MUST 立刻返回 false（退回 1-RTT），MUST NOT 阻塞等待补充。
	if _, _, ok := w.take(now); ok {
		t.Fatal("exhausted wallet must report empty, not hand out a reused ticket")
	}
}

// ---------------------------------------------------------------------------
// 填充
// ---------------------------------------------------------------------------

func TestPaddingPhases(t *testing.T) {
	p := newPaddingScheduler()
	if p.Phase() != PhaseDecision {
		t.Fatal("must start in the decision window")
	}
	padded := 0
	for i := 0; i < 100; i++ {
		if p.padFor(1, 100) > 0 {
			padded++
		}
	}
	if padded < 50 {
		t.Fatalf("decision window padded only %d/100 frames", padded)
	}
	// 推到批量阶段
	for p.Phase() != PhaseBulk {
		p.padFor(1, MaxPayload)
	}
	for i := 0; i < 50; i++ {
		if got := p.padFor(1, MaxPayload); got != 0 {
			t.Fatalf("bulk phase must not pad, got %d", got)
		}
	}
}

// 填充后的线上长度必须落在 HTTPS 分布的支撑集内，否则填了等于没填。
func TestPaddedLengthsLookLikeHTTPS(t *testing.T) {
	p := newPaddingScheduler()
	for i := 0; i < 100; i++ {
		body := 40
		pad := p.padFor(1, body)
		wire := frameOverhead(1, body+pad+2) + body + pad + 2
		if pad > 0 && (wire < 60 || wire > 16500) {
			t.Fatalf("padded wire length %d outside the HTTPS support set", wire)
		}
	}
}

// ---------------------------------------------------------------------------
// 端到端
// ---------------------------------------------------------------------------

type harness struct {
	t      *testing.T
	srv    *Server
	ln     net.Listener
	cover  net.Listener
	client *Client
}

func newHarness(t *testing.T, tune func(*ClientConfig, *ServerConfig)) *harness {
	t.Helper()
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// 公钥要能经过 base64 往返——配置文件里就是这么传的。
	pub, err := ParsePublicKey(priv.Public().String())
	if err != nil {
		t.Fatalf("public key base64 round trip: %v", err)
	}

	cover, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := cover.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()

	scfg := &ServerConfig{
		PrivateKey: priv,
		TLSConfig:  testTLSServer(t),
		CoverAddr:  cover.Addr().String(),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ccfg := &ClientConfig{
		Server:    ln.Addr().String(),
		PublicKey: pub,
		TLSConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "tide.test"},
	}
	if tune != nil {
		tune(ccfg, scfg)
	}
	srv, err := NewServer(scfg)
	if err != nil {
		t.Fatal(err)
	}
	// 回声服务：测试里唯一需要的上游行为。
	srv.Handler = func(ctx context.Context, st *Stream) {
		defer st.Close()
		io.Copy(st, st)
	}
	go srv.Serve(ln)

	cl, err := NewClient(ccfg)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, srv: srv, ln: ln, cover: cover, client: cl}
	t.Cleanup(func() {
		cl.Close()
		srv.Close()
		ln.Close()
		cover.Close()
	})
	return h
}

func testTLSServer(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tide.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"tide.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
	}
}

func TestEndToEndEcho(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c, err := h.client.DialContext(ctx, "tcp", "example.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	msg := bytes.Repeat([]byte("tide-"), 20000) // 100 KB，跨过判决窗口进入衰减阶段
	go func() { c.Write(msg); c.(*Stream).CloseWrite() }()
	got, err := io.ReadAll(io.LimitReader(c, int64(len(msg))))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: got %d bytes want %d", len(got), len(msg))
	}
}

// 第二个会话必须走 0-RTT：第一次握手下发了 1024 张票据，钱包里还有。
func TestZeroRTTOnReconnect(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	c1, err := h.client.DialContext(ctx, "tcp", "a.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	c1.Close()

	if got := h.client.wallet.remaining(time.Now()); got < DefaultTicketCount-4 {
		t.Fatalf("wallet has %d tickets after first handshake, expected ~%d", got, DefaultTicketCount)
	}

	// 强制会话重建：关掉现有会话，下一次拨号必须用票据。
	h.client.mu.Lock()
	sess := h.client.sess
	h.client.sess = nil
	h.client.mu.Unlock()
	sess.closeWith(ErrClosed)

	// 不能看 remaining()：握手成功会**再**发一批 1024 张，净值反而涨了。
	// 单调递增的 taken 才分得清 0-RTT 和 1-RTT。
	before := h.client.wallet.taken.Load()
	c2, err := h.client.DialContext(ctx, "tcp", "b.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if after := h.client.wallet.taken.Load(); after != before+1 {
		t.Fatalf("second handshake took %d tickets (want exactly 1): it was not 0-RTT", after-before)
	}
}

// 重放同一张票据必须被拒。这里直接在 store 层验证语义，
// 因为线上重放会被 §6 转发给掩护站点，客户端看到的是一个"正常的网站"。
func TestZeroRTTReplayRejected(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	c, err := h.client.DialContext(ctx, "tcp", "a.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	store := h.srv.store.(*MemTicketStore)
	store.mu.Lock()
	if len(store.index) == 0 {
		store.mu.Unlock()
		t.Fatal("server issued no tickets")
	}
	base := store.index[0].base
	store.mu.Unlock()

	if _, _, ok := store.consumeAny(base + 5); !ok {
		t.Fatal("fresh ticket should consume")
	}
	if _, _, ok := store.consumeAny(base + 5); ok {
		t.Fatal("replayed ticket accepted — replay protection is broken")
	}
}

// 认证失败必须被**真的转发**到掩护源站，而不是模拟或直接关。
func TestFailClosedForwardsToCover(t *testing.T) {
	h := newHarness(t, nil)
	raw, err := net.Dial("tcp", h.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "tide.test"})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	// 一段完全不是 TIDE 的字节。掩护源站是个回声服务，所以我们应该原样收回来。
	probe := []byte("GET / HTTP/1.1\r\nHost: tide.test\r\n\r\n")
	if _, err := tc.Write(probe); err != nil {
		t.Fatal(err)
	}
	tc.SetReadDeadline(time.Now().Add(10 * time.Second))
	start := time.Now()
	got := make([]byte, len(probe))
	if _, err := io.ReadFull(tc, got); err != nil {
		t.Fatalf("cover origin did not echo: %v", err)
	}
	if !bytes.Equal(got, probe) {
		t.Fatalf("cover echo mismatch: %q", got)
	}
	// ★ 时序才是这里真正难伪造的东西。掩护源站是本机回声服务，毫秒级就该回来；
	// 如果要等到握手读超时才转发，探测方量一下响应时间分布就把伪装拆穿了。
	if el := time.Since(start); el > time.Second {
		t.Fatalf("fail-closed took %v to reach the cover origin — a prober can distinguish "+
			"that from a real site by response time alone", el)
	}
}

func TestUDPAssociation(t *testing.T) {
	h := newHarness(t, nil)
	// UDP 回声上游
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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

	ctx := context.Background()
	ps, err := h.client.DialPacket(ctx, pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()

	payload := []byte("datagram-over-tide")
	// UDP 不可靠：重试几次，只要有一次通就算过。
	ps.SetReadDeadline(time.Now().Add(5 * time.Second))
	for i := 0; i < 5; i++ {
		if _, err := ps.WriteTo(payload, pc.LocalAddr().String()); err != nil {
			t.Fatal(err)
		}
		d, err := ps.ReadFrom()
		if err == nil && bytes.Equal(d.Data, payload) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("no datagram round-tripped")
}

// ---------------------------------------------------------------------------
// ★ 网络波动：这一组是整个协议存在的理由
// ---------------------------------------------------------------------------

// killAllPaths 模拟"网线被拔了"：直接关掉底层 conn，不走任何优雅关闭流程。
func killAllPaths(s *Session) int {
	for _, p := range s.pathsSnapshot() {
		p.conn.Close()
	}
	return len(s.pathsSnapshot())
}

// 一条流写到一半路径被打死，重连后数据必须**一个字节都不少、不重、不乱**。
func TestStreamSurvivesPathDeath(t *testing.T) {
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		cc.ProbeInterval = 200 * time.Millisecond
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	sess, _ := h.client.Session(ctx)

	// 发送方：把一串带序号的块写进去，序号让我们能精确定位丢/重/乱。
	const blocks = 400
	const blockSize = 1024
	var sendWG sync.WaitGroup
	sendWG.Add(1)
	go func() {
		defer sendWG.Done()
		buf := make([]byte, blockSize)
		for i := 0; i < blocks; i++ {
			binary.BigEndian.PutUint32(buf[:4], uint32(i))
			for j := 4; j < blockSize; j++ {
				buf[j] = byte(i)
			}
			if _, err := c.Write(buf); err != nil {
				t.Errorf("write block %d: %v", i, err)
				return
			}
			if i%100 == 99 {
				// 传输正酣时把路径打死。每次都等到重连真的完成再继续——
				// 否则下一次 kill 会打在同一条早就关掉的 conn 上，
				// 测试看起来是绿的，实际只触发了一次恢复。
				before := sess.pathsAdded.Load()
				killAllPaths(sess)
				deadline := time.Now().Add(20 * time.Second)
				for sess.pathsAdded.Load() == before && time.Now().Before(deadline) {
					time.Sleep(2 * time.Millisecond)
				}
			}
		}
	}()

	got := make([]byte, blocks*blockSize)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	sendWG.Wait()

	// 环回网络上重连快到几毫秒，很容易出现"测试通过但恢复逻辑压根没跑"的假绿。
	if n := sess.pathsAdded.Load(); n < 4 {
		t.Fatalf("only %d paths were ever established — the kills did not actually "+
			"force a reconnect, so this test proved nothing", n)
	} else {
		t.Logf("survived %d path deaths with %d KB transferred intact", n-1, blocks*blockSize/1024)
	}

	for i := 0; i < blocks; i++ {
		blk := got[i*blockSize : (i+1)*blockSize]
		if n := binary.BigEndian.Uint32(blk[:4]); n != uint32(i) {
			t.Fatalf("block %d has sequence number %d — data was lost, duplicated or reordered "+
				"across the migration", i, n)
		}
		for j := 4; j < blockSize; j++ {
			if blk[j] != byte(i) {
				t.Fatalf("block %d byte %d corrupted", i, j)
			}
		}
	}
}

// 会话必须在路径全灭之后活下来并自己接回去（0-RTT 重连 + 服务端宽限期）。
func TestSessionSurvivesTotalOutage(t *testing.T) {
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		cc.ProbeInterval = 200 * time.Millisecond
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if _, err := c.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}

	sess, _ := h.client.Session(ctx)
	sid := sess.ID()
	killAllPaths(sess)

	// 同一条流、同一个会话继续用。会话 id 不能变——变了就说明是重建而不是恢复，
	// 那样服务端那边的上游连接早就断了。
	if _, err := c.Write([]byte("after!")); err != nil {
		t.Fatalf("write after outage: %v", err)
	}
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read after outage: %v", err)
	}
	if string(buf) != "after!" {
		t.Fatalf("got %q after outage", buf)
	}
	if sess.ID() != sid {
		t.Fatal("session was rebuilt, not resumed — upstream connections would have been dropped")
	}
	if n := sess.pathsAdded.Load(); n < 2 {
		t.Fatalf("only %d paths established — the outage never happened", n)
	}
}

// 冗余路径开启时，杀掉一条不应该产生任何可观察的中断。
func TestRedundancyMasksPathLoss(t *testing.T) {
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		cc.Redundancy = true
		cc.ProbeInterval = 200 * time.Millisecond
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 等第二条路径建好。
	deadline := time.Now().Add(20 * time.Second)
	for len(sess.pathsSnapshot()) < 2 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if n := len(sess.pathsSnapshot()); n < 2 {
		t.Fatalf("redundancy did not establish a second path (have %d)", n)
	}

	c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// 只杀一条路径，另一条还在——数据不该有任何中断。
	paths := sess.pathsSnapshot()
	paths[0].conn.Close()

	payload := bytes.Repeat([]byte("R"), 64*1024)
	go func() { c.Write(payload) }()
	got := make([]byte, len(payload))
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("transfer interrupted despite a healthy second path: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload corrupted across path loss")
	}
}

// 路径健康状态机不能抖：一个孤立的坏样本不足以把 active 打到 dead。
func TestPathStateHysteresis(t *testing.T) {
	p := &path{pending: make(map[uint64]time.Time), dead: make(chan struct{})}
	p.sess = newSession([16]byte{}, true, DefaultStreamWindow, time.Minute, time.Second, 16)
	p.wcond = sync.NewCond(&p.wmu)
	p.conn = &nopConn{}

	// 一次丢失：仍然可用。
	p.hmu.Lock()
	p.pending[1] = time.Now().Add(-time.Hour)
	p.hmu.Unlock()
	p.reapProbes()
	if !p.usable() {
		t.Fatalf("one lost probe demoted the path to %v — that will flap on any jitter", p.State())
	}
	// 连续丢到阈值：才降级。
	for i := 2; i <= suspectAfterLostProbes; i++ {
		p.hmu.Lock()
		p.pending[uint64(i)] = time.Now().Add(-time.Hour)
		p.hmu.Unlock()
		p.reapProbes()
	}
	if p.State() != pathSuspect {
		t.Fatalf("after %d consecutive losses state is %v, want suspect", suspectAfterLostProbes, p.State())
	}
}

type nopConn struct{ net.Conn }

func (nopConn) Close() error                       { return nil }
func (nopConn) Write(p []byte) (int, error)        { return len(p), nil }
func (nopConn) Read(p []byte) (int, error)         { select {} }
func (nopConn) LocalAddr() net.Addr                { return streamAddr("nop") }
func (nopConn) RemoteAddr() net.Addr               { return streamAddr("nop") }
func (nopConn) SetDeadline(t time.Time) error      { return nil }
func (nopConn) SetReadDeadline(t time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(t time.Time) error { return nil }

// ---------------------------------------------------------------------------
// 拥塞控制与 QUIC 数据报
// ---------------------------------------------------------------------------

// setCongestion 必须**静默**容忍内核里没有该算法的情况。
// 它只是优化，绝不能因为设不上就让连接建不起来——而 "bbr" 在很多发行版上
// 默认没编进去，这是常态而不是异常。
func TestCongestionSetIsBestEffort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			setCongestion(c, "definitely-not-a-real-algo")
			c.Close()
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	setCongestion(c, "definitely-not-a-real-algo")
	// 连接必须仍然可用。
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("connection broken after a failed congestion setting: %v", err)
	}
}

// UDP 关联在开了 QUIC 路径的会话上也必须能通。
//
// ★ 这条专门守 spec §12.8 的回归：DATAGRAM 改走 RFC 9221 的 QUIC 数据报之后，
// 编解码路径与普通帧完全不同（没有流、自带完整帧头、超限要回退到控制流）。
// 走错任何一步的现象都是"UDP 静默不通"，而 TCP 一切正常——
// 这种半瘫状态最容易在自检全绿的情况下溜过去。
func TestUDPOverQUICPath(t *testing.T) {
	port := freeUDPPort(t)
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		cc.EnableQUIC = true
		// ★ 不能改 Server：那是 TCP 路径的目标。QUIC 端口单独给，
		// 否则客户端会拿 TCP 去连一个只监听 UDP 的端口。
		cc.QUICPort = port
		cc.ProbeInterval = 200 * time.Millisecond
	})
	serveQUICOn(t, h, port)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], addr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 等 QUIC 路径接上
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		hasQUIC := false
		for _, p := range sess.Paths() {
			if p.Kind == "quic" {
				hasQUIC = true
			}
		}
		if hasQUIC {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	ps, err := h.client.DialPacket(ctx, pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()
	payload := bytes.Repeat([]byte("q"), 600)
	ps.SetReadDeadline(time.Now().Add(10 * time.Second))
	for i := 0; i < 8; i++ {
		if _, err := ps.WriteTo(payload, pc.LocalAddr().String()); err != nil {
			t.Fatal(err)
		}
		if d, err := ps.ReadFrom(); err == nil && bytes.Equal(d.Data, payload) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("no datagram round-tripped over the QUIC path")
}

// 超过单个 QUIC 数据报上限的载荷必须**回退到控制流**，而不是静默丢弃。
// 真实世界里超 MTU 的 UDP 会被 IP 分片而不是消失；静默丢会让大 DNS 响应之类
// 无声失败，排查时完全看不出跟大小有关。
func TestOversizeDatagramFallsBack(t *testing.T) {
	port := freeUDPPort(t)
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		cc.EnableQUIC = true
		cc.QUICPort = port
		cc.ProbeInterval = 200 * time.Millisecond
	})
	serveQUICOn(t, h, port)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], addr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ps, err := h.client.DialPacket(ctx, pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()

	// 8 KiB 远超任何 QUIC 数据报能装下的量，必须走回退路径。
	payload := bytes.Repeat([]byte("L"), 8*1024)
	ps.SetReadDeadline(time.Now().Add(15 * time.Second))
	for i := 0; i < 8; i++ {
		if _, err := ps.WriteTo(payload, pc.LocalAddr().String()); err != nil {
			t.Fatal(err)
		}
		if d, err := ps.ReadFrom(); err == nil && bytes.Equal(d.Data, payload) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("oversize datagram was dropped instead of falling back to the control stream")
}

// freeUDPPort 抢一个空闲 UDP 端口号（立刻释放，供随后的 QUIC 监听使用）。
func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func serveQUICOn(t *testing.T, h *harness, port int) {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	go func() { _ = h.srv.ServeQUIC(addr) }()
	time.Sleep(300 * time.Millisecond)
}

// QUIC 路径不能凭空建会话——它没有掩护，不该是一个可独立进入的入口（spec §12.6）。
//
// 这条守的是安全属性，不是功能：去掉那个检查，功能测试全部照常通过，
// 只是 UDP 端口悄悄变成了一个不设防的入口。所以必须有一条测试专门盯着它。
func TestQUICCannotCreateSession(t *testing.T) {
	port := freeUDPPort(t)
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		cc.EnableQUIC = true
		cc.QUICPort = port
		cc.ProbeInterval = 200 * time.Millisecond
	})
	serveQUICOn(t, h, port)

	// 一个全新的客户端，从来没有通过 TCP 建立过会话。
	fresh, err := NewClient(&ClientConfig{
		Server:     h.client.cfg.Server,
		PublicKey:  h.client.cfg.PublicKey,
		TLSConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: "tide.test"},
		EnableQUIC: true,
		QUICPort:   port,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()

	sess := newSession([16]byte{}, true, DefaultStreamWindow, time.Minute, time.Second, 16)
	sess.wallet = fresh.wallet
	// 4 秒足够证明"没成功"。不用更长是因为服务端现在**故意不关**这条连接
	// （关得太干脆本身就是给探测方的判据），客户端只能等到自己的 deadline——
	// 也就是说这个 ctx 时限就是本用例的耗时下界。
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	// join=false 且 session_id 为全零：服务端必须拒绝。
	if p, err := fresh.dialQUICPath(ctx, sess, false); err == nil {
		p.markDead()
		t.Fatal("a QUIC connection created a brand-new session — the UDP port is an " +
			"unprotected entry point, since QUIC does no cover forwarding")
	}
}

// ★ §12.6 的全部意义：一个只会说 HTTP/3 的探测方，打到 TIDE 的 UDP 端口上，
// 必须拿到**掩护源站的真实响应**，而不是沉默、也不是模拟的内容。
//
// 这条测试守的是伪装，不是功能——去掉 h3Cover 之后所有功能测试照常绿，
// 只是那个 UDP 端口重新变成一个"会握手但不说话"的异常端点。
func TestH3ProbeGetsCoverSite(t *testing.T) {
	// 掩护源站必须是**真的 HTTP 服务器**：h3Cover 会把请求转成 HTTP/1.1 发过去
	// 再把响应搬回来。harness 默认的那个是字节回声，不是 HTTP。
	cover := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.27.1")
		io.WriteString(w, "<!doctype html><title>It works</title>")
	}))
	t.Cleanup(cover.Close)
	coverAddr := strings.TrimPrefix(cover.URL, "http://")

	port := freeUDPPort(t)
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		cc.EnableQUIC = true
		cc.H3 = true
		cc.QUICPort = port
		sc.CoverAddr = coverAddr
	})
	go func() { _ = h.srv.ServeH3(net.JoinHostPort("127.0.0.1", strconv.Itoa(port))) }()
	time.Sleep(400 * time.Millisecond)

	// 一个普通的 HTTP/3 客户端，对 TIDE 一无所知。
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "tide.test", NextProtos: []string{"h3"}},
	}
	defer tr.Close()
	cli := &http.Client{Transport: tr, Timeout: 15 * time.Second}

	resp, err := cli.Get("https://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/")
	if err != nil {
		t.Fatalf("h3 prober got no response at all — the UDP port is a silent QUIC "+
			"endpoint, which is exactly the anomaly §12.6 exists to remove: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	// harness 的掩护源站是个回声服务：它会把我们发过去的 HTTP/1.1 请求原样回来。
	// 只要拿到了**非空的、来自掩护源站的**字节，就说明反代真的发生了。
	if !bytes.Contains(body, []byte("It works")) {
		t.Fatalf("h3 prober did not get the cover origin's content (status=%d, body=%q)",
			resp.StatusCode, body)
	}
	if got := resp.Header.Get("Server"); got != "nginx/1.27.1" {
		t.Fatalf("cover origin's Server header did not survive the proxy: %q", got)
	}
	t.Logf("h3 prober saw a genuine cover response: status=%d Server=%q %d bytes",
		resp.StatusCode, resp.Header.Get("Server"), len(body))
}

// TIDE 自己在 h3 模式下也必须能跑——掩护做得再好，代理不通就没意义。
func TestTIDEOverH3(t *testing.T) {
	// 曾经这里有个环境变量开关，因为本用例约 1/4 概率失败。那个不稳定**就是** bug 本身
	// （服务端建 sealed 记录层而客户端走 bare，见 server.go 的 isQUICConn 说明），
	// 修掉之后 -race -count=25 连续通过，开关也就没有存在的理由了。
	port := freeUDPPort(t)
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		cc.EnableQUIC = true
		cc.H3 = true
		cc.QUICPort = port
		cc.ProbeInterval = 200 * time.Millisecond
	})
	go func() { _ = h.srv.ServeH3(net.JoinHostPort("127.0.0.1", strconv.Itoa(port))) }()
	time.Sleep(400 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 等 h3 路径接上
	deadline := time.Now().Add(20 * time.Second)
	var haveH3 bool
	for time.Now().Before(deadline) && !haveH3 {
		for _, p := range sess.Paths() {
			if p.Kind == "quic" {
				haveH3 = true
			}
		}
		if !haveH3 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !haveH3 {
		// 这里是本 bug 的现场：把死因序列打出来，四个 markDead 调用点里
		// 是谁在杀它，一看便知。
		t.Fatalf("the HTTP/3 path never came up; paths established=%d, deaths=%q",
			sess.PathsEstablished(), sess.PathDeaths())
	}

	// ★ 光有路径不算数：调度器要过几轮才会把流迁过去。不等它就发数据，
	// 字节全走 TCP，测试照样绿——而 h3 数据面一个字节都没被跑到。
	// 这正是本仓库反复踩的"假绿"，所以下面**断言 h3 路径真的扛了量**。
	h3Before := uint64(0)
	for _, p := range sess.Paths() {
		if p.Kind == "quic" {
			h3Before = p.TX
		}
	}

	c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// 先小发一轮把流建起来，再等调度器迁移，然后才发大块。
	c.Write([]byte("warmup"))
	buf := make([]byte, 6)
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("warmup echo over h3 session failed: %v", err)
	}
	// ★ 不能靠调度器自然迁移：环回上两条路径评分几乎相同，rebalance 要求目标好 2 倍
	// 才动手，所以它**正确地**不迁。这里直接把流钉到 h3 路径上，
	// 才能确定性地跑到 h3 的数据面——否则字节全走 TCP，测试绿得毫无意义。
	st, ok := c.(*Stream)
	if !ok {
		t.Fatal("expected a *Stream")
	}
	var h3ID uint32
	for _, p := range sess.pathsSnapshot() {
		if p.kind == "quic" {
			h3ID = p.id
		}
	}
	if h3ID == 0 {
		t.Fatal("no HTTP/3 path to pin the stream to")
	}
	st.pathID.Store(h3ID)
	_ = h3Before

	msg := bytes.Repeat([]byte("h3-"), 20000) // 60 KB，跨过多个帧
	go func() { c.Write(msg) }()
	got := make([]byte, len(msg))
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("echo over the HTTP/3 path failed: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("payload corrupted over the HTTP/3 path")
	}

	var h3TX, h3RX uint64
	for _, p := range sess.Paths() {
		t.Logf("path %d %s tx=%dB rx=%dB", p.ID, p.Kind, p.TX, p.RX)
		if p.Kind == "quic" {
			h3TX, h3RX = p.TX, p.RX
		}
	}
	// 只断言**发送**方向：上面钉的是本端这条流的亲和，对端的回程仍按它自己的
	// 路径亲和走（这里是 TCP），所以 h3 的 rx 本来就该接近 0。
	// 净荷完整回来了 = 服务端确实在 h3 上把这 60 KB 全收到了，
	// 也就证明了 h3 数据面通。
	if h3TX < 32*1024 {
		t.Fatalf("the HTTP/3 path only sent %dB — the payload went over TCP, so this test "+
			"proved nothing about the h3 data path", h3TX)
	}
	t.Logf("h3 data path verified: %d KB sent over HTTP/3, payload returned byte-exact "+
		"(rx=%dB is expected — the peer echoes on its own path affinity)", h3TX/1024, h3RX)
}

// 诊断用：直接拨一条 h3 路径，把真实错误打出来。
func TestH3DialDiag(t *testing.T) {
	port := freeUDPPort(t)
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		cc.EnableQUIC = true
		cc.H3 = true
		cc.QUICPort = port
	})
	go func() { _ = h.srv.ServeH3(net.JoinHostPort("127.0.0.1", strconv.Itoa(port))) }()
	time.Sleep(400 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p, err := h.client.dialH3Path(ctx, sess, true)
	if err != nil {
		t.Fatalf("dialH3Path: %v", err)
	}
	t.Logf("h3 path up: id=%d kind=%s", p.id, p.kind)
	p.markDead()
}

// 乱序缓冲的上界必须限住**真实内存**，不是载荷字节。
//
// ★ 这条测试是拿实际堆占用去校准 reorderSegOverhead 的，不是走个过场：
// 修复前 1 字节段能让 reorderN 报 512 KiB 而真实堆占用 42.5 MB（81 倍），
// 乘上 MaxStreams=1024 就是几十 GB——对端只要把 STREAM_DATA 拆成 1 字节一段、
// 段间留空洞永远接不上，就能在完全合法的流控之内把接收方撑爆。
// 上界限错了量这件事编译期看不出来、功能测试也测不出来，只有量内存能看出来。
func TestReorderBufferFootprint(t *testing.T) {
	heap := func() uint64 {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	// 最坏情况：段越小，固定开销占比越高。1 字节是下界。
	for _, segLen := range []int{1, 8, 64, 1024} {
		sess := newSession([16]byte{}, false, DefaultStreamWindow, time.Minute, time.Second, 16)
		st := newStream(sess, 2, "1.2.3.4:80", DefaultStreamWindow)
		data := make([]byte, segLen)
		before := heap()
		// 段间永远留一个字节的空洞，谁也接不上，全部滞留在 reorder 里。
		for off := uint64(1); ; off += uint64(segLen) + 1 {
			st.rmu.Lock()
			full := uint64(st.reorderN)+uint64(reorderCost(segLen)) > st.window
			st.rmu.Unlock()
			if full {
				break
			}
			if err := st.onData(off, data); err != nil {
				t.Fatal(err)
			}
		}
		used := heap() - before
		runtime.KeepAlive(st)

		// 留 2 倍余量：Go 版本、GC 时机、map 装载因子都会让这个数浮动，
		// 但 81 倍那种量级的错误一定会被抓住。
		if limit := uint64(DefaultStreamWindow) * 2; used > limit {
			t.Fatalf("segLen=%d: 乱序缓冲实占 %d 字节，窗口只有 %d —— "+
				"上界限的是载荷字节而不是真实内存，对端可以用小段把它放大到 OOM",
				segLen, used, DefaultStreamWindow)
		}
		t.Logf("segLen=%-5d heap=%-9d window=%d", segLen, used, DefaultStreamWindow)
	}
}

// ---------------------------------------------------------------------------
// 抢跑的数据报
// ---------------------------------------------------------------------------

// 一条 UDP 关联的第一个数据报**理应**跑在它自己的 STREAM_OPEN 前面：
// 数据报走不可靠数据面，STREAM_OPEN 走可靠流，两者之间没有任何顺序关系。
// 丢掉它不会报错，只表现为"每开一个新 UDP 连接就卡一下"——
// DNS 等自己的重传超时（通常 1 秒），被代理的 QUIC 少一个 Initial 退避一轮。
// 处置照 RFC 9297 §5.2：在一个 RTT 量级内暂存等待流建立。
func TestEarlyDatagramHeldUntilAssociationExists(t *testing.T) {
	s := newSession([16]byte{}, false, DefaultStreamWindow, time.Minute, time.Second, 16)
	const assoc = 5
	want := []string{"first", "second", "third"}
	for _, w := range want {
		if err := s.onDatagram(udpFrame(t, assoc, "10.0.0.1:53", []byte(w))); err != nil {
			t.Fatal(err)
		}
	}
	// 此刻关联还不存在，数据报只能在暂存区里。
	if got := s.earlyHeld(); got != len(want) {
		t.Fatalf("early datagrams held = %d, want %d", got, len(want))
	}

	// STREAM_OPEN 追上来了——照 onStreamOpen 的样子把关联建起来。
	st := newStream(s, assoc, "10.0.0.1:53", DefaultStreamWindow)
	st.udp = true
	st.pkt = newPacketStream(s, st)
	s.mu.Lock()
	s.streams[assoc] = st
	s.mu.Unlock()
	s.releaseEarlyDatagrams(st)

	if got := s.earlyHeld(); got != 0 {
		t.Fatalf("early buffer not drained: %d left", got)
	}
	// ★ 顺序也要对：补交的必须按原序，否则上层看到的是被重排过的 UDP 流。
	for _, w := range want {
		st.pkt.SetReadDeadline(time.Now().Add(2 * time.Second))
		d, err := st.pkt.ReadFrom()
		if err != nil {
			t.Fatalf("read %q: %v", w, err)
		}
		if string(d.Data) != w {
			t.Fatalf("got %q, want %q — 补交乱序了", d.Data, w)
		}
	}
}

// 暂存区必须有硬上界。没有上界的话，对端只要对**不存在**的流号狂发 DATAGRAM，
// 就能让一条会话白占内存——而且完全在协议允许的范围内，不触发任何错误路径。
func TestEarlyDatagramBounded(t *testing.T) {
	s := newSession([16]byte{}, false, DefaultStreamWindow, time.Minute, time.Second, 16)

	// 单个关联：超过 earlyDatagramPerAssoc 就丢最老的，条数不再增长。
	for i := 0; i < earlyDatagramPerAssoc*3; i++ {
		s.onDatagram(udpFrame(t, 7, "10.0.0.1:53", []byte{byte(i)}))
	}
	if got := s.earlyHeld(); got != earlyDatagramPerAssoc {
		t.Fatalf("per-assoc cap not enforced: held %d, want %d", got, earlyDatagramPerAssoc)
	}

	// 全会话字节数：拿不同流号灌满，总字节不得越界。
	big := make([]byte, 8<<10)
	for id := uint64(100); id < 400; id++ {
		s.onDatagram(udpFrame(t, id, "10.0.0.1:53", big))
	}
	s.earlyMu.Lock()
	bytesHeld, assocs := s.earlyBytes, len(s.early)
	s.earlyMu.Unlock()
	if bytesHeld > earlyDatagramBytes {
		t.Fatalf("byte cap breached: %d > %d", bytesHeld, earlyDatagramBytes)
	}
	if assocs > earlyDatagramAssocs {
		t.Fatalf("assoc cap breached: %d > %d", assocs, earlyDatagramAssocs)
	}

	// ★ 只限字节挡不住"小数据报 + 不同流号"：每条记录的 map 表项、slice、
	// Datagram 结构与地址字符串合计一两百字节，且与载荷长度无关。
	// 用 1 字节的数据报灌 20 万个流号，条数上界是唯一拦得住的东西。
	s2 := newSession([16]byte{}, false, DefaultStreamWindow, time.Minute, time.Second, 16)
	for id := uint64(0); id < 200_000; id++ {
		s2.onDatagram(udpFrame(t, id, "10.0.0.1:53", []byte{1}))
	}
	s2.earlyMu.Lock()
	assocs2 := len(s2.early)
	s2.earlyMu.Unlock()
	if assocs2 > earlyDatagramAssocs {
		t.Fatalf("1 字节数据报绕过了上界：暂存了 %d 个关联，上界是 %d",
			assocs2, earlyDatagramAssocs)
	}
}

// 关闭会话的**同时**对端还在发数据报，是一次远端可触发的进程崩溃：
// closeWith 是接收侧，onDatagram 是发送侧，接收侧关掉发送侧还在用的通道，
// 在 Go 里必定 panic（`select` + `default` 也挡不住）。
func TestDatagramAfterSessionCloseDoesNotPanic(t *testing.T) {
	s := newSession([16]byte{}, false, DefaultStreamWindow, time.Minute, time.Second, 16)
	s.closeWith(ErrClosed)
	for i := 0; i < 64; i++ {
		if err := s.onDatagram(udpFrame(t, uint64(i), "10.0.0.1:53", []byte("x"))); err != nil {
			t.Fatal(err)
		}
	}
}

// udpFrame 拼一个 DATAGRAM 帧的载荷：SOCKS 地址 + 数据。
func udpFrame(t *testing.T, assoc uint64, addr string, data []byte) Frame {
	t.Helper()
	payload, err := appendSocksAddr(nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	return Frame{Type: FrameDatagram, StreamID: assoc, Payload: append(payload, data...)}
}

// UDP 在 h3 路径上必须走 RFC 9297 的 HTTP Datagram（spec §12.6 / §9.1）。
//
// ★ 这条守的是**语义**，不是连通性：把 DATAGRAM 塞进可靠有序的流里，UDP 照样能通，
// 测试照样绿——但被代理的 QUIC 就会跑在一条替它重传的通道上，
// 两层拥塞控制打架，现象是吞吐周期性崩塌而两层统计都看不出问题。
// 所以这里除了断言收发正常，还断言**数据报没有落到流上**。
func TestUDPOverH3Datagrams(t *testing.T) {
	port := freeUDPPort(t)
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		cc.EnableQUIC = true
		cc.H3 = true
		cc.QUICPort = port
		cc.ProbeInterval = 200 * time.Millisecond
	})
	go func() { _ = h.srv.ServeH3(net.JoinHostPort("127.0.0.1", strconv.Itoa(port))) }()
	time.Sleep(400 * time.Millisecond)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	var h3ID uint32
	for time.Now().Before(deadline) && h3ID == 0 {
		for _, p := range sess.pathsSnapshot() {
			if p.kind == "quic" {
				h3ID = p.id
			}
		}
		if h3ID == 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if h3ID == 0 {
		t.Fatalf("no HTTP/3 path; deaths=%q", sess.PathDeaths())
	}

	ps, err := h.client.DialPacket(ctx, pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()
	// 把这条关联钉到 h3 路径上，否则可能走 TCP，测的就不是 RFC 9297 了。
	ps.st.pathID.Store(h3ID)

	// 流字节 = 总字节 − 数据报字节。这个差才是"UDP 有没有被塞进可靠流"的证据；
	// 只看总量的话，"没走流"和"根本没发出去"长得一模一样。
	streamTx := func() uint64 {
		for _, p := range sess.pathsSnapshot() {
			if p.id == h3ID {
				return p.txBytes.Load() - p.txDgram.Load()
			}
		}
		return 0
	}
	txBefore := streamTx()

	payload := []byte("datagram-over-http3")
	ok := false
	// ★ 读超时必须**每轮重设**。它是绝对时刻，不是"每次调用的等待时长"：
	// 在循环外设一次的话，第一次 ReadFrom 就会把整个 10 秒吃光，
	// 剩下 9 轮都在已过期的 deadline 上立刻返回——写出去了，但根本没等回来。
	// 那样这个循环名为"重试 10 次"，实为"试 1 次"，而失败恰好耗时 10 秒，
	// 看起来像超时，掩盖了真正的原因。
	for i := 0; i < 10 && !ok; i++ {
		if _, err := ps.WriteTo(payload, pc.LocalAddr().String()); err != nil {
			t.Fatal(err)
		}
		ps.SetReadDeadline(time.Now().Add(time.Second))
		if d, err := ps.ReadFrom(); err == nil && bytes.Equal(d.Data, payload) {
			ok = true
		}
	}
	if !ok {
		t.Fatal("no datagram round-tripped over the HTTP/3 path")
	}

	// ★ 关键断言：数据报走的是 HTTP Datagram，**不该**在流上留下字节。
	if grew := streamTx() - txBefore; grew > 512 {
		t.Fatalf("the h3 path's stream bytes grew by %d during a UDP-only exchange — "+
			"the datagrams went over a reliable stream instead of RFC 9297 HTTP Datagrams, "+
			"which silently gives UDP retransmission it must not have (spec §9.1)", grew)
	}
}
