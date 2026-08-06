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
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

// 事后拿到服务端静态私钥，**不得**能解开之前录下的会话（前向保密）。
//
// ★ design.md §10 把"服务端事后被攻破 —— 前向保密限制损失范围"列为已解决的威胁。
// 这条测试就是那句话的凭据：攻击者手里只有一份录音（kem_share、client_random、
// ACCEPT 密文都是明文可见的线上字节）和事后取得的静态私钥，
// 必须**推不出**会话密钥。
//
// 修复前推得出来，而且是完整的：ikm = X25519(静态私钥, 客户端临时公钥) ||
// MLKEM.Decapsulate(静态私钥, ct)，两项都只依赖静态私钥和录音里的字节，
// 于是 k_hs → ACCEPT → session_id/ticket_seed → 会话密钥全部还原。
// 握手里从头到尾没有任何服务端临时密钥——Noise IK 里叫 `ee` 的那一步，TIDE 缺了。
func TestForwardSecrecyAgainstStaticKeyCompromise(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(priv.Public().String())
	if err != nil {
		t.Fatal(err)
	}

	// —— 线上录得到的东西 ——
	kemShare, ikm, cliEph, err := encapsulate(pub)
	if err != nil {
		t.Fatal(err)
	}
	var cr [32]byte
	if _, err := rand.Read(cr[:]); err != nil {
		t.Fatal(err)
	}
	transcript := transcriptHash(ProtocolVersion, kemShare, cr[:])
	kHS, err := handshakeKey(cr[:], ikm, transcript)
	if err != nil {
		t.Fatal(err)
	}
	// 服务端这一侧：临时密钥对 + 混合 ee。服务端的临时私钥**只出现在它自己的内存里**，
	// 握手一结束就没了，录音里没有，事后攻破也拿不到。
	// 客户端的临时公开材料分散在 kem_share 两头（中间那段是发给静态密钥的密文）。
	cliEphPub := append(append([]byte{}, kemShare[:x25519PubLen]...), kemShare[kemStaticLen:kemShareLen]...)
	srvEphPub, ee, err := serverEphemeral(cliEphPub)
	if err != nil {
		t.Fatal(err)
	}
	sid := [16]byte{1, 2, 3}
	real, err := sessionSecret(kHS, ee, sid[:])
	if err != nil {
		t.Fatal(err)
	}
	// 客户端用录音里的 srvEphPub + 自己的临时私钥算出同一个 ee——功能不能坏。
	cliEE, err := clientEphemeralShared(cliEph, srvEphPub)
	if err != nil {
		t.Fatal(err)
	}
	mirrored, err := sessionSecret(kHS, cliEE, sid[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(real, mirrored) {
		t.Fatal("两端算出的会话密钥不一致 —— ee 接错了，握手直接不通")
	}

	// —— 攻击者：录音 + 事后取得的静态私钥 ——
	ikm2, err := decapsulate(priv, kemShare)
	if err != nil {
		t.Fatal(err)
	}
	kHS2, err := handshakeKey(cr[:], ikm2, transcript)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kHS, kHS2) {
		t.Fatal("测试前提不成立：k_hs 本来就推不出来")
	}
	// 先把攻击本身演示清楚：**没有 ee 的话**，攻击者算出的会话密钥与真的一模一样。
	// 这就是修复前的处境——录音 + 静态私钥 = 整条会话的明文。
	oldReal, err := sessionSecret(kHS, nil, sid[:])
	if err != nil {
		t.Fatal(err)
	}
	oldForged, err := sessionSecret(kHS2, nil, sid[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldReal, oldForged) {
		t.Fatal("测试前提不成立：不混 ee 时攻击者本来就算不出来")
	}

	// k_hs 推得出来是设计使然（ACCEPT 要靠它保护，1-RTT 躲不掉）。
	// 但**会话密钥**必须推不出来——差的就是那个只在服务端内存里待过的临时私钥。
	forged := oldForged
	if bytes.Equal(real, forged) {
		t.Fatal("拿静态私钥 + 一份录音就还原出了会话密钥 —— 没有前向保密。" +
			"design.md §10 把这条列为已解决的威胁，实际上握手里没有任何服务端临时密钥")
	}

	// ★ 最要紧的一条：**静态私钥泄露 + 量子计算机**同时成立时也必须挡住。
	//
	// design.md §10 把"先收割后解密（第 5 条）"与"服务端事后被攻破（第 7 条）"
	// 分别列为已解决，但它们**不组合**：ee 若只有 X25519，量子对手解掉它、
	// 静态私钥重算出 k_hs，会话密钥就全还原了。而这恰恰是同一个敌手——
	// 能查抄服务器的国家级对手，也正是有能力"先收割后解密"的那一个。
	//
	// 这里用"把 ee 的 X25519 那一半直接送给攻击者"来模拟量子能力：
	// X25519 部分视作已破，ML-KEM 部分仍然安全。
	if len(ee) <= x25519PubLen {
		t.Fatal("ee 里没有后量子部分 —— 静态私钥泄露 + 量子对手就能还原整条会话")
	}
	quantumEE := append([]byte{}, ee[:x25519PubLen]...) // 只有被量子解掉的经典那一半
	quantumForged, err := sessionSecret(kHS2, quantumEE, sid[:])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(real, quantumForged) {
		t.Fatal("静态私钥 + 量子能力（X25519 视作已破）就还原出了会话密钥 —— " +
			"ee 缺后量子那一半。§10 的第 5 条与第 7 条各自成立，合起来不成立")
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

// 伪造的 ZERO_RTT **不得**烧掉票据。
//
// ★ ticket_id 是明文（服务端要靠它反查密钥，鸡生蛋只能这么解），而 MemTicketStore
// 从一个全局单调计数器分配基址——于是 ticket_id 完全可预测：0、1、2……
// 如果服务端在验证之前就置位，任何人都能把整台服务器上所有用户的票据挨个烧掉：
// 每张只要一个 ~124 字节的伪造帧，服务端回的还是掩护站点，全程静默。
// 后果是所有人永久退回 1-RTT——0-RTT 是 TIDE 两个招牌特性之一，
// 而且"这台机器上每条连接都变慢一个 RTT"本身就是个可观测的指纹。
//
// RFC 8446 §8.2 给的顺序正相反：服务端**先验 PSK binder**，
// 之后才去碰防重放记录。TIDE 这里对应的就是"先 AEAD 解开（证明持有密钥），
// 再原子置位"。原子性由置位本身保证，不需要靠"先置位"来换。
func TestForgedZeroRTTDoesNotBurnTickets(t *testing.T) {
	h := newHarness(t, nil)
	var user [16]byte
	base, _, err := h.srv.store.Issue(user, 32)
	if err != nil {
		t.Fatal(err)
	}
	before := h.srv.store.Remaining(user)

	// 伪造：ticket_id 猜对（可预测），密文是垃圾。攻击者不持有任何密钥。
	for id := base; id < base+uint64(before); id++ {
		z := &zeroRTTMsg{version: ProtocolVersion, ticketID: id}
		z.sealed = bytes.Repeat([]byte{0xAB}, zeroSealLen+16)
		f := Frame{Type: FrameZeroRTT, Payload: z.marshal()}
		tc := &teeConn{Conn: &nopConn{}}
		if _, _, err := h.srv.handleZeroRTT(tc, f, [cbHashLen]byte{}); err == nil {
			t.Fatal("伪造的 ZERO_RTT 竟然通过了认证")
		}
	}

	if after := h.srv.store.Remaining(user); after != before {
		t.Fatalf("%d 张票据被伪造帧烧掉了（%d → %d）—— 攻击者不持有任何密钥，"+
			"却能把全服务器的票据挨个烧光，所有人永久退回 1-RTT", before-after, before, after)
	}
	// 烧不掉，但真正持有密钥的一方仍然必须能用掉它（别把功能一起关了）。
	if _, _, ok := h.srv.store.(*MemTicketStore).consumeAny(base + 1); !ok {
		t.Fatal("合法消费也被挡住了")
	}
}

// 把"消费"挪到"认证"之后**不能**削弱重放保护。
//
// ★ 这是上面那个修复唯一真正的风险，所以要正面测：同一份**真实**的 ZERO_RTT
// 并发重放 N 份，必须恰好只有一份把票据消费掉。原子性由 consume 那一步自己保证，
// 不需要靠"先于解密"来换——这正是原来那条注释搞反的地方。
func TestConcurrentGenuineZeroRTTConsumesExactlyOnce(t *testing.T) {
	h := newHarness(t, nil)
	var user [16]byte
	base, seed, err := h.srv.store.Issue(user, 8)
	if err != nil {
		t.Fatal(err)
	}
	before := h.srv.store.Remaining(user)

	// 造一份**真的**能解开的 ZERO_RTT：我们手上有 seed，所以能算出票据密钥。
	id := base + 2
	tkey, err := ticketKey(seed[:], id)
	if err != nil {
		t.Fatal(err)
	}
	z := &zeroRTTMsg{version: ProtocolVersion, ticketID: id}
	ad := append(append([]byte{z.version}, appendU64(nil, id)...), z.nonce[:]...)
	zs := &zeroSeal{timestamp: time.Now().Unix(), user: user}
	zs.cbHash[0] = 0xFF // 与下面传进去的 cb 不同，认证通过后停在信道绑定这一步
	if z.sealed, err = sealFixed(tkey, z.nonce[:], zs.marshal(nil), ad, false); err != nil {
		t.Fatal(err)
	}
	f := Frame{Type: FrameZeroRTT, Payload: z.marshal()}

	const racers = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			h.srv.handleZeroRTT(&teeConn{Conn: &nopConn{}}, f, [cbHashLen]byte{})
		}()
	}
	close(start)
	wg.Wait()

	if got := before - h.srv.store.Remaining(user); got != 1 {
		t.Fatalf("%d 份并发重放消费掉了 %d 张票据，必须恰好 1 张 —— "+
			"重放保护失效时不会有任何报错，重放的连接会正常建立", racers, got)
	}
}

// 客户端取票的顺序，必须和服务端淘汰批次的顺序对得上。
//
// ★ 这两件事是分两轮加进来的，各自都对，**配在一起就坏**：
//
//	· 服务端给单用户的活跃批次设了上界（防止对端刷 TICKET_REQUEST 撑爆票据库），
//	  超了淘汰**最老**的一批。
//	· 客户端的 take() 从头扫，也就是**先用最老**的一批。
//
// 于是客户端总是优先去用服务端最可能已经淘汰掉的那些票据：每张都换来一次
// 完整的失败连接（服务端 ErrBadTicket → 失败关闭 → 客户端读到掩护站点的回声
// → ErrProtocol → 整条路径拨号失败），然后才退回 1-RTT。
//
// 触发条件一点都不苛刻：**每次握手（含加入路径与重连）都会签发一批**，
// 长会话攒过上界是常态。
func TestWalletAndStoreAgreeOnEvictionOrder(t *testing.T) {
	st := NewMemTicketStore()
	w := newTicketWallet()
	var user [16]byte
	now := time.Now()

	// 模拟一条长会话：反复握手，每次服务端签一批、客户端收进钱包。
	rounds := maxLiveBatchesPerUser + 4
	for i := 0; i < rounds; i++ {
		base, seed, err := st.Issue(user, 64)
		if err != nil {
			t.Fatal(err)
		}
		w.add(base, 64, seed, now)
	}

	// 客户端接连取票去做 0-RTT。每一张都必须是服务端**还认**的。
	for i := 0; i < 200; i++ {
		id, _, ok := w.take(now)
		if !ok {
			break // 钱包用光了，正常退回 1-RTT
		}
		if _, _, ok := st.peekAny(id); !ok {
			st.mu.Lock()
			live := len(st.users[user])
			st.mu.Unlock()
			t.Fatalf("第 %d 张票 id=%d 服务端已经不认了（活跃批次 %d 个，上界 %d）—— "+
				"客户端与服务端对批次的取用/淘汰顺序相反。每张这样的票都换来一次"+
				"完整的失败连接，然后才退回 1-RTT", i+1, id, live, maxLiveBatchesPerUser)
		}
	}
}

// 重放一个捕获到的 HELLO **不得**在受害者会话上留下一条活着的路径。
//
// ★ 单次票据只管 0-RTT；1-RTT 的 HELLO 没有票据也没有 nonce 缓存，
// 在 ±120 秒的时间戳窗口内是**字节级可重放**的。这一点 design.md 第 6 条没有覆盖。
//
// 后果不止"多一次握手"：被重放的 HELLO 里带着 session_id（请求**加入**已有会话）。
// 一旦成功，攻击者就把一条自己控制的路径挂进了受害者的会话，
// 调度器随时可能把受害者的流量派到那条路上黑洞掉。内容它读不了（会话密钥推不出来），
// 但足以让会话卡死。
//
// ⚠️ 本用例只断言**结果**，不断言是哪个机制挡住的。试过把服务端的 cb_hash 比对
// 摘掉，它照样通过——也就是说保护不（只）来自那处比较。没查清之前不写归因：
// 一条把功劳记错地方的注释，会让后来人放心地去动那个其实不承重的地方。
func TestReplayedHelloCannotJoinVictimSession(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 受害者建会话，并让它多挂一条路径——第二条走的正是 join 流程。
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := h.client.dialPath(ctx, sess, true)
	if err != nil {
		t.Fatal(err)
	}
	if !sess.addPath(p2) {
		t.Fatal("第二条路径没挂上")
	}
	// ★ 要看的是**服务端**那一侧的会话：攻击者一旦 join 成功，多出来的路径挂在
	// 服务端的会话对象上，客户端自己的 sess 里根本看不见。
	// 第一版这条用例就断言错了对象，负对照（摘掉 cb 比对）照样绿——
	// 一条永远通过的安全测试比没有更糟。
	srvPaths := func() int {
		h.srv.mu.Lock()
		ss := h.srv.sessions[sess.ID()]
		h.srv.mu.Unlock()
		if ss == nil {
			return -1
		}
		return len(ss.sess.pathsSnapshot())
	}
	if n := srvPaths(); n < 1 {
		t.Fatalf("服务端上找不到这条会话（%d）", n)
	}

	// 攻击者：捕获受害者那条 join HELLO 的**明文字节**（最强假设——
	// 相当于外层 TLS 已经被看穿），在自己的 TLS 连接上原样重放。
	var captured []byte
	victim := &captureConn{}
	{
		// 用同一个客户端再拨一次 join，把写出去的字节录下来。
		raw, err := net.Dial("tcp", h.ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		tc := tls.Client(raw, h.client.tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			t.Fatal(err)
		}
		victim.Conn = tc
		if _, err := h.client.handshake(ctx, sess, victim, true, "tcp"); err != nil {
			t.Fatalf("受害者自己的 join 就失败了，测不下去：%v", err)
		}
		captured = victim.written()
	}
	if len(captured) == 0 {
		t.Fatal("没录到 HELLO 字节")
	}
	// ★ 基线必须在**受害者自己那次 join 之后**才取：那次握手服务端侧也会加一条路径
	// （客户端没 addPath，但服务端 handleConn 会）。在它之前取基线，
	// 受害者自己加的那条会被算到攻击者头上。
	time.Sleep(300 * time.Millisecond)
	before := srvPaths()

	// 攻击者的连接：另一条 TLS，原样重放那串字节。
	atk, err := tls.Dial("tcp", h.ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, ServerName: "tide.test", MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer atk.Close()
	if _, err := atk.Write(captured); err != nil {
		t.Fatal(err)
	}
	// 服务端应当失败关闭并转给掩护源站（回声），而**不是**回一个 ACCEPT。
	atk.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(captured))
	n, _ := io.ReadFull(atk, buf)
	if n > 0 && bytes.Equal(buf[:n], captured[:n]) {
		t.Logf("重放被失败关闭，字节原样转给了掩护源站（%d 字节回声）", n)
	}

	time.Sleep(500 * time.Millisecond)
	if after := srvPaths(); after > before {
		t.Fatalf("重放的 HELLO 把攻击者的连接挂进了受害者的会话（服务端路径 %d → %d）—— "+
			"攻击者可以就此把受害者的流量吸到自己控制的路径上黑洞掉", before, after)
	}
}

// captureConn 记录写出去的字节，用来"捕获"一条握手。
type captureConn struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
}

func (c *captureConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.buf = append(c.buf, p...)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *captureConn) written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...)
}

// 包装之后 exporterFor 认不出底下的 *tls.Conn 了，得自己把导出器透出来——
// 否则握手会以"transport does not support channel binding"失败，
// 那样这条用例测的就不是重放，而是包装写错了。
func (c *captureConn) ExportKeyingMaterial(label string, ctx []byte, n int) ([]byte, error) {
	tc, ok := c.Conn.(*tls.Conn)
	if !ok {
		return nil, errNoExporter
	}
	cs := tc.ConnectionState()
	return cs.ExportKeyingMaterial(label, ctx, n)
}

// 版本不匹配必须被**当作版本问题**认出来，而不是掉进"协议错误"里。
//
// ★ 版本字节存在的全部意义，就是让"两端版本不一样"这件事能被明确识别。
// 但 handleHello 原先是先 parseHello 再查版本，而 parseHello 的第一件事是按
// **当前版本**的 kemShareLen 校验长度——于是一个旧版本客户端总是先在长度上被否掉，
// 返回 ErrProtocol，版本字节根本没被看过一眼。
//
// 这不是纯洁癖：draft-01 → draft-02 改了三处线格式（kem_share 1120→2304、
// ACCEPT.srv_eph 32→1120、zero_seal.eph 32→1216），升级期两端版本不一致是常态。
// 运维看到"协议错误"和看到"版本不匹配"，要做的事完全不同。
func TestVersionMismatchIsReportedAsVersionError(t *testing.T) {
	h := newHarness(t, nil)

	// 一个"旧版本"的 HELLO：版本字节是 0x01，且 kem_share 用的是旧长度。
	oldKemShare := 32 + 1088 // draft-01 的 kemShareLen
	body := make([]byte, 1+oldKemShare+32+2+authPlainLen+16)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	body[0] = 0x01 // draft-01
	sl := authPlainLen + 16
	body[1+oldKemShare+32] = byte(sl >> 8)
	body[1+oldKemShare+33] = byte(sl)

	_, _, err := h.srv.handleHello(&teeConn{Conn: &nopConn{}}, Frame{Type: FrameHello, Payload: body}, [cbHashLen]byte{})
	if !errors.Is(err, ErrVersion) {
		t.Fatalf("旧版本的 HELLO 报的是 %v，不是 ErrVersion —— "+
			"版本字节没能起作用：它在 parseHello 的长度校验之后才被查，"+
			"而旧客户端总是先在长度上出局。升级期两端版本不一致是常态，"+
			"运维看到“协议错误”和看到“版本不匹配”要做的事完全不同", err)
	}

	// 反过来：当前版本但内容是垃圾，必须仍然是 ErrProtocol，别把两类混为一谈。
	body[0] = ProtocolVersion
	if _, _, err := h.srv.handleHello(&teeConn{Conn: &nopConn{}}, Frame{Type: FrameHello, Payload: body}, [cbHashLen]byte{}); errors.Is(err, ErrVersion) {
		t.Fatal("当前版本的畸形 HELLO 被报成了版本错误")
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

// TICKET_REQUEST 是全协议最便宜的帧（4 字节），却让服务端起协程、读 crypto/rand、
// 在票据库里新建一批留存 24 小时的位图，再回 42 字节。
// 逐帧响应就是 RFC 9000 §21.9 说的那种"处理开销相对带宽不成比例"，
// 一个已认证的对端在循环里发它就能把服务端撑死。必须合并 + 限速。
func TestTicketRequestFloodIsCoalesced(t *testing.T) {
	s := newSession([16]byte{}, false, DefaultStreamWindow, time.Minute, time.Second, 16)
	defer s.closeWith(ErrClosed)

	var issued atomic.Int64
	s.onTicketReq = func() { issued.Add(1) }
	go s.ticketServeLoop()

	// 一万个请求。逐帧响应的话这里会签出一万批票据、起一万个协程。
	before := runtime.NumGoroutine()
	for i := 0; i < 10000; i++ {
		if err := s.handleFrame(nil, Frame{Type: FrameTicketReq}); err != nil {
			t.Fatal(err)
		}
	}
	// 给补票协程一点时间跑完第一次（第一次不受冷却约束）。
	time.Sleep(200 * time.Millisecond)

	if n := issued.Load(); n > 2 {
		t.Fatalf("一万个 TICKET_REQUEST 签出了 %d 批票据 —— 没有合并，"+
			"对端可以用 4 字节的帧换服务端 330 字节留存 24 小时（RFC 9000 §21.9）", n)
	}
	if grew := runtime.NumGoroutine() - before; grew > 8 {
		t.Fatalf("一万个 TICKET_REQUEST 多起了 %d 个协程 —— 每帧一个协程是无上界并发", grew)
	}
}

// 签发侧同样必须有上界。Sweep 只清"已过期或已用完"的批次，刚签出的两样都不是，
// 于是在 24 小时的 TicketLifetime 之内，签发路径上一个上界都没有。
func TestTicketStoreBoundsBatchesPerUser(t *testing.T) {
	st := NewMemTicketStore()
	var user [16]byte
	user[0] = 7
	for i := 0; i < 5000; i++ {
		if _, _, err := st.Issue(user, 1024); err != nil {
			t.Fatal(err)
		}
	}
	st.mu.Lock()
	batches, index := len(st.users[user]), len(st.index)
	st.mu.Unlock()
	if batches > maxLiveBatchesPerUser {
		t.Fatalf("单个用户攒了 %d 批，上界是 %d —— 对端刷 TICKET_REQUEST 就能把票据库撑爆，"+
			"顺带让 Consume 的线性扫描变成同样长", batches, maxLiveBatchesPerUser)
	}
	// 索引必须跟着一起收，否则它自己变成第二个泄漏点。
	if index > maxLiveBatchesPerUser {
		t.Fatalf("索引留了 %d 项而活跃批次只有 %d —— 索引没跟着裁", index, batches)
	}
	// 上界不能把功能一起干掉：最新签出的那批必须还能消费。
	base, _, err := st.Issue(user, 16)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := st.consumeAny(base + 3); !ok {
		t.Fatal("加了上界之后最新签出的票据也消费不了了")
	}
}

// 钱包由**对端发来的帧**驱动增长，所以必须有上界。
// sweep 只清"已过期或已用完"的批次，而刚收到的新批次两样都不是——
// 一个恶意服务端刷 TICKET_REPLENISH，能让客户端一直涨到 24 小时后。
func TestWalletBatchesBounded(t *testing.T) {
	w := newTicketWallet()
	now := time.Now()
	var seed [32]byte
	for i := 0; i < 100000; i++ {
		w.add(uint64(i)*2000, 1024, seed, now)
	}
	w.mu.Lock()
	n := len(w.batches)
	w.mu.Unlock()
	if n > maxWalletBatches {
		t.Fatalf("钱包里堆了 %d 批，上界是 %d —— 对端可以刷 TICKET_REPLENISH 把客户端撑爆",
			n, maxWalletBatches)
	}
	// 上界不能把功能一起干掉：最新的那批必须还能用。
	if _, _, ok := w.take(now); !ok {
		t.Fatal("加了上界之后钱包一张票也取不出来了")
	}
}

// 握手帧的线上长度**不得**是常量。
//
// ★ 每条 TIDE 连接的第一条应用记录就是 HELLO（或 ZERO_RTT）那一帧。
// 它的长度完全由协议结构决定——`1 + kem_share + client_random + 2 + sealed`，
// 全是定长——所以不填充的话，**每条连接都是同一个数**，与用户、时间、内容都无关。
// DPI 只要问"TLS 握手后的第一条应用记录是不是恰好 N 字节"，看一个包就认出 TIDE 了。
// 这比第 7 轮那个 1Hz 节拍器还好用：节拍器要观察一段时间，这个只要一个包。
//
// §8.3 的判决窗口救不了它：那套填充是**握手之后**才开始的，
// 而握手帧走 writeFrameExact，压根不过填充调度器。
// 后量子把这个常量从 1.2 KB 顶到 2.4 KB，更显眼，但它本来就不该是常量。
func TestHandshakeFrameLengthIsNotConstant(t *testing.T) {
	// 三种握手帧的真实 body 大小。
	for _, tc := range []struct {
		name string
		body int
	}{
		{"HELLO", 1 + kemShareLen + 32 + 2 + authPlainLen + 16},
		{"ZERO_RTT", 1 + 8 + 12 + 2 + zeroSealLen + 16},
		{"ACCEPT", acceptFixed + 16},
	} {
		seen := map[int]int{}
		const n = 400
		for i := 0; i < n; i++ {
			pad := handshakePad(tc.body)
			seen[frameOverhead(0, tc.body+pad+2)+tc.body+pad+2]++
		}
		bare := frameOverhead(0, tc.body) + tc.body
		if len(seen) < 64 {
			t.Fatalf("%s：%d 次采样只有 %d 种线上长度（不填充时恒为 %d）—— "+
				"接近常量，DPI 看一个包就能把这条连接认出来", tc.name, n, len(seen), bare)
		}
		lo, hi := 1<<30, 0
		for k := range seen {
			if k < lo {
				lo = k
			}
			if k > hi {
				hi = k
			}
		}
		// 开销要有上界：往分布尾部乱填会让 1/5 的握手发出 11–16 KB 的记录，
		// 那比 2.5 KB 更不像正常流量，而且白花带宽。
		if grew := hi - bare; grew > handshakePadSpan+64 {
			t.Fatalf("%s：最大填充 %d 字节，超过了 %d 的预算", tc.name, grew, handshakePadSpan)
		}
		t.Logf("%-9s 不填充恒为 %5d；填充后 %d 种取值，范围 %d..%d",
			tc.name, bare, len(seen), lo, hi)
	}
}

// ---------------------------------------------------------------------------
// 填充
// ---------------------------------------------------------------------------

// tsConn 记录底层 net.Conn 上每次 Write 的时刻 = DPI 看到的包到达时刻。
type tsConn struct {
	net.Conn
	mu *sync.Mutex
	at *[]time.Time
}

func (c *tsConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	*c.at = append(*c.at, time.Now())
	c.mu.Unlock()
	return n, err
}

// 应用层静默时，线上包的到达间隔**不得**是一个节拍器。
//
// ★ 填充把**长度**修得再像 HTTPS 也没用——长度和时序是两个彼此独立的维度，
// 而时序这一维原先是完全裸奔的：探测循环 t.Reset(interval) 用的是常量，
// 实测一条静默连接的包间隔是 **均值 1000.2ms、标准差 0.15ms、变异系数 0.00015**，
// 一个精确到 0.15 毫秒的节拍器。识别它不需要任何机器学习，
// 对到达间隔做个直方图就一眼看穿，而真实 HTTPS 浏览的间隔是重尾且高度不规则的。
//
// 修法两件：探测间隔加 ±40% 抖动，以及把写好却从没被调用过的 maybeHeartbeat
// 接上（判决窗口内往静默间隔里插 PADDING 帧，即 WTF-PAD 那一类 adaptive padding）。
func TestIdleTimingIsNotAMetronome(t *testing.T) {
	var mu sync.Mutex
	var at []time.Time
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		cc.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := net.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			return &tsConn{Conn: c, mu: &mu, at: &at}, nil
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if _, err := h.client.Session(ctx); err != nil {
		t.Fatal(err)
	}
	// 开一条流让路径处于"有活跃流"状态，然后**什么都不发**。
	c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	at = at[:0]
	mu.Unlock()

	time.Sleep(5 * time.Second)

	mu.Lock()
	ts := append([]time.Time(nil), at...)
	mu.Unlock()

	// 只看"真正的周期"：突发内部几十微秒的间隔不是时序特征。
	var gaps []float64
	for i := 1; i < len(ts); i++ {
		if g := ts[i].Sub(ts[i-1]).Seconds() * 1000; g > 50 {
			gaps = append(gaps, g)
		}
	}
	if len(gaps) < 3 {
		t.Skipf("静默期只采到 %d 个间隔，样本不够下结论", len(gaps))
	}
	var sum, sum2 float64
	for _, g := range gaps {
		sum += g
		sum2 += g * g
	}
	n := float64(len(gaps))
	mean := sum / n
	cv := math.Sqrt(sum2/n-mean*mean) / mean
	t.Logf("静默期 %d 个包 / %d 个间隔：均值 %.1fms 变异系数 %.4f", len(ts), len(gaps), mean, cv)

	// 光是 ±40% 均匀抖动，变异系数就有 0.8/√12 ≈ 0.23；心跳帧会把它推得更高。
	// 阈值取 0.15 —— 低于它基本只可能是"根本没抖"。
	if cv < 0.15 {
		t.Fatalf("空闲时包间隔的变异系数只有 %.5f（均值 %.1fms）—— 这是一个节拍器。"+
			"长度伪装得再好也没用，一次自相关就能把这条连接从 HTTPS 里挑出来", cv, mean)
	}
}

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

// 失败关闭的响应时间**不得**明显取决于探测方发了什么。
//
// ★ §7.1 要求"尽早判定"，于是不同探测在不同深度出局：一个 HTTP 请求第 2 个字节
// 就被否掉，而一个长得像 HELLO 的探测要等服务端做完 X25519 + ML-KEM-768 解封装
// 才在 AEAD 上失败。那段密码学运算的时间会直接写进"多久之后掩护源站开始回话"。
//
// 这是一个**自足**的判据：探测方不需要任何对照基线，拿同一台机器自己跟自己比就行。
// 而一台真正的 nginx 对这两个输入的响应时间没有任何差别——两者都只是畸形请求。
// （讽刺的是 §7 建议掩护源站放本机以压低延迟，那反而抬高信噪比、让差值更好测。）
//
// 实测（本机掩护源站，长度对齐的两种探测各 400 次）：
//
//	修复前：182µs vs 315µs，差 133µs / +73%，Welch t = 38.7
//	修复后：197µs vs 261µs，差  64µs / +33%，Welch t = 19.1
//
// 修法是把掩护连接的拨号提到读第一个字节**之前**，并在密码学验证开始前就把已收到的
// 字节推给掩护源站，让两者并行而不是串行。
//
// ⚠️ 残留的 33% 短期内消不掉：掩护源站的字节**在确认握手失败之前绝不能回给客户端**，
// 所以任何走到密码学那一步的探测都必然要等它。要彻底抹平只有两条路，都更糟——
// 对所有输入都做一遍 KEM（4 字节的探测就能换一次 ML-KEM 解封装，
// 正是 RFC 9000 §21.9 那类放大），或者给失败响应加一个固定下限
// （那会让所有畸形请求都恰好耗时 T，本身又是个特征）。
// 这条测试守的是"别退回修复前"，不是"已经解决"。
func TestFailClosedTimingDoesNotLeakHandshakeDepth(t *testing.T) {
	// -race 给每次内存访问插桩，密码学运算被拖慢的比例远大于 I/O，
	// 于是这里量的"相对时间差"在 -race 下反映的是插桩开销而不是产品的性质。
	if raceDetector {
		t.Skip("时序测量在 -race 下失真；请用不带 -race 的一轮跑它")
	}
	h := newHarness(t, nil)
	addr := h.ln.Addr().String()

	// B：能过类型/长度检查，逼服务端做完整 KEM 解封装，最后卡在 AEAD。
	body := make([]byte, minHelloBody)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	body[0] = ProtocolVersion
	sl := authPlainLen + 16
	body[1+kemShareLen+32] = byte(sl >> 8)
	body[1+kemShareLen+33] = byte(sl)
	kemProbe := AppendFrame(nil, FrameHello, FlagPush, 0, body, 0)

	// A：**同样大小**的垃圾，第 2 个字节就出局。长度必须对齐——不然量到的差里
	// 混着"请求大一点自然回得晚一点"，那在任何服务器上都成立，不是 TIDE 的特征。
	head := []byte("GET / HTTP/1.1\r\nHost: a\r\nX-Pad: ")
	tail := []byte("\r\n\r\n")
	httpProbe := append([]byte{}, head...)
	httpProbe = append(httpProbe, bytes.Repeat([]byte("a"), len(kemProbe)-len(head)-len(tail))...)
	httpProbe = append(httpProbe, tail...)

	probe := func(payload []byte) (time.Duration, bool) {
		c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
		if err != nil {
			return 0, false
		}
		defer c.Close()
		start := time.Now()
		if _, err := c.Write(payload); err != nil {
			return 0, false
		}
		var b [1]byte
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Read(b[:]); err != nil {
			return 0, false
		}
		return time.Since(start), true
	}

	var a, b []float64
	for i := 0; i < 150; i++ {
		// 交替采样，抵消机器负载漂移
		if d, ok := probe(httpProbe); ok {
			a = append(a, float64(d.Microseconds()))
		}
		if d, ok := probe(kemProbe); ok {
			b = append(b, float64(d.Microseconds()))
		}
	}
	if len(a) < 50 || len(b) < 50 {
		t.Skipf("样本不够：%d / %d", len(a), len(b))
	}
	sort.Float64s(a)
	sort.Float64s(b)
	medA, medB := a[len(a)/2], b[len(b)/2]
	rel := (medB - medA) / medA
	t.Logf("失败关闭响应中位数：垃圾探测 %.0fus  像HELLO %.0fus  相对差 %.1f%%", medA, medB, 100*rel)

	// 修复前是 +73%。阈值取 55%：既能抓住"把提前拨号挪回 failClosed"这类回退，
	// 又给机器负载留了余量。
	if rel > 0.55 {
		t.Fatalf("两类探测的失败关闭响应时间相差 %.1f%%（%.0fus vs %.0fus）—— "+
			"探测方拿同一台机器自己跟自己比就能确认这跑的是 TIDE，不需要任何对照基线",
			100*rel, medA, medB)
	}
}

// 一个终止并重建外层 TLS 的中间人 MUST 被拒（spec §5 信道绑定 / design.md §10 第 4 条）。
//
// ★ 这是整份威胁模型里最需要测、却一直一条测试都没有的一条。
// 客户端在企业 CA / 被强装根证书的环境里**会**信任中间人的证书——
// 测试里的 InsecureSkipVerify 正是这个场景的忠实模拟。TLS 那一层不会报任何错，
// 于是信道绑定是用户与全量 MITM 之间**唯一**的东西。
//
// 它的原理：cb = TLS-Exporter(外层信道)。中间人两侧是两条独立的 TLS 会话，
// 导出值必然不同；客户端把自己那份封进 sealed_auth，服务端拿自己这份比对，对不上就失败关闭。
func TestMITMTerminatingTLSIsRejected(t *testing.T) {
	mitmLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer mitmLn.Close()

	// 客户端被指向中间人，而不是真服务端。
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		cc.Server = mitmLn.Addr().String()
	})
	realAddr := h.ln.Addr().String()

	mitmCert := testTLSServer(t)
	// relayed 统计"两条 TLS 都建起来了、而且真的搬过字节"的次数。
	// 没有它，这条测试在"客户端压根没连上中间人"的情况下也会通过。
	var relayed atomic.Int64
	go func() {
		for {
			c, err := mitmLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// 对客户端：用**自己的**证书建一条 TLS（客户端信任它）。
				down := tls.Server(c, mitmCert)
				if err := down.Handshake(); err != nil {
					return
				}
				// 对服务端：另建一条 TLS，把解密出来的 TIDE 字节原样搬过去。
				up, err := tls.Dial("tcp", realAddr, &tls.Config{
					InsecureSkipVerify: true, ServerName: "tide.test", MinVersion: tls.VersionTLS13,
				})
				if err != nil {
					return
				}
				defer up.Close()
				go func() {
					if n, _ := io.Copy(up, down); n > 0 {
						relayed.Add(n)
					}
				}()
				io.Copy(down, up)
			}(c)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := h.client.Session(ctx); err == nil {
		t.Fatal("中间人终止并重建了外层 TLS，TIDE 握手却成功了 —— 信道绑定没起作用。" +
			"在被强装根证书的环境里，这等于代理内容对中间人完全透明")
	}
	// ★ 必须确认中间人**真的把 TLS 劫持成功了**：两条 TLS 都建起来、字节确实搬过去了。
	// 否则这条拒绝可能只是"客户端连不上中间人"，与信道绑定毫无关系。
	time.Sleep(200 * time.Millisecond) // 等中继协程把计数写完
	if n := relayed.Load(); n == 0 {
		t.Fatal("中间人一个字节都没中继成功 —— 这条用例没有真的测到信道绑定")
	} else {
		t.Logf("中间人成功劫持了外层 TLS 并中继了 %d 字节，TIDE 仍然拒绝了握手", n)
	}

	// ★ 对照组：同样的配置直连必须成功。没有它，上面那条断言在"客户端根本连不上"
	// 的情况下也会通过——那就成了一条永远绿、什么也没守住的测试。
	direct, err := NewClient(&ClientConfig{
		Server:    realAddr,
		PublicKey: h.client.cfg.PublicKey,
		UserID:    h.client.cfg.UserID,
		TLSConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "tide.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	if _, err := direct.Session(ctx); err != nil {
		t.Fatalf("对照组直连也失败了（%v）—— 上面那条拒绝说明不了任何问题", err)
	}
}

// 信道绑定值必须"同一条连接两端相同、不同连接互不相同"。
//
// ★ 这两条缺任何一条，§5 都会**静默**失效而所有功能测试照样全绿：
// 两端算得不一样 → 合法握手全挂（这个至少看得见）；
// 不同连接算出同一个值 → 比对永远通过，中间人畅通无阻，而且不会有任何症状。
// 后者正是最危险的形态——一个退化成常量（或全零）的导出器长得和正常的一模一样。
func TestChannelBindingIsPerConnection(t *testing.T) {
	srvCfg := testTLSServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvCB := make(chan [cbHashLen]byte, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				tc := tls.Server(c, srvCfg)
				if err := tc.Handshake(); err != nil {
					return
				}
				exp, err := exporterFor(tc)
				if err != nil {
					return
				}
				cb, err := channelBinding(exp)
				if err != nil {
					return
				}
				srvCB <- cb
			}(c)
		}
	}()

	dial := func() [cbHashLen]byte {
		t.Helper()
		tc, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			InsecureSkipVerify: true, ServerName: "tide.test", MinVersion: tls.VersionTLS13,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { tc.Close() })
		exp, err := exporterFor(tc)
		if err != nil {
			t.Fatal(err)
		}
		cb, err := channelBinding(exp)
		if err != nil {
			t.Fatal(err)
		}
		return cb
	}

	c1, c2 := dial(), dial()
	var s1, s2 [cbHashLen]byte
	for _, dst := range []*[cbHashLen]byte{&s1, &s2} {
		select {
		case v := <-srvCB:
			*dst = v
		case <-time.After(10 * time.Second):
			t.Fatal("服务端没算出信道绑定值")
		}
	}

	var zero [cbHashLen]byte
	for i, cb := range [][cbHashLen]byte{c1, c2, s1, s2} {
		if cb == zero {
			t.Fatalf("第 %d 个信道绑定值是全零 —— 导出器没真的工作，比对形同虚设", i)
		}
	}
	// 两条连接的 cb 必须不同。相同就意味着中间人可以把一条连接上认证过的
	// sealed_auth 原样搬到另一条连接上用。
	if c1 == c2 {
		t.Fatal("两条不同的 TLS 连接算出了相同的信道绑定值 —— 导出器退化成常量了，" +
			"中间人可以把一条连接上的认证材料搬到另一条上，§5 完全失效")
	}
	// 同一条连接的两端必须一致（顺序：服务端按 accept 顺序回，与 dial 顺序一致）。
	if c1 != s1 || c2 != s2 {
		t.Fatalf("同一条连接两端算出的信道绑定值不一致 —— 合法握手会全部失败\n"+
			"  client1=%x server1=%x\n  client2=%x server2=%x", c1[:8], s1[:8], c2[:8], s2[:8])
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

// 多路径爬坡（TCP 起来之后再加一条 QUIC）**不得**触发全量重发。
//
// ★ addPath 曾经无条件 rewindAll()，把每条流的待发指针退回最后确认点。
// 数据明明还在一条健康的路径上飞，接收方又按绝对偏移去重，于是重发的字节纯属浪费；
// 更糟的是加路径这件事由对端驱动——任何一次 join 都能触发一次全量重发，
// 最坏是 maxStreams × window ≈ 512 MB 的出向流量外加每条流一个 pump 协程。
// 多路径 QUIC 的原则也是一样的：确认丢失或路径判死之前不重传，就是为了躲开虚假重传。
func TestAddingHealthyPathDoesNotResendEverything(t *testing.T) {
	port := freeUDPPort(t)
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		cc.EnableQUIC = true
		cc.QUICPort = port
		cc.ProbeInterval = 200 * time.Millisecond
	})
	serveQUICOn(t, h, port)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 先在 TCP 路径上把几条流跑起来，确保有已发送的数据。
	payload := bytes.Repeat([]byte("x"), 8192)
	var conns []net.Conn
	for i := 0; i < 4; i++ {
		c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Write(payload); err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	// 等这批数据真的走完，免得把"还没发完"误判成"被重发了"。
	buf := make([]byte, len(payload))
	for _, c := range conns {
		c.SetReadDeadline(time.Now().Add(20 * time.Second))
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatal(err)
		}
	}

	before := sess.StreamResumes()
	// 等 QUIC 路径加进来。
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if len(sess.pathsSnapshot()) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n := len(sess.pathsSnapshot()); n < 2 {
		t.Skipf("QUIC path never came up (%d paths); nothing to assert", n)
	}
	time.Sleep(300 * time.Millisecond) // 让 addPath 的后续动作跑完

	if grew := sess.StreamResumes() - before; grew > 0 {
		t.Fatalf("加一条健康路径触发了 %d 次全量退回重发 —— 数据还在一条好路径上飞，"+
			"这些字节是白发的；而且加路径由对端驱动，反复 join 就能把出口打满", grew)
	}
}

// 一条会话能挂的路径数必须有上界：加路径由对端驱动，每条路径要付 3 个协程
// 加一个 32 KiB 的解帧缓冲，还会让 pickPath 的每次发送变成 O(路径数)。
func TestPathsPerSessionBounded(t *testing.T) {
	s := newSession([16]byte{}, false, DefaultStreamWindow, time.Minute, time.Second, 16)
	defer s.closeWith(ErrClosed)
	accepted := 0
	for i := 0; i < maxPathsPerSession*4; i++ {
		p := &path{
			id: uint32(i + 1), kind: "tcp", sess: s, conn: &nopConn{},
			pad: newPaddingScheduler(), pending: make(map[uint64]time.Time),
			created: time.Now(), dead: make(chan struct{}),
		}
		p.wcond = sync.NewCond(&p.wmu)
		p.lastRecv.Store(time.Now().UnixNano())
		p.peek = newPeekReader(p.conn, 48)
		p.fr = newFrameReader(p.peek)
		if s.addPath(p) {
			accepted++
		}
	}
	if accepted > maxPathsPerSession {
		t.Fatalf("接纳了 %d 条路径，上界是 %d", accepted, maxPathsPerSession)
	}
	if n := len(s.pathsSnapshot()); n > maxPathsPerSession {
		t.Fatalf("会话上挂了 %d 条路径，上界是 %d", n, maxPathsPerSession)
	}
}

// 会话挂满路径之后，后台的 QUIC 维持循环**不得**变成一台握手风暴发生器。
//
// ★ 这是第 4 轮的路径上界与既有 maintainQUIC 之间的配合问题，两边各自都对：
//
//	· addPath 到上界就把新路径顶回来（防对端不断加路径）；
//	· maintainQUIC 看"有没有 QUIC 路径"决定要不要拨，而它把 addPath 的返回值**丢掉了**。
//
// 于是 hasQUIC 永远为假（新路径根本挂不上），每 5 秒拨一次全新的 QUIC 路径，
// 每次都做完整的 KEM 握手、服务端也陪着做一遍，然后被拒、判死、重来——会话活多久刷多久。
//
// 死因环形缓冲让它可观测：每条被顶回来的路径都会留下一条
// "too many paths on this session"。
func TestFullSessionDoesNotSpinDialingQUIC(t *testing.T) {
	port := freeUDPPort(t)
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		cc.EnableQUIC = true
		cc.QUICPort = port
		cc.ProbeInterval = 200 * time.Millisecond
	})
	serveQUICOn(t, h, port)

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 用假路径把会话填满（kind 用 tcp，好让 hasQUIC 保持为假）。
	for len(sess.pathsSnapshot()) < maxPathsPerSession {
		p := &path{
			id: 900 + uint32(len(sess.pathsSnapshot())), kind: "tcp", sess: sess, conn: &nopConn{},
			pad: newPaddingScheduler(), pending: make(map[uint64]time.Time),
			created: time.Now(), dead: make(chan struct{}),
		}
		p.wcond = sync.NewCond(&p.wmu)
		p.lastRecv.Store(time.Now().UnixNano())
		p.peek = newPeekReader(p.conn, 48)
		p.fr = newFrameReader(p.peek)
		if !sess.addPath(p) {
			break
		}
	}
	if n := len(sess.pathsSnapshot()); n < maxPathsPerSession {
		t.Skipf("没能把会话填满（%d/%d）", n, maxPathsPerSession)
	}

	// 让 maintainQUIC 跑一会儿。修复前它每 5 秒拨一次并被顶回来。
	time.Sleep(16 * time.Second)

	rejected := 0
	for _, d := range sess.PathDeaths() {
		if strings.Contains(d, "too many paths") {
			rejected++
		}
	}
	if rejected > 1 {
		t.Fatalf("会话挂满之后仍然反复拨号：死因里有 %d 条“路径太多”—— "+
			"每一条都是一次完整的 KEM 握手，客户端和服务端各做一遍，然后扔掉", rejected)
	}
	t.Logf("会话挂满 16 秒，被顶回来的拨号次数 = %d", rejected)
}

// 一次**成功**的握手，不得往掩护源站发任何字节。
//
// ★ 掩护源站只在认证失败时才该被碰到（§7）——Xray/Trojan 的 fallback 也是这条线。
// 合法会话往那边漏字节有三重代价：掩护源站为每次正常连接记一条畸形请求日志（噪音）；
// 谁能看到那份日志就能数出 TIDE 的握手次数（相关性信号）；
// 掩护源站若是第三方站点，等于替用户往别人服务器上发垃圾。
//
// 这条测试是为了守住第 8 轮那个"提前把请求推给掩护源站"的改动**不要再回来**：
// 它当初是想让掩护源站的处理与本端密码学运算并行，实测一无所得
// （响应在确认握手失败之前本来就不能回给客户端），代价却是上面这三条。
func TestSuccessfulHandshakeSendsNothingToCover(t *testing.T) {
	cover, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cover.Close()
	var got atomic.Int64
	go func() {
		for {
			c, err := cover.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						got.Add(int64(n))
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()

	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		sc.CoverAddr = cover.Addr().String()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 几次完整的、成功的握手 + 一点真实流量。
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		p, err := h.client.dialPath(ctx, sess, true)
		if err != nil {
			t.Fatal(err)
		}
		sess.addPath(p)
	}
	c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msg := bytes.Repeat([]byte("z"), 4096)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)

	if n := got.Load(); n != 0 {
		t.Fatalf("合法握手往掩护源站漏了 %d 字节 —— 掩护源站只在认证失败时才该被碰到。"+
			"漏过去的是加密后的握手帧，对端读不懂，但它给掩护源站的日志留下了"+
			"一条一一对应的记录：数那份日志就能数出 TIDE 的握手次数", n)
	}
}

// QUIC/h3 路径也必须填充，且填充预算只花在判决窗口里。
//
// ★ QUIC 路径**恒为 bare**（服务端对每条 QUIC 连接都置 acceptModeBare）。
// 而 newPath 曾经在 bare 分支里把填充整个关掉，理由是"要插填充就得在用户态碰载荷，
// 那 splice 就没了"——那个理由已经不存在（§12.3 定稿：kTLS + splice 在多路复用协议里
// 根本做不到）。一个为已被否决的优化让路的开关，就那么一直开着。
//
// 后果：QUIC/h3 路径既没有长度填充、也没有时序心跳，而 §8.1 恰恰把**批量**流往
// QUIC 上偏——承载字节最多的那条路，防护是零。学界对 QUIC 的网站指纹攻击
// 只要 40 个包就能到 95% 准确率，包长是主要特征之一。
//
// 这条测试守两头：判决窗口内**要**填充，批量阶段**不**填充（否则吞吐白白变差）。
func TestQUICPathIsPaddedInDecisionWindowOnly(t *testing.T) {
	port := freeUDPPort(t)
	h := newHarness(t, func(cc *ClientConfig, sc *ServerConfig) {
		cc.EnableQUIC = true
		cc.QUICPort = port
		cc.ProbeInterval = 200 * time.Millisecond
	})
	serveQUICOn(t, h, port)

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	sess, err := h.client.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var qp *path
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && qp == nil {
		for _, p := range sess.pathsSnapshot() {
			if p.kind == "quic" {
				qp = p
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if qp == nil {
		t.Skip("QUIC 路径没起来")
	}

	send := func(n, times int) uint64 {
		t.Helper()
		c, err := h.client.DialContext(ctx, "tcp", "echo.invalid:80")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.(*Stream).pathID.Store(qp.id)
		msg := bytes.Repeat([]byte("q"), n)
		buf := make([]byte, n)
		before := qp.txBytes.Load()
		for i := 0; i < times; i++ {
			if _, err := c.Write(msg); err != nil {
				t.Fatal(err)
			}
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(c, buf); err != nil {
				t.Fatal(err)
			}
		}
		return qp.txBytes.Load() - before
	}

	// 判决窗口：100 字节的小包必须被填到 HTTPS 量级，也就是远超载荷本身。
	if qp.pad.Phase() != PhaseDecision {
		t.Skipf("路径已经不在判决窗口了（%s），测不到", qp.pad.Phase())
	}
	grew := send(100, 20)
	if raw := uint64(20 * (100 + 8)); grew < raw*4 {
		t.Fatalf("判决窗口内 QUIC 路径只发出 %d 字节（裸载荷约 %d）—— 帧没有被填充，"+
			"而 §8.1 把批量流往 QUIC 上偏，等于最重要的那条路裸奔", grew, raw)
	}

	// 把预算烧完，进入批量阶段。
	for qp.pad.Phase() != PhaseBulk {
		send(8192, 8)
	}
	// 批量阶段：填充必须归零，否则这个修复就是拿吞吐换来的。
	big := send(8192, 16)
	if raw := uint64(16 * 8192); big > raw+raw/4 {
		t.Fatalf("批量阶段仍在填充：发 %d KiB 载荷用掉了 %d KiB —— "+
			"填充预算本该只花在判决窗口", raw/1024, big/1024)
	}
	t.Logf("判决窗口 20×100B → %d 字节；批量阶段 16×8KiB → %d 字节（载荷 %d）",
		grew, big, 16*8192)
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
