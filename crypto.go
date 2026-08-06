package tide

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/cpu"
)

// 版本字节。draft-01 相对 spec.md 的 draft-00 有三处线格式变化，见 spec.md §11 变更记录：
// STREAM_DATA 带绝对 offset、新增 STREAM_ACK/TICKET_REQUEST、填充长度改为尾部 u16。
const (
	ProtocolVersion     uint8 = 0x01
	labelHandshake            = "tide/draft-01 handshake"
	labelSession              = "tide/draft-01 session"
	labelC2S                  = "tide/draft-01 c2s"
	labelS2C                  = "tide/draft-01 s2c"
	labelPath                 = "tide/draft-01 path"
	labelTicket               = "tide/draft-01 ticket"
	labelZeroRTT              = "tide/draft-01 0rtt"
	ChannelBindingLabel       = "tide-channel-binding"
)

const (
	x25519PubLen = 32
	// kem_share = X25519 临时公钥 || 发给服务端**静态** ML-KEM 的密文
	//           || 客户端**临时** ML-KEM 封装密钥
	//
	// ★ 最后那一段（1184 字节）是后量子前向保密的前提，理由见 serverEphemeral。
	// 前两段只做"到静态密钥"的封装：它给的是隐式服务端认证，**不是**前向保密——
	// 静态密钥一旦事后泄露，配上录音就能把 ikm 重算出来。
	kemShareLen = x25519PubLen + mlkem.CiphertextSize768 + mlkem.EncapsulationKeySize768
	// kemStaticLen 是 kem_share 里"到静态密钥"的那一段，decapsulate 只看这一段。
	kemStaticLen = x25519PubLen + mlkem.CiphertextSize768
	// srvEphLen 是 ACCEPT 里服务端临时材料的长度：X25519 公钥 || 到客户端临时 ML-KEM 的密文。
	srvEphLen = x25519PubLen + mlkem.CiphertextSize768
	// cliEphLen 是 zero_seal 里客户端临时材料的长度：X25519 公钥 || 临时 ML-KEM 封装密钥。
	// 0-RTT 没有 kem_share，这两样只能自己带。
	cliEphLen = x25519PubLen + mlkem.EncapsulationKeySize768
	pubKeyLen = x25519PubLen + mlkem.EncapsulationKeySize768
	cbHashLen = 32
)

// preferAES 在有硬件 AES 的机器上为 true。ChaCha20-Poly1305 是默认值，因为无 AES-NI 时
// 它比软件 AES-GCM 快一个数量级；但**有** AES-NI 时 AES-GCM 反过来快 2–3 倍，
// 而代理的瓶颈就在这条路径上，所以值得按机器选。
var preferAES = func() bool {
	return cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ || cpu.ARM64.HasAES
}()

// 握手 flags 位。
const (
	flagRequestBare uint8 = 1 << 0
	flagHasAESNI    uint8 = 1 << 1
	flagJoinSession uint8 = 1 << 2 // auth_plain 中的 session_id 非零，请求加入已有会话
)

// ---------------------------------------------------------------------------
// 静态密钥
// ---------------------------------------------------------------------------

// PrivateKey 是服务端长期密钥：X25519 静态私钥 + ML-KEM-768 解封装私钥。
type PrivateKey struct {
	x25519 *ecdh.PrivateKey
	mlkem  *mlkem.DecapsulationKey768
	seed   [64]byte // ML-KEM 种子，序列化用
	xseed  [32]byte
}

// PublicKey 是客户端配置里那一大坨 base64：X25519 公钥(32) || ML-KEM-768 封装公钥(1184)。
//
// 1216 字节 → base64 约 1624 字符，确实不好看。但这是后量子的真实价格：
// ML-KEM 的公钥就是这么大，而客户端必须在**第一个包**里就完成封装才能 0-RTT，
// 没有"先问服务端要公钥"的余地——那会引入一个 RTT，把机制 1 的全部收益抵消掉。
type PublicKey struct {
	x25519 *ecdh.PublicKey
	mlkem  *mlkem.EncapsulationKey768
	raw    [pubKeyLen]byte
}

// GenerateKey 生成一对新的服务端静态密钥。
func GenerateKey() (*PrivateKey, error) {
	var xseed [32]byte
	if _, err := io.ReadFull(rand.Reader, xseed[:]); err != nil {
		return nil, err
	}
	var mseed [64]byte
	if _, err := io.ReadFull(rand.Reader, mseed[:]); err != nil {
		return nil, err
	}
	return newPrivateKey(xseed, mseed)
}

func newPrivateKey(xseed [32]byte, mseed [64]byte) (*PrivateKey, error) {
	xk, err := ecdh.X25519().NewPrivateKey(xseed[:])
	if err != nil {
		return nil, err
	}
	mk, err := mlkem.NewDecapsulationKey768(mseed[:])
	if err != nil {
		return nil, err
	}
	return &PrivateKey{x25519: xk, mlkem: mk, seed: mseed, xseed: xseed}, nil
}

// Seed 序列化私钥为 96 字节（32 X25519 + 64 ML-KEM 种子）。
func (k *PrivateKey) Seed() []byte {
	out := make([]byte, 0, 96)
	out = append(out, k.xseed[:]...)
	return append(out, k.seed[:]...)
}

func (k *PrivateKey) String() string { return base64.RawURLEncoding.EncodeToString(k.Seed()) }

// ParsePrivateKey 解析 Seed()/String() 的产物。
func ParsePrivateKey(s string) (*PrivateKey, error) {
	b, err := decodeB64(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 96 {
		return nil, fmt.Errorf("tide: private key must be 96 bytes, got %d", len(b))
	}
	var xs [32]byte
	var ms [64]byte
	copy(xs[:], b[:32])
	copy(ms[:], b[32:])
	return newPrivateKey(xs, ms)
}

// Public 导出对应的客户端公钥。
func (k *PrivateKey) Public() *PublicKey {
	var raw [pubKeyLen]byte
	copy(raw[:], k.x25519.PublicKey().Bytes())
	copy(raw[x25519PubLen:], k.mlkem.EncapsulationKey().Bytes())
	pk, _ := ParsePublicKeyBytes(raw[:])
	return pk
}

func (p *PublicKey) Bytes() []byte  { return p.raw[:] }
func (p *PublicKey) String() string { return base64.RawURLEncoding.EncodeToString(p.raw[:]) }

// ParsePublicKey 解析配置里的 base64 公钥（标准或 URL 变体、有无 padding 都接受）。
func ParsePublicKey(s string) (*PublicKey, error) {
	b, err := decodeB64(s)
	if err != nil {
		return nil, err
	}
	return ParsePublicKeyBytes(b)
}

func ParsePublicKeyBytes(b []byte) (*PublicKey, error) {
	if len(b) != pubKeyLen {
		return nil, fmt.Errorf("tide: public key must be %d bytes, got %d", pubKeyLen, len(b))
	}
	xp, err := ecdh.X25519().NewPublicKey(b[:x25519PubLen])
	if err != nil {
		return nil, fmt.Errorf("tide: bad X25519 component: %w", err)
	}
	mp, err := mlkem.NewEncapsulationKey768(b[x25519PubLen:])
	if err != nil {
		return nil, fmt.Errorf("tide: bad ML-KEM component: %w", err)
	}
	p := &PublicKey{x25519: xp, mlkem: mp}
	copy(p.raw[:], b)
	return p, nil
}

func decodeB64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("tide: value is not valid base64")
}

// ---------------------------------------------------------------------------
// 混合 KEM
// ---------------------------------------------------------------------------

// ephSecrets 是客户端本次连接的一对临时私钥。它们**从不上线**，握手结束即丢——
// 前向保密全部落在这一点上。
type ephSecrets struct {
	x     *ecdh.PrivateKey
	mlkem *mlkem.DecapsulationKey768
}

// encapsulate 由客户端调用：生成 kem_share 与共享密钥输入材料。
func encapsulate(pub *PublicKey) (kemShare []byte, ikm []byte, eph *ephSecrets, err error) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	xShared, err := x.ECDH(pub.x25519)
	if err != nil {
		return nil, nil, nil, err
	}
	mShared, ct := pub.mlkem.Encapsulate()
	// 客户端**临时** ML-KEM 密钥对：公钥随 kem_share 发出，服务端拿它封装一次，
	// 得到的共享值进 ee。没有这一对，后量子那一半就只挂在服务端静态密钥上。
	ek, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, nil, err
	}

	kemShare = make([]byte, 0, kemShareLen)
	kemShare = append(kemShare, x.PublicKey().Bytes()...)
	kemShare = append(kemShare, ct...)
	kemShare = append(kemShare, ek.EncapsulationKey().Bytes()...)

	ikm = make([]byte, 0, len(xShared)+len(mShared))
	ikm = append(ikm, xShared...)
	ikm = append(ikm, mShared...)
	return kemShare, ikm, &ephSecrets{x: x, mlkem: ek}, nil
}

// newEphSecrets 生成一对客户端临时密钥，并给出线上要发的那份公开材料
// （X25519 公钥 || ML-KEM 封装密钥）。0-RTT 路径没有 kem_share，用它自己带。
func newEphSecrets() (pub []byte, eph *ephSecrets, err error) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ek, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, err
	}
	pub = make([]byte, 0, cliEphLen)
	pub = append(pub, x.PublicKey().Bytes()...)
	pub = append(pub, ek.EncapsulationKey().Bytes()...)
	return pub, &ephSecrets{x: x, mlkem: ek}, nil
}

// ---------------------------------------------------------------------------
// 前向保密：ephemeral-ephemeral
// ---------------------------------------------------------------------------
//
// ★ 上面的 ikm 两项——X25519(客户端临时, 服务端**静态**) 与
// MLKEM.Decapsulate(服务端**静态**, ct)——都只依赖服务端的长期私钥和线上可见的字节。
// 也就是说，事后拿到静态私钥的人，配上一份录音就能把 k_hs 重算出来，
// 进而解开 ACCEPT、拿到 session_id 与 ticket_seed，还原整条会话。
// 握手里如果没有任何**服务端临时密钥**，前向保密就是零——这正是 Noise IK 里
// `ee` 那一步存在的理由（IK 的第二条消息带上响应方的临时公钥并做 ee，
// 传输阶段的前向保密全靠它）。
//
// 所以服务端每次握手另生成一对临时密钥：公钥放进 ACCEPT（它被 k_hs 保护，
// 事后攻破者能读到，但没关系——**私钥从不上线**，握手一结束就丢），
// 双方各自算出同一个 ee 并把它混进会话密钥。攻击者缺的就是这个私钥。
//
// ★ ee **必须是混合的**，只做 X25519 不够。这一步 2026-08 补过两次，第二次才补对：
//
// design.md §10 把"先收割后解密（第 5 条）"和"服务端事后被攻破（第 7 条）"
// 分别列为已解决，但它们**不组合**。ee 只有 X25519 时：
//   · 只有量子计算机 → ikm 里的 ML-KEM 那一半还在，k_hs 安全。挡住。
//   · 只有静态私钥泄露 → ee 还在，会话密钥安全。挡住。
//   · **两者都有** → 静态私钥重算出 k_hs，量子计算机解掉 X25519 的 ee，
//     会话密钥全部还原。而这恰恰是同一个敌手：能查抄服务器的国家级对手，
//     也正是有能力"先收割后解密"的那一个。
//
// 所以 ee = X25519(临时,临时) || ML-KEM(客户端临时封装密钥)。后者要求客户端
// 在第一个飞行里就发出自己的临时 ML-KEM **封装密钥**（1184 字节），
// 服务端对它封装一次、把密文放进 ACCEPT（1088 字节）——这正是 TLS 1.3 的
// X25519MLKEM768 的做法，浏览器已经在默认这么付这笔字节了。
//
// 注意"到静态密钥的封装"不能省：它给的是**隐式服务端认证**（只有真服务端能解开
// HELLO.sealed），是 1-RTT 能成立的前提，与前向保密是两件事。
//
// 代价：kem_share +1184、ACCEPT +1088、zero_seal +1184，多一次 ML-KEM 封装/解封装。
// **不需要多一个往返，1-RTT 与 0-RTT 的性质都不变。**
//
// ⚠️ 仍然**不**前向保密的部分（与 TLS 1.3 的 0-RTT 同款取舍，RFC 8446 §2.3）：
// HELLO.sealed 与 ACCEPT 自身、以及 0-RTT 的 early_data。它们必须在拿到对方临时
// 公钥之前就能读，1-RTT 里躲不掉。会话数据——也就是绝大部分字节——是保护住的。

// serverEphemeral 由服务端调用：生成一对临时密钥，与客户端的临时公开材料做混合 ee。
// clientEph 是 X25519 公钥 || ML-KEM 封装密钥，取自 kem_share 的尾部（1-RTT）
// 或 zero_seal.eph（0-RTT）。
func serverEphemeral(clientEph []byte) (pub []byte, ee []byte, err error) {
	if len(clientEph) < cliEphLen {
		return nil, nil, ErrProtocol
	}
	peer, err := ecdh.X25519().NewPublicKey(clientEph[:x25519PubLen])
	if err != nil {
		return nil, nil, err
	}
	peerEK, err := mlkem.NewEncapsulationKey768(clientEph[x25519PubLen:cliEphLen])
	if err != nil {
		return nil, nil, err
	}
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	xShared, err := x.ECDH(peer)
	if err != nil {
		return nil, nil, err
	}
	mShared, ct := peerEK.Encapsulate()

	pub = make([]byte, 0, srvEphLen)
	pub = append(pub, x.PublicKey().Bytes()...)
	pub = append(pub, ct...)
	ee = make([]byte, 0, len(xShared)+len(mShared))
	ee = append(ee, xShared...)
	ee = append(ee, mShared...)
	return pub, ee, nil
}

// clientEphemeralShared 是客户端那一半：拿自己的两把临时私钥与 ACCEPT 里的
// 服务端临时材料算出同一个 ee。
func clientEphemeralShared(eph *ephSecrets, srvEph []byte) ([]byte, error) {
	if eph == nil || len(srvEph) < srvEphLen {
		return nil, ErrProtocol
	}
	peer, err := ecdh.X25519().NewPublicKey(srvEph[:x25519PubLen])
	if err != nil {
		return nil, err
	}
	xShared, err := eph.x.ECDH(peer)
	if err != nil {
		return nil, err
	}
	mShared, err := eph.mlkem.Decapsulate(srvEph[x25519PubLen:srvEphLen])
	if err != nil {
		return nil, err
	}
	ee := make([]byte, 0, len(xShared)+len(mShared))
	ee = append(ee, xShared...)
	ee = append(ee, mShared...)
	return ee, nil
}

// decapsulate 由服务端调用。
//
// ⚠️ 失败时**不能**提前返回一个可区分的错误路径：调用方必须无论成败都走完 §6 的
// 失败关闭流程。这里返回 error 只是让调用方知道"要转发给掩护站点"，而不是"回错误"。
func decapsulate(priv *PrivateKey, kemShare []byte) ([]byte, error) {
	if len(kemShare) != kemShareLen {
		return nil, ErrProtocol
	}
	cliPub, err := ecdh.X25519().NewPublicKey(kemShare[:x25519PubLen])
	if err != nil {
		return nil, err
	}
	xShared, err := priv.x25519.ECDH(cliPub)
	if err != nil {
		return nil, err
	}
	// 只解"到静态密钥"的那一段；kem_share 尾部的客户端临时 ML-KEM 封装密钥
	// 由 serverEphemeral 使用，与 ikm 无关。
	mShared, err := priv.mlkem.Decapsulate(kemShare[x25519PubLen:kemStaticLen])
	if err != nil {
		return nil, err
	}
	ikm := make([]byte, 0, len(xShared)+len(mShared))
	ikm = append(ikm, xShared...)
	ikm = append(ikm, mShared...)
	return ikm, nil
}

// ---------------------------------------------------------------------------
// 密钥调度
// ---------------------------------------------------------------------------

func transcriptHash(version uint8, kemShare, clientRandom []byte) []byte {
	h := sha256.New()
	h.Write([]byte{version})
	h.Write(kemShare)
	h.Write(clientRandom)
	return h.Sum(nil)
}

// handshakeKey 派生 k_hs（spec §3.1）。
func handshakeKey(clientRandom, ikm, transcript []byte) ([]byte, error) {
	info := make([]byte, 0, len(labelHandshake)+len(transcript))
	info = append(info, labelHandshake...)
	info = append(info, transcript...)
	return hkdf.Key(sha256.New, ikm, clientRandom, string(info), 32)
}

// sessionSecret 由 k_hs（1-RTT）或 ticket_key（0-RTT）、ephemeral-ephemeral 共享值
// 与 session_id 派生会话主密钥。
//
// ★ ee 必须混进来，否则整条会话的密钥都能由"服务端静态私钥 + 一份录音"重算出来
// （见 serverEphemeral 上面那段）。ee 为空只在解析老对端时出现，
// 那种情况下前向保密不成立，属于兼容性降级而不是正常路径。
func sessionSecret(base, ee []byte, sessionID []byte) ([]byte, error) {
	ikm := make([]byte, 0, len(base)+len(ee))
	ikm = append(ikm, base...)
	ikm = append(ikm, ee...)
	return hkdf.Key(sha256.New, ikm, sessionID, labelSession, 32)
}

// ticketKey 由种子派生第 id 张票据的密钥（spec §3.2）。
func ticketKey(seed []byte, id uint64) ([]byte, error) {
	info := make([]byte, 0, len(labelTicket)+8)
	info = append(info, labelTicket...)
	info = binary.BigEndian.AppendUint64(info, id)
	return hkdf.Expand(sha256.New, seed, string(info), 32)
}

// UserIDFromPassword 把任意长度的口令折成 16 字节 user_id。
//
// 直接截断口令是不行的：短口令会留下尾部零字节，长口令则丢掉后半段——
// 两个前 16 字节相同的口令会塌成同一个用户，而且不会有任何报错，
// 表现为 A 的流量被记在 B 头上、或者 A 能用 B 的票据。
// 用 SHA-256 折叠保证任意两个不同口令映射到同一个 id 的概率可忽略。
func UserIDFromPassword(password string) [16]byte {
	sum := sha256.Sum256([]byte("tide/draft-01 user\x00" + password))
	var id [16]byte
	copy(id[:], sum[:16])
	return id
}

// hkdfKey 是 HKDF(salt, ikm, info) → 32 字节的薄封装。
func hkdfKey(ikm, salt []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, ikm, salt, info, 32)
}

// directionKeys 从会话主密钥派生两个方向的基密钥。
func directionKeys(secret []byte) (c2s, s2c []byte, err error) {
	if c2s, err = hkdf.Expand(sha256.New, secret, labelC2S, 32); err != nil {
		return
	}
	s2c, err = hkdf.Expand(sha256.New, secret, labelS2C, 32)
	return
}

// pathKey 把方向基密钥再按 path_id 分叉。
//
// ★ 这一步是多路径正确性的关键：AEAD 的 nonce 是序号，而两条路径各自独立发送，
// 序号必然会撞。如果两条路径共用一把密钥，同一个 (key, nonce) 会被用两次——
// 对 ChaCha20-Poly1305 和 GCM 都是灾难性的（直接泄露明文异或、伪造 tag）。
// 按路径分叉密钥后，序号只需在路径内唯一，迁移时也不必同步任何计数器。
func pathKey(dirKey []byte, pathID uint32) ([]byte, error) {
	info := make([]byte, 0, len(labelPath)+4)
	info = append(info, labelPath...)
	info = binary.BigEndian.AppendUint32(info, pathID)
	return hkdf.Expand(sha256.New, dirKey, string(info), 32)
}

func newAEAD(key []byte, useAES bool) (cipher.AEAD, error) {
	if useAES {
		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(blk)
	}
	return chacha20poly1305.New(key)
}

// ---------------------------------------------------------------------------
// 定长封装（握手用，非记录层）
// ---------------------------------------------------------------------------

func sealFixed(key, nonce, plaintext, ad []byte, useAES bool) ([]byte, error) {
	a, err := newAEAD(key, useAES)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, nonce, plaintext, ad), nil
}

func openFixed(key, nonce, ciphertext, ad []byte, useAES bool) ([]byte, error) {
	a, err := newAEAD(key, useAES)
	if err != nil {
		return nil, err
	}
	return a.Open(nil, nonce, ciphertext, ad)
}

// zeroNonce 是握手阶段用的全零 nonce。安全的前提是每次握手的密钥都不同
// （k_hs 里混入了 client_random 与 transcript），因此 (key, nonce) 不会重复。
var zeroNonce = make([]byte, 12)
