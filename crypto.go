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
	kemShareLen  = x25519PubLen + mlkem.CiphertextSize768 // 32 + 1088 = 1120
	pubKeyLen    = x25519PubLen + mlkem.EncapsulationKeySize768
	cbHashLen    = 32
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

// encapsulate 由客户端调用：生成 kem_share 与共享密钥输入材料。
func encapsulate(pub *PublicKey) (kemShare []byte, ikm []byte, err error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	xShared, err := eph.ECDH(pub.x25519)
	if err != nil {
		return nil, nil, err
	}
	mShared, ct := pub.mlkem.Encapsulate()

	kemShare = make([]byte, 0, kemShareLen)
	kemShare = append(kemShare, eph.PublicKey().Bytes()...)
	kemShare = append(kemShare, ct...)

	ikm = make([]byte, 0, len(xShared)+len(mShared))
	ikm = append(ikm, xShared...)
	ikm = append(ikm, mShared...)
	return kemShare, ikm, nil
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
	mShared, err := priv.mlkem.Decapsulate(kemShare[x25519PubLen:])
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

// sessionSecret 由 k_hs（1-RTT）或 ticket_key（0-RTT）+ session_id 派生会话主密钥。
func sessionSecret(base []byte, sessionID []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, base, sessionID, labelSession, 32)
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
