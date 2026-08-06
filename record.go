package tide

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

// sealed 模式的记录层。一条记录 = u16 长度前缀 + AEAD 密文，明文是若干个连着的帧。
//
// 按**批**而不是按帧加密：交互阶段一批就是一帧，没有损失；批量阶段一批装满 MTU，
// 16 字节的 tag 摊到 16 KiB 上是 0.1%。反过来按帧加密会让每个小帧都背一个 tag，
// 而小帧恰恰是交互流量的全部。
//
// bare 模式（spec §4 信道绑定通过后才允许）完全不走这一层——帧直接落在外层 TLS 记录里，
// 那才是 kTLS/splice 能生效的前提：用户态一旦要做 AEAD，就不可能不碰载荷。

const (
	maxRecordPlain = 60 * 1024
	recordHdrLen   = 2
)

var errRecordTooLarge = errors.New("tide: record exceeds 64 KiB")

type recordSealer struct {
	mu    sync.Mutex
	aead  cipher.AEAD
	seq   uint64
	nonce [12]byte
}

func newRecordSealer(key []byte, useAES bool) (*recordSealer, error) {
	a, err := newAEAD(key, useAES)
	if err != nil {
		return nil, err
	}
	return &recordSealer{aead: a}, nil
}

// Seal 把 plain（若干个已序列化的帧）封成一条线上记录，追加到 dst。
func (s *recordSealer) Seal(dst, plain []byte) ([]byte, error) {
	if len(plain) > maxRecordPlain {
		return nil, errRecordTooLarge
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	ctLen := len(plain) + s.aead.Overhead()
	if ctLen > 0xffff {
		return nil, errRecordTooLarge
	}
	var hdr [recordHdrLen]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(ctLen))

	binary.BigEndian.PutUint64(s.nonce[4:], s.seq)
	s.seq++

	dst = append(dst, hdr[:]...)
	// AD 绑定长度前缀：否则攻击者可以改长度前缀把一条记录切成两条，
	// AEAD 本身察觉不到——它只认密文。
	return s.aead.Seal(dst, s.nonce[:], plain, hdr[:]), nil
}

// recordOpener 把底层 io.Reader（外层 TLS 连接）适配成一个吐**明文帧字节流**的
// io.Reader，从而 frameReader 可以原样复用，不必区分 sealed / bare。
type recordOpener struct {
	r     io.Reader
	aead  cipher.AEAD
	seq   uint64
	nonce [12]byte

	hdr  [recordHdrLen]byte
	ct   []byte
	pt   []byte // 已解密、未被上层读走的明文
	ptOf int
}

func newRecordOpener(r io.Reader, key []byte, useAES bool) (*recordOpener, error) {
	a, err := newAEAD(key, useAES)
	if err != nil {
		return nil, err
	}
	return &recordOpener{r: r, aead: a, ct: make([]byte, 0, 8*1024), pt: make([]byte, 0, 8*1024)}, nil
}

func (o *recordOpener) Read(p []byte) (int, error) {
	for o.ptOf >= len(o.pt) {
		if err := o.nextRecord(); err != nil {
			return 0, err
		}
	}
	n := copy(p, o.pt[o.ptOf:])
	o.ptOf += n
	return n, nil
}

func (o *recordOpener) nextRecord() error {
	if _, err := io.ReadFull(o.r, o.hdr[:]); err != nil {
		return err
	}
	ctLen := int(binary.BigEndian.Uint16(o.hdr[:]))
	if ctLen < o.aead.Overhead() {
		return ErrProtocol
	}
	if cap(o.ct) < ctLen {
		o.ct = make([]byte, ctLen)
	}
	o.ct = o.ct[:ctLen]
	if _, err := io.ReadFull(o.r, o.ct); err != nil {
		return err
	}
	binary.BigEndian.PutUint64(o.nonce[4:], o.seq)
	o.seq++

	pt, err := o.aead.Open(o.pt[:0], o.nonce[:], o.ct, o.hdr[:])
	if err != nil {
		// 解密失败 = 篡改或密钥不同步。两者都不可恢复，且**不能**重试或降级：
		// 任何"再试一次"的行为都会给主动探测方一个可测量的差异。
		return ErrProtocol
	}
	o.pt = pt
	o.ptOf = 0
	return nil
}
