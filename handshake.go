package tide

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"time"
)

// 握手消息的编解码（spec §3）。这里只做字节搬运，密钥调度在 crypto.go，
// 流程与失败关闭在 client.go / server.go。

const (
	authPlainLen = 16 + 8 + cbHashLen + 1 + 16 + 4 // user||ts||cb||flags||session||path
	acceptFixed  = 16 + 1 + 4 + ticketGrantLen     // session||mode||path_id||ticket
	zeroSealLen  = cbHashLen + 8 + 16 + 16 + 1 + 4 // cb||ts||user||session||flags||path
)

type authPlain struct {
	user      [16]byte
	timestamp int64
	cbHash    [cbHashLen]byte
	flags     uint8
	sessionID [16]byte
	pathID    uint32
}

func (a *authPlain) marshal() []byte {
	b := make([]byte, 0, authPlainLen)
	b = append(b, a.user[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(a.timestamp))
	b = append(b, a.cbHash[:]...)
	b = append(b, a.flags)
	b = append(b, a.sessionID[:]...)
	return binary.BigEndian.AppendUint32(b, a.pathID)
}

func parseAuthPlain(b []byte) (*authPlain, bool) {
	if len(b) < authPlainLen {
		return nil, false
	}
	a := &authPlain{}
	copy(a.user[:], b[:16])
	a.timestamp = int64(binary.BigEndian.Uint64(b[16:24]))
	copy(a.cbHash[:], b[24:24+cbHashLen])
	o := 24 + cbHashLen
	a.flags = b[o]
	o++
	copy(a.sessionID[:], b[o:o+16])
	o += 16
	a.pathID = binary.BigEndian.Uint32(b[o : o+4])
	return a, true
}

// helloMsg 是 HELLO 帧的载荷。
type helloMsg struct {
	version      uint8
	kemShare     []byte // 1120
	clientRandom [32]byte
	sealed       []byte
	earlyData    []byte
}

func (h *helloMsg) marshal() []byte {
	b := make([]byte, 0, 1+kemShareLen+32+2+len(h.sealed)+len(h.earlyData))
	b = append(b, h.version)
	b = append(b, h.kemShare...)
	b = append(b, h.clientRandom[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(h.sealed)))
	b = append(b, h.sealed...)
	return append(b, h.earlyData...)
}

func parseHello(b []byte) (*helloMsg, bool) {
	const fixed = 1 + kemShareLen + 32 + 2
	if len(b) < fixed {
		return nil, false
	}
	h := &helloMsg{version: b[0]}
	h.kemShare = b[1 : 1+kemShareLen]
	copy(h.clientRandom[:], b[1+kemShareLen:1+kemShareLen+32])
	sl := int(binary.BigEndian.Uint16(b[fixed-2 : fixed]))
	if len(b) < fixed+sl {
		return nil, false
	}
	h.sealed = b[fixed : fixed+sl]
	h.earlyData = b[fixed+sl:]
	return h, true
}

// zeroRTTMsg 是 ZERO_RTT 帧的载荷。
type zeroRTTMsg struct {
	version  uint8
	ticketID uint64
	nonce    [12]byte
	sealed   []byte // AEAD(ticket_key, zeroSeal || early_data)
}

func (z *zeroRTTMsg) marshal() []byte {
	b := make([]byte, 0, 1+8+12+2+len(z.sealed))
	b = append(b, z.version)
	b = binary.BigEndian.AppendUint64(b, z.ticketID)
	b = append(b, z.nonce[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(z.sealed)))
	return append(b, z.sealed...)
}

func parseZeroRTT(b []byte) (*zeroRTTMsg, bool) {
	const fixed = 1 + 8 + 12 + 2
	if len(b) < fixed {
		return nil, false
	}
	z := &zeroRTTMsg{version: b[0]}
	z.ticketID = binary.BigEndian.Uint64(b[1:9])
	copy(z.nonce[:], b[9:21])
	sl := int(binary.BigEndian.Uint16(b[21:23]))
	if len(b) < fixed+sl {
		return nil, false
	}
	z.sealed = b[fixed : fixed+sl]
	return z, true
}

// zeroSeal 是 ZERO_RTT sealed 的明文头部。
type zeroSeal struct {
	cbHash    [cbHashLen]byte
	timestamp int64
	user      [16]byte
	sessionID [16]byte
	flags     uint8
	pathID    uint32
}

func (z *zeroSeal) marshal(early []byte) []byte {
	b := make([]byte, 0, zeroSealLen+len(early))
	b = append(b, z.cbHash[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(z.timestamp))
	b = append(b, z.user[:]...)
	b = append(b, z.sessionID[:]...)
	b = append(b, z.flags)
	b = binary.BigEndian.AppendUint32(b, z.pathID)
	return append(b, early...)
}

func parseZeroSeal(b []byte) (*zeroSeal, []byte, bool) {
	if len(b) < zeroSealLen {
		return nil, nil, false
	}
	z := &zeroSeal{}
	copy(z.cbHash[:], b[:cbHashLen])
	o := cbHashLen
	z.timestamp = int64(binary.BigEndian.Uint64(b[o : o+8]))
	o += 8
	copy(z.user[:], b[o:o+16])
	o += 16
	copy(z.sessionID[:], b[o:o+16])
	o += 16
	z.flags = b[o]
	o++
	z.pathID = binary.BigEndian.Uint32(b[o : o+4])
	o += 4
	return z, b[o:], true
}

// acceptMsg 是 ACCEPT 的明文。整体再被 k_hs 封一层——此时记录层还没建立
// （它的密钥要等 session_id 定下来才能派生），所以只能用握手密钥保护。
// ACCEPT 的 mode 位。把"用不用 AES"放在服务端回的这条消息里，而不是各自按本机
// CPU 决定：记录层的算法必须两端一致，而只有服务端同时知道两边的能力。
const (
	acceptModeBare uint8 = 1 << 0
	acceptModeAES  uint8 = 1 << 1
)

type acceptMsg struct {
	sessionID   [16]byte
	mode        uint8
	pathID      uint32
	ticketBase  uint64
	ticketCount uint16
	ticketSeed  [32]byte
	serverData  []byte
}

func (a *acceptMsg) marshal() []byte {
	b := make([]byte, 0, acceptFixed+len(a.serverData))
	b = append(b, a.sessionID[:]...)
	b = append(b, a.mode)
	b = binary.BigEndian.AppendUint32(b, a.pathID)
	b = appendTicketGrant(b, a.ticketBase, a.ticketCount, a.ticketSeed)
	return append(b, a.serverData...)
}

func parseAccept(b []byte) (*acceptMsg, bool) {
	if len(b) < acceptFixed {
		return nil, false
	}
	a := &acceptMsg{}
	copy(a.sessionID[:], b[:16])
	a.mode = b[16]
	a.pathID = binary.BigEndian.Uint32(b[17:21])
	base, count, seed, ok := parseTicketGrant(b[21:])
	if !ok {
		return nil, false
	}
	a.ticketBase, a.ticketCount, a.ticketSeed = base, count, seed
	a.serverData = b[acceptFixed:]
	return a, true
}

// ---------------------------------------------------------------------------

func newSessionID() ([16]byte, error) {
	var id [16]byte
	_, err := io.ReadFull(rand.Reader, id[:])
	return id, err
}

// timestampSane 校验 ±120 秒容差（spec §3.1）。
//
// 窗口不能太紧：客户端时钟偏几十秒是常态（尤其是刚开机、没同步 NTP 的设备），
// 而窗口太松又会给重放留下更长的可用期。120 秒是"票据位图才是重放防线，
// 时间戳只是粗筛"这个分工下的合理取值。
func timestampSane(ts int64, now time.Time) bool {
	d := now.Unix() - ts
	if d < 0 {
		d = -d
	}
	return time.Duration(d)*time.Second <= TimestampTolerance
}
