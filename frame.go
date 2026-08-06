package tide

import (
	"encoding/binary"
	"errors"
	"io"
)

// 帧格式（spec §2）：
//
//	type(1) | flags(1) | length(varint) | stream_id(varint) | payload… | padding…
//
// length 覆盖 payload+padding 的总长；PAD 标志置位时填充区首字节起是 varint pad_len，
// 其后才是填充内容。之所以把 pad_len 放在**填充区开头**而不是帧头，是为了让不带填充的
// 帧头保持最短——批量阶段（§7 阶段 3）根本不填充，那时每帧省下的 1–2 字节是纯收益。

type FrameType uint8

const (
	FrameHello       FrameType = 0x01
	FrameAccept      FrameType = 0x02
	FrameZeroRTT     FrameType = 0x03
	FrameStreamOpen  FrameType = 0x10
	FrameStreamData  FrameType = 0x11
	FrameStreamFin   FrameType = 0x12
	FrameStreamRst   FrameType = 0x13
	FrameStreamAck   FrameType = 0x14 // draft-01 新增，见 spec §2.1 注
	FrameDatagram    FrameType = 0x20
	FramePathProbe   FrameType = 0x30
	FramePathAck     FrameType = 0x31
	FramePathMigrate FrameType = 0x32
	FrameTicketRepl  FrameType = 0x40
	FrameTicketReq   FrameType = 0x41 // draft-01 新增
	FramePadding     FrameType = 0x50
	FrameClose       FrameType = 0x5F
)

func (t FrameType) String() string {
	switch t {
	case FrameHello:
		return "HELLO"
	case FrameAccept:
		return "ACCEPT"
	case FrameZeroRTT:
		return "ZERO_RTT"
	case FrameStreamOpen:
		return "STREAM_OPEN"
	case FrameStreamData:
		return "STREAM_DATA"
	case FrameStreamFin:
		return "STREAM_FIN"
	case FrameStreamRst:
		return "STREAM_RST"
	case FrameStreamAck:
		return "STREAM_ACK"
	case FrameDatagram:
		return "DATAGRAM"
	case FramePathProbe:
		return "PATH_PROBE"
	case FramePathAck:
		return "PATH_ACK"
	case FramePathMigrate:
		return "PATH_MIGRATE"
	case FrameTicketRepl:
		return "TICKET_REPLENISH"
	case FrameTicketReq:
		return "TICKET_REQUEST"
	case FramePadding:
		return "PADDING"
	case FrameClose:
		return "CLOSE"
	}
	return "UNKNOWN"
}

// 标志位（spec §2.2）。
const (
	FlagPad  uint8 = 1 << 0
	FlagEnd  uint8 = 1 << 1
	FlagPush uint8 = 1 << 2
)

// MaxFrameBody 是 length 字段允许的上限。定成 56 KiB 而不是 varint 的 2^62：
// 一个恶意对端只要声明一个巨大的 length 就能让接收方预分配等量内存，
// 上限是这里唯一的防线。上界还必须让一帧装得进一条 sealed 记录（见 record.go 的
// maxRecordPlain），否则批量阶段会出现"帧合法但永远发不出去"的死角。
const MaxFrameBody = 56 * 1024

// MaxPayload 是单个 STREAM_DATA 的载荷上限。16 KiB 对齐 TLS 记录最大明文长度，
// 让"一帧 = 一条 TLS 记录"在批量阶段成立，避免一帧被拆进两条记录后产生额外的包长特征。
const MaxPayload = 16 * 1024

// Frame 是解码后的帧。Payload 指向读缓冲的切片——调用方若要跨帧持有必须自己拷贝，
// 解帧循环会复用底层数组。
type Frame struct {
	Type     FrameType
	Flags    uint8
	StreamID uint64
	Payload  []byte
}

// AppendFrame 把一帧序列化到 b。pad 为附加的填充字节数（0 表示不填充）。
func AppendFrame(b []byte, t FrameType, flags uint8, streamID uint64, payload []byte, pad int) []byte {
	if pad > 0 {
		flags |= FlagPad
	} else {
		flags &^= FlagPad
	}
	bodyLen := len(payload)
	if pad > 0 {
		bodyLen += pad + 2 // 填充内容 + 尾部 u16 pad_len
	}
	b = append(b, byte(t), flags)
	b = AppendVarint(b, uint64(bodyLen))
	b = AppendVarint(b, streamID)
	b = append(b, payload...)
	if pad > 0 {
		// 填充内容用零而非随机数：它在外层 AEAD 之内，密文与随机数不可区分，
		// 花 CPU 生成随机填充是纯浪费。
		b = appendPadding(b, pad)
	}
	return b
}

// frameOverhead 返回帧头 + 填充记账开销的字节数，供填充调度器把"目标线上总长"
// 换算成"该填多少"。bodyLen 需为含填充的最终 body 长度。
func frameOverhead(streamID uint64, bodyLen int) int {
	return 2 + VarintLen(uint64(bodyLen)) + VarintLen(streamID)
}

// readFrameExact 用 io.ReadFull **精确**读出一帧，一个多余的字节都不消费。
//
// 握手阶段必须用它而不是 frameReader：sealed 模式在 ACCEPT 之后立刻切到记录层，
// 而带缓冲的读法可能已经把记录层的头几个字节吸进自己的缓冲里，切换后就永远错位。
// 这类 bug 只在服务端"回完 ACCEPT 马上又发东西"时才出现，握手多跑几次都未必撞上。
func readFrameExact(r io.Reader) (Frame, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	return readFrameRest(r, hdr, MaxFrameBody)
}

// readFrameRest 在 type/flags 已被读走之后读完余下部分。
//
// 拆出这一步是为了让服务端能在**只读到 2 个字节**时就判定"这不是 TIDE"，
// 立刻转给掩护源站。等读完整帧再判，探测方发一个 HTTP 请求过来会挂到读超时，
// 而真实站点毫秒级就回——那个时间差就是 §6 反复警告的、唯一真正难伪造的东西。
// maxBody 让调用方按帧类型收紧上界，进一步提前判定。
func readFrameRest(r io.Reader, hdr [2]byte, maxBody uint64) (Frame, error) {
	var f Frame
	f.Type = FrameType(hdr[0])
	f.Flags = hdr[1]

	readVar := func() (uint64, error) {
		var first [1]byte
		if _, err := io.ReadFull(r, first[:]); err != nil {
			return 0, err
		}
		size := varintSizeHint(first[0])
		buf := make([]byte, size)
		buf[0] = first[0]
		if size > 1 {
			if _, err := io.ReadFull(r, buf[1:]); err != nil {
				return 0, err
			}
		}
		v, _ := ReadVarint(buf)
		return v, nil
	}
	bodyLen, err := readVar()
	if err != nil {
		return f, err
	}
	if bodyLen > maxBody {
		return f, ErrFrameTooLarge
	}
	if f.StreamID, err = readVar(); err != nil {
		return f, err
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return f, err
	}
	if f.Flags&FlagPad != 0 {
		p, err := splitPadding(body)
		if err != nil {
			return f, err
		}
		f.Payload = p
	} else {
		f.Payload = body
	}
	return f, nil
}

// writeFrameExact 直接把一帧写到 w（握手用，不经攒批与填充调度）。
func writeFrameExact(w io.Writer, t FrameType, flags uint8, streamID uint64, payload []byte, pad int) error {
	buf := AppendFrame(nil, t, flags, streamID, payload, pad)
	_, err := w.Write(buf)
	return err
}

// frameReader 从底层 io.Reader 增量解帧。它自己管缓冲，因为帧头长度可变，
// 必须"先读 1 字节确定 length 的宽度，再读够 length"——bufio 给不了这个粒度。
type frameReader struct {
	r   io.Reader
	buf []byte
	off int // 已消费
	end int // 已填充
}

func newFrameReader(r io.Reader) *frameReader {
	return &frameReader{r: r, buf: make([]byte, 0, 32*1024)}
}

func (fr *frameReader) fill(need int) error {
	for fr.end-fr.off < need {
		if fr.off > 0 && fr.end-fr.off < cap(fr.buf)/2 {
			copy(fr.buf[:cap(fr.buf)], fr.buf[fr.off:fr.end])
			fr.end -= fr.off
			fr.off = 0
		}
		if need > cap(fr.buf) {
			nb := make([]byte, need+need/2)
			copy(nb, fr.buf[fr.off:fr.end])
			fr.end -= fr.off
			fr.off = 0
			fr.buf = nb
		}
		fr.buf = fr.buf[:cap(fr.buf)]
		n, err := fr.r.Read(fr.buf[fr.end:])
		fr.end += n
		if err != nil {
			if fr.end-fr.off >= need {
				break
			}
			if errors.Is(err, io.EOF) && fr.end == fr.off {
				return io.EOF
			}
			return err
		}
	}
	return nil
}

// ReadFrame 解出下一帧。返回的 Frame.Payload 在下一次 ReadFrame 前有效。
func (fr *frameReader) ReadFrame() (Frame, error) {
	var f Frame
	if err := fr.fill(3); err != nil {
		return f, err
	}
	f.Type = FrameType(fr.buf[fr.off])
	f.Flags = fr.buf[fr.off+1]

	lenSize := varintSizeHint(fr.buf[fr.off+2])
	if err := fr.fill(2 + lenSize + 1); err != nil {
		return f, err
	}
	bodyLen, _ := ReadVarint(fr.buf[fr.off+2 : fr.off+2+lenSize])
	if bodyLen > MaxFrameBody {
		return f, ErrFrameTooLarge
	}
	sidSize := varintSizeHint(fr.buf[fr.off+2+lenSize])
	hdr := 2 + lenSize + sidSize
	if err := fr.fill(hdr + int(bodyLen)); err != nil {
		if errors.Is(err, io.EOF) {
			return f, io.ErrUnexpectedEOF
		}
		return f, err
	}
	f.StreamID, _ = ReadVarint(fr.buf[fr.off+2+lenSize : fr.off+hdr])
	body := fr.buf[fr.off+hdr : fr.off+hdr+int(bodyLen)]
	fr.off += hdr + int(bodyLen)

	if f.Flags&FlagPad != 0 {
		payload, err := splitPadding(body)
		if err != nil {
			return f, err
		}
		f.Payload = payload
	} else {
		f.Payload = body
	}
	return f, nil
}

// splitPadding 从 body 中剥掉填充。
//
// 线格式上 payload 与 padding 是连着的，接收方不知道 payload 到哪结束——
// 除非 pad_len 出现在一个能被独立定位的地方。draft-01 把它固定放在 body 的**最后**
// 一个字节起的定长 u16（大端），即 body = payload || pad_bytes || u16(pad_len)。
// 这样接收方只看最后 2 字节就能切开，不需要解方程或线性扫描。
//
// 代价是每个带填充的帧多 2 字节；收益是解帧路径没有任何歧义。批量阶段不填充，
// 所以这 2 字节不进入吞吐关键路径。
func splitPadding(body []byte) ([]byte, error) {
	if len(body) < 2 {
		return nil, ErrProtocol
	}
	padLen := int(binary.BigEndian.Uint16(body[len(body)-2:]))
	if padLen > len(body)-2 {
		return nil, ErrProtocol
	}
	return body[:len(body)-2-padLen], nil
}

// appendPadding 与 splitPadding 对称。
func appendPadding(b []byte, pad int) []byte {
	for i := 0; i < pad; i++ {
		b = append(b, 0)
	}
	return binary.BigEndian.AppendUint16(b, uint16(pad))
}

// peekReader 留一份**最开头**若干字节的副本。
//
// 排查"帧解析失败"时，光有错误类型（长度超限 / 协议违规）没用——那只说明
// 字节流对不齐，说不出对不齐成什么样。把开头几十字节原样拿出来，
// 一眼就能认出它是别的协议的帧头、是半个帧、还是纯粹的垃圾。
type peekReader struct {
	r    io.Reader
	head []byte
	max  int
}

func newPeekReader(r io.Reader, max int) *peekReader {
	return &peekReader{r: r, max: max}
}

func (p *peekReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 && len(p.head) < p.max {
		room := p.max - len(p.head)
		if room > n {
			room = n
		}
		p.head = append(p.head, b[:room]...)
	}
	return n, err
}

func (p *peekReader) Head() []byte { return p.head }
