package tide

import "errors"

// QUIC 变长整数编码（RFC 9000 §16）。首字节高 2 位给出总长度 1/2/4/8 字节，
// 因此可编码范围是 [0, 2^62)。选它而不是 protobuf 那种 7-bit-per-byte 的原因是
// 长度自描述在**首字节**就能确定——解帧循环拿到 1 个字节就知道还要等几个，
// 不需要"边读边判断有没有续位"的状态机。

const MaxVarint = uint64(1)<<62 - 1

var errVarintTooLarge = errors.New("tide: varint out of range (>= 2^62)")

// VarintLen 返回 v 编码后的字节数。v 超范围时返回 0。
func VarintLen(v uint64) int {
	switch {
	case v <= 63:
		return 1
	case v <= 16383:
		return 2
	case v <= 1073741823:
		return 4
	case v <= MaxVarint:
		return 8
	}
	return 0
}

// AppendVarint 把 v 追加到 b。超范围时 panic——这是编码器内部约束，
// 所有调用点的取值都在协议定义的范围内，运行期出现只可能是逻辑错误。
func AppendVarint(b []byte, v uint64) []byte {
	switch VarintLen(v) {
	case 1:
		return append(b, byte(v))
	case 2:
		return append(b, byte(v>>8)|0x40, byte(v))
	case 4:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	case 8:
		return append(b, byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	panic(errVarintTooLarge)
}

// ReadVarint 从 b 头部解出一个 varint，返回值与消耗的字节数。
// 字节不足时返回 n=0——调用方据此判断"还要继续收"，而不是报错。
func ReadVarint(b []byte) (v uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	size := 1 << (b[0] >> 6) // 00→1, 01→2, 10→4, 11→8
	if len(b) < size {
		return 0, 0
	}
	v = uint64(b[0] & 0x3f)
	for i := 1; i < size; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, size
}

// varintSizeHint 只看首字节就给出总长度，供解帧循环决定还要读多少。
func varintSizeHint(first byte) int { return 1 << (first >> 6) }
