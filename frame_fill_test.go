package tide

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"testing"
	"time"
)

// readFramesWithin 在限时内连读 n 帧（载荷拷出来，Frame.Payload 只活到下一次 ReadFrame）。
// fill 一旦空转就永远不返回，所以必须放进 goroutine 里限时等，否则整个测试一起挂死。
func readFramesWithin(t *testing.T, fr *frameReader, n int, d time.Duration) []Frame {
	t.Helper()
	type result struct {
		frames []Frame
		err    error
	}
	done := make(chan result, 1)
	go func() {
		var out []Frame
		for i := 0; i < n; i++ {
			f, err := fr.ReadFrame()
			if err != nil {
				done <- result{out, err}
				return
			}
			f.Payload = append([]byte(nil), f.Payload...)
			out = append(out, f)
		}
		done <- result{out, nil}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("读到第 %d 帧出错: %v", len(r.frames), r.err)
		}
		return r.frames
	case <-time.After(d):
		t.Fatalf("%v 内没读完 %d 帧：fill 卡住了（off=%d end=%d cap=%d）", d, n, fr.off, fr.end, cap(fr.buf))
		return nil
	}
}

func sealedFrameReader(t *testing.T, plain []byte, recordSizes func(rest int) int) *frameReader {
	t.Helper()
	key := bytes.Repeat([]byte{5}, 32)
	sealer, err := newRecordSealer(key, false)
	if err != nil {
		t.Fatal(err)
	}
	var wire []byte
	for off := 0; off < len(plain); {
		n := recordSizes(len(plain) - off)
		if wire, err = sealer.Seal(wire, plain[off:off+n]); err != nil {
			t.Fatal(err)
		}
		off += n
	}
	op, err := newRecordOpener(bytes.NewReader(wire), key, false)
	if err != nil {
		t.Fatal(err)
	}
	return newFrameReader(op)
}

// 缓冲区读满、剩余已过半、而下一帧又比剩余大时，fill 曾既不挪也不扩容，拿长度为 0 的
// 切片去 Read；recordOpener 手里还有明文时对空切片立刻回 (0, nil)，于是 readLoop
// 永久空转一个核，这条路径也永远走不到 markDead（2026-10-04 真机：CoastTunnel 常驻 400% CPU）。
//
// 一个满载的 STREAM_DATA（MaxPayload + 帧头）恰好比半个缓冲大几个字节，所以生产上就是这个形状：
// 前一帧消费完剩下的字节落进 [cap/2, 满载帧长) 这几个字节宽的窗口。
func TestFrameReaderFullBufferNextFrameLarger(t *testing.T) {
	bufCap := cap(newFrameReader(nil).buf)
	full := AppendFrame(nil, FrameStreamData, 0, 1, bytes.Repeat([]byte{0xbb}, MaxPayload), 0)

	// 第一帧长 la：消费后缓冲里剩 len(full)-1 字节——过半（不挪）、差 1 字节装不下第二帧、
	// 第二帧又不超过容量（不扩容）。
	la := bufCap - (len(full) - 1)
	if rest := bufCap - la; rest < bufCap/2 || rest >= len(full) || len(full) > bufCap {
		t.Fatalf("构造前提不成立: cap=%d la=%d 满载帧=%d", bufCap, la, len(full))
	}
	pa := la
	for pa+frameOverhead(1, pa) != la {
		pa--
	}
	first := AppendFrame(nil, FrameStreamData, 0, 1, bytes.Repeat([]byte{0xaa}, pa), 0)
	plain := append(append(first, full...), full...)

	fr := sealedFrameReader(t, plain, func(rest int) int { return min(rest, maxRecordPlain) })
	got := readFramesWithin(t, fr, 3, 5*time.Second)
	for i, want := range []int{pa, MaxPayload, MaxPayload} {
		if len(got[i].Payload) != want {
			t.Fatalf("第 %d 帧载荷 %d 字节，应为 %d", i, len(got[i].Payload), want)
		}
	}
}

// 帧长随机（含满载与超过半个缓冲的大帧）、记录边界随机且不与帧对齐：
// 不管缓冲停在哪个位置，fill 都必须向前推进。
func TestFrameReaderRandomFrameSizesThroughRecords(t *testing.T) {
	rng := rand.New(rand.NewSource(20261004))
	var plain []byte
	var want [][]byte
	for i := 0; i < 3000; i++ {
		var size, pad int
		switch rng.Intn(4) {
		case 0:
			size = rng.Intn(64)
		case 1:
			size = MaxPayload - rng.Intn(64) // 满载附近：生产上触发的就是这一档
		case 2:
			size = rng.Intn(MaxPayload + 1)
		default:
			size = rng.Intn(MaxFrameBody - 300)
			pad = rng.Intn(256)
		}
		p := make([]byte, size)
		rng.Read(p)
		want = append(want, p)
		plain = AppendFrame(plain, FrameStreamData, 0, uint64(i), p, pad)
	}
	fr := sealedFrameReader(t, plain, func(rest int) int { return min(rest, 1+rng.Intn(maxRecordPlain)) })
	got := readFramesWithin(t, fr, len(want), 20*time.Second)
	for i := range want {
		if got[i].StreamID != uint64(i) || !bytes.Equal(got[i].Payload, want[i]) {
			t.Fatalf("第 %d 帧不对: sid=%d 载荷 %d 字节（应为 %d）", i, got[i].StreamID, len(got[i].Payload), len(want[i]))
		}
	}
}

type emptyReader struct{}

func (emptyReader) Read([]byte) (int, error) { return 0, nil }

// 下层一直回 (0, nil) 时要像 bufio 一样报 io.ErrNoProgress 让路径判死，
// 而不是空转一个核、把整个会话攥在栈上永不释放。
func TestFrameReaderNoProgressFails(t *testing.T) {
	fr := newFrameReader(emptyReader{})
	done := make(chan error, 1)
	go func() {
		_, err := fr.ReadFrame()
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrNoProgress) {
			t.Fatalf("应报 io.ErrNoProgress，得到 %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("下层不给数据也不报错时 fill 空转不返回")
	}
}
