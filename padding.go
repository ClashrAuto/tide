package tide

import (
	crand "crypto/rand"
	"encoding/binary"
	"math/rand/v2"
	"sync"
)

// 前重后轻的填充预算（design.md 机制 6a）。
//
// 关键观察：流量分类器的判决发生在连接的前几百个包，之后再填充对分类结果的影响急剧衰减。
// 所以把 30% 的开销全部花在前 64 KiB——10 MB 下载摊下来是 0.2%，
// 而交互流量本来就一直待在这个阶段，正好是它需要保护的地方。

const (
	phase1Bytes  = 64 * 1024
	phase1Frames = 100
	phase2Bytes  = 256 * 1024
)

// PaddingPhase 供日志与自检观察当前处于哪一阶段。
type PaddingPhase uint8

const (
	PhaseDecision PaddingPhase = iota // 判决窗口：每帧填到采样目标长度
	PhaseDecay                        // 衰减：填充概率线性降到 0
	PhaseBulk                         // 批量：不填充
)

func (p PaddingPhase) String() string {
	switch p {
	case PhaseDecision:
		return "decision"
	case PhaseDecay:
		return "decay"
	}
	return "bulk"
}

// httpsLengthCDF 是"真实 HTTPS 浏览"的 TLS 记录长度分布的分段拟合。
//
// ★ spec draft-00 §10 未定项 2（填充分布的数据来源）在这里定稿：
// 分布**不做在线拟合**，而是一张编译期常量表，随协议版本走。理由有两条——
//
//  1. 在线拟合需要采样本机真实流量，那是个隐私问题，也让不同用户的填充行为可区分；
//     一张所有实现共用的静态表反而让所有 TIDE 客户端在这一维上**互相不可区分**。
//  2. 分布只需要"像"，不需要"准"。分类器要的是把 TIDE 从 HTTPS 里分出来，
//     只要落在 HTTPS 的支撑集内且大致同形，多几个百分点的 KL 散度不改变结论。
//
// 表的形状来自公开的 HTTPS 记录长度经验分布三个主要模态：
// 小记录（请求头、ACK 类交互，~100–600B）、中记录（HTML/JSON 响应片段，~1.2–1.5KB
// 即一个 MTU）、大记录（图片/脚本主体，接近 TLS 记录上限 16KB）。
// 更新这张表必须同时更新 paddingProfileVersion，否则新旧客户端在同一时期呈现两种
// 分布，反而制造了一个可分的特征。
const paddingProfileVersion = 1

var httpsLengthCDF = [...]struct {
	cum      float64 // 累积概率
	lo, hi   uint32  // 该桶的长度区间（含）
	quantize uint32  // 桶内取值对齐到这个粒度，模拟真实实现的记录切分
}{
	{0.10, 64, 180, 4},        // TLS 心跳/小控制帧
	{0.34, 180, 620, 8},       // 请求头、小 JSON
	{0.46, 620, 1180, 16},     // 中等响应片段
	{0.78, 1180, 1460, 4},     // 一个 MTU——HTTPS 里最密集的模态
	{0.88, 1460, 4096, 64},    // 多段聚合
	{0.96, 4096, 11000, 256},  // 大响应主体
	{1.00, 11000, 16384, 512}, // 接近 TLS 记录上限
}

// paddingScheduler 是**每路径**一个的。
//
// 之所以不是每会话一个：分类器观察的是一条 TCP/QUIC 连接。会话迁移到新路径后，
// 新路径在观察者眼里就是一条全新的连接，必须重新走一遍判决窗口——
// 如果沿用会话级的计数器，迁移后的新连接会直接以"批量、零填充"开场，
// 那是一个极其显眼的特征（正常 HTTPS 连接不会一上来就发满 MTU 的定长包）。
// 网络波动越频繁、迁移越多，这一点越重要。
type paddingScheduler struct {
	mu     sync.Mutex
	bytes  uint64
	frames uint64
	rng    *rand.Rand
}

func newPaddingScheduler() *paddingScheduler {
	var seed [16]byte
	// 用密码学随机源播种：填充量本身若可预测，就从"抗分类手段"变成了"指纹"。
	if _, err := crand.Read(seed[:]); err != nil {
		// crypto/rand 失败在 Go 里是不可恢复的系统故障，退回一个仍然不可预测性更弱
		// 但可用的源，好过让整条连接失败。
		return &paddingScheduler{rng: rand.New(rand.NewPCG(1, 2))}
	}
	return &paddingScheduler{rng: rand.New(rand.NewPCG(
		binary.LittleEndian.Uint64(seed[:8]),
		binary.LittleEndian.Uint64(seed[8:]),
	))}
}

func (p *paddingScheduler) phase() PaddingPhase {
	switch {
	case p.bytes < phase1Bytes && p.frames < phase1Frames:
		return PhaseDecision
	case p.bytes < phase1Bytes+phase2Bytes:
		return PhaseDecay
	}
	return PhaseBulk
}

// Phase 返回当前阶段（自检/日志用）。
func (p *paddingScheduler) Phase() PaddingPhase {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.phase()
}

// padFor 给出一个 body 长度为 bodyLen、流号为 streamID 的帧应附加多少填充字节。
// wireLen 是不含填充时该帧在线上的总长。
func (p *paddingScheduler) padFor(streamID uint64, bodyLen int) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	wireLen := frameOverhead(streamID, bodyLen) + bodyLen
	pad := 0
	switch p.phase() {
	case PhaseDecision:
		target := p.sampleTarget()
		// 只能往上填，填不到就算了——截断载荷去凑目标长度会引入分片，
		// 而分片本身又是一个特征，得不偿失。
		if int(target) > wireLen+2 {
			pad = int(target) - wireLen - 2 // 2 = 尾部 u16 pad_len
		}
	case PhaseDecay:
		// 概率自 1.0 线性衰减至 0。
		done := float64(p.bytes-phase1Bytes) / float64(phase2Bytes)
		if p.rng.Float64() > done {
			target := p.sampleTarget()
			if int(target) > wireLen+2 {
				pad = int(target) - wireLen - 2
			}
		}
	case PhaseBulk:
		pad = 0
	}
	if pad > MaxFrameBody-bodyLen-2 {
		pad = MaxFrameBody - bodyLen - 2
	}
	if pad < 0 {
		pad = 0
	}
	p.bytes += uint64(wireLen + pad)
	p.frames++
	return pad
}

func (p *paddingScheduler) sampleTarget() uint32 {
	u := p.rng.Float64()
	for _, b := range httpsLengthCDF {
		if u <= b.cum {
			span := b.hi - b.lo
			if span == 0 {
				return b.lo
			}
			v := b.lo + uint32(p.rng.IntN(int(span)))
			if b.quantize > 1 {
				v -= v % b.quantize
				if v < b.lo {
					v = b.lo
				}
			}
			return v
		}
	}
	return httpsLengthCDF[len(httpsLengthCDF)-1].hi
}

// maybeHeartbeat 决定判决窗口内**这一刻**要不要插一个纯 PADDING 帧。
//
// 只填充"有数据要发的帧"是不够的：交互流量的**静默间隔**本身就是特征
// （请求-等待-响应的节奏在包到达时间上一览无余）。判决窗口内以低概率插入独立填充帧，
// 把这段静默填成看起来像浏览器在后台拉资源。批量阶段不做——那时链路已经饱和，
// 插心跳只会挤占带宽。
//
// ⚠️ 这个函数写完之后有很长一段时间**没有任何地方调用它**：填充的长度那一半上线了，
// 时序这一半没有。调用方见 path.heartbeatLoop。
//
// 只返回"要不要发"，长度交给 padFor 从同一张分布表里采——两处各采一次会让
// 心跳帧的长度分布和数据帧不一致，那本身又是一个可分的特征。
func (p *paddingScheduler) maybeHeartbeat() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.phase() != PhaseDecision {
		return false
	}
	return p.rng.Float64() <= 0.35
}

// handshakePad 给握手帧（HELLO / ZERO_RTT / ACCEPT）算一个填充量。
//
// ★ 这三个帧原先一律 pad=0，于是每条 TIDE 连接的**第一条应用记录**长度是个常量：
// 它完全由协议结构决定（HELLO = 1 + kem_share + client_random + 2 + sealed，全定长），
// 与用户、时间、内容都无关。DPI 只要问一句"TLS 握手之后的第一条应用记录是不是恰好
// N 字节"，就把 TIDE 挑出来了——比周期性心跳还好用，因为它一条连接只需要看一个包。
//
// §8.3 的判决窗口救不了这一条：那套填充是**握手之后**才开始的，
// 而握手帧走的是 writeFrameExact，压根不过填充调度器。
//
// 后量子（§3.1 的临时 ML-KEM 封装密钥）把这个常量顶到了 2.4 KB 以上，
// 落在 HTTPS 记录长度分布的稀疏尾部，比原先更显眼——但它本来就不该是常量。
//
// 做法：在 [当前长度, 当前长度 + handshakePadSpan) 里均匀取一个目标长度。
//
// ⚠️ 这里**没有**沿用 §8.3 那张 HTTPS 分布表，是权衡过的：握手帧已经 2.4 KB，
// 分布里能装下它的只剩三个尾部桶，按质量采样出来的均值是 6.6 KB——
// 也就是每次握手平均多花 4.2 KB，而且 18% 的握手会发一条 11–16 KB 的记录，
// 那本身比 2.5 KB 更不像正常流量。要消掉的是"**恒等于**某个值"这件事，
// 不是把它挪到分布的另一个稀疏角落。均匀展宽 4 KiB 就够：
// 常量没了，开销有上界，长度仍落在 1460–11000 这两个真实存在的桶里。
//
// 用 crypto/rand 而不是调度器那个 PCG：握手一条路径只发生一次，不在热路径上，
// 而填充量若可预测，这层伪装就等于没有。
const handshakePadSpan = 4096

func handshakePad(bodyLen int) int {
	// 上界：服务端对握手帧的 body 有独立的收紧上限（maxHandshakeBody），
	// 填过头会被自己人按"声称长度超限"拒掉。
	maxBody := maxHandshakeBody - 64
	if bodyLen+2 >= maxBody {
		return 0
	}
	pad := cryptoIntn(handshakePadSpan)
	if bodyLen+pad+2 > maxBody {
		pad = maxBody - bodyLen - 2
	}
	if pad < 0 {
		return 0
	}
	return pad
}

func cryptoIntn(n int) int {
	if n <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		// crypto/rand 失败是系统级故障。返回 0 会让长度退回常量，
		// 所以宁可给一个固定的非零值，也别悄悄把伪装关掉。
		return n / 2
	}
	return int(binary.BigEndian.Uint64(b[:]) % uint64(n))
}
