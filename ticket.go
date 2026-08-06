package tide

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// 单次票据（design.md 机制 1）。票据一次性消费 + 位图去重，让 0-RTT 与重放保护同时成立。
//
// 连续编号是这里唯一的实现技巧：1024 张票据只要 128 字节位图 + 一个基址，
// 而不是一张 1024 项的哈希表。位图是**服务端硬状态**，多节点部署必须共享——
// 见 TicketStore 的文档与 spec §3.3 的部署警告。

const (
	DefaultTicketCount = 1024
	TicketLifetime     = 24 * time.Hour
	// ticketLowWater：剩余票据低于这个比例时主动补充。
	// 25% 不是拍脑袋：补充帧要跨一个 RTT 才到，期间客户端可能连开几十条连接；
	// 留 256 张的余量足以覆盖任何合理的突发，同时补充频率仍然很低。
	ticketLowWater = 0.25
)

// TicketStore 是票据消费状态的存储接口。
//
// ★ Consume 必须是**原子的**：同一个 (user, id) 并发到达时只能有一个返回 true。
// 违反这一条，重放保护就完全失效，而且不会有任何报错——攻击者重放的连接会正常建立。
// 这也是 spec §3.3 步骤 3 要求"置位先于解密 early_data"的原因。
//
// 多节点部署：MemTicketStore 只在单机正确。集群必须换成共享实现（Redis 的
// SETBIT + Lua 保证原子性，或按 user_id 一致性哈希把同一用户钉在同一节点）。
// 这是 TIDE 唯一显著增加运维负担的地方。
type TicketStore interface {
	// Issue 为 user 签发一批新票据，返回基址与种子。
	Issue(user [16]byte, count uint16) (base uint64, seed [32]byte, err error)
	// Consume 原子地消费一张票据。返回 (ticketKey 派生用的种子, ok)。
	Consume(user [16]byte, id uint64) (seed [32]byte, ok bool)
	// Remaining 返回该用户当前未消费票据数，供补充决策。
	Remaining(user [16]byte) int
	// Sweep 清理过期批次。
	Sweep(now time.Time)
}

type ticketBatch struct {
	base     uint64
	count    uint16
	seed     [32]byte
	consumed []uint64 // 位图，每 uint64 管 64 张
	left     int
	expires  time.Time
}

func (b *ticketBatch) consume(id uint64) bool {
	if id < b.base || id >= b.base+uint64(b.count) {
		return false
	}
	i := id - b.base
	word, bit := i/64, uint(i%64)
	if b.consumed[word]&(1<<bit) != 0 {
		return false
	}
	b.consumed[word] |= 1 << bit
	b.left--
	return true
}

// MemTicketStore 是单进程实现。
//
// 除了 per-user 的批次链，它还维护一份**按 base 排序的全局批次索引**。
// 这是为了解开 0-RTT 里的一个鸡生蛋：服务端要先查位图才能解密，
// 而用户身份就在待解密的密文里。全局基址单调分配 ⇒ ticket_id 本身唯一确定批次
// ⇒ 可以先按 id 反查到批次（连带用户），再原子消费，最后才解密。
// 集群实现要么复制这个性质（全局单调发号），要么把 user_id 明文放进 ZERO_RTT——
// 后者会泄露用户标识，不可接受。
type MemTicketStore struct {
	mu      sync.Mutex
	users   map[[16]byte][]*ticketBatch
	index   []batchRef // 按 base 升序
	nextID  uint64
	nowFunc func() time.Time
}

type batchRef struct {
	base  uint64
	count uint16
	user  [16]byte
	b     *ticketBatch
}

func NewMemTicketStore() *MemTicketStore {
	return &MemTicketStore{users: make(map[[16]byte][]*ticketBatch), nowFunc: time.Now}
}

// consumeAny 按 ticket_id 反查批次并原子消费，同时返回该票据所属用户。
func (s *MemTicketStore) consumeAny(id uint64) ([32]byte, [16]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := sort.Search(len(s.index), func(i int) bool {
		return s.index[i].base+uint64(s.index[i].count) > id
	})
	if i >= len(s.index) || id < s.index[i].base {
		var z1 [32]byte
		var z2 [16]byte
		return z1, z2, false
	}
	ref := s.index[i]
	if s.now().After(ref.b.expires) || !ref.b.consume(id) {
		var z1 [32]byte
		var z2 [16]byte
		return z1, z2, false
	}
	return ref.b.seed, ref.user, true
}

// ConsumeAny 是 anyConsumer 的导出版本，让外部 store 实现可以照抄这个契约。
func (s *MemTicketStore) ConsumeAny(id uint64) ([32]byte, [16]byte, bool) {
	return s.consumeAny(id)
}

func (s *MemTicketStore) now() time.Time {
	if s.nowFunc != nil {
		return s.nowFunc()
	}
	return time.Now()
}

func (s *MemTicketStore) Issue(user [16]byte, count uint16) (uint64, [32]byte, error) {
	var seed [32]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return 0, seed, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// 基址在全局单调递增的空间里分配，跨批次不会重叠——
	// 否则新批次的 id 会撞上老批次里"已消费"的位，表现为随机的 0-RTT 失败。
	base := s.nextID
	s.nextID += uint64(count) + 1
	b := &ticketBatch{
		base:     base,
		count:    count,
		seed:     seed,
		consumed: make([]uint64, (int(count)+63)/64),
		left:     int(count),
		expires:  s.now().Add(TicketLifetime),
	}
	s.users[user] = append(s.users[user], b)
	// base 单调递增，所以直接追加就保持有序，不需要排序。
	s.index = append(s.index, batchRef{base: base, count: count, user: user, b: b})
	return base, seed, nil
}

func (s *MemTicketStore) Consume(user [16]byte, id uint64) ([32]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for _, b := range s.users[user] {
		if now.After(b.expires) {
			continue
		}
		if b.consume(id) {
			return b.seed, true
		}
	}
	var zero [32]byte
	return zero, false
}

func (s *MemTicketStore) Remaining(user [16]byte) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for _, b := range s.users[user] {
		if !now.After(b.expires) {
			n += b.left
		}
	}
	return n
}

func (s *MemTicketStore) Sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	alive := make(map[*ticketBatch]bool)
	for u, bs := range s.users {
		keep := bs[:0]
		for _, b := range bs {
			if !now.After(b.expires) && b.left > 0 {
				keep = append(keep, b)
				alive[b] = true
			}
		}
		if len(keep) == 0 {
			delete(s.users, u)
		} else {
			s.users[u] = keep
		}
	}
	idx := s.index[:0]
	for _, r := range s.index {
		if alive[r.b] {
			idx = append(idx, r)
		}
	}
	s.index = idx
}

// ---------------------------------------------------------------------------
// 客户端侧票据钱包
// ---------------------------------------------------------------------------

// ticketWallet 是客户端手里那叠票据。
//
// ★ 票据耗尽的降级行为（spec draft-00 §10 未定项 4）在这里定稿为：**退回 1-RTT，
// 绝不阻塞等待补充**。理由是网络波动下补充帧本身就可能丢——如果耗尽时选择阻塞，
// 一次补充帧丢失就会让所有新连接卡死到超时，而 1-RTT 只是多花一个 RTT。
// 用可预测的一点延迟换掉一个不可预测的挂死，这个交换在弱网下永远划算。
type ticketWallet struct {
	mu      sync.Mutex
	batches []*walletBatch
	// taken 累计取出过多少张。remaining() 会被补充批次抬高，光看它分不清
	// "这次握手是不是 0-RTT"——单调递增的计数器才分得清。
	taken atomic.Uint64
}

type walletBatch struct {
	base    uint64
	count   uint16
	seed    [32]byte
	next    uint64 // 下一张未用的 id
	expires time.Time
}

func newTicketWallet() *ticketWallet { return &ticketWallet{} }

func (w *ticketWallet) add(base uint64, count uint16, seed [32]byte, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.batches = append(w.batches, &walletBatch{
		base: base, count: count, seed: seed, next: base,
		expires: now.Add(TicketLifetime),
	})
}

// take 取出一张票据。没有可用票据时返回 ok=false，调用方据此走 1-RTT。
func (w *ticketWallet) take(now time.Time) (id uint64, key []byte, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, b := range w.batches {
		if now.After(b.expires) || b.next >= b.base+uint64(b.count) {
			continue
		}
		id = b.next
		b.next++
		k, err := ticketKey(b.seed[:], id)
		if err != nil {
			return 0, nil, false
		}
		w.taken.Add(1)
		return id, k, true
	}
	return 0, nil, false
}

func (w *ticketWallet) remaining(now time.Time) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, b := range w.batches {
		if now.After(b.expires) {
			continue
		}
		n += int(b.base + uint64(b.count) - b.next)
	}
	return n
}

func (w *ticketWallet) sweep(now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	keep := w.batches[:0]
	for _, b := range w.batches {
		if !now.After(b.expires) && b.next < b.base+uint64(b.count) {
			keep = append(keep, b)
		}
	}
	w.batches = keep
}

// ---------------------------------------------------------------------------
// 帧编解码
// ---------------------------------------------------------------------------

// TICKET_REPLENISH / ACCEPT 里的票据批次描述：base(u64) || count(u16) || seed(32B)。
const ticketGrantLen = 8 + 2 + 32

func appendTicketGrant(b []byte, base uint64, count uint16, seed [32]byte) []byte {
	b = binary.BigEndian.AppendUint64(b, base)
	b = binary.BigEndian.AppendUint16(b, count)
	return append(b, seed[:]...)
}

func parseTicketGrant(b []byte) (base uint64, count uint16, seed [32]byte, ok bool) {
	if len(b) < ticketGrantLen {
		return 0, 0, seed, false
	}
	base = binary.BigEndian.Uint64(b[:8])
	count = binary.BigEndian.Uint16(b[8:10])
	copy(seed[:], b[10:ticketGrantLen])
	return base, count, seed, true
}
