# TIDE 线格式规范

> **draft-01 · 有实现、未冻结**
>
> 本文是规范性文本，只描述"是什么"。每个字段"为什么存在"见 [`design.md`](design.md)，
> 建议先读完那篇——脱离取舍论证看本文，会觉得很多字段是多余的。
>
> draft-00 是纯设计稿。draft-01 是**照着实现和实测改回来**的版本：三处线格式变化、
> 五个未决项全部定稿、以及一条被实测证伪的调度判据（§8）。变更清单见 §11。

本文中 **MUST / MUST NOT / SHOULD / MAY** 按 RFC 2119 解释。

---

## 1. 术语与约定

| 术语 | 含义 |
|---|---|
| 外层信道 | 承载 TIDE 的加密通道：TLS 1.3（TCP 路径）或 QUIC-TLS（QUIC 路径） |
| 会话 (Session) | 由 Session ID 标识的逻辑连接，**独立于任何一条路径存在** |
| 路径 (Path) | 承载会话的一条具体传输连接 |
| 流 (Stream) | 会话内的一条应用层字节流，对应一个被代理的 TCP 连接 |

- 所有整数为**大端序**。
- `varint` 采用 QUIC 变长整数编码（RFC 9000 §16）：首字节高 2 位给出总长度 1/2/4/8 字节。
- 版本字节 `0x01`。
- **握手消息**的 AEAD 恒为 ChaCha20-Poly1305（理由见 §3.0）。
- **记录层**的 AEAD 由 `ACCEPT.mode` 敲定：ChaCha20-Poly1305 或 AES-256-GCM。

---

## 2. 帧格式

所有 TIDE 通信（握手之后）由帧构成，帧位于外层信道内部。

```
 type(u8) | flags(u8) | length(varint) | stream_id(varint) | payload… | padding…
```

`length` 覆盖 `payload + padding` 的总长。

### 2.1 填充的定位

`PAD` 标志置位时，body 的**最后 2 字节**是大端 `u16 pad_len`，其前 `pad_len` 字节为填充：

```
body = payload || pad_bytes[pad_len] || u16(pad_len)
```

> draft-00 把 `pad_len` 写在填充区开头。那样接收方无法定位 payload 的结束位置——
> 它得先知道填充有多长才能找到 `pad_len`，而 `pad_len` 正是要找的东西。
> 放在末尾则只看最后 2 字节就能切开，没有任何歧义。代价是每个带填充的帧多 1 字节
> （相对 varint 的常见情形），而批量阶段根本不填充，不进吞吐关键路径。

填充内容 MUST 为零字节。它位于外层 AEAD 之内，密文与随机数不可区分，
生成随机填充是纯粹的 CPU 浪费。

### 2.2 帧类型

| type | 名称 | 方向 | 说明 |
|---:|---|---|---|
| 0x01 | `HELLO` | C→S | 首次握手，见 §3.1 |
| 0x02 | `ACCEPT` | S→C | 握手响应 + 首批票据，见 §3.2 |
| 0x03 | `ZERO_RTT` | C→S | 0-RTT 握手，见 §3.3 |
| 0x10 | `STREAM_OPEN` | 双向 | 新建流，见 §4.1 |
| 0x11 | `STREAM_DATA` | 双向 | 流数据，**带绝对偏移**，见 §4.2 |
| 0x12 | `STREAM_FIN` | 双向 | 单向关闭，payload 为 varint 最终偏移 |
| 0x13 | `STREAM_RST` | 双向 | 异常关闭，payload 为 u32 错误码 |
| 0x14 | `STREAM_ACK` | 双向 | 累积确认 + 流控通告，见 §4.3 |
| 0x20 | `DATAGRAM` | 双向 | UDP 数据报，见 §5 |
| 0x30 | `PATH_PROBE` | 双向 | 路径质量探测，payload = `u64 seq \|\| u64 sender_nanos` |
| 0x31 | `PATH_ACK` | 双向 | 原样回显 `PATH_PROBE` 的 16 字节 |
| 0x32 | `PATH_MIGRATE` | 双向 | 声明该流已迁至本路径，payload = varint 当前确认偏移 |
| 0x40 | `TICKET_REPLENISH` | S→C | 增量补充单次票据 |
| 0x41 | `TICKET_REQUEST` | C→S | 票据见底，请求补充 |
| 0x50 | `PADDING` | 双向 | 纯填充帧，接收方 MUST 丢弃 |
| 0x5F | `CLOSE` | 双向 | 关闭会话 |

未知 type 的帧接收方 MUST 忽略并跳过（依 `length`），以便后续版本扩展。

`PATH_ACK` **原样回显**探测帧的时间戳，因此两端不需要时钟同步——
发起方只用自己的两次读数做差。

### 2.3 标志位

| bit | 名称 | 含义 |
|---:|---|---|
| 0 | `PAD` | body 尾部有填充，见 §2.1 |
| 1 | `END` | 本帧为该流的最后一帧（等价于紧跟 `STREAM_FIN`） |
| 2 | `PUSH` | 提示立即冲刷，不要等待聚合 |
| 3–7 | — | 保留，发送方 MUST 置 0，接收方 MUST 忽略 |

### 2.4 上限

- 单帧 body MUST ≤ 56 KiB。接收方 MUST 在 `length` 超限时立即失败关闭——
  没有这个上限，对端只要声明一个巨大的 `length` 就能让接收方预分配等量内存。
- `sealed` 记录的明文 MUST ≤ 60 KiB（§6.1）。帧 MAY 跨记录边界。

---

## 3. 握手

### 3.0 握手消息的 AEAD

握手消息（`HELLO.sealed_auth`、`ZERO_RTT.sealed`、`ACCEPT`）的封装 MUST 使用
**ChaCha20-Poly1305**，与两端有无硬件 AES 无关。

> 接收方在解开这条消息之前无从知道对方用了什么算法——`flags` 就在密文里。
> 依次尝试两种算法会让"认证成功"与"认证失败"产生可测量的时间差，
> 而这正是 §7 反复要求消除的东西。记录层（批量数据）才是 AES 值得快那 2–3 倍的地方，
> 由服务端在 `ACCEPT.mode` 里一锤定音。

### 3.1 `HELLO`（首次连接，1-RTT）

在外层 TLS 握手完成后，作为**第一个应用数据记录**发送。

```
HELLO {
    version       : u8 = 0x01
    kem_share     : X25519_pub(32) || MLKEM768_ct(1088)      // 1120 字节
    client_random : 32 bytes
    sealed_len    : u16
    sealed_auth   : AEAD(k_hs, auth_plain, ad = transcript)  // nonce = 全零
    early_data    : opt bytes
}

auth_plain {                       // 77 字节
    user_id    : 16 bytes
    timestamp  : u64               // Unix 秒
    cb_hash    : 32 bytes          // 见 §5
    flags      : u8                // bit0 请求 bare；bit1 本机有 AES-NI；bit2 加入已有会话
    session_id : 16 bytes          // 全零 = 新建会话；否则请求加入该会话（§9）
    path_id    : u32               // 本路径在会话内的编号
}

transcript = SHA256( version || kem_share || client_random )
k_hs       = HKDF( ikm  = X25519_shared || MLKEM_shared,
                   salt = client_random,
                   info = "tide/draft-01 handshake" || transcript )
```

`X25519_shared` 由客户端临时私钥与**服务端静态 X25519 公钥**协商；
`MLKEM_shared` 由客户端向**服务端静态 ML-KEM-768 封装公钥**封装得到。
两者一并作为 ikm，任一方被攻破都不足以恢复会话密钥。

服务端 MUST 校验 `timestamp` 在 ±120 秒容差内，且 `cb_hash` 与本连接实际的
TLS Exporter 相等。任一校验失败 → 走 §7 的失败关闭流程。

### 3.2 `ACCEPT`

```
ACCEPT_plain {
    session_id  : 16 bytes
    mode        : u8            // bit0 bare；bit1 记录层用 AES-256-GCM
    path_id     : u32           // 服务端最终采用的路径编号
    ticket_base : u64
    ticket_count: u16           // 默认 1024
    ticket_seed : 32 bytes
    server_data : opt bytes
}

ACCEPT.payload = AEAD(k_hs, ACCEPT_plain, ad = transcript)   // nonce = 0…01

ticket_key[i] = HKDF-Expand(ticket_seed, "tide/draft-01 ticket" || u64(id), 32)
```

只下发一个 32 字节种子而非 1024 把密钥，是为了让 `ACCEPT` 保持小帧——
整批密钥两端各自派生即可。

`ACCEPT` 的 nonce MUST 与 `HELLO` 的全零 nonce 区分（本规范取 `0…01`）：
同一把 `k_hs` 下重复使用同一个 nonce 会直接泄露明文异或并允许伪造 tag。

服务端 MUST NOT 通告 `bare`，除非外层信道提供 AEAD 且 §5 的信道绑定校验已通过。

### 3.3 `ZERO_RTT`（后续连接，0-RTT）

```
ZERO_RTT {
    version    : u8 = 0x01
    ticket_id  : u64
    nonce      : 12 bytes
    sealed_len : u16
    sealed     : AEAD(ticket_key, zero_seal || early_data,
                      ad = version || ticket_id || nonce)
}

zero_seal {                        // 77 字节
    cb_hash    : 32 bytes
    timestamp  : u64
    user_id    : 16 bytes
    session_id : 16 bytes
    flags      : u8
    path_id    : u32
}

k_hs = HKDF( ikm = ticket_key, salt = cb_hash, info = "tide/draft-01 0rtt" )
```

服务端处理流程（顺序 MUST 严格保持）：

1. 按 `ticket_id` 查**未消费票据位图**。
2. 若已消费或超出范围 → **静默丢弃，转入 §7 失败关闭流程**。
   MUST NOT 返回任何区别于掩护站点的响应。
3. 置位（标记消费）。此步 MUST 在解密 `sealed` **之前**完成，
   且对同一 `ticket_id` 的并发请求 MUST 原子化，否则重放保护失效。
4. 解密，校验 `cb_hash`、`timestamp`、`user_id` 与票据归属一致。

票据 MUST 在签发后 24 小时过期，即使未被消费。

> **鸡生蛋**：第 1 步要查位图就得先知道用户，而 `user_id` 在待解密的密文里。
> 本规范的解法是要求票据编号在**全局单调**空间内分配，于是 `ticket_id` 本身
> 唯一确定所属批次（连带用户）。集群实现要么复制这个性质（全局单调发号），
> 要么把 `user_id` 明文放进 `ZERO_RTT`——后者泄露用户标识，MUST NOT。

> **多节点部署警告**：位图是**服务端硬状态**。若同一用户可能落在不同节点上，
> 位图必须共享，否则重放保护在节点间失效——攻击者只需把重放流量投给另一个节点。
> 这是本协议唯一显著增加运维负担的地方。见 §12.1。

---

## 4. 流

### 4.1 `STREAM_OPEN`

```
payload {
    kind        : u8        // 0 = TCP 流；1 = UDP 关联
    recv_window : varint    // 本端初始接收窗口
    addr        : SOCKS5 地址格式（ATYP + ADDR + PORT）
}
```

接收方 MUST 幂等处理重复的 `STREAM_OPEN`（相同 `stream_id` 视为同一条流）——
重连后发送方会补发它，见 §9。

流号 MUST 奇偶分家：客户端用奇数、服务端用偶数。两端因此可以同时开流而无需协商。

接收方 SHOULD 在建流后立刻回一个 `STREAM_ACK` 通告真实窗口。
在收到它之前，发送方 MUST NOT 发送超过 64 KiB。

### 4.2 `STREAM_DATA`

```
payload { offset : varint,  data : bytes }
```

`offset` 是该流发送方向上的**绝对字节偏移**，从 0 开始。

> ★ 这是 draft-01 相对 draft-00 最重要的一处改动，也是"路径死掉而连接不断"的全部机理。
>
> 底层 TCP/QUIC 已经是可靠的，但"可靠"是**每条路径**的属性，而会话要活得比路径长。
> 路径断掉的那一刻，已被内核 ACK、但尚未抵达对端**应用层**的字节全部消失，
> 且本端无从知道丢了哪些——TCP 的 ACK 只保证到达内核，不保证到达对端应用。
> 没有会话级的绝对偏移，一次 Wi-Fi 切换就会让每条流中间凭空少掉一段，
> 表现为"网页加载到一半卡住"或"下载文件校验和不对"，**且不会有任何报错**。
>
> 有了绝对偏移，重发就是幂等的：接收方丢弃 `offset + len ≤ recv_offset` 的重复段，
> 缓存 `offset > recv_offset` 的乱序段，于是发送方可以无脑地从最后确认点整段重来。

接收方：
- `offset + len ≤ recv_offset` → MUST 丢弃（迁移后的正常重复）。
- `offset > recv_offset` → MAY 缓存至乱序缓冲；缓冲量超过接收窗口时 MUST 丢弃，
  由发送方重传。缓冲无上界是内存炸弹，而重传的代价有界。
- 否则取尾部有用段，推进 `recv_offset`，并尝试排空乱序缓冲。

### 4.3 `STREAM_ACK`

```
payload { ack_offset : varint,  max_offset : varint }
```

- `ack_offset`：已**连续**收到的偏移（累积确认）。累积语义使 ACK 丢失可自愈——
  下一个 ACK 覆盖前一个，不需要重传 ACK。
- `max_offset`：允许对端发送到的上界 = `ack_offset + 剩余缓冲`。
  应用读得慢会自然把窗口压小，反压一路传回发送端。

发送方 MUST NOT 使 `send_offset` 超过 `max_offset`，
且 MUST 将未确认字节 `[ack_offset, send_offset)` 保留在重传缓冲中，上限即流窗口。

接收方 SHOULD 在累积 32 KiB 或收到 `STREAM_FIN` 时发送 `STREAM_ACK`。

### 4.4 重传超时（RTO）

发送方 MUST 维护一个兜底重传定时器：若某条流存在未确认字节、且超过一个 RTO
（SHOULD 取 `clamp(2×min(path SRTT) + 200ms, 500ms, 4s)`）没有任何确认进展，
则 MUST 把待发指针回退到 `ack_offset` 并重发。

> 路径健康检查看的是**路径**，而丢帧可以在路径完全健康时发生——比如 `STREAM_OPEN`
> 恰好落在路径断掉的那一刻，或对端因流表满而丢弃了帧。没有 RTO，这类情况表现为
> 一条永远卡住的连接，且两端都认为自己没问题。这是弱网下最难查的一类故障。

---

## 5. 信道绑定

```
cb_hash = TLS-Exporter( label   = "tide-channel-binding",
                        context = empty,
                        length  = 32 )
```

QUIC 路径使用 QUIC-TLS 的等价导出器。若某传输**无法**提供导出器，
实现 MUST 在该传输上失败关闭，MUST NOT 跳过信道绑定继续——
悄悄跳过一个安全属性，没人会发现它已经没了。

客户端 MUST 将 `cb_hash` 纳入 `sealed_auth`（§3.1）或 `sealed`（§3.3）的被认证数据；
服务端 MUST 独立计算并比对。不匹配 → 失败关闭，MUST NOT 降级重试。

此机制使任何终止并重建外层 TLS 的中间实体（企业 MITM CA、CDN 回源、透明代理）
都无法完成握手，同时是启用 `bare` 模式的前提。

---

## 6. 记录层与模式

### 6.1 `sealed`

```
record = u16 ct_len || AEAD(k_path, frames…, ad = u16 ct_len)
nonce  = 4 个零字节 || u64 大端序号（每路径独立自增）
```

AD 绑定长度前缀：否则攻击者可以改前缀把一条记录切成两条，AEAD 本身察觉不到。

明文按**批**封装（一批可含多个帧），而非每帧一封。交互阶段一批就是一帧、没有损失；
批量阶段一批装满 MTU，16 字节 tag 摊到 16 KiB 上是 0.1%。

密钥按方向再按路径分叉：

```
secret   = HKDF( k_hs, salt = session_id, info = "tide/draft-01 session" )
k_c2s    = HKDF-Expand(secret, "tide/draft-01 c2s", 32)
k_s2c    = HKDF-Expand(secret, "tide/draft-01 s2c", 32)
k_path   = HKDF-Expand(k_dir, "tide/draft-01 path" || u32(path_id), 32)
```

> ★ 按路径分叉是多路径正确性的硬要求，不是洁癖。AEAD 的 nonce 就是序号，
> 而两条路径各自独立发送，序号必然会撞。共用一把密钥就会出现 (key, nonce) 复用——
> 对 ChaCha20-Poly1305 和 GCM 都是灾难性的。分叉之后序号只需在路径内唯一，
> 迁移时也不必同步任何计数器。

### 6.2 `bare`

内层不加密，帧直接落在外层 TLS/QUIC 记录里。安全性完全由外层承担，
前提是 §5 的信道绑定已**密码学地**证明外层未被中间人替换。

`bare` 模式 MUST 关闭填充：要插填充就得在用户态碰载荷，而 `bare` 的全部意义
就是让用户态不碰载荷（从而 kTLS/`splice()` 可用）。

---

## 7. 失败关闭

任何认证失败（`sealed_auth` 校验失败、`cb_hash` 不匹配、票据已消费、时间戳超窗、
版本不支持）时，服务端：

1. MUST NOT 返回任何 TIDE 帧或错误指示。
2. MUST 将该连接**已接收和后续全部字节**原样代理至掩护源站，直至任一端关闭连接。
3. MUST NOT 对该路径做特殊的超时、限速或日志分支处理。

> **关键**：不能"模拟"掩护站点的响应，必须**真的转发**。若认证失败路径耗时 0.1ms
> 而真实站点路径耗时 50ms，探测方只需测量响应时间分布即可区分两者。
> **时序是这里唯一真正难伪造的东西。** 掩护源站 MUST 真实可达且延迟合理（同机房或本机）。

### 7.1 判定必须**尽早**

服务端 MUST 在能够判定"这不是 TIDE"的**最早时刻**转入失败关闭，具体地：

- 读到 `type` 字节后，若不属于 `{HELLO, ZERO_RTT}` → 立即失败关闭。
- 读到 `length` 后，若超出该类型的合理范围 → 立即失败关闭。
- 握手帧的读取超时 SHOULD ≤ 5 秒。合法客户端在外层握手完成后立刻发出整个握手帧，
  一个 RTT 都不等。

> 这一节是实现时补的，因为最初的实现"读完整帧再判"直接把伪装作废了：
> 探测方发一个 HTTP 请求过来，`GET /…` 被当成一个声称长度 5152 字节的帧，
> 服务端一直等到读超时（15 秒）才转发，而真实站点毫秒级就回。
> 只看 2 个字节就能否掉绝大多数探测——HTTP 以 `G`/`P`/`H` 开头，
> TLS-in-TLS 以 `0x16` 开头，端口扫描往往一个字节都不发。

### 7.2 掩护源站不可达

若掩护源站连不上，服务端 MUST 保持连接并读到对端放弃，MUST NOT 立即关闭——
立即关闭是一个可测量的、与真实站点截然不同的行为。

---

## 8. 多路径与调度

- 会话可同时绑定多条路径。每条路径独立完成 §3 握手，并在 `auth_plain.session_id`
  中携带已有会话号以加入现有会话。
- 调度器 SHOULD 默认自 TCP 路径起步，后台建立 QUIC 路径。
- QUIC 路径探测失败（UDP 被封锁）时，MUST 静默全量回落 TCP，不得向用户暴露错误。
- 单条流的帧 SHOULD 保持路径亲和，以避免跨路径乱序开销。
- 拥塞控制每路径独立。MUST NOT 默认启用无上界的激进拥塞控制。

### 8.1 迁移判据 —— 用相对评分，**不要**用丢包率

调度器 SHOULD 周期性（约 2 秒）比较各路径评分，把流迁到最好的那条。
判据 SHOULD 为：

```
score = SRTT_ms + 2 × RTTVAR_ms + loss × 2000
迁移条件：best.score × 2 < current.score，且连续 2 次观测都成立
```

> ★ **draft-00 §8 那条"TCP 路径丢包率持续超过 2% 时迁移"是错的，按字面实现永远不会触发。**
>
> `PATH_PROBE` 走在 TCP 连接内部，丢掉的段由内核重传，探测最终**总会**到达，
> 只是变慢。所以应用层测到的 TCP 丢包率恒为 0——丢包在 TCP 上不表现为丢包，
> 表现为 RTT 膨胀与队头阻塞。
>
> 实测（树莓派 5 ↔ x86，netem 5% 丢包，见 §11.2）：同一时刻 TCP 路径报
> `loss=0.00% / srtt=44.69ms`，并存的 QUIC 路径 `srtt=1.26ms`。
> 按丢包率写的判据一次都没触发，QUIC 路径建起来了却只拿到 0.1 MiB，
> 而 TCP 扛了 52.2 MiB。改成按评分迁移后，p90 从 187ms 降到 9ms。
>
> 两个门槛都是必需的：**2 倍**保证只有显著差距才值得付迁移的代价（未确认字节要重发、
> 两条路径的拥塞窗口都要重新长起来）；**连续 2 次**保证不被一次抖动骗到。
> 没有滞回的实现会在阈值附近每秒来回迁移几十次，比不迁移还糟。

### 8.2 路径健康状态机

| 状态 | 含义 | 进入条件 |
|---|---|---|
| `active` | 正常 | 连续 3 次探测成功且丢包估计 ≤ 2% |
| `degraded` | 仍可用，但该让出批量流 | 丢包估计 > 2% |
| `suspect` | 新流不再选它 | 连续丢失 2 个探测 |
| `dead` | 流全部撤离 | 连续丢失 4 个探测，**或**静默超过 8 秒 |

- 探测超时 SHOULD 取 `max(3×SRTT + 4×RTTVAR, 2s)`。下界是为了不误杀高延迟线路——
  卫星/跨洲链路 RTT 600ms 是正常的，用固定 2 秒判丢会让它一直处于"丢包 100%"的假象里。
- **静默计时器是独立于探测的第二个死亡判据，MUST 实现。** 探测的往返依赖对端还在响应；
  若对端进程活着但会话状态已丢（如服务端重启），探测可能仍被回复，而流数据永远不来。
  静默计时器不看语义，只看物理层面有没有字节，是更硬的证据。
- 已判 `dead` 的路径 MUST NOT 复活：会话侧的流已经撤离，复活会造成两条路径同时认领同一批流。

### 8.3 每路径独立的填充调度

填充阶段计数器 MUST 是**每路径**的，不是每会话的。

> 分类器观察的是一条 TCP/QUIC 连接。会话迁移到新路径后，新路径在观察者眼里
> 就是一条全新的连接，必须重新走一遍判决窗口。沿用会话级计数器会让迁移后的
> 新连接直接以"批量、零填充"开场——正常 HTTPS 连接不会一上来就发满 MTU 的定长包，
> 那是个极其显眼的特征。网络波动越频繁、迁移越多，这一点越重要。

---

## 9. 会话存活与重连

- 会话在**一条路径都没有**的情况下 MUST 继续存在至少 `SessionGrace`（默认 120 秒）。
  服务端在此期间 MUST 保留流状态、未确认字节与上游连接。
- 客户端在失去全部路径后 SHOULD 以指数退避 + 抖动重拨，并携带原 `session_id` 加入。
  退避 SHOULD 上限 5 秒；抖动是必需的——波动往往是整片网络的，
  几十个客户端同时重连会把刚恢复的链路再打垮一次。
- 新路径接入后，发送方 MUST 对每条流：
  1. 若 `STREAM_OPEN` 尚未被对端确认（未收到该流的任何帧），先补发 `STREAM_OPEN`；
  2. 将待发指针回退到 `ack_offset`，重发未确认段；
  3. 若已发过 `STREAM_FIN`，补发之。
- 服务端若不认识客户端声称的 `session_id`（宽限期已过或服务端重启），
  MUST 当作新会话建立并在 `ACCEPT` 中返回新的 `session_id`，
  MUST NOT 失败关闭——这不是攻击，是正常超时。客户端据此放弃旧会话。
- 宽限期耗尽后，会话 MUST 干净地失败（向上层报错），MUST NOT 无限挂起。

### 9.1 UDP 不重传

`DATAGRAM` MUST NOT 进入重传缓冲。UDP 本就不可靠，给它加可靠性会改变上层协议
（QUIC、DNS、游戏）自己的拥塞与超时行为，通常比丢包更糟。
路径切换期间丢掉的数据报就是丢了——这与在真实网络上丢包没有区别。

---

## 10. UDP

```
DATAGRAM payload {
    addr : SOCKS5 地址格式（ATYP + ADDR + PORT）
    data : bytes
}
```

`stream_id` 即关联标识，由 `STREAM_OPEN(kind=1)` 建立。

身份信息挂在**会话**上，而非每个数据报上。因此不存在 SOCKS5 UDP 中继那个已知问题——
那里的中继是共享 socket、数据报不携带认证，客户端不得不在 ASSOCIATE 请求中申报
真实来源地址来让服务端做 `addr → user` 归属（参见仓库根 `CLAUDE.md` 关于 Windows 侧
SOCKS UDP 的说明）。那条链路上任何一环申报错了都不会报错，只是 `IN-USER` 规则对 UDP
静默失配。TIDE 中该问题在架构上不存在：归属是结构决定的，不需要申报。

---

## 11. 变更记录与实测

### 11.1 draft-00 → draft-01

| 变化 | 原因 |
|---|---|
| `STREAM_DATA` 增加绝对 `offset` | 路径死亡时内核已 ACK、应用未收的字节会静默丢失（§4.2） |
| 新增 `STREAM_ACK`(0x14) | 累积确认 + 流控；没有它就不知道从哪重发 |
| 新增 `TICKET_REQUEST`(0x41) | 票据补充的客户端触发 |
| 填充长度移到 body 末尾 u16 | 放在开头无法被接收方定位（§2.1） |
| `auth_plain` 增加 `session_id`/`path_id` | 重连加入已有会话；路径密钥分叉 |
| 握手 AEAD 固定 ChaCha20-Poly1305 | 试两种算法会产生可测的时间差（§3.0） |
| `ACCEPT.mode` 增加 AES 位 | 记录层算法必须两端一致，只有服务端同时知道两边能力 |
| `ACCEPT` nonce 改为 `0…01` | 与 `HELLO` 的全零 nonce 区分，避免同密钥 nonce 复用 |
| §7.1 尽早判定 | 读完整帧再判会把伪装作废（实现时发现） |
| §8.1 迁移判据改为相对评分 | 原判据依赖的丢包率在 TCP 上恒为 0（实测证伪） |

### 11.2 实测数据

树莓派 5（arm64，客户端）↔ x86 Ubuntu（服务端），千兆 LAN，
`netem` 只作用于目的端口 8443（TCP 与 UDP 同时受损），4 条并发流，25–60 秒。

**持续 5% 丢包下的往返时延分布：**

| 配置 | p50 | p90 | p99 | p99.9 |
|---|---|---|---|---|
| 无损伤基线（单 TCP） | 0.71ms | 0.95ms | 1.52ms | 3.92ms |
| 单 TCP 路径 | 1.11ms | 197ms | 619ms | 760ms |
| 双 TCP 路径（冗余） | 1.05ms | 120ms | 323ms | 455ms |
| TCP + QUIC，按丢包率迁移 | 1.26ms | 187ms | 537ms | 641ms |
| **TCP + QUIC，按评分迁移** | **1.04ms** | **9.0ms** | **194ms** | **237ms** |

最后一行的路径分配：QUIC 32.2 MiB / TCP 18.2 MiB。倒数第二行是 0.1 MiB / 52.2 MiB——
判据不对时，路径建起来了也没用。

**完全断网的恢复开销**（`max RTT − 断网时长`，即链路恢复到首个数据块完成往返）：

| 断网时长 | 恢复开销 | 重连次数 | 数据完整性 |
|---|---|---|---|
| 5 秒 | 11ms | 1 | 零丢失 |
| 20 秒 | 225ms | 1 | 零丢失 |
| 60 秒 | 274ms | 1 | 零丢失 |
| 25 秒（宽限期设为 10 秒） | — | — | 干净失败：`session grace period expired` |

---

## 12. 未定项（draft-02 前待决）

draft-00 的五个未决项均已在本版定稿：票据位图多节点同步见 §12.1、
填充分布数据来源见 §12.2、kTLS 回退见 §12.3、票据耗尽降级见 §12.4、
迁移期乱序边界见 §4.2。以下是**本版新增**的待决项。

### 12.1 已定稿：票据位图的多节点同步

单机用内存位图。集群 MUST 提供一个满足以下契约的实现：

- `ConsumeAny(ticket_id) → (seed, user, ok)` 必须**原子**，同一 id 并发只能有一个 `ok=true`；
- 票据编号必须在集群内**全局单调**分配（见 §3.3 的鸡生蛋说明）。

参考实现路线：Redis `SETBIT` + Lua 保证原子性，或按 `user_id` 一致性哈希把同一用户
钉在同一节点（后者不需要共享状态，但会牺牲负载均衡的自由度）。

### 12.2 已定稿：填充分布的数据来源

分布**不做在线拟合**，而是一张编译期常量表，随协议版本走（当前 `profile_version = 1`）。
两条理由：① 在线拟合要采样本机真实流量，是隐私问题，也让不同用户的填充行为可区分；
一张所有实现共用的静态表反而让所有 TIDE 客户端在这一维上**互相不可区分**。
② 分布只需要"像"，不需要"准"——只要落在 HTTPS 的支撑集内且大致同形，
多几个百分点的 KL 散度不改变分类器的结论。

更新该表 MUST 同时递增 `profile_version`，否则新旧客户端在同一时期呈现两种分布，
反而制造了一个可分的特征。

### 12.3 已定稿：kTLS 可用性与回退

kTLS 是纯优化，与 `bare` 的**协商**解耦：`bare` 由 §5 信道绑定决定，
kTLS 由运行时探测决定（Linux 上尝试 `setsockopt(TCP_ULP, "tls")`）。
探测失败即回退到用户态拷贝，不影响协议正确性，不需要任何线上信令。

### 12.4 已定稿：票据耗尽的降级

**退回 1-RTT，MUST NOT 阻塞等待补充。**
弱网下补充帧本身就可能丢；耗尽时若选择阻塞，一次补充帧丢失就会让所有新连接卡死到超时，
而 1-RTT 只是多花一个 RTT。用可预测的一点延迟换掉一个不可预测的挂死，这个交换永远划算。

客户端 SHOULD 在剩余量跌破 25% 时发 `TICKET_REQUEST`。

### 12.5 待决：QUIC 路径的流映射

当前实现把一条 QUIC 路径映射为**一条** QUIC 流，因此路径内部仍有队头阻塞
（同一条 QUIC 流上的丢包照样挡住其后的字节）。把每条 TIDE 流映射到独立的 QUIC 流
可以彻底消除它，但多条 QUIC 流之间没有全局顺序，`sealed` 记录层的按路径序号会立刻失效。
要走那条路必须在 QUIC 路径上强制 `bare` 模式。收益（§11.2 的 p99 还能降多少）
需要先测再决定。

### 12.6 待决：QUIC 路径的主动探测防御

当前实现**不对 QUIC 路径做掩护转发**：QUIC 的掩护对象只能是另一个 QUIC/HTTP-3 服务，
字节流也不能直接搬过去（QUIC 有自己的流语义）。因此 QUIC 路径的定位是
**已建立会话的加速通道**，不是首次接入的门面；伪装完全依赖 TCP 那条路径。
这个定位是否够用，取决于"只开 UDP 而不开 TCP 的部署"是否存在——目前认为不存在，
但没有验证过。

### 12.7 待决：拥塞控制

规范要求"每路径独立、不得默认激进"，但没有指定算法。当前实现直接继承内核 TCP
与 quic-go 的默认（Cubic），design.md 里写的 BBRv3 尚未接入。
