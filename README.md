# TIDE

**T**ransport-**I**ndependent **D**ata **E**nvelope —— Coast 自研的代理协议。

> **状态：draft-01，有可用实现，规范未冻结。**
> 三期机制全部落地并在实网（树莓派 5 ↔ x86，`netem` 制造损伤）上验过。
> 仍不建议第三方据此实现服务端——线格式可能随实测继续调整。

## 为什么是 TIDE 这个名字

配置里它长这样：`type: tide`。选它的理由按重要性排：

1. **不撞车**。全仓库（含 `clash/` 子模块的全部 40 个协议实现）搜索 `tide` 零命中；现有生态里也没有同名协议。相比之下 `surge` 直接出局——那是 Snell 作者的客户端。
2. **语义贴合设计**。潮汐会**改变方向**，而这个协议的核心机制之一就是路径调度器按线路质量在 TCP/QUIC 之间迁移。名字描述的是它实际干的事，不是随便挑的海洋词。
3. **符合品牌**。产品叫 Coast，协议叫 Tide。
4. **工程上好用**。4 个字母，全小写无歧义，作为 YAML 标量、Go 包名、日志前缀都不需要转义或缩写。

落选的候选：`STRAIT`（海峡，"狭窄通道"语义其实最准，但 6 个字母且与 straight 同音易混）、`RIPTIDE`（离岸流，是 TIDE 的加长版，没有额外收益）、`UNDERTOW`（暗流，语义好但太长）、`SURGE`（与现有产品冲突，直接排除）。

## 为什么单独放在仓库根目录，而不是塞进 `clash/`

`clash/` 是 MetaCubeX/mihomo 的 fork，按 `CLAUDE.md` 的约定**上游变更只能靠 merge 拿，不能手工搬运**。往里面直接加一个完整的新协议（握手、帧、多路径调度、填充策略）会在 `adapter/`、`transport/`、`listener/` 三处同时留下大片自有代码，每次 merge 上游都要在这些文件上处理冲突。

所以 TIDE 做成**独立的 Go module**（`github.com/ClashrAuto/tide`），`clash/` 那边只留最薄的一层适配：一个 outbound、一个 listener、一处 registry 注册。上游合并面从"三个目录的大片改动"缩到"三个新文件"。

## 目录结构

```
tide/
├── README.md
├── go.mod                  # 独立 module，供 clash fork 引用
├── docs/
│   ├── design.md           # 设计动机与取舍论证（先读这个）
│   └── spec.md             # 线格式规范（规范性文本，draft-01）
├── cmd/tide-selftest/      # 自检 + 实网波动压测工具
├── varint.go frame.go record.go        # 线格式
├── crypto.go handshake.go ticket.go    # 混合后量子握手 + 单次票据
├── session.go stream.go path.go        # 会话层：复用、可靠性、调度
├── client.go server.go transport_quic.go
├── padding.go addr.go datagram.go diag.go
└── tide_test.go
```

## 阅读顺序

先读 [`docs/design.md`](docs/design.md)——它解释了「低延迟 / 高吞吐 / 高安全」这三个目标彼此冲突在哪，以及每个机制是为了化解哪一组冲突。脱离这个上下文看 [`docs/spec.md`](docs/spec.md) 的线格式，会觉得很多字段是多余的。

## 一键部署（Docker Compose）

```bash
git clone https://github.com/ClashrAuto/tide.git && cd tide
cp .env.example .env      # 至少把 TIDE_PASSWORD 改掉
docker compose up -d
docker compose logs tide  # 这里会打印客户端该贴的完整配置（含 public-key）
```

编排里有**两个**服务，第二个不是凑数的：

- `tide` —— 服务端，TCP 与 QUIC 共用 8443（QUIC 是加速通道，丢包链路上 p90 从 197ms
  降到 9ms；UDP 被封时客户端静默回落 TCP）。
- `cover` —— 掩护源站（nginx）。认证失败时 TIDE 把连接的**全部字节原样转发**给它，
  而不是模拟一个响应。时序是伪装里唯一真正难伪造的东西：失败路径 0.1ms 而真实站点
  50ms，探测方量一下响应时间分布就分开了（spec §7）。所以它必须真实可达、延迟合理，
  放在同一个 compose 网络里正合适。把它换成你自己的站点会更像样。

几件必须知道的事：

- **`/data` 一定要是持久卷。** 静态密钥在里面，删了就等于换了 `public-key`，
  所有客户端配置一起作废。
- **默认用自动生成的自签证书。** 能跑，但**削弱伪装**——真实网站都有受信任的证书。
  正式部署把真证书挂到 `/data/tls.crt` 与 `/data/tls.key`，并把客户端的
  `skip-cert-verify` 删掉。
- **QUIC 想吃满带宽要调宿主的 UDP 缓冲**（`net.core.rmem_max` 不是命名空间隔离的，
  在 compose 里写 `sysctls` 无效）：

  ```bash
  printf 'net.core.rmem_max=7500000\nnet.core.wmem_max=7500000\n' > /etc/sysctl.d/99-tide.conf && sysctl --system
  ```

- `proxy.golang.org` 连不上的网络里，`.env` 里把 `GOPROXY` 换成 `https://goproxy.cn,direct`。

## 不用 Docker 跑

```bash
# 进程内跑完整链路（握手 → 0-RTT 复用 → 失败关闭 → 路径迁移 → UDP），exit 0 = 通过
go run ./cmd/tide-selftest -mode local

# 生成一对静态密钥
go run ./cmd/tide-server -keygen

# 服务端（真代理）
go run ./cmd/tide-server -listen :8443 -quic-listen :8443 \
    -cover 127.0.0.1:8080 -users alice:<password> -advertise example.com

# 压测客户端（输出往返时延的尾部分位 + 每条路径的收发字节）
go run ./cmd/tide-selftest -mode client -server host:8443 -key <public> \
    -duration 60s -quic
```

⚠️ `tide-selftest -mode server` 把每条流**回声**回去，那是压测夹具，**不是代理**。
要部署的是 `tide-server`。

`-cover` 必须指向一个**真实可达、延迟合理**的源站。认证失败时这条连接的全部字节会被
原样转发过去——这不是可选项，见 spec §7。

## 落地状态

| 期 | 内容 | 状态 |
|---|---|---|
| 一 | 前重后轻填充、裸帧模式协商 | 已实现。kTLS + `splice()` **做不到**且已从待办移除——多路复用协议拿不到零拷贝转发，理由见 spec §12.3 |
| 二 | 单次票据 0-RTT、信道绑定、混合后量子 | 已实现并实测 |
| 三 | 多路径调度（TCP ↔ QUIC） | 已实现。**每条流一条独立 QUIC 流**，路径内队头阻塞已消除（spec §12.5）；UDP 走 RFC 9221 数据报（§12.8） |

spec §12 的八个条目里七个已定稿，唯一残留的是 §12.6 的一半：QUIC 端口现在
"什么也给不出"（强制只能加入已有会话），但还没有伪装成别的东西——那需要
完整的 HTTP/3 掩护，做半套比不做更糟。

## 实测（详见 spec §11.2）

树莓派 5 ↔ x86，`netem` 只损伤目的端口 8443（TCP/UDP 同时）：

- **持续 5% 丢包**：单 TCP 路径 p99 = 619ms；TCP+QUIC 按评分调度 p99 = **194ms**、p90 从 197ms 降到 **9ms**。
- **完全断网**：5s / 20s / 60s 三档，恢复开销分别为 **11ms / 225ms / 274ms**，各只重连一次，**零字节丢失、零乱序**。
- 断网超过宽限期则**干净失败**（`session grace period expired`），不挂死。

三个反直觉、且都是**实测把设计推翻**的结论：

- **TCP 路径的丢包率从应用层看恒为 0**（spec §8.1）。探测走在 TCP 里，丢的段由内核
  重传，所以永远测不到丢包——draft-00 那条"丢包率超 2% 就迁移"按字面实现从不触发。
- **单 QUIC 流复用比裸 TCP 还差**（spec §12.5）。对照组是 4 条独立连接、一条丢包只卡
  自己；单流复用把 4 条流全塞进一条，一个丢包卡住四条。分流后 p90 从 8.6ms 降到 1.67ms。
- **BBR 把尾部搞差了 5 倍**（spec §12.7）。design.md 写的是 BBRv3，而 Linux 内核里的
  `bbr` 是 v1，它对随机丢包的处理正是弱点。默认已改回"不动系统默认"。

共同的教训：**判据必须建立在能观测到的量上，而"更好的算法"必须实测**。

## ⚠️ 在推广前必须先回答的问题

**没有任何机场会提供 TIDE 节点。** 这个协议只对自建服务端的用户有意义。如果 Coast 的用户主要用订阅节点，它的实际使用率会接近零。这一条不因为代码写完了就消失——它决定的是要不要在 UI 里给它一等公民的位置。

另一条同等重要的：**一个设计更好的新协议，在头两年里的实际安全性大概率低于一个设计一般但被审烂了的老协议。** Trojan 有十年公开审计，TIDE 只有一个实现、零第三方审计。上面那些实测数字全是**性能与可用性**的，不是安全性的——不要把它们当成安全性的证据，也不要在文档或 UI 里把 TIDE 宣传成"比 Trojan 更安全"。
