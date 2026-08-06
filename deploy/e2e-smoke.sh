#!/bin/bash
# 端到端冒烟：用**真的两个入口程序**跑一次真的代理往返。
#
# ★ 为什么单元测试不够用。第 17–19 轮连着三个问题，全部躲过了整套单元测试与 -mode local，
# 因为它们都不在库里，而在"两个二进制怎么配合"这一层：
#
#   · tide-selftest 没有 -password，而 tide-server 要求至少一个用户
#     → README 里那条客户端命令握手直接失败，谁照抄谁踩；
#   · 压测客户端的目标地址硬写成 echo.invalid:80（RFC 2606 保留的不可解析域名），
#     对着真代理跑每条流都被 RST；
#   · cmd/ 两个目录因为 .gitignore 缺前导斜杠**从未被提交**，
#     克隆下来的仓库里根本没有入口程序。
#
# 这三件事的共同点：库的测试全绿，`-mode local` 也全绿，因为它们都在同一个进程里
# 用同一份内存中的 Server/Client 对象，从不经过命令行、配置解析、两个进程的握手。
# 这个脚本补的就是那一层。
#
# ⚠️ 速率故意压得很低（32 KiB/s、单流）。这是**冒烟**，要证明的是"这条路通"，
# 不是量吞吐——CI 的 runner 是两核共享机，把吞吐指标塞进门禁只会换来偶发的红，
# 而一个偶发红的门禁比没有门禁更糟：它会训练所有人无视它。
# 真要量吞吐用 `tide-selftest -mode client` 单独跑。
set -euo pipefail

cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
  rm -rf "$tmp"
}
trap cleanup EXIT

echo "== 编译两个入口程序 =="
go build -o "$tmp/tide-server" ./cmd/tide-server
go build -o "$tmp/tide-selftest" ./cmd/tide-selftest

# 回声上游：既当被代理的目标，也当掩护源站（失败关闭只是把字节对拷过去，回声足够）。
wait_port() {
  for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then exec 3<&- 3>&-; return 0; fi
    sleep 0.2
  done
  echo "端口 $1 一直没起来"; return 1
}

# ★ 端口随机挑，不要写死，而且**必须挑在内核临时端口区间之外**。
#
# 写死的话，任何一次残留进程（上一次跑挂了、或者同机上并发跑一次）都会让后续每次
# 都以 "bind: address already in use" 失败，而那条错误躲在服务端日志里，
# 脚本表面上只是"取不到 public-key"——排查方向完全被带偏。
#
# 但"随机挑一个当前连不上的端口"还不够。第一版从 20000–40000 里挑，撞上了
# Linux 的 ip_local_port_range（典型 32768–60999）：整套测试跑起来会发出上百个
# 出向连接，内核就从这个区间里给它们分配源端口。于是流程是
#   ① 脚本探测 39852，没人 listen，判定空闲
#   ② 内核把 39852 分给某条出向连接的源端口
#   ③ tide-server bind(39852) → address already in use
# 三步之间毫秒级，探测再准也没用——这不是"检查得不够仔细"，
# 是**跟内核抢同一个池子**。它当然是概率性的：第一轮全绿，第二轮才炸。
#
# 官方给的两个解法（bind 端口 0 让内核选、IP_BIND_ADDRESS_NO_PORT）都要求
# 绑端口的那个进程自己来做，而这里端口是脚本挑好交给子进程的，用不上。
# 那就换个方向：**别去那个池子里挑**。区间从 /proc 读，不要硬编码——
# 这个值是可调的，硬编码等于把同一个 bug 埋深一层。
EPHEMERAL_LO=32768
if [ -r /proc/sys/net/ipv4/ip_local_port_range ]; then
  read -r EPHEMERAL_LO _ < /proc/sys/net/ipv4/ip_local_port_range
fi
PORT_LO=10000
PORT_HI=$((EPHEMERAL_LO - 1000))
[ "$PORT_HI" -le "$PORT_LO" ] && PORT_HI=$((PORT_LO + 1000))

pick_port() {
  for _ in $(seq 1 200); do
    local p=$((PORT_LO + RANDOM % (PORT_HI - PORT_LO)))
    # 连得上 = 有人在 listen = 不能用。连不上才是空闲。
    # 参数 $1 是"已经挑走的端口"，必须排除：两个服务撞同一个端口时，
    # 后起的那个才报 bind 失败，而它的失败同样只会表现成"取不到 public-key"。
    [ "$p" = "${1:-}" ] && continue
    if ! (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then echo "$p"; return 0; fi
  done
  echo "找不到空闲端口" >&2; return 1
}
ECHO_PORT=$(pick_port)
TIDE_PORT=$(pick_port "$ECHO_PORT")

"$tmp/tide-selftest" -mode raw-server -listen "127.0.0.1:$ECHO_PORT" >"$tmp/echo.log" 2>&1 &
pids+=($!)
wait_port "$ECHO_PORT"

run_case() {
  local label="$1" srv_extra="$2" cli_extra="$3" want_paths="$4"
  echo "== $label =="

  local srv="" pub=""
  # 挑在临时端口区间之外已经把主要的抢占源去掉了，但"两个并发跑的实例撞上同一个
  # 随机端口"仍然可能。那是**重试一次就好**的事，不该让整条门禁变红——
  # 一个偶发红的门禁比没有门禁更糟，它会训练所有人无视它。
  local attempt
  for attempt in 1 2 3; do
    rm -rf "$tmp/data"; mkdir -p "$tmp/data"
    : >"$tmp/srv.log"
    # shellcheck disable=SC2086
    "$tmp/tide-server" $srv_extra \
      -listen 127.0.0.1:$TIDE_PORT -quic-listen 127.0.0.1:$TIDE_PORT \
      -cover 127.0.0.1:$ECHO_PORT -users alice:smoke-pw \
      -key-file "$tmp/data/k" -cert "$tmp/data/c" -cert-key "$tmp/data/ck" \
      >"$tmp/srv.log" 2>&1 &
    srv=$!
    pids+=("$srv")

    # ★ 等的是**横幅**，不是端口。
    # 端口在 net.Listen 那一刻就可连了，而公钥要等 printBanner 才写出来——
    # 按端口判就绪是个竞态，机器一忙就抓到空的 public-key，
    # 表现是脚本毫无征兆地退出（`pub=` 之后直接 return 1）。
    # 这个脚本要的就绪信号本来就是"横幅出来了"，那就直接等它。
    pub=""
    local i
    for i in $(seq 1 100); do
      # ⚠️ 末尾的 `|| true` 不能省：横幅还没写出来时 grep 返回 1，
      # 而 set -o pipefail 让整条管道也返回 1，赋值语句于是"失败"，set -e 当场退出——
      # 表现是脚本在这里毫无输出地结束，看起来像卡住而不是出错。
      # 同理别写成 `[ -n "$pub" ] && break`：pub 为空时它返回 1，
      # 作为循环体最后一条命令同样会被 set -e 干掉。
      pub=$(grep -m1 'public-key:' "$tmp/srv.log" 2>/dev/null | sed 's/.*public-key: //' || true)
      if [ -n "$pub" ]; then break; fi
      # 端口被抢了就别再等满 20 秒——立刻换一个重来。
      if grep -q 'address already in use' "$tmp/srv.log" 2>/dev/null; then break; fi
      sleep 0.2
    done
    if [ -n "$pub" ]; then break; fi
    kill "$srv" 2>/dev/null || true
    if grep -q 'address already in use' "$tmp/srv.log" 2>/dev/null; then
      local old=$TIDE_PORT
      TIDE_PORT=$(pick_port "$ECHO_PORT")
      echo "  端口 $old 被抢了，换 $TIDE_PORT 重试（第 $attempt 次）"
      continue
    fi
    echo "服务端横幅里一直没出现 public-key："; cat "$tmp/srv.log"; return 1
  done
  if [ -z "$pub" ]; then echo "连换 3 个端口都没起来："; cat "$tmp/srv.log"; return 1; fi
  wait_port "$TIDE_PORT"

  # shellcheck disable=SC2086
  if ! "$tmp/tide-selftest" -mode client \
      -server 127.0.0.1:$TIDE_PORT -key "$pub" -password smoke-pw \
      -target 127.0.0.1:$ECHO_PORT -duration 4s -streams 1 -rate 32768 $cli_extra \
      >"$tmp/cli.log" 2>&1; then
    echo "客户端失败："; tail -20 "$tmp/cli.log"; return 1
  fi
  grep -E 'blocks=|paths established' "$tmp/cli.log" || true
  # 真的搬过字节才算数：blocks=0 也会 PASS，那等于什么都没测。
  if grep -qE 'blocks=0[^0-9]' "$tmp/cli.log"; then
    echo "一个块都没跑完往返"; return 1
  fi
  # ★ 还要断言**加速通道真的起来了**。这一条是补第一版漏掉的洞：
  # QUIC/h3 配错时客户端会按 §8 的要求**静默回落 TCP**，于是 blocks 照样非零、
  # 客户端照样 PASS——第 17 轮那个"服务端根本没法开 h3"的 bug 就是这么躲过去的。
  # 唯一能分辨"加速通道在工作"和"悄悄退回 TCP"的观测量是路径条数。
  local got
  got=$(grep -oE 'paths established=[0-9]+' "$tmp/cli.log" | head -1 | cut -d= -f2)
  if [ "${got:-0}" -lt "$want_paths" ]; then
    echo "只建起 ${got:-0} 条路径，期望 $want_paths —— 加速通道没生效，" \
         "而客户端会静默回落 TCP，所以它自己不会报错"
    return 1
  fi
  kill "$srv" 2>/dev/null || true
  wait "$srv" 2>/dev/null || true
  sleep 0.5
}

run_case "TCP + 原生 QUIC" ""    "-quic"      2
run_case "TCP + HTTP/3"    "-h3" "-quic -h3" 2

echo "== 端到端冒烟通过 =="
