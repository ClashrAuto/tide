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
echo "== 起回声上游 =="
"$tmp/tide-selftest" -mode raw-server -listen 127.0.0.1:19000 >"$tmp/echo.log" 2>&1 &
pids+=($!)

wait_port() {
  for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then exec 3<&- 3>&-; return 0; fi
    sleep 0.2
  done
  echo "端口 $1 一直没起来"; return 1
}
wait_port 19000

run_case() {
  local label="$1" srv_extra="$2" cli_extra="$3" want_paths="$4"
  echo "== $label =="
  rm -rf "$tmp/data"; mkdir -p "$tmp/data"
  # shellcheck disable=SC2086
  "$tmp/tide-server" $srv_extra \
    -listen 127.0.0.1:18443 -quic-listen 127.0.0.1:18443 \
    -cover 127.0.0.1:19000 -users alice:smoke-pw \
    -key-file "$tmp/data/k" -cert "$tmp/data/c" -cert-key "$tmp/data/ck" \
    >"$tmp/srv.log" 2>&1 &
  local srv=$!
  pids+=("$srv")
  wait_port 18443

  # 公钥只能从服务端自己打印的横幅里拿——这一步顺带验证了那段横幅还是对的。
  local pub
  pub=$(grep -m1 'public-key:' "$tmp/srv.log" | sed 's/.*public-key: //')
  if [ -z "$pub" ]; then echo "没能从服务端横幅里取到 public-key"; cat "$tmp/srv.log"; return 1; fi

  # shellcheck disable=SC2086
  if ! "$tmp/tide-selftest" -mode client \
      -server 127.0.0.1:18443 -key "$pub" -password smoke-pw \
      -target 127.0.0.1:19000 -duration 4s -streams 2 -rate 262144 $cli_extra \
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
