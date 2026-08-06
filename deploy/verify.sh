#!/bin/bash
# 一条命令跑完整套验证——而且是对**仓库里的代码**跑，不是对工作区跑。
#
#   bash deploy/verify.sh          # 验证暂存区（= 这次提交会包含的内容）
#   bash deploy/verify.sh --head   # 验证 HEAD（= 别人克隆下来会拿到的内容）
#   bash deploy/verify.sh --here   # 就地验证当前目录（CI 里用这个：检出本身就是提交态）
#
# ★ 为什么要专门导出一份再验，而不是直接在工作区里跑：
#
# 工作区里能跑通，不代表仓库里的代码能跑通。这个项目上栽过两次，都很贵：
#
#   1. go.sum 缺条目——本地因为某次 `-mod=mod` 就地补过而一直能编，
#      而干净克隆 `go build ./...` 直接失败。
#   2. cmd/ 下两个入口程序因为 .gitignore 缺前导斜杠**从未被提交**。
#      `git status` 干净、本地编得过跑得通，我甚至在那个不完整的仓库上
#      跑通了实网代理和 docker compose——但克隆下来的人拿到的是一个
#      没有任何入口程序的库。这件事瞒了十八轮。
#
# 两次的共同点：**被验证的东西和被发布的东西不是同一份**。
# 所以这个脚本默认先 `git archive` 出一份干净的树，再在那上面跑。
set -euo pipefail

cd "$(dirname "$0")/.."
mode="${1:---index}"

# 编排文件里设的每一个 TIDE_* 变量，服务端必须真的读它。
#
# ★ 这一条防的是本项目反复出现的那类错误：**写了但没接上**。
# 编排里多一个变量、二进制里少一处读取，两边各自都是合法文件，谁也不会报错，
# 而用户改了那个变量之后什么都不会发生——配置静默失效是最难查的一种。
# 第 26 轮真的踩到过一次：TIDE_PORT 改了对外端口，横幅却照着容器内的监听端口
# 打客户端配置，于是"贴进客户端就能用"的那段配置连不上，且没有任何线索指向端口。
check_compose_env() {
  echo "== 编排变量是否都被真的读取 =="
  local missing=""
  local v
  for v in $(grep -oE '^\s+TIDE_[A-Z_]+:' docker-compose.yaml | tr -d ' :' | sort -u); do
    if ! grep -q "\"$v\"" cmd/tide-server/main.go; then
      missing="$missing $v"
    fi
  done
  if [ -n "$missing" ]; then
    echo "docker-compose.yaml 设了这些变量，但 cmd/tide-server 一个都不读：$missing"
    echo "用户改了它们不会有任何效果，也不会有任何报错。"
    return 1
  fi
}

run_all() {
  check_compose_env
  echo "== gofmt =="
  fmt=$(gofmt -l .)
  if [ -n "$fmt" ]; then echo "以下文件未格式化："; echo "$fmt"; return 1; fi
  echo "== go vet =="
  go vet ./...
  echo "== go test -race =="
  go test -race -count=1 -timeout 10m ./...
  # 时序类用例在 -race 下会自己跳过（插桩把密码学运算拖慢的比例远大于 I/O），
  # 所以必须再跑一轮不带 -race 的，否则那几条断言在 CI 里等于不存在。
  echo "== go test（不带 -race：时序用例只在这一轮真正执行） =="
  go test -count=1 -timeout 10m ./...
  echo "== 进程内自检 =="
  go run ./cmd/tide-selftest -mode local
  echo "== 跨进程端到端冒烟 =="
  bash deploy/e2e-smoke.sh
}

case "$mode" in
  --here)
    run_all
    ;;
  --head|--index)
    if [ "$mode" = "--head" ]; then tree=HEAD; label="HEAD（别人克隆会拿到的内容）"
    else tree=$(git write-tree); label="暂存区（这次提交会包含的内容）"; fi
    out=$(mktemp -d)
    trap 'rm -rf "$out"' EXIT
    echo "== 导出 $label 到临时目录 =="
    git archive "$tree" | tar x -C "$out"
    # ★ 这一步本身就是一道检查：入口程序若因为 .gitignore 之类的原因没被提交，
    # 导出的树里就没有 cmd/，下面第一步 go vet 立刻炸——而不是等到别人克隆才发现。
    for d in cmd/tide-server cmd/tide-selftest; do
      if [ ! -d "$out/$d" ]; then
        echo "导出的树里缺 $d —— 它没有被提交进仓库。"
        echo "多半是 .gitignore 里某条模式没加前导斜杠，把同名的源码目录一起忽略了；"
        echo "用 git check-ignore -v $d/main.go 可以直接看到是哪一行。"
        return 1 2>/dev/null || exit 1
      fi
    done
    cd "$out"
    run_all
    ;;
  *)
    echo "用法: $0 [--index|--head|--here]"; exit 2
    ;;
esac

echo
echo "== 全部通过 =="
