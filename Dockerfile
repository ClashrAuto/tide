# syntax=docker/dockerfile:1

# ---- build ----
FROM golang:1.26-alpine AS build
WORKDIR /src

# 拉依赖的代理。默认走官方，但 proxy.golang.org 在不少网络里根本连不上——
# 而这恰恰是最可能部署 TIDE 的那批网络。留成构建参数，别让人为了换个源去改 Dockerfile。
#   docker compose build --build-arg GOPROXY=https://goproxy.cn,direct
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

# 先只拷依赖清单，让 go mod download 能吃到构建缓存：改一行业务代码不必重下依赖。
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO_ENABLED=0 换来一个不依赖 libc 的静态二进制，才能塞进 alpine（以及 scratch）。
# -trimpath 去掉构建机的绝对路径，别把 /home/someone/... 写进发布产物。
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/tide-server ./cmd/tide-server \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/tide-selftest ./cmd/tide-selftest

# ---- runtime ----
FROM alpine:3.21
# ca-certificates 是给**被代理的出站流量**用的（服务端要去连各种 HTTPS 目标）。
# tzdata 让日志时间戳可读。两个都很小，值得。
RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -H -u 10001 tide
COPY --from=build /out/tide-server /usr/local/bin/tide-server
COPY --from=build /out/tide-selftest /usr/local/bin/tide-selftest

# /data 放静态密钥与证书。**必须挂成持久卷**：密钥丢了，所有客户端的
# public-key 一起作废，得挨个换配置。
VOLUME ["/data"]
RUN mkdir -p /data && chown tide:tide /data
USER tide

EXPOSE 8443/tcp 8443/udp

# 健康检查故意只做 TCP 连通性，不发任何应用层探针。
# TIDE 没有、也不该有健康检查端点：任何可区分的响应都是给主动探测方的指纹，
# 而这正是 spec §7 花整节篇幅要消除的东西。
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD nc -z 127.0.0.1 8443 || exit 1

ENTRYPOINT ["/usr/local/bin/tide-server"]
