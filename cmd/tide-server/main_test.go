package main

import "testing"

// 启动横幅打出来的那段客户端配置，`port:` 一栏必须是**客户端要拨的**端口，
// 而不是服务端在本地监听的端口。容器里这两个经常不是一回事。
//
// ★ 这不是假想的边角情况，是 docker compose 的默认形态。编排里写的是
// `${TIDE_PORT:-8443}:8443`，容器内永远监听 8443；把 .env 里的 TIDE_PORT
// 改成别的值（.env.example 明确邀请用户这么做——"对外端口，TCP 与 UDP 用同一个"），
// 横幅照旧打 `port: 8443`。而 README 的整个卖点就是
// "docker compose logs tide 会打印客户端该贴的完整配置"。
// 用户照抄，然后连不上，且没有任何线索指向端口。
//
// 容器**没有办法**自己发现宿主侧的映射端口——moby/moby#7421 从 2014 年开到现在，
// 标准做法就是把同一个值再用环境变量传一遍。所以这里加 TIDE_ADVERTISE_PORT，
// 由编排文件用同一个 ${TIDE_PORT} 填上。
func TestAdvertiseHostPort(t *testing.T) {
	cases := []struct {
		name          string
		advertise     string
		advertisePort string
		listen        string
		wantHost      string
		wantPort      string
	}{
		{
			name:   "什么都没配：主机是占位符，端口取监听端口",
			listen: ":8443", wantHost: "<your-server>", wantPort: "8443",
		},
		{
			name:      "非容器部署：监听端口就是对外端口",
			advertise: "example.com", listen: ":9000",
			wantHost: "example.com", wantPort: "9000",
		},
		{
			name:      "compose：容器内监听 8443，宿主发布 18443",
			advertise: "example.com", advertisePort: "18443", listen: ":8443",
			wantHost: "example.com", wantPort: "18443",
		},
		{
			// 用户很自然会把端口直接写进 advertise 里。写了就该听他的，
			// 而不是打出一个 host:port 的"主机名"配上另一个端口——那是双重错误。
			name:      "advertise 自带端口时最具体，优先",
			advertise: "example.com:443", advertisePort: "18443", listen: ":8443",
			wantHost: "example.com", wantPort: "443",
		},
		{
			name:      "IPv6 字面量不带端口时不能被误拆",
			advertise: "2001:db8::1", advertisePort: "443", listen: ":8443",
			wantHost: "2001:db8::1", wantPort: "443",
		},
		{
			name:      "IPv6 带端口按方括号形式解析",
			advertise: "[2001:db8::1]:443", listen: ":8443",
			wantHost: "2001:db8::1", wantPort: "443",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port := advertiseHostPort(tc.advertise, tc.advertisePort, tc.listen)
			if host != tc.wantHost || port != tc.wantPort {
				t.Fatalf("得到 %q / %q，期望 %q / %q", host, port, tc.wantHost, tc.wantPort)
			}
		})
	}
}
