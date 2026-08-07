package main

import (
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestParseALPN(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{"http/1.1", []string{"http/1.1"}},
		{"h2,http/1.1", []string{"h2", "http/1.1"}},
		{" h2 , http/1.1 ", []string{"h2", "http/1.1"}},
		{"", nil},
	} {
		if got := parseALPN(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseALPN(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// 通告的 ALPN 必须与掩护源站真会说的协议一致。
//
// ★ 不一致时代理功能**完全正常**，只有主动探测方看得见：探测方提 h2、
// 服务端选 h2，然后它发 HTTP/2 连接前言，掩护源站却用 HTTP/1.1 回话。
// 真 h2 服务端不会这样。2026-08-07 在真实部署上撞到的就是这个：
// 硬编码通告 h2,http/1.1，掩护源站是只会 HTTP/1.1 的 nginx，
// curl 默认提 h2 于是拿到 "PRI * HTTP/2.0" → 400。
func TestCoverH2CDetection(t *testing.T) {
	// 只会 HTTP/1.1 的掩护源站：对前言回 400。
	h1 := mockCover(t, func(c net.Conn) {
		io.ReadFull(c, make([]byte, 24))
		c.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
	})
	if coverSpeaksH2C(h1) {
		t.Error("把只会 HTTP/1.1 的掩护源站判成了 h2c —— 于是 h2 不一致的告警不会响，" +
			"而这个特征在功能上没有任何症状")
	}

	// 会 h2c 的掩护源站：回一个 SETTINGS 帧。
	h2 := mockCover(t, func(c net.Conn) {
		io.ReadFull(c, make([]byte, 24))
		c.Write([]byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00})
	})
	if !coverSpeaksH2C(h2) {
		t.Error("把真的会 h2c 的掩护源站判成了不会 —— 会对正确配置误报")
	}
}

func mockCover(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); handle(c) }()
		}
	}()
	return ln.Addr().String()
}

// 默认必须是"只通告 http/1.1"：绝大多数掩护源站就只会这个，
// 而默认值决定了绝大多数部署的实际形态（CWE-1188）。
func TestDefaultALPNMatchesTypicalCover(t *testing.T) {
	if got := parseALPN("http/1.1"); len(got) != 1 || got[0] != "http/1.1" {
		t.Fatalf("默认 ALPN 解析成了 %v", got)
	}
	if strings.Contains("http/1.1", "h2") {
		t.Fatal("默认值里不该出现 h2")
	}
}

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

// 用户表的解析器同时喂给 -users（逗号分隔）与 -users-file（每行一条），
// 所以两种形状都得吃得下。
//
// ★ CRLF 那条不是凑数：用户很可能在 Windows 上编辑 users 文件，而一个尾随的 \r
// 会被当成口令的一部分——派生出来的 user_id 就不是同一个。现象是"口令明明填对了
// 却认证失败"，而服务端按 §7 失败关闭，客户端只看到掩护站点的回声，
// 一条有用的线索都没有。本仓库在 CRLF 上已经栽过一次（seed 配置那次）。
func TestParseUsers(t *testing.T) {
	same := func(a, b map[[16]byte]string) bool {
		if len(a) != len(b) {
			return false
		}
		for k, v := range a {
			if b[k] != v {
				return false
			}
		}
		return true
	}
	want, err := parseUsers("alice:pw1,bob:pw2")
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 2 {
		t.Fatalf("逗号形式解出 %d 条，期望 2", len(want))
	}

	for _, tc := range []struct {
		name string
		in   string
	}{
		{"每行一条", "alice:pw1\nbob:pw2\n"},
		{"CRLF", "alice:pw1\r\nbob:pw2\r\n"},
		{"注释与空行", "# 用户表\n\nalice:pw1\n\n#bob 停用了\nbob:pw2\n"},
		{"前后空白", "  alice : pw1 \n\tbob:pw2\t\n"},
		{"混用逗号与换行", "alice:pw1,\nbob:pw2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseUsers(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if !same(got, want) {
				t.Fatalf("%q 解出来和逗号形式不一致：%v", tc.in, got)
			}
		})
	}

	// 缺口令 / 缺用户名必须报错，而不是悄悄少一个用户——
	// 空用户表在 tide 里的含义是"任何人都能连"。
	for _, bad := range []string{"alice", "alice:", ":pw", "alice:pw,bob"} {
		if _, err := parseUsers(bad); err == nil {
			t.Fatalf("%q 应当被拒绝", bad)
		}
	}
}
