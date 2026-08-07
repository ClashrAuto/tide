// tide-server 是 TIDE 的生产服务端。
//
// 与 cmd/tide-selftest 的区别要说清楚：selftest 的 `-mode server` 把每条流回声回去，
// 那是压测夹具，**不是代理**。这个程序才真的去连目标地址。别把 selftest 部署上线。
//
// 全部参数都能用环境变量给（容器友好），命令行标志优先级更高。
// 首次启动会自动补齐缺失的静态密钥与自签证书，并把客户端该填的配置打出来。
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ClashrAuto/tide"
)

func main() {
	var (
		listen     = flag.String("listen", env("TIDE_LISTEN", ":8443"), "TCP listen address")
		quicListen = flag.String("quic-listen", env("TIDE_QUIC_LISTEN", ""), "QUIC listen address (optional accelerator)")
		h3         = flag.Bool("h3", env("TIDE_H3", "") != "", "serve the QUIC accelerator over HTTP/3 (spec §12.6); MUST match the client's h3 setting")
		keyFile    = flag.String("key-file", env("TIDE_KEY_FILE", "/data/tide.key"), "static key file (auto-generated if missing)")
		cover      = flag.String("cover", env("TIDE_COVER", ""), "cover origin host:port (required)")
		coverALPN  = flag.String("cover-alpn", env("TIDE_COVER_ALPN", "http/1.1"), "ALPN list to advertise, comma-separated; MUST be protocols the cover origin can actually serve")
		certFile   = flag.String("cert", env("TIDE_CERT", "/data/tls.crt"), "outer TLS certificate (PEM)")
		keyPEMFile = flag.String("cert-key", env("TIDE_CERT_KEY", "/data/tls.key"), "outer TLS private key (PEM)")
		certHost   = flag.String("cert-host", env("TIDE_CERT_HOST", "tide.local"), "CN/SAN for the auto-generated self-signed certificate")
		users      = flag.String("users", env("TIDE_USERS", ""), "comma-separated name:password pairs")
		usersFile  = flag.String("users-file", env("TIDE_USERS_FILE", ""), "read name:password pairs from this file instead of -users (keeps credentials out of the environment)")
		grace      = flag.Duration("grace", envDuration("TIDE_GRACE", tide.DefaultSessionGrace), "session grace period")
		allowBare  = flag.Bool("allow-bare", env("TIDE_ALLOW_BARE", "") != "", "allow negotiating bare-frame mode")
		advertise  = flag.String("advertise", env("TIDE_ADVERTISE", ""), "host clients will dial (may include :port); only used to print the sample config")
		advPort    = flag.String("advertise-port", env("TIDE_ADVERTISE_PORT", ""), "port clients will dial, when it differs from -listen (container port mapping)")
		keygenOnly = flag.Bool("keygen", false, "print a fresh key pair and exit")
	)
	flag.Parse()

	if *keygenOnly {
		k, err := tide.GenerateKey()
		if err != nil {
			fatal(err)
		}
		fmt.Printf("private: %s\npublic:  %s\n", k.String(), k.Public().String())
		return
	}
	if *cover == "" {
		fatal(fmt.Errorf("cover is required.\n" +
			"  TIDE 认证失败时会把连接的全部字节**原样转发**给掩护源站——不是模拟响应，是真转发。\n" +
			"  时序是伪装里唯一真正难伪造的东西：失败路径 0.1ms 而真实站点 50ms，\n" +
			"  探测方量一下响应时间分布就把你拆穿了。所以它必须指向一个真实可达、\n" +
			"  延迟合理的源站（同机/同机房）。docker-compose.yaml 里默认给了一个 nginx。\n" +
			"  明知风险仍要放弃伪装，填 -cover drop。"))
	}

	priv, err := loadOrCreateKey(*keyFile)
	if err != nil {
		fatal(err)
	}
	cert, generated, err := loadOrCreateCert(*certFile, *keyPEMFile, *certHost)
	if err != nil {
		fatal(err)
	}

	spec := *users
	if *usersFile != "" {
		// 文件优先。两个都给时不静默取一个——那正是"改了配置却没生效"的经典来源。
		if spec != "" {
			fatal(fmt.Errorf("give -users or -users-file, not both"))
		}
		b, err := os.ReadFile(*usersFile)
		if err != nil {
			fatal(fmt.Errorf("read -users-file: %w", err))
		}
		spec = string(b)
	}
	userMap, err := parseUsers(spec)
	if err != nil {
		fatal(err)
	}
	if len(userMap) == 0 {
		// 空用户表在 tide 里表示"接受任何通过认证的 user_id"，而 user_id 是由口令派生的——
		// 也就是**任何人都能连**。这在只有静态公钥当凭据的部署里勉强说得通，
		// 但绝不该是默认，所以这里直接拒绝启动而不是打个警告了事。
		fatal(fmt.Errorf("at least one user is required: -users alice:<password> (or -users-file)"))
	}

	srv, err := tide.NewServer(&tide.ServerConfig{
		PrivateKey: priv,
		Users:      userMap,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			// 一个只谈 TLS 却不通告任何 ALPN 的服务端本身就是特征。
			//
			// ★ 但通告什么，取决于**掩护源站能服务什么**，不取决于什么好看。
			// 失败关闭时应答探测方的是掩护源站（§7），所以 ALPN 谈成了 h2、
			// 而掩护源站只会 HTTP/1.1 的话，探测方会拿到一个
			// “协商了 h2，却回了一句 HTTP/1.1 400”的组合——真 h2 服务端永远不会这样。
			// 这比“不通告 ALPN”特征强得多。默认因此只报 http/1.1：
			// 绝大多数掩护源站（nginx 默认站点、静态页）就只会这个，
			// 而一个只支持 http/1.1 的 HTTPS 站点毫不稀奇。
			// 掩护源站真的开了 h2c 时，用 -cover-alpn h2,http/1.1 打开。
			NextProtos: parseALPN(*coverALPN),
		},
		CoverAddr:    *cover,
		AllowBare:    *allowBare,
		SessionGrace: *grace,
	})
	if err != nil {
		fatal(err)
	}
	// 默认 Handler 就是"连目标、对拷"，正是代理该干的事。
	srv.Handler = tide.DefaultHandler
	srv.PacketHandler = tide.DefaultPacketHandler

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fatal(err)
	}
	go func() {
		if err := srv.Serve(ln); err != nil {
			fmt.Fprintf(os.Stderr, "tcp listener stopped: %v\n", err)
		}
	}()
	if *quicListen != "" {
		// ★ ServeQUIC 与 ServeH3 是**互斥**的两种 QUIC 面，客户端那边也有对应开关，
		// 两端必须一致——不一致时的表现极难查，所以这里要说清楚：
		//
		// 两者的 ALPN 都是 "h3"，于是 QUIC 握手会**成功**，问题出在之后：
		// h3 客户端在流上先发 HTTP/3 的 HEADERS 帧（类型 0x01），而 TIDE 的 HELLO
		// 也是 0x01（§12.6 说的就是这个歧义）。ServeQUIC 会把 HEADERS 当 HELLO 解，
		// 自然解不出来，路径悄悄死掉、客户端静默回落 TCP——按 §8 的要求 QUIC 失败
		// 本来就不该报错给用户，于是这个配置错误**一点症状都没有**，
		// 只是加速通道白配了。
		//
		// h3 模式（§12.6）是有意义的：ServeQUIC 对非 TIDE 的 QUIC 连接只能沉默，
		// 而一台在 UDP/443 上跑着"会完成握手但对 h3 请求不吭声"的服务端本身就是异常；
		// ServeH3 让它变成一台货真价实的 HTTP/3 服务器，非 TIDE 请求一律反代到掩护源站。
		serve := srv.ServeQUIC
		if *h3 {
			serve = srv.ServeH3
		}
		go func() {
			if err := serve(*quicListen); err != nil {
				// QUIC 只是加速通道，起不来不该让整个服务端退出——
				// 客户端会静默回落 TCP，这正是 spec §8 要求的行为。
				fmt.Fprintf(os.Stderr, "quic listener stopped (clients fall back to TCP): %v\n", err)
			}
		}()
	}

	printBanner(priv, *listen, *quicListen, *h3, *cover, *advertise, *advPort, *certHost, userMap, generated)
	go warnIfDefaultCover(*cover)
	go warnIfALPNMismatch(*cover, parseALPN(*coverALPN))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Println("shutting down…")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { srv.Close(); ln.Close() }()
	<-ctx.Done()
}

func printBanner(priv *tide.PrivateKey, listen, quicListen string, h3 bool, cover, advertise, advertisePort, certHost string,
	users map[[16]byte]string, selfSigned bool) {

	host, port := advertiseHostPort(advertise, advertisePort, listen)
	names := make([]string, 0, len(users))
	for _, n := range users {
		names = append(names, n)
	}

	fmt.Printf("\ntide-server listening on %s", listen)
	if quicListen != "" {
		mode := "raw QUIC"
		if h3 {
			mode = "HTTP/3"
		}
		fmt.Printf(" (+QUIC %s, %s)", quicListen, mode)
	}
	fmt.Printf("\n  cover origin : %s\n  users        : %s\n", cover, strings.Join(names, ", "))
	if selfSigned {
		fmt.Printf("\n  ⚠️  用的是自动生成的自签证书。它能跑，但**削弱伪装**：真实网站都有\n" +
			"     受信任的证书，一个自签证书本身就是一个可被动观测到的特征。\n" +
			"     正式部署请把真证书挂到 /data/tls.crt 与 /data/tls.key。\n")
	}
	fmt.Printf(`
把下面这段贴进客户端的 proxies:（clash / Coast）

  - name: tide
    type: tide
    server: %s
    port: %s
    password: <这个用户在 -users / -users-file 里的口令>
    public-key: %s
    sni: %s
    udp: true
    quic: %v
    # 移动网络建议再加 redundancy: true —— 常驻两条路径，
    # 路径死掉时不用重连，流直接切过去。
`, host, port, priv.Public().String(), certHost, quicListen != "")
	if quicListen != "" && h3 {
		// ★ 必须打出来。h3 是两端各一个开关、没有协商、不一致时**完全没有症状**的那种配置：
		// 两边 ALPN 都是 "h3"，QUIC 握手照样成功，之后服务端把 h3 的 HEADERS 帧
		// 当 TIDE 的 HELLO 解，路径悄悄死掉，客户端按 §8 静默回落 TCP。
		// 用户只会觉得"加速通道好像没生效"，而日志里一个字都没有。
		fmt.Printf("    h3: true                 # 服务端开了 -h3，这一行**必须**跟着开，否则 QUIC 通道会静默失效\n")
	}
	if selfSigned {
		fmt.Printf("    skip-cert-verify: true   # 自签证书才需要；换成真证书后请删掉这行\n")
	}
	fmt.Println()
}

// parseUsers 解析用户表。逗号与换行都算分隔符，所以同一个解析器既能吃 -users
// 的 "alice:pw,bob:pw"，也能吃 -users-file 的每行一条。
//
// ★ 支持文件是为了让口令**不必经过环境变量**。编排里原本是
// `TIDE_USERS: "alice:${TIDE_PASSWORD}"`，那意味着口令出现在
// `docker inspect`、`/proc/<pid>/environ`，以及容器里任何一个进程眼里——
// 而在这个协议里口令就是凭据，泄露 = 代理被人白嫖，且在威胁模型里还牵扯归属。
// Docker 自己的建议就是敏感值走 secrets 挂成文件（/run/secrets/<name>），
// 别走环境变量。
//
// ⚠️ 必须容忍 CRLF。用户很可能在 Windows 上编辑这个文件，而一个尾随的 CR
// 会被当成口令的一部分——派生出来的 user_id 就不是同一个，
// 现象是"口令明明填对了却认证失败"，且服务端按 §7 失败关闭，
// 客户端只会看到掩护站点的回声，一条有用的线索都没有。
func parseUsers(spec string) (map[[16]byte]string, error) {
	out := map[[16]byte]string{}
	for _, line := range strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	}) {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		name, password, ok := strings.Cut(entry, ":")
		name = strings.TrimSpace(name)
		password = strings.TrimSpace(password)
		if !ok || name == "" || password == "" {
			return nil, fmt.Errorf("bad user entry %q, want name:password", entry)
		}
		out[tide.UserIDFromPassword(password)] = name
	}
	return out, nil
}

// advertiseHostPort 决定横幅里那段客户端配置该写哪个 server / port。
//
// ★ 端口不能想当然地取 -listen。容器里监听地址与客户端要拨的地址**不是同一个**：
// docker compose 写的是 `${TIDE_PORT:-8443}:8443`，容器内永远监听 8443，
// 而宿主发布的是 TIDE_PORT。照着监听端口打，用户把 .env 里的端口一改，
// 横幅就开始给出一份连不上的配置，且没有任何线索指向端口——
// 而 README 的整个卖点就是"docker compose logs tide 会打印客户端该贴的完整配置"。
//
// 容器**没有办法**自己发现宿主侧的映射端口（moby/moby#7421 从 2014 年开到现在），
// 标准做法就是把同一个值再用环境变量传一遍。编排文件里用同一个 ${TIDE_PORT} 填
// TIDE_ADVERTISE_PORT，两个值就不可能漂移。
func advertiseHostPort(advertise, advertisePort, listen string) (host, port string) {
	host = advertise
	if host == "" {
		host = "<your-server>"
	}
	port = "8443"
	if _, p, err := net.SplitHostPort(listen); err == nil && p != "" {
		port = p
	}
	if advertisePort != "" {
		port = advertisePort
	}
	// 用户很自然会把端口直接写进 -advertise。写了就听他的——它比任何默认都具体。
	// SplitHostPort 对不带端口的主机名/裸 IPv6 会报错，那时保持原样即可。
	if h, p, err := net.SplitHostPort(host); err == nil && p != "" {
		host, port = h, p
	}
	return host, port
}

// defaultCoverMarker 是仓库自带那张占位掩护页里的标记。
// 换掉页面（或反代到真实站点）之后它自然消失，告警随之停止——
// 也就是说这个检测不需要维护任何哈希常量，页面怎么改都不会误报。
// parseALPN 把逗号分隔的 ALPN 列表切开。空串等于"不通告"——那本身是个特征，
// 但既然是显式写空的，就照办，不替运维改主意。
func parseALPN(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// warnIfALPNMismatch 检查"通告的 ALPN"与"掩护源站真会说的协议"是否一致。
//
// ★ 这条不一致是**比不通告 ALPN 更强的特征**，而且完全没有症状：
// 代理功能一切正常，只有主动探测方看得见。2026-08-07 在真实部署上就是这样发现的——
// curl 默认提 h2，服务端（当时硬编码通告 h2,http/1.1）欣然选了 h2，
// 探测方于是发出 HTTP/2 连接前言 "PRI * HTTP/2.0"，而掩护源站 nginx 只会 HTTP/1.1，
// 回了个 400。真 h2 服务端绝不会"协商了 h2 却用 HTTP/1.1 回话"。
//
// Xray 对同一个问题的做法是按协商结果分流到不同后端（其文档明说，
// 起因正是 nginx 的 h2c 与 http/1.1 无法在同一端口共存）。
// TIDE 只有一个掩护源站，所以走另一条同样自洽的路：**通告的以掩护源站为准**。
func warnIfALPNMismatch(cover string, alpn []string) {
	if cover == "" || cover == "drop" {
		return
	}
	advertisesH2 := false
	for _, p := range alpn {
		if p == "h2" {
			advertisesH2 = true
		}
	}
	if !advertisesH2 {
		return
	}
	if coverSpeaksH2C(cover) {
		return
	}
	fmt.Printf("\n  ⚠️  通告了 ALPN \"h2\"，但掩护源站 %s **不会说 h2c**。\n"+
		"     这在功能上毫无症状，却是一个很强的主动探测特征：探测方提 h2、\n"+
		"     服务端选了 h2，接着它发 HTTP/2 连接前言，掩护源站却用 HTTP/1.1 回话\n"+
		"     （通常是 400）。真正的 h2 服务端不会这样。\n"+
		"     要么去掉 h2（-cover-alpn http/1.1，默认值），\n"+
		"     要么让掩护源站真的开 h2c（nginx: listen 80 http2;）。\n\n", cover)
}

// coverSpeaksH2C 发一次 HTTP/2 连接前言，看掩护源站是按 h2 回（SETTINGS 帧）
// 还是按 HTTP/1.1 回（"HTTP/1.1 400 ..."）。
func coverSpeaksH2C(cover string) bool {
	c, err := net.DialTimeout("tcp", cover, 5*time.Second)
	if err != nil {
		// 连不上是另一个问题（§7.2 自己会处理），不在这里把话说死。
		return true
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	// 前言 + 一个空 SETTINGS 帧（长度 0、类型 0x04、流 0）。
	preface := append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
		0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00)
	if _, err := c.Write(preface); err != nil {
		return true
	}
	var head [9]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return false
	}
	if string(head[:5]) == "HTTP/" {
		return false // 明摆着的 HTTP/1.x 应答
	}
	return head[3] == 0x04 // 帧头第 4 字节是类型；SETTINGS = 0x04
}

const defaultCoverMarker = "tide-default-cover"

// warnIfDefaultCover 启动时抓一次掩护源站，看它是不是还在用仓库自带的占位页。
//
// ★ 为什么值得专门检测：掩护站点的全部意义是让探测方拿到一个**普通网站**的响应。
// 而仓库自带的那张页面在每一个用默认配置的部署上**逐字节相同**——
// 扫一遍 Content-Length + 正文就能把所有默认部署一网打尽。
// 更糟的是它本身就不像真站点：一台在 443 上服务 HTTPS 的主机返回一张
// "It works / Nothing to see here"，这件事自己就是异常。
//
// 这和已经有的自签证书告警是同一类：能跑，但**削弱伪装**，
// 而且不告诉运维他就不会知道。放在启动横幅之后打印，位置一致。
func warnIfDefaultCover(cover string) {
	if cover == "" || cover == "drop" {
		return
	}
	c, err := net.DialTimeout("tcp", cover, 5*time.Second)
	if err != nil {
		return // 连不上是另一个问题，§7.2 自己会处理，这里不重复告警
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	host, _, err := net.SplitHostPort(cover)
	if err != nil {
		host = cover
	}
	if _, err := fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host); err != nil {
		return
	}
	body, err := io.ReadAll(io.LimitReader(c, 64<<10))
	if err != nil && len(body) == 0 {
		return
	}
	if !strings.Contains(string(body), defaultCoverMarker) {
		return
	}
	fmt.Printf("\n  ⚠️  掩护源站返回的还是仓库自带的**占位页**。它能跑，但**削弱伪装**：\n" +
		"     这张页面在每一个用默认配置的部署上逐字节相同，扫一遍正文就能把它们\n" +
		"     一网打尽；而且一台在 443 上服务 HTTPS 的主机返回一张\n" +
		"     “It works / Nothing to see here”，这件事本身就不像真站点。\n" +
		"     换成你自己的内容，或让掩护源站反代到一个真实域名（deploy/cover 那一层）。\n" +
		"     换掉之后这条告警会自动消失。\n\n")
}

// loadOrCreateKey 读取静态密钥，不存在就生成一份并落盘。
// 密钥丢了等于所有客户端都要换配置，所以务必把 /data 挂成持久卷。
func loadOrCreateKey(path string) (*tide.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		return tide.ParsePrivateKey(strings.TrimSpace(string(b)))
	}
	k, err := tide.GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(k.String()+"\n"), 0o600); err != nil {
		return nil, err
	}
	fmt.Printf("generated a new static key at %s (back this up — losing it invalidates every client config)\n", path)
	return k, nil
}

func loadOrCreateCert(certPath, keyPath, host string) (tls.Certificate, bool, error) {
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return c, false, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, false, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		DNSNames:              []string{host},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return tls.Certificate{}, false, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, false, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, false, err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	return c, true, err
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envDuration(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "tide-server: %v\n", err)
	os.Exit(1)
}
