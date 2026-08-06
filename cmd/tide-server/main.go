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
		certFile   = flag.String("cert", env("TIDE_CERT", "/data/tls.crt"), "outer TLS certificate (PEM)")
		keyPEMFile = flag.String("cert-key", env("TIDE_CERT_KEY", "/data/tls.key"), "outer TLS private key (PEM)")
		certHost   = flag.String("cert-host", env("TIDE_CERT_HOST", "tide.local"), "CN/SAN for the auto-generated self-signed certificate")
		users      = flag.String("users", env("TIDE_USERS", ""), "comma-separated name:password pairs")
		grace      = flag.Duration("grace", envDuration("TIDE_GRACE", tide.DefaultSessionGrace), "session grace period")
		allowBare  = flag.Bool("allow-bare", env("TIDE_ALLOW_BARE", "") != "", "allow negotiating bare-frame mode")
		advertise  = flag.String("advertise", env("TIDE_ADVERTISE", ""), "host clients will dial; only used to print the sample config")
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

	userMap := map[[16]byte]string{}
	for _, pair := range strings.Split(*users, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		name, password, ok := strings.Cut(pair, ":")
		if !ok || password == "" {
			fatal(fmt.Errorf("bad -users entry %q, want name:password", pair))
		}
		userMap[tide.UserIDFromPassword(password)] = name
	}
	if len(userMap) == 0 {
		// 空用户表在 tide 里表示"接受任何通过认证的 user_id"，而 user_id 是由口令派生的——
		// 也就是**任何人都能连**。这在只有静态公钥当凭据的部署里勉强说得通，
		// 但绝不该是默认，所以这里直接拒绝启动而不是打个警告了事。
		fatal(fmt.Errorf("at least one user is required: -users alice:<password>"))
	}

	srv, err := tide.NewServer(&tide.ServerConfig{
		PrivateKey: priv,
		Users:      userMap,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			// 一个只谈 TLS 却不通告任何 ALPN 的服务端本身就是特征。
			NextProtos: []string{"h2", "http/1.1"},
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

	printBanner(priv, *listen, *quicListen, *h3, *cover, *advertise, *certHost, userMap, generated)
	go warnIfDefaultCover(*cover)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Println("shutting down…")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { srv.Close(); ln.Close() }()
	<-ctx.Done()
}

func printBanner(priv *tide.PrivateKey, listen, quicListen string, h3 bool, cover, advertise, certHost string,
	users map[[16]byte]string, selfSigned bool) {

	host := advertise
	if host == "" {
		host = "<your-server>"
	}
	port := "8443"
	if _, p, err := net.SplitHostPort(listen); err == nil && p != "" {
		port = p
	}
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
    password: <你在 -users 里给这个用户设的口令>
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

// defaultCoverMarker 是仓库自带那张占位掩护页里的标记。
// 换掉页面（或反代到真实站点）之后它自然消失，告警随之停止——
// 也就是说这个检测不需要维护任何哈希常量，页面怎么改都不会误报。
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
