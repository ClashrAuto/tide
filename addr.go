package tide

import (
	"encoding/binary"
	"net"
	"strconv"
)

// SOCKS5 地址编码：ATYP(1) || ADDR || PORT(u16 大端)。
// 复用 SOCKS5 的格式而不是自定义，纯粹是因为代理链路两端本来就到处在解这个格式，
// 少一种编码就少一处转换和一类 bug。

const (
	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4
)

func appendSocksAddr(b []byte, hostport string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, ErrProtocol
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append(b, atypIPv4)
			b = append(b, v4...)
		} else {
			b = append(b, atypIPv6)
			b = append(b, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, ErrProtocol
		}
		b = append(b, atypDomain, byte(len(host)))
		b = append(b, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}

// parseSocksAddr 解出地址，并返回消耗的字节数（便于后面还跟着数据的场景）。
func parseSocksAddr(b []byte) (string, int, error) {
	if len(b) < 1 {
		return "", 0, ErrProtocol
	}
	var host string
	var n int
	switch b[0] {
	case atypIPv4:
		if len(b) < 1+4+2 {
			return "", 0, ErrProtocol
		}
		host = net.IP(b[1:5]).String()
		n = 5
	case atypIPv6:
		if len(b) < 1+16+2 {
			return "", 0, ErrProtocol
		}
		host = net.IP(b[1:17]).String()
		n = 17
	case atypDomain:
		if len(b) < 2 {
			return "", 0, ErrProtocol
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return "", 0, ErrProtocol
		}
		host = string(b[2 : 2+l])
		n = 2 + l
	default:
		return "", 0, ErrProtocol
	}
	port := binary.BigEndian.Uint16(b[n : n+2])
	n += 2
	return net.JoinHostPort(host, strconv.Itoa(int(port))), n, nil
}
