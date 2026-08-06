//go:build !linux

package tide

import (
	"net"
	"syscall"
)

// 非 Linux 平台没有按 socket 选拥塞控制的接口（macOS/Windows 都是全局设置），
// 所以这里是空实现。见 congestion_linux.go 的说明。
var defaultCongestion = ""

func setCongestion(c net.Conn, algo string) {}

func controlCongestion(algo string) func(network, address string, c syscall.RawConn) error {
	return nil
}
