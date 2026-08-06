package tide

import "errors"

// 协议级错误。注意：这些**不会**被发到线上——§6 的失败关闭要求任何认证失败都不产生
// 可区分的响应。它们只用于本地日志与调用方决策。
var (
	ErrClosed          = errors.New("tide: session closed")
	ErrStreamClosed    = errors.New("tide: stream closed")
	ErrStreamReset     = errors.New("tide: stream reset by peer")
	ErrProtocol        = errors.New("tide: protocol violation")
	ErrFrameTooLarge   = errors.New("tide: frame exceeds max size")
	ErrBadTicket       = errors.New("tide: ticket invalid or already consumed")
	ErrTicketExhausted = errors.New("tide: no unconsumed tickets left")
	ErrChannelBinding  = errors.New("tide: channel binding mismatch")
	ErrStaleTimestamp  = errors.New("tide: timestamp outside tolerance window")
	ErrVersion         = errors.New("tide: unsupported version")
	ErrNoPath          = errors.New("tide: no usable path")
	ErrSessionGone     = errors.New("tide: session grace period expired")
	ErrFlowControl     = errors.New("tide: peer exceeded flow-control window")
	ErrTooManyStreams  = errors.New("tide: stream limit reached")
)

// StreamError 是 STREAM_RST 携带的错误码。
type StreamError uint32

const (
	StreamErrNone         StreamError = 0
	StreamErrRefused      StreamError = 1 // 目标连接失败
	StreamErrCanceled     StreamError = 2 // 本端主动取消
	StreamErrFlowControl  StreamError = 3
	StreamErrProtocol     StreamError = 4
	StreamErrSessionClose StreamError = 5
)

func (e StreamError) Error() string {
	switch e {
	case StreamErrNone:
		return "tide: stream closed"
	case StreamErrRefused:
		return "tide: destination refused"
	case StreamErrCanceled:
		return "tide: canceled"
	case StreamErrFlowControl:
		return "tide: flow control violation"
	case StreamErrProtocol:
		return "tide: protocol violation"
	case StreamErrSessionClose:
		return "tide: session closing"
	}
	return "tide: stream error"
}
