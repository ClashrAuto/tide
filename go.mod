// TIDE — Transport-Independent Data Envelope
//
// 独立 module，供 clash fork（github.com/ClashrAuto/coast）以薄适配层引用。
// 这样上游 mihomo 的 merge 面只有三个新文件，而不是三个目录的大片改动。
// 详见 ../README.md。
module github.com/ClashrAuto/tide

go 1.26

require (
	github.com/quic-go/quic-go v0.61.0
	golang.org/x/crypto v0.54.0
	golang.org/x/sys v0.47.0
)

require (
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)
