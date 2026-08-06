//go:build !race

package tide

// raceDetector 告诉时序测量类用例现在是不是开着竞态检测器跑。
// -race 会给每一次内存访问插桩，密码学运算被拖慢的比例远大于 I/O，
// 于是"两类探测的相对时间差"这个量在 -race 下失真，测出来的不是产品的性质。
const raceDetector = false
