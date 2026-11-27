package flowtls

// ip_id_mark 的派生。
//
// ## 为什么从 password 派生，而不是让部署方手填
//
// `ip_id_mark` 是**服务端与所有客户端必须共享**的标识：服务端靠
// 「IP ID 高字节 == mark」判断这个包是否属于本协议（见 listener.go 的
// protocolOwned），内核层靠它写 drop 规则（见 rules.go）。
//
// 它不能像 source_port 那样各自动态生成 —— 两端对不上就等于隧道不通。
// 但它也绝不能长期用同一个公开默认值：`ip_id_mark` 与 SNI、服务器 IP
// 一起构成部署指纹，DPI 只要加一条「IP ID 高字节 == 0x1e」的规则就能
// 一次性命中所有没改过默认值的部署（AGENTS 约束 18）。
//
// 既然 password 本来就是两端共享、且每个部署各不相同的秘密，
// 那「mark = f(password)」就是唯一同时满足这两条的方案：
//
//	自动一致 —— 客户端用自己那份 password 算，服务端用同一个 password 算，
//	            不需要任何手工同步；
//	自动不同 —— 不同部署的 password 不同，mark 自然不同；
//	自动支持多凭据 —— 服务端为**每条**密码各算一个 mark。
//
// ## 为什么用 HKDF 而不是直接 hash
//
// 与 codec.go 里 AEAD 密钥、authID 的做法保持一致：同一个 HKDF-SHA256、
// 同一个 salt，只换 info 字符串。这样三者的输出在密码学上互不相关
// （知道 mark 推不出密钥，反之亦然），也不用担心「同一个 hash 用在不同
// 地方会不会有交叉影响」这种问题。
//
// ## 为什么只取高字节
//
// IP ID 是 16 位，但低字节按包递增（见 NextIPID），只有高字节稳定。
// 所以 mark 的实际取值是 0xNN00 形式，有效空间 256 个。
//
// 256 个听起来不多，但这个标记的作用是「让内核与其它程序的包不撞车
// 的前提下尽量窄」，不是密码学防护 —— 真正的鉴权是握手首包的 AEAD。
// Rust 版用 0xF100，同样只有 256 个可能值。

import (
	"crypto/hkdf"
	"crypto/sha256"
)

// markDeriveInfo 是 HKDF 的 info 参数。
//
// 与 codec.go 的 AEAD 密钥、authID 用**不同的 info**，保证三者无关。
// 带版本号：将来若要改派生方式，只要改这里的 v1 → v2，
// 新旧部署不会因为算法不一致而静默不通（会表现为握手失败，很明显）。
const markDeriveInfo = "flowtls isn mark v1"

// DeriveISNMark 从 password 派生 TCP ISN 分流标记（16 位，全位可用）。
//
// 同一对 password 在客户端与服务端**必然**得到同一个值 —— 这就是
// 零配置同步的全部原理。
//
// # 为什么标记在 TCP ISN 而不是 IP ID
//
// 早期实现放在 IP ID 高字节，但 IP ID 会被中间设备随机化（RFC 6528 的
// 防侧信道要求，多数 NAT / 云网关实现得更粗暴）。2026-11-28 三角测量实测：
// 同一客户端经 hk1 到 sg1 正常，到 tk3 却握手超时 —— 差别只在中间路径
// 有没有改写 IP ID 的设备。ISN 没有任何设备会改写（改了 TCP 就废了），
// 是唯一可靠且可被 nft 静态匹配的载体。
//
// 完整论证与字段对比表见 packet.go 的 `---- TCP ISN 分流标记 ----`。
func DeriveISNMark(password string) uint16 {
	k, err := hkdf.Key(sha256.New, []byte(password), []byte(hkdfSalt),
		markDeriveInfo, 2)
	if err != nil {
		// hkdf.Key 只在参数非法时失败；长度固定 2，实际不可能触发。
		panic("flowtls: hkdf isn mark: " + err.Error())
	}
	mark := uint16(k[0])<<8 | uint16(k[1])
	// mark == 0 在代码里表示「未配置」，会让调用方退回默认值。
	// 派生出 0 的概率 1/65536，换成一个固定的替换值。
	if mark == 0 {
		mark = 0x4D4B
	}
	return mark
}

// DeriveIPIDMark 从 password 派生 ip_id_mark（返回 0xNN00 形式）。
//
// 同一对 password 在客户端与服务端**必然**得到同一个值 —— 这就是
// 零配置同步的全部原理。
func DeriveIPIDMark(password string) uint16 {
	k, err := hkdf.Key(sha256.New, []byte(password), []byte(hkdfSalt),
		markDeriveInfo, 2)
	if err != nil {
		// hkdf.Key 只在参数非法时失败；长度固定 2，实际不可能触发。
		panic("flowtls: hkdf ip id mark: " + err.Error())
	}
	mark := uint16(k[0]) << 8
	// 极小概率（1/256）派生出 0x00 —— 而 mark == 0 在代码里表示
	// 「未配置」，会让调用方退回默认值。这里换成一个固定的替换值，
	// 代价是那一组 password 与「派生结果为 0x4000」的部署共享标记，
	// 概率 1/65536，可接受。
	if mark == 0 {
		mark = 0x4000
	}
	return mark
}
