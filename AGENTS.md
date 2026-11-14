# AGENTS.md — FlowTLS 开发指南

## 项目是什么

FlowTLS 是一个「外观是 TCP + TLS、内部是 QUIC 数据报」的代理。

它与 hysteria2 / anytls 同一形态：**sing-box 的一个独立协议库**。
发行版从本仓库构建，二进制名保持 `sing-box`，只靠版本号
`1.14.4-rev.N` 与官方版区分。

同端口（默认 8443）还需要一个真证书网站用于应对主动端口探测——
注意 Go 版里这是**独立进程**，不在 flowtls inbound 内（见「已知限制」）。
443 端口实测不可用：国内出口设备对 443 的伪造 TCP 检查更严，包发不出去。

**Rust 实现已冻结**：最早用 Rust 验证了协议（wire format v2），
现在源码只在 `legacy-rust` 分支，主分支只维护 Go。
为什么换、冻结在哪、怎么查历史 → [`docs/EVOLUTION.md`](docs/EVOLUTION.md)。

## 架构

```
sing-box 入口（socks / mixed / tun / ...，全部由 sing-box 提供）
        │
        ▼
sing-box 路由（route.rules / DNS / rule_set）
        │
        ▼
protocol/flowtls 适配层（adapter.Outbound / adapter.Inbound）
        │
        ▼
flowtls/quic（quic-go：单连接多流，BBR）
        │  QUIC 数据报（TCP 走双向流，UDP 走 RFC 9221 DATAGRAM）
        ▼
flowtls 传输层
  - 伪 TLS 记录外观：17 03 03 len + nonce + ChaCha20-Poly1305(QUIC)
  - 标准三次握手：SYN → SYN-ACK → ACK，之后才发数据
    （严格 NAT 会丢弃握手完成前的数据包；零等待版本已废弃）
  - AEAD 密钥 = HKDF-SHA256(password)，解密成功即鉴权
  - 伪包识别特征 = **TCP 窗口缩放因子 wscale=12**（只在 SYN/SYN-ACK 里）
    真实 Linux 是 7~10，`wscale=12` 在真实栈上极小概率出现；
    TCP 选项是**端到端字段，运营商 NAT / 云网关不会改写**。
    **不要改回 9**：IP ID 不再可靠（见下），9 与真实浏览器无法区分，
    服务端会给真实 SYN 也回 SYN-ACK，与内核（伪装站）抢同一四元组。
        │  原始 IPv4 报文
        ▼
================ TCP 8443 ================
        │  原始 IPv4 报文
        ▼
flowtls 传输层（服务端，AEAD 验签失败静默丢弃）
        │
        ▼
flowtls/quic → 流 / DATAGRAM 交回 router → 出站

同端口的真证书网站（可选，masquerade）：
  内核 TCP listener 绑同一个端口，靠 raw/PREROUTING 那条 DROP 规则分流——
  带标记的伪造包被 DROP 后内核看不到，AF_PACKET 在 netfilter 之前照旧收包；
  其余包（真实浏览器）落到内核 TCP，由伪装站回应。
```

## 目录结构

```
flowtls/                    独立 Go 模块 github.com/luowei729/flowtls
  packet.go                 IP/TCP 头构造解析、校验和、TS/wscale 选项
  codec.go                  wire format v2：伪 TLS 记录 + AEAD + 多用户 authID
  addr.go                   地址帧编解码（流首帧 / DATAGRAM 内嵌）
  udp.go                    UDP 会话帧编解码
  socket_linux.go           AF_PACKET 收包 / IPPROTO_RAW 发包 / 默认路由与 ARP
  socket_stub.go            非 Linux 空实现（保证能交叉编译）
  session.go                单条会话，net.PacketConn 语义
  listener.go               服务端：共享 raw socket + 单收包协程 + 四元组分发
  rules.go                  iptables 规则构造（u32 匹配 IP ID 标记）+ 三种模式
  rules_linux.go            Linux 上执行 iptables / 非 Linux 为 rules_stub.go
  quic/client.go            quic-go 客户端
  quic/server.go            quic-go 服务端
  cmd/ftdial/               联调：TCP（-streams N）
  cmd/ftudp/                联调：UDP（-sessions N -rounds N）
  cmd/ftserver/             联调：服务端
  testdata/                 wire format v2 冻结向量（兼容性基线，勿删）

sing-box/                   git subtree，上游源码 + 最小补丁
  protocol/flowtls/         outbound.go / inbound.go / masquerade.go（适配层）
  option/flowtls.go         配置结构
  constant/flowtls.go       类型常量与错误
  include/flowtls.go        编译期开关（with_flowtls tag）+ stub
  include/registry.go       ← 补丁（4 行）
  constant/proxy.go         ← 补丁（3 行）

docs/
  DESIGN.md                 wire format 权威文档
  EVOLUTION.md              Rust → Go 演进与冻结点
  MIGRATION.md              Rust YAML → sing-box JSON 字段对照
  SINGBOX_INTEGRATION.md    接入 sing-box 的工程细节
  interop_check.sh          冻结向量门禁（无需 root / 无需 Rust）
  e2e_matrix.sh             真链路矩阵（需要 root）
  test_udp.py               SOCKS5 UDP 端到端测试
  bench.sh                  延迟分层体检

web/index.html              伪装网站页面素材
Makefile + VERSION          rev 发行版构建（版本号唯一真源）
```

## 开发命令

```bash
export PATH=/usr/local/go/bin:$PATH GOPATH=/root/go GOTOOLCHAIN=local

# 全量构建（唯一发行入口）
make build
make verify                       # 验收：版本号带 rev、tags 带 with_flowtls

# Go 模块单测
cd flowtls && go test -race ./...

# 冻结向量门禁（不需要 root / 不需要 Rust）
bash docs/interop_check.sh

# 真链路矩阵（需要 root；未设 RUST_FLOWTLS 时只跑 Go↔Go）
bash docs/e2e_matrix.sh
RUST_FLOWTLS=/tmp/flowtls-rust/target/debug/flowtls bash docs/e2e_matrix.sh

# 配置校验（不需要 root，这是硬要求）
./dist/sing-box-1.14.4-rev.1-linux-amd64 check -c client.json
```

## 部署命令

```bash
sudo ./dist/sing-box-1.14.4-rev.1-linux-amd64 run -c server.json   # 服务端
sudo ./dist/sing-box-1.14.4-rev.1-linux-amd64 run -c client.json   # 客户端
```

配置示例见 `deploy.example/`，字段说明见 `docs/MIGRATION.md`。

## 必须遵守的约束

1. **wire format 不许悄悄改**。改动必须同时更新 `flowtls/testdata/` 里的冻结向量
   与 `docs/DESIGN.md`，并在 `CHANGELOG.md` 记为破坏性变更。
2. **raw socket 只能在 `Start(StartStateStart)` 里申请**。
   `sing-box check` 会完整走一遍构造再关闭，构造函数里开 raw socket
   会让纯语法检查也要求 root。
3. **服务端只有 `Listener` 能收包**。`Session` 在服务端绝不能启动自己的
   `recvLoop`（会抢同一个 socket 的包），详见 `DEVTIPS.md` 第 69 条。
4. **纯 SYN 判断要优先于「已有会话」**。客户端源端口固定，重启后四元组完全相同，
   否则新 SYN 会被旧会话当乱序包吞掉（`DEVTIPS.md` 第 70 条）。
5. 代码每步写中文注释，说明「做什么」和「为什么」。
6. 改动前输出「改动前总结」，改动后输出「改动后总结」。
7. 每次改动按北京时间更新 `CHANGELOG.md`、`DEVTIPS.md`、`PROJECT_PLAN.md`。
8. 根目录只放 `AGENTS.md` / `CHANGELOG.md` / `DEPLOY_CREDENTIALS.md` /
   `DEVTIPS.md` / `PROJECT_PLAN.md` / `README.md` / `Makefile` / `VERSION`，
   其他文档放 `docs/`。
9. 依赖版本必须与 sing-box 完全一致（`github.com/sagernet/quic-go`、
   `github.com/sagernet/sing` 的 pseudoversion 要逐字节对齐），
   否则 `M.Socksaddr` 这类类型会不兼容。
10. **不要引入 `golang.org/x/sys`**：它缺 `Sendmmsg` / `IfNametoindex`，
    且 go directive 会强制升到 1.26。用标准库 `syscall` + `net.InterfaceByName`。
11. 不要为了省事删除已有功能或绕过 iptables 分支。
12. **u32 的右值必须带 `0x` 前缀**（`...=0xf1004000`）：内核用
    `simple_strtoul(base=0)` 解析，不带前缀会失败返回 0，规则永不命中，
    而 `iptables -C` 依然报告规则存在（`DEVTIPS.md` 第 74 条）。
13. **iptables 规则刻意不自动删除**。重启期间规则必须继续生效，
    否则内核会回 RST 打断重建中的隧道。卸载命令由 `print` 模式打印。
14. **服务端分流必须按 wscale 判断，不能按 IP ID**：IP ID 掩码匹配
    （`& 0x1E00 == 0x1E00`）有 1/16 误命中率，且部分链路会改写它。
    误命中会让真实浏览器的 SYN 也收到伪 SYN-ACK（`DEVTIPS.md` 第 93 条）。
15. **收包缓冲必须 ≥ 256KB**：网卡 GRO 会把多个 TCP 段合并成超过 64KB 的
    skb，缓冲不足时 `recvmmsg` **静默截断**（QUIC 的 `lost=` 恒为 0，
    只表现为握手慢、RTT 虚高）。同时必须保留 `MSG_TRUNC` 检测
    （`DEVTIPS.md` 第 98 条）。
16. **AF_PACKET 发送 fd 必须是阻塞的**（配 `SO_SNDTIMEO` 兜底）。
    非阻塞 fd + `EAGAIN` 静默丢弃会让握手包随机丢失，
    而伪 TCP 层没有重传（`DEVTIPS.md` 第 98 条）。
17. **`handleIncoming` 必须忽略 RST**：本协议从不发 RST，
    收到 RST 只可能来自对端内核。把它当「对端存活」会让死连接被长期复用
    （`DEVTIPS.md` 第 98 条）。

## 已知限制

- FakeTCP 目前只支持 IPv4。
- **UDP 不走重传也不分片**：QUIC DATAGRAM 语义，队列满/超 MTU 即丢（对齐 hysteria2）；
  单包上限约 1200 字节，更大的 UDP 报文直接丢弃。
- 需要 root 或 CAP_NET_RAW。
- **NAT 云主机可用**（Oracle Cloud 已验证）：网卡只有内网地址时，
  包里必须填**内网地址**，让网关做 1:1 SNAT。填公网地址会被网关
  反欺骗**静默丢弃**。Go 版已自动纠正并打到启动日志（`DEVTIPS.md` 87）。
- **443 端口不可用**：国内出口设备对 443 的伪造 TCP 检查更严，建议用 8443/9443。
- **单流窗口受 quic-go 组装器约束**：高丢包时窗口过大会积累大量乱序空洞，
  因此用自适应窗口规避。
- **伪装网站必须用真证书**：不开 `masquerade` 时 inbound 只做隧道，
  需另起进程监听同端口；开了则由 inbound 自己 bind（唯一会 bind 内核 TCP 的地方）。
  自签证书等于自报家门，两种方式都不行。
- **iptables 规则不会自动删除**：`auto` 幂等写入但不清理，
  升级/卸载后按 `print` 输出里的卸载命令手工清。
- 内层 QUIC 证书是运行时自签，安全由外层 AEAD 保证。
