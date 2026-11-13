# FlowTLS 集成到 sing-box（rev 发行版）设计文档

> 状态：P0 已落地（2026-11-13）
> 基线：sing-box v1.14.4（`git subtree` 引入，位于 `sing-box/`）
> 版本号：`<上游版本>-rev.<自增>`，当前 `1.14.4-rev.1`

## 1. 目标与边界

**目标**：把 FlowTLS 做成 sing-box 的独立协议库，形态与 `sing-quic`（hysteria2）、
`sing-anytls` 完全平级；并在本仓库单独发行一个带 flowtls 的 sing-box 构建。

**边界**：

| 维度 | 结论 |
|---|---|
| 代码结构 | 与 hy2/anytls 同级：独立 module + `protocol/flowtls` 适配层 |
| 二进制名 | **保持 `sing-box`**，只用版本号区分官方版 |
| 版本号 | `1.14.4-rev.1`（合法 semver prerelease，第三方客户端可 parse） |
| 运行条件 | 无法平级：Linux + IPv4 + root/CAP_NET_RAW + iptables |
| 上游合并 | 不作为目标（raw socket 类协议维护者通常不收） |

## 2. 三层结构

```
flowtls/                       独立 Go module，不 import sing-box
  doc.go  config.go  errors.go
  packet.go  codec.go  session.go              ← 已实现（P1）
  socket_linux.go  socket_stub.go              ← 已实现（P1）
  listener.go                                   ← P4
  quic/                                         ← P2，唯一依赖 quic-go 的子包

sing-box/protocol/flowtls/     适配层，~300 行（与 protocol/anytls 同形状）
  inbound.go  outbound.go

sing-box/option/flowtls.go     配置结构
sing-box/constant/flowtls.go   类型常量与错误（新文件，永不冲突）
sing-box/include/flowtls.go    //go:build with_flowtls
sing-box/include/flowtls_stub.go  //go:build !with_flowtls
```

依赖方向必须单向：`sing-box → flowtls → sagernet/sing`。
`flowtls` 依赖的 `sagernet/sing` 版本必须与 `sing-box/go.mod` 完全一致
（当前 `v0.9.7-0.20261023115459-5dc452e537bf`），否则 `M.Socksaddr` 等类型会对不上。

## 3. 上游补丁清单（必须保持最小）

P0 结束时上游改动只有 **2 个文件、7 行**：

```
sing-box/constant/proxy.go    +3   ProxyDisplayName 增加 FlowTLS 分支
sing-box/include/registry.go  +4   inbound/outbound 各插一行注册调用
```

原则：

- **常量、错误、协议实现全部放新文件**——新文件在 `git subtree pull` 时永不冲突；
- `registry.go` 的两行插在 `registerStubForRemoved*` 之前，该位置上游极少变动；
- 不修改 `route/`、`common/`、`adapter/` 等核心目录。

## 4. 构建与发行

见根目录 `Makefile`，唯一版本真源是 `VERSION` 文件。

```bash
make build                # 产出 dist/sing-box-$(VERSION)-linux-amd64
make build GOARCH=arm64   # 交叉编译
make release-musl         # 静态版（软路由/NAS）
make verify               # 断言版本号与 with_flowtls tag
make check CONFIG=x.json  # 配置校验
make upstream-pull TO=v1.15.0
```

版本注入是纯 ldflags，**不改上游源码**：

```
-X github.com/sagernet/sing-box/constant.Version=1.14.4-rev.1
```

`Tags:` 输出里带 `with_flowtls`，是第二个天然区分标志。

## 5. 上游同步流程

```bash
make upstream-pull TO=v1.15.0
git rerere on          # 同类冲突自动复用解法
make verify
```

同步后必须跑互通矩阵，**这一步比编译通过重要得多**：

| 用例 | 客户端 | 服务端 | 门槛 |
|---|---|---|---|
| TCP 基本（curl） | Go | Rust | P2 必须通过 |
| TCP 基本（curl） | Rust | Go | P4 必须通过 |
| TCP 基本 | Go | Go | P4 必须通过 |
| UDP / dig | 三种组合 | 三种组合 | P3 必须通过 |
| 200MB 下载完整性 | Go | Rust | P5 |
| `tc netem loss 5%` | Go | Rust | P5 |
| 断线重连 + 4 路并发 | Go | Rust | P5 |
| `sing-box check` 不需要 root | — | — | **任何时候** |

## 6. wire format 红线（改了就不通）

| 项 | 现值 |
|---|---|
| 外层开销 | IP(20) + TCP(20) + `17 03 03` + len(2) + nonce(12) + tag(16) |
| AEAD | HKDF-SHA256，salt=`flowtls-faketcp-v1`，info=`flowtls faketcp aead key` |
| 伪 ClientHello | Chrome 风格，目标 ~512 字节，含 GREASE 与 padding |
| 伪包识别 | TCP 选项 `MSS 1460 + SACK + WS shift=12`（**不能用 IP ID**，会被 NAT 改写） |
| 握手 | 标准三次握手，握手完成前不得发数据 |
| 流首帧 | `[len u16][ATYP][ADDR][PORT]` |
| 流响应 | **无响应头**，直接双向数据（与 hysteria2 的 WriteTCPResponse 相反） |
| UDP 上行 | `[session u32][addrLen u16][ATYP][ADDR][PORT][payload]` |
| UDP 下行 | `[session u32][payload]` |

`M.SocksaddrSerializer` **不能**用于流首帧——它没有 u16 长度前缀。

## 7. 已知陷阱

1. **构造函数里不能开 raw socket**
   `sing-box check` 会完整走 `box.New()` 再 `Close()`。在 `NewInbound`/`NewOutbound`
   里申请 fd 会让 `check` 也要求 root。所有需权限的动作必须在
   `Start(stage == adapter.StartStateStart)` 里做。

2. **iptables 默认只打印不执行**
   `iptables_mode` 三态：`none` / `print`（默认）/ `auto`。
   `auto` 需要显式开启，且要考虑与 sing-box 的 nftables / auto_redirect 冲突。

3. **不能用 `common/listener`**
   flowtls inbound 自己开 AF_PACKET，不 bind 内核端口。
   同端口的真证书网站另开一个原生 `tls`/`http` inbound，两个 inbound 各管一路。

4. **`socket_stub.go` 必须覆盖非 Linux**
   上游 lint 会跑 `GOOS=windows/darwin/android`，缺 stub 会让 `go build ./...` 直接失败。

5. **配置格式断层**
   Rust 版是 YAML，rev 版是 sing-box JSON，两套不能互认。迁移需要映射表。

6. **每客户端一个 goroutine + quic.Transport**
   hy2 可以一个 UDP socket 管所有客户端；flowtls 每个客户端有独立 seq/ack 空间，
   必须一客户端一 Session 一 Transport。高并发内存/CPU 会明显高于 Rust 单循环模型。

## 8. 里程碑

| 阶段 | 内容 | 状态 |
|---|---|---|
| P0 | subtree + 补丁 + stub 注册 + Makefile，`version`/`check` 可用 | ✅ 2026-11-13 |
| P1 | `flowtls/` 主包：packet/codec/socket/session + 单测 | ✅ 2026-11-13 |
| P2 | `quic/` 子包 + Go 客户端打通 Rust 服务端 | ✅ 2026-11-13 |
| P3 | UDP（QUIC DATAGRAM）+ 多会话路由 | ✅ 2026-11-13 |
| P4 | `listener.go`（服务端 Accept）+ outbound/inbound 适配 | 待办 |
| P5 | 打包脚本、CI 互通矩阵、配置迁移文档 | 待办 |

### P3 实测（Rust 服务端）

| 用例 | 结果 |
|---|---|
| 单会话 5 轮 DNS | PASS，61 字节回程，109ms |
| 4 并发会话 × 3 轮 | PASS |
| 多目标（8.8.8.8 / 1.1.1.1） | PASS |
| TCP 回归 | 小包 + 4 流 × 5MB，0 背压 |

**UDP 与其他协议的关键差异**：上行每包带目标地址（多 7~9 字节），
换来服务端完全无状态——客户端重连后第一个带地址的包就能自愈。
副作用是 `net.PacketConn` 语义更自然：一个 session 可同时发往多个目标。

**实现约束**：`quic.Conn.ReceiveDatagram` 是单消费者语义，
必须有唯一的分发协程按 session 路由（不能让每个 `udpConn` 自读，会抢包）。

### P2 实测（Rust 服务端）

| 用例 | Rust 基线 | Go |
|---|---|---|
| 小包 928B | — | PASS，rtt 4.2ms |
| 单流 40MB | 18.7s / 2.14 MB/s | 18.5s / **2.16 MB/s** |
| 单连接 4 流 × 10MB | — | 19.2s / 1.99 MB/s，0 背压 |
| 多用户 | — | 服务端正确识别 user |
| 错误密码 | — | 10.5s 明确失败 |

**协议层已与 Rust 等价。** P2 期间修掉的 5 个真实 bug 见 DEVTIPS 64~68，
全部集中在 QUIC 集成层（丢包语义、队列容量、ctx 取消、关闭顺序、deadline），
与协议格式无关——这印证了「Go 化不是翻译，而是重新踩 QUIC 栈的坑」。

### 权威实现与冻结策略

Go 版为权威实现；Rust 版在 P4 通过后冻结，仅作为互通基准与回滚版本。
wire format 的**权威定义是 `docs/DESIGN.md` 第 1 节 + `docs/interop_vectors/`**，
两份代码都只是「实现」。

P1 已完成的部分（均已有单测）：

| 文件 | 内容 |
|---|---|
| `packet.go` | IP/TCP 头、校验和、seq/ack、SYN 选项、TcpClock、IP ID、窗口 |
| `codec.go` | v2 记录格式 + ChaCha20-Poly1305 + authID 派生 + 多用户表 |
| `socket_linux.go` / `socket_stub.go` | AF_PACKET 收发 / 非 Linux 明确报错 |
| `session.go` | `net.PacketConn` + 三次握手 + 接收循环（客户端方向） |

**已建立的双向互通门禁**（`bash docs/interop_check.sh`）：

- authID 派生两端逐字节一致；
- Rust 加密 → Go 解密；
- Go 加密 → Rust 解密。

这比两端各自单测全绿重要得多——参数、AAD 或布局任一处不一致，
现象都是「自测全绿、联调全挂」，且日志里只有 AEAD 解密失败。

P2 是分水岭：Go 客户端跑通 Rust 服务端的 `curl` + `dig`，才能证明线路兼容。

## 9. 待决策

1. **wire format 是否加版本位**
   当前没有任何版本标识，将来改握手/ack 策略无法协商。
   建议在 AEAD 的 AD 里塞 1 字节，**在 P2 之前完成**最便宜。

2. **是否支持多用户**
   hy2 用 `Service[U]` + `UpdateUsers`。flowtls 目前单密码。
   若要支持，`session.go` 的密钥结构现在就要按「密码表 → 用户 ID」设计，
   否则后续改动会波及 wire format。

3. **`REV` 是否自动递增**
   目前手工改 `VERSION`。可改为绑定 `git rev-list --count`。
