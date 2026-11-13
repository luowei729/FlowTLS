# 全局代码审查清单（2026-11-13）

审查范围：`flowtls/`（Go 模块）+ `sing-box/protocol/flowtls/` + `sing-box/option/flowtls.go`

判定标准：能否在真实链路 + 高并发 + 长期运行下正确工作。
每条问题必须能被一次具体实验验证（不接受「可能」「或许」）。

---

## 已确认 Bug

### BUG-1（严重）客户端 `udpConn.Close()` 后 `rx` 通道永不关闭 → 读阻塞泄漏

`flowtls/quic/client.go`

```go
func (u *udpConn) Close() error {
    u.client.udpRoutes.Delete(u.sess.id)
    // 不关 rx：分发协程可能正在写入，关掉会 panic。
    return nil
}
```

问题：
- `ReadFrom` 阻塞在 `<-u.sess.rx`，Close 后**永不返回**。
- 调用方（sing-box）的读协程永久泄漏，每个关闭的 UDP 会话一个协程。
- 注释里「关掉会 panic」是错的——分发协程用的是
  `select { case s.rx <- buf: default: }`，加一个 `case <-s.closed`
  就能安全退出，根本不需要「不关」。

正确做法（上游 hysteria2 的 `client_packet.go` 就是这么做的）：
用一个 `closed chan struct{}`，Close 时 close 它；
`ReadFrom` 用 `select { case data := <-rx: ... case <-closed: return net.ErrClosed }`。

验证方法：建立 N 个 UDP 会话后全部 Close，检查 goroutine 数是否回到基线。

---

### BUG-2（严重）客户端 `WriteTo` 在 `addr` 非 UDPAddr 时静默用错目标

`flowtls/quic/client.go`

```go
frame := u.sess.targetFrame
if addr != nil {
    if ap, ok := addrPortOf(addr); ok {
        frame, err = flowtls.EncodeAddressFrame(ap)
    }
    // ok == false 时直接用 sess.targetFrame，不报错
}
```

问题：`addr` 不为 nil 但不是 UDPAddr/TCPAddr 时，**静默回退到默认目标**，
把包发到错误的地方。这种「静默降级」在代理场景下会造成难以排查的
串流（比如 UDP 数据被发到另一个服务）。

正确做法：`addr != nil` 但无法解析 → 返回错误，不要回退。

验证方法：`WriteTo(pkt, fakeAddr{})` 应返回 error。

---

### BUG-3（中）`EncodeAddressFrame` 的返回值复用了切片 → 可能被覆盖

`flowtls/quic/client.go` 的 `addrPortOf` 分支里每次新建切片，这里没问题；
但 `sess.targetFrame` 被所有 `WriteTo` 共享，且 `EncodeClientDatagram`
如果直接 append 到传入切片就会污染。

需确认 `EncodeClientDatagram` 是否 `append` 到传入的 frame。
（待查 `flowtls/udp.go`）

---

### BUG-4（严重）服务端 UDP 会话无限增长 → 吃光整机临时端口

`sing-box/protocol/flowtls/inbound.go`

实测数据：7 分钟 28185 个会话 → 28185 个出站 UDP socket，
Linux 临时端口范围 32768~60999（28232 个）被占满，整机
`bind: address already in use`，所有出站连接失败。

根因：
- `metadata.UDPTimeout` 未设置 → router 只能按目标端口查
  `C.PortProtocols`（只覆盖 DNS 53 / QUIC 443 等少数端口），
  NTP(123) 之类端口的会话永不超时。
- `inboundPacketConn` 自身也没有超时。

**注意**：不要自己发明 janitor。先看 hysteria2 的
`service_packet.go` / `sing-quic/hysteria2/client_packet.go`
怎么处理会话生命周期，照做。

---

## 待审查文件（按风险排序）

- [ ] `flowtls/session.go`（680 行，并发核心）
- [ ] `flowtls/listener.go`（557 行，四元组分发）
- [ ] `flowtls/quic/client.go`（635 行，已发现 3 个 bug）
- [ ] `flowtls/quic/server.go`
- [ ] `flowtls/socket_linux.go`（403 行，raw socket）
- [ ] `flowtls/packet.go`（403 行，报文构造）
- [ ] `flowtls/codec.go`（312 行，加密）
- [ ] `sing-box/protocol/flowtls/inbound.go`
- [ ] `sing-box/protocol/flowtls/outbound.go`
- [ ] `sing-box/protocol/flowtls/masquerade.go`

---

## 审查要点清单（每文件都过一遍）

1. **goroutine 泄漏**：每个 `go func()` 是否有明确退出路径？
2. **通道关闭**：谁关？关几次？读者能否退出？
3. **静默降级**：错误是否被吞掉？失败是否被当成功？
4. **锁**：有 `mu` 保护的字段是否都在锁内访问？有无死锁顺序？
5. **切片复用**：`append` 到传入切片是否污染调用方数据？
6. **资源释放**：socket / listener / timer 是否都有 Close 路径？
7. **错误语义**：临时错误 vs 永久错误是否区分？
8. **边界**：0 长度、超长、nil、负数。

---

## 修复记录（2026-11-13 晚）

全部按「参考 hysteria2 + Rust 老代码」处理，未新增自造机制。

### FIX-1 服务端 UDP 会话泄漏（根因，「一会断开」的真正原因）

**实测**：7 分钟 28185 个会话 → 28185 个出站 UDP socket；
Linux 临时端口 32768~60999（28232 个）被占满后，
`python3 -c "bind 200 次"` → 成功 0/200，整机 `bind: address already in use`。

**根因**：`inboundPacketConn.SetReadDeadline` 是空实现且返回 `nil`。
sing-box 的 `canceler.NewPacketConn` 先试 `SetReadDeadline`，
返回 nil 就走 `NewTimeoutPacketConn` 分支——它靠 read deadline 判断空闲。
空实现让那条分支**永不超时**，会话不回收、出站 socket 不释放。

**修法**（照 `sing-quic/hysteria2/service_packet.go` + `packet.go`）：

| 项 | 之前（自造） | 现在（照抄 hy2） |
|---|---|---|
| 生命周期 | `closed chan` + 自建 janitor 扫描协程 | `ctx` + `cancel(context.CancelCauseFunc)` |
| 读超时 | `SetReadDeadline` 空实现 | `pipe.MakeDeadline()`，真正生效 |
| 空闲回收 | 自造 janitor（每 500ms~5s 扫 map） | `canceler.NewPacketConn(ctx, conn, timeout)` |
| 会话注销 | janitor 删除 | `onDestroy` 回调删除（hy2 同款） |
| 复用判断 | 仅判 `exists` | `!exists or common.Done(pc.ctx)`（hy2 同款） |
| 上限 | 驱逐最久未活动 | **只拦新建**，不驱逐（Rust 老代码取舍） |

**验证**：60 个会话 → 5s 后 22 → 20s 后 1 → 稳态 1（之前是 28021）。

### FIX-2 客户端 `udpConn.Close()` 后 `ReadFrom` 永久阻塞

`flowtls/quic/client.go`：`rx` 通道从不关闭，`ReadFrom` 阻塞在
`<-u.sess.rx` 上永不返回，调用方读协程泄漏、会话无法释放。

注释里「关掉会 panic」的判断是错的——分发协程用 `select` 带 `default`，
根本不需要「不关」。

**修法**（同 hy2 的 `udpPacketConn`）：`ctx` + `cancel` + `readDeadline`，
`ReadFrom` 三分支 select；`Close` 先注销路由再 cancel。
分发协程在连接断开时改为**逐个 cancel**，不再 `close(rx)`。

### FIX-3 客户端 `WriteTo` 静默用错目标

`addr != nil` 但类型无法解析时，原代码落回 `sess.targetFrame`，
把包发到错误的目标。代理场景下这类串流极难排查。

**修法**：返回错误，不回退。

### FIX-4 单条流失败杀掉整条 QUIC 连接

`handleStream` 读地址帧失败时执行 `conn.CloseWithError(0, "")`，
把同一连接上其他正在传输的流（浏览器并发请求）一起杀掉。

**修法**（同 hy2 `service.go:344`）：只 `stream.CancelRead(0)` + `stream.Close()`。

### FIX-5 `masquerade` + `iptables_mode=none` 缺警告

伪装站 bind 内核 TCP 端口后，内核会对伪造 SYN 回自己的 SYN-ACK，
与 flowtls 的 SYN-ACK 抢同一四元组。实测多数情况能通（flowtls 的包先到），
但属于时序竞争，不可依赖。

**修法**：启动时 Warn（不报错，与 Rust 版允许 `net.mode: none` 一致）。

---

## 遗留风险（已评估，暂不改动）

### R-1 `deliver` 阻塞共享 recvLoop

`Session.deliver` 在 `rx` 满时阻塞，而服务端所有会话共用一个
`Listener.recvLoop`——一条会话卡住会阻塞全部。

**为什么暂不改**：`rx` 深度 16384 包（约 22MB）> quic-go 的 15MB 连接窗口，
正常流控下不会填满；会话关闭时 `closeCh` 会唤醒。改造需要给每条会话
独立分发协程，属于架构级改动，按「不自己造轮子」的原则先记录。

### R-2 `Probe` 的判定阈值为经验值

`idleProbeThreshold = 5s` 贴近保活周期。误判代价是一个 RTT（多探一次），
漏判代价是首个请求卡 15~30s，取舍偏向「多探」。

---

## 审查结论

| 文件 | 状态 |
|---|---|
| `flowtls/quic/client.go` | 修 3 处（FIX-2/3 + deadline） |
| `flowtls/session.go` | 未发现新问题（锁、缓冲归还、序号处理均正确） |
| `flowtls/listener.go` | 未发现新问题（SYN 优先、四元组分发、空闲回收正确） |
| `flowtls/codec.go` | 未发现新问题（sendCtr/established 为 atomic，AEAD 并发安全） |
| `flowtls/packet.go` | 未发现新问题 |
| `flowtls/udp.go` | 未发现新问题（与 Rust 老代码逐字节一致） |
| `flowtls/socket_linux.go` | 未发现新问题 |
| `flowtls/rules.go` | 未发现新问题（u32 十六进制前缀已有单测钉住） |
| `sing-box/.../inbound.go` | 修 3 处（FIX-1/4/5） |
| `sing-box/.../outbound.go` | 未发现新问题 |
| `sing-box/.../masquerade.go` | 早前已修（ErrorLog / 路径重写 / 校验分层） |
