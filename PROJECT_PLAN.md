# PROJECT_PLAN

## 当前状态（2026-11-12 14:42 北京时间）

v0.2.0：在 v0.1.0 基础上完成稳定性与自适应优化，已通过跨境实测（100M 端口 79/64 Mbps）。

**生产服务端已切到新加坡 ARM 千兆机 `203.0.113.10:8443`**（2026-11-12 12:06 全量重编部署）。
国内家宽实测：单流 200MB **4/4 完整下载**（127~135 Mbps），8 流 184 Mbps，
服务端 CPU 22~25%，客户端 24~28%，`mtu` 恒 1340、`loss_pct=0`。
香港 `203.0.113.12` 保留为备用。

## 已完成

### v0.1.0 基础能力

- [x] Cargo 工程、CLI、YAML 配置、日志
- [x] FakeTCP：IP/TCP 头构造、校验和、AF_PACKET 收 / IPPROTO_RAW 发
- [x] 伪 TLS 记录 + HKDF + ChaCha20-Poly1305 外层鉴权
- [x] quinn-proto 0.11.19 单连接多流 + BBR
- [x] SOCKS5（用户名密码）、HTTP（CONNECT/普通请求/Basic）、HTTPS 本地入口
- [x] 同端口内核 TCP 真证书网站 + 内置 HTML
- [x] iptables 规则自动安装（net.mode auto/none）
- [x] 单元测试、本机联调、跨境联调、错误密码拒绝

### v0.2.0 稳定性优化

- [x] **标准三次握手**：严格 NAT 只放行 SYN-ACK 之后的数据，零等待版本已废弃
- [x] **伪包识别改用 wscale=12**：NAT 会把 IP ID 改写为 0，旧魔数分流失效
- [x] **自适应窗口**：按丢包率 1.5~8MB 自动调整，零配置
- [x] **断线自动重连**：5s→60s 指数退避，实测 5.3 秒恢复
- [x] **端到端背压**：pending 字节高水位，避免目标数据无限堆积
- [x] **quinn 空洞上限规避**：按 MAX_CHUNKS 反算安全窗口
- [x] **读取失败 stop + 去重**：避免窗口泄漏与 CPU 空转
- [x] **流表 5 分钟空闲清理**：解决测速后流数残留
- [x] **HTTPS 入口默认开启**：证书自签或自定义，鉴权沿用 SOCKS5
- [x] 批量收包（256/轮）、有界通道、`join!` 双向搬运
- [x] `faketcp.local_ip`：支持 NAT 机器指定公网源 IP
- [x] **云 NAT 机器恢复可用**：Oracle 新加坡机靠 `local_ip` 显式指定公网源地址，FakeTCP 已跑通
- [x] **发送路径零系统调用瓶颈**：AF_PACKET + QDISC_BYPASS + sendmmsg + GSO 批量取包，
      服务端 CPU 从 100%（@100Mbps）降到 22%（@190Mbps）
- [x] **背压模型修正**：水位绑 BDP、Notify 事件驱动等待，消除自造 bufferbloat（pending 214MB→18MB）
- [x] **关闭 PMTUD**：跨境丢包会触发 quinn 黑洞检测，把 MTU 永久塌到 1200
- [x] **收尾三连修复**：`ReadableError::ClosedStream` 不再误杀流、
      `send_window`/channel 在途数据计入背压、`finish()` 延到 pending 清空后
      （单流 200MB 从「下到 6MB 就断」到 4/4 完整）

## 待办（按优先级）

1. [ ] **伪装加固（待立项）**：tcpdump 对比真实 HTTPS 后确认 8 处可识别特征，
       最关键的是缺 TCP 时间戳选项（真实流量 100% 有）、窗口恒 65535、
       数据阶段零纯 ACK、wscale=12（分流指纹，真实是 9）、IP ID 高字节固定 0xF1。
       改此项需改协议，两端同步升级
2. [ ] 单流 BBR 爬升偏慢：单流 127~135 Mbps，8 流能到 184 Mbps，
       差距在单连接拥塞控制而非 CPU
3. [ ] 客户端中断后未及时发 `STOP_SENDING`，服务端要等满 30 秒背压兜底
4. [ ] 真 GSO：当前 `sendmmsg` 每包仍是独立 skb，可试 `PACKET_VNET_HDR`
5. [ ] 服务端 SYN 表增加超时清理（当前仅建连时 remove，僵尸 SYN 仍会残留）
6. [ ] 增加 `flowtls check` 配置校验子命令
7. [ ] 可选：MTU 探测（已固定 1340，可尝试 1360~1400，注意留足外层开销余量）
8. [ ] 可选：QUIC 0-RTT 会话复用，降低重连延迟
9. [ ] 可选：多用户（users map）与服务端用户隔离
10. [ ] 可选：伪装网站反向代理真实站点
11. [ ] 可选：FEC 前向纠错，减少高丢包下的重传

## 已知问题

- 跨境链路丢包 20%~44%，BBR 靠重传硬跑，仍有带宽浪费。
- 服务端 1 核，outbound 任务与事件循环共享 worker，重负载下 RTT 抖动。
- 云主机在 NAT 后面时必须显式配 `faketcp.local_ip` 为公网地址，否则客户端会丢包
  （路由探测只能拿到内网 10.x）。已在新加坡机上验证可用。
- 千兆机 8 流已到 174~196 Mbps，同链路 iperf3 UDP 上限约 274 Mbps，还有约 30% 空间；
  单流反而只有 87 Mbps，说明瓶颈在 BBR 单连接爬升而非 CPU。
- 同机 hysteria1 能跑 300+ Mbps：它只有 1 层 AEAD（QUIC 自带 TLS1.3）
  且用 UDP + GSO；我们 2 层（外层 ChaCha20 + 内层 AES-GCM）合计仅 5% CPU，
  差距不在加密，而在单流拥塞控制与是否用真 GSO。
- CloudFlare Origin 证书浏览器不信任，仅适合代理伪装；生产建议换 Let's Encrypt 或商业证书。
