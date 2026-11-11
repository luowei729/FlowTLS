# PROJECT_PLAN

## 当前状态（2026-11-11 23:10 北京时间）

v0.1.0 已完成并通过香港 → 国内实测。

## 已完成

- [x] Cargo 工程、CLI、YAML 配置、日志
- [x] FakeTCP：IP/TCP 头构造、校验和、AF_PACKET 收 / IPPROTO_RAW 发
- [x] 伪 TLS 记录 + HKDF + ChaCha20-Poly1305 外层鉴权
- [x] 裸 SYN + 伪 ClientHello + QUIC Initial 同批零等待发出
- [x] 象征性三次握手（SYN-ACK seq 连续，客户端回 ACK）
- [x] quinn-proto 0.11.19 单连接多流 + BBR
- [x] SOCKS5（用户名密码）、HTTP（CONNECT/普通请求/Basic）、HTTPS 本地入口
- [x] 同端口内核 TCP 真证书网站 + 内置 HTML
- [x] iptables 规则自动安装（net.mode auto/none）
- [x] 单元测试 5 项、本机联调、跨境联调、错误密码拒绝

## 待办（按优先级）

1. [ ] 客户端 `tick` 从固定 5ms 改为「精确 deadline + 最小 5ms」，降低 RTT 和 CPU 唤醒
2. [ ] 支持 `listen: :443` 生产端口（已支持配置，仅测试用 8443）
3. [ ] 服务端 `syn_seqs` 表增加超时清理，避免长期运行内存增长
4. [ ] 增加 `flowtls check` 配置校验子命令
5. [ ] 可选：MTU 1400 探测（当前 1200，包数多 14%）
6. [ ] 可选：QUIC 0-RTT 会话复用，降低重连延迟
7. [ ] 可选：多用户（users map）与服务端用户隔离
8. [ ] 可选：伪装网站反向代理真实站点
9. [ ] 可选：客户端连接池（多 QUIC 连接分摊单连接丢包）

## 已知问题

- 跨境链路实测丢包较高（BBR 统计 lost 比例大），但吞吐已达 1.6MB/s。
- 服务端 1 核，outbound 任务与事件循环共享 worker，重负载下 RTT 抖动。
- CloudFlare Origin 证书浏览器不信任，仅适合代理伪装；生产建议换 Let's Encrypt 或商业证书。
