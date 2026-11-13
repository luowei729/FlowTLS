# 配置迁移：Rust YAML → sing-box JSON

Rust 实现已冻结（见 [`EVOLUTION.md`](EVOLUTION.md)），配置格式也从 YAML 变成
sing-box 的 JSON。本文是逐字段对照表。

> 重要差别：**sing-box 没有自带入口**。
> Rust 版自带 SOCKS5 / HTTP / HTTPS 入口，sing-box 版把入口交给 sing-box 的
> `socks` / `http` / `mixed` inbound，flowtls 只负责隧道。

---

## 服务端

### Rust（`server.yaml`）

```yaml
listen: "0.0.0.0:8443"
password: "换成你自己的密码"
users:                          # 可选，多用户
  - name: "alice"
    password: "alice-pass"
tls:                            # 伪装网站的真证书
  cert: "/etc/ssl/fullchain.pem"
  key: "/etc/ssl/privkey.pem"
site:
  dir: ""                       # 留空用内置页面
faketcp:
  ip_id_magic: 0xF107
  handshake: symbolic
  local_ip: "1.2.3.4"
net:
  mode: "auto"
  max_cwnd: 8388608
udp:
  enabled: true
  max_sessions: 256
  timeout_secs: 120
```

### sing-box（`server.json`）

```json
{
  "inbounds": [
    {
      "type": "flowtls",
      "tag": "flowtls-in",
      "listen": "0.0.0.0",
      "listen_port": 8443,
      "password": "换成你自己的密码",
      "users": [{ "name": "alice", "password": "alice-pass" }],
      "local_ip": "1.2.3.4",
      "ip_id_mark": 61703,
      "udp_session_timeout": 120,
      "iptables_mode": "print"
    }
  ],
  "outbounds": [{ "type": "direct", "tag": "direct" }]
}
```

### 字段对照

| Rust YAML | sing-box JSON | 说明 |
|---|---|---|
| `listen: "0.0.0.0:8443"` | `listen` + `listen_port` | 拆成两个字段 |
| `password` | `password` | 一致；外层 AEAD 的密钥来源 |
| `users[].name/password` | `users[].name/password` | 一致；`users` 非空时忽略 `password` |
| `faketcp.ip_id_magic` | `ip_id_mark` | 改名；**十进制** JSON 数值（`0xF107` = `61703`） |
| `faketcp.local_ip` | `local_ip` | 提到顶层；NAT 后必须填公网 IP |
| `faketcp.handshake` | —— | 服务端恒为「标准三次握手」，无开关 |
| `udp.timeout_secs` | `udp_session_timeout` | 改名，单位仍是秒 |
| `udp.enabled` | —— | DATAGRAM 恒开（不配就是不允许，配了就有） |
| `udp.max_sessions` | —— | 由 QUIC 流控与内存自然约束，不再单独设上限 |
| `net.mode` | `iptables_mode` | `none`/`print`/`auto` 语义相同，但默认是 `print` |
| `net.max_cwnd` | —— | Go 侧交给 quic-go 的 BBR，不再手工设窗口上限 |
| `tls.cert` / `tls.key` | `masquerade.certificate_path` / `key_path` | 伪装网站的真证书，不是协议证书（见下） |
| `site.dir` | `masquerade.site_dir` | 留空返回占位页，生产必须填真实内容 |

### 两个「消失」的字段怎么处理

**1. `tls.cert` / `tls.key`（伪装网站证书）**

Go 版对应 `masquerade.certificate_path` / `masquerade.key_path`，
语义完全一样：**真证书**（Let's Encrypt / CloudFlare Origin CA 等）。

```json
"masquerade": {
  "site_dir": "/var/www/lumen-edge",
  "certificate_path": "/etc/ssl/private/fullchain.pem",
  "key_path": "/etc/ssl/private/privkey.pem"
}
```

不配 `masquerade` 时 inbound 只做隧道，端口交给别的进程也行：

```bash
caddy file-server --root /var/www --listen :8443 --tls you@example.com
```

> 内层 QUIC 用的证书是**运行时自签**，不需要配置——安全性由外层 AEAD 保证。
> 这两者不要混淆。

**2. `site.dir`**

对应 `masquerade.site_dir`。留空会返回一个 503 占位页——
**生产必须填真实内容**，占位页本身就是指纹。页面素材可用
[`web/index.html`](../web/index.html)。

---

## 客户端

### Rust（`client.yaml`）

```yaml
server: "1.2.3.4:8443"
password: "与服务端一致"
sni: "your.domain"
faketcp:
  source_port: 44300
  handshake: symbolic
  ip_id_magic: 0xF107
socks5:
  listen: "0.0.0.0:1080"
  username: "admin"
  password: "abcd1234"
http:
  listen: "0.0.0.0:8080"
  username: "admin"
  password: "abcd1234"
https:
  listen: "127.0.0.1:8443"
  self_signed: true
net:
  mode: "auto"
```

### sing-box（`client.json`）

```json
{
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 1080,
      "users": [{ "username": "admin", "password": "abcd1234" }]
    }
  ],
  "outbounds": [
    {
      "type": "flowtls",
      "tag": "flowtls-out",
      "server": "1.2.3.4",
      "server_port": 8443,
      "password": "与服务端一致",
      "source_port": 44300,
      "ip_id_mark": 61703,
      "sni": "your.domain"
    }
  ]
}
```

### 字段对照

| Rust YAML | sing-box JSON | 说明 |
|---|---|---|
| `server: "host:port"` | `server` + `server_port` | 拆成两个字段 |
| `password` | `password` | 一致 |
| `sni` | `sni` | 一致，只影响伪 ClientHello 外观 |
| `faketcp.source_port` | `source_port` | 一致；用于 iptables 精确匹配内核 RST |
| `faketcp.ip_id_magic` | `ip_id_mark` | 改名，十进制（`0xF107` = `61703`） |
| `faketcp.handshake: symbolic` | （默认开启） | 无需配置 |
| `faketcp.handshake: none` | `"disable_handshake": true` | **反向字段**：不写＝开启握手 |
| `socks5.listen/username/password` | `socks` inbound 的 `listen_port`/`users` | 用 sing-box 自带的 |
| `http.*` | `http` inbound | 用 sing-box 自带的 |
| `https.*` | `mixed` inbound（需 TLS 时用 `http` + `tls`） | 用 sing-box 自带的 |
| `net.mode` | `iptables_mode` | 客户端建议 `auto` |

> `disable_handshake` 为什么是反的：Go 的 bool 零值是 `false`，
> 若字段写成 `handshake`，默认行为会变成「关闭握手」——而正确默认是**开启**
> （严格 NAT 只放行握手完成的流量）。反向命名让零值等于安全默认。

---

## 一次性迁移的取舍

| 项 | Rust | sing-box |
|---|---|---|
| 多用户 | `users` 列表 | `users` 列表（`authID` 由密码派生，用户名只进日志） |
| UDP | SOCKS5 UDP ASSOCIATE | QUIC DATAGRAM，任意入站都能用 |
| 路由 | 无 | 全套（`route.rules`、DNS、`rule_set`） |
| TUN | 无 | 有 |
| 面板 | 无 | Clash API / 官方面板 |
| 伪装网站 | 内置 | `masquerade` 开启后内置于 inbound（也可交给 nginx/caddy） |
| 配置校验 | `flowtls check --server a.yaml --client b.yaml` | `sing-box check -c config.json`（**不需要 root**） |

---

## 迁移检查清单

1. `ip_id_magic` 的十六进制值换成十进制写进 `ip_id_mark`（或直接用字符串以外的数字）。
2. `listen: "host:port"` 拆成 `listen` + `listen_port`。
3. 客户端原来的 `socks5`/`http`/`https` 入口换成 sing-box inbound。
4. `net.mode: auto` 换成 `iptables_mode: "auto"`；第一次先留 `"print"` 看一眼规则。
5. 伪装网站单独起进程，证书别和内层 QUIC 的自签证书搞混。
6. `sing-box check -c client.json` / `server.json` 都过一遍再启动。
7. 用 `bash docs/e2e_matrix.sh` 在生产链路附近做一次实测（4 格矩阵或 Go↔Go）。
