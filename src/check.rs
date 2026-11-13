//! 配置校验子命令（`flowtls check`）。
//!
//! 为什么需要它：
//! 这个项目里有几处「两端必须一致、否则静默失效」的约束，
//! 排查成本很高，且失败现象都不指向真实原因：
//!
//! | 不一致项 | 现象 | 排查难度 |
//! |---|---|---|
//! | `password` | 外层 AEAD 全部解密失败，服务端只看到「收到 raw 包 conns=0」 | 高 |
//! | `ip_id_magic` | iptables 规则不命中 → 内核回 RST → 连接建不起来 | 高 |
//! | 证书路径 | 启动即 panic，但有自签回退时会被忽略 | 中 |
//! | `net.mode` 与实际规则 | 规则缺失但进程不报错 | 高 |
//!
//! 这些都是我们实际踩过的坑（见 DEVTIPS 28 / 38），所以做成显式检查。
//! 设计原则：**只做只读检查**，不改任何文件、不动 iptables，
//! 输出按「错误 / 警告 / 通过」分组，退出码 0=无错误、1=有错误。

use std::path::Path;

use anyhow::Result;

use crate::config::{ClientFile, ServerFile};

/// 一条检查结果
enum Level {
    Ok,
    Warn,
    Error,
}

struct Item {
    level: Level,
    text: String,
}

/// 收集检查项，最后统一输出
#[derive(Default)]
struct Report {
    items: Vec<Item>,
}

impl Report {
    fn ok(&mut self, text: impl Into<String>) {
        self.items.push(Item {
            level: Level::Ok,
            text: text.into(),
        });
    }

    fn warn(&mut self, text: impl Into<String>) {
        self.items.push(Item {
            level: Level::Warn,
            text: text.into(),
        });
    }

    fn error(&mut self, text: impl Into<String>) {
        self.items.push(Item {
            level: Level::Error,
            text: text.into(),
        });
    }

    fn errors(&self) -> usize {
        self.items
            .iter()
            .filter(|i| matches!(i.level, Level::Error))
            .count()
    }

    fn warns(&self) -> usize {
        self.items
            .iter()
            .filter(|i| matches!(i.level, Level::Warn))
            .count()
    }

    fn print(&self) {
        for it in &self.items {
            let tag = match it.level {
                Level::Ok => "  通过",
                Level::Warn => "  警告",
                Level::Error => "  错误",
            };
            println!("{tag}  {}", it.text);
        }
    }
}

/// 入口：`flowtls check [--server s.yaml] [--client c.yaml]`
/// 两个都不给时，按当前目录的 server.yaml / client.yaml 自动探测。
pub fn run(server: Option<&Path>, client: Option<&Path>) -> Result<bool> {
    let mut report = Report::default();

    let server_path = server
        .map(|p| p.to_path_buf())
        .or_else(|| Some("server.yaml".into()).filter(|p: &std::path::PathBuf| p.exists()));
    let client_path = client
        .map(|p| p.to_path_buf())
        .or_else(|| Some("client.yaml".into()).filter(|p: &std::path::PathBuf| p.exists()));

    let mut server_cfg: Option<ServerFile> = None;
    let mut client_cfg: Option<ClientFile> = None;

    // ---- 服务端 ----
    if let Some(p) = &server_path {
        match ServerFile::load(p) {
            Ok(cfg) => {
                report.ok(format!("服务端配置已加载: {}", p.display()));
                check_server(&cfg, &mut report);
                server_cfg = Some(cfg);
            }
            Err(e) => report.error(format!("服务端配置加载失败 {}: {e:#}", p.display())),
        }
    }

    // ---- 客户端 ----
    if let Some(p) = &client_path {
        match ClientFile::load(p) {
            Ok(cfg) => {
                report.ok(format!("客户端配置已加载: {}", p.display()));
                check_client(&cfg, &mut report);
                client_cfg = Some(cfg);
            }
            Err(e) => report.error(format!("客户端配置加载失败 {}: {e:#}", p.display())),
        }
    }

    if server_cfg.is_none() && client_cfg.is_none() {
        report.error("没有找到任何配置（可用 --server / --client 指定路径）");
    }

    // ---- 两端一致性 ----
    if let (Some(s), Some(c)) = (&server_cfg, &client_cfg) {
        check_pair(s, c, &mut report);
    }

    report.print();
    let (e, w) = (report.errors(), report.warns());
    println!();
    println!("汇总: {e} 个错误, {w} 个警告");
    Ok(e == 0)
}

/// 服务端单端检查
fn check_server(cfg: &ServerFile, r: &mut Report) {
    // 监听地址必须能解析
    match crate::config::parse_listen(&cfg.listen) {
        Ok(_) => r.ok(format!("listen 可解析: {}", cfg.listen)),
        Err(e) => r.error(format!("listen 无法解析 ({}): {e:#}", cfg.listen)),
    }

    check_server_users(cfg, r);

    // 证书与私钥：必须存在、可读，且能被 rustls 解析。
    // 只检查文件存在是不够的——路径对但文件是空的/格式错时，
    // 服务端会回退到自签证书，伪装网站的证书就悄悄变成了自签，
    // 浏览器访问会直接报不可信。
    check_cert_pair(&cfg.tls.cert, &cfg.tls.key, r);

    if !cfg.site.dir.is_empty() && !Path::new(&cfg.site.dir).exists() {
        r.warn(format!("site.dir 不存在，将使用内置页面: {}", cfg.site.dir));
    }

    check_faketcp(cfg.faketcp.ip_id_magic, &cfg.faketcp.handshake, r);

    if let Some(ip) = &cfg.faketcp.local_ip {
        match ip.parse::<std::net::Ipv4Addr>() {
            Ok(_) => r.ok(format!("faketcp.local_ip 合法: {ip}")),
            Err(_) => r.error(format!("faketcp.local_ip 不是合法 IPv4: {ip}")),
        }
    } else {
        r.warn(
            "未配置 faketcp.local_ip：云主机在 NAT 后面时源 IP 会是内网地址，\
             客户端会丢弃所有回包（本地直连公网的机器可忽略）",
        );
    }

    check_net(&cfg.net.mode, cfg.net.max_cwnd, r);

    // UDP 转发：服务端关掉时客户端发来的 datagram 会被读出来丢弃，
    // 现象是「DNS 能解析（走 TCP 回退）但游戏/语音完全不可用」。
    if cfg.udp.enabled {
        r.ok(format!(
            "UDP 转发已启用（并发会话上限 {}，空闲回收 {}s）",
            cfg.udp.max_sessions, cfg.udp.timeout_secs
        ));
        // 会话上限为 0 会让所有 UDP 会话都被拒绝创建，
        // 但 UDP 本身不报错，只表现为「发出去的包都没有回音」。
        if cfg.udp.max_sessions == 0 {
            r.error("udp.max_sessions 不能为 0（会拒绝所有 UDP 会话）");
        }
        if cfg.udp.timeout_secs == 0 {
            r.warn("udp.timeout_secs=0 会被钳到 10 秒，低频 UDP 会话会被过早回收");
        }
    } else {
        r.warn("udp.enabled=false：客户端发来的 UDP 数据报会被全部丢弃");
    }

    // iptables 规则是否已按该 magic 安装
    if cfg.net.mode == "auto" {
        if let Ok(port) = crate::config::parse_listen(&cfg.listen) {
            let has = crate::rules::check_server(port.port(), cfg.faketcp.ip_id_magic);
            if has {
                r.ok(format!(
                    "iptables 规则已安装（端口 {}, 标记 0x{:04x}）",
                    port.port(),
                    cfg.faketcp.ip_id_magic & 0xFF00
                ));
            } else {
                r.error(format!(
                    "iptables 规则缺失或标记不匹配（期望 0x{:04x}）；\
                     内核会对伪包回 RST，连接建不起来",
                    cfg.faketcp.ip_id_magic & 0xFF00
                ));
            }
        }
    }
}

/// 客户端单端检查
fn check_client(cfg: &ClientFile, r: &mut Report) {
    match crate::config::parse_host_port(&cfg.server) {
        Ok((host, port)) => {
            if host.is_empty() {
                r.error("server 缺少主机名");
            } else if port == 0 {
                r.error("server 端口为 0");
            } else {
                r.ok(format!("server 可解析: {host}:{port}"));
                if port == 443 {
                    r.warn("服务端端口是 443：实测国内出口对 443 的伪造 TCP 检查更严，建议 8443/9443");
                }
            }
        }
        Err(e) => r.error(format!("server 无法解析 ({}): {e:#}", cfg.server)),
    }

    check_password(&cfg.password, "客户端", r);

    // 源端口：0 非法；与监听端口相同会导致规则歧义
    if cfg.faketcp.source_port == 0 {
        r.error("faketcp.source_port 不能为 0");
    } else {
        r.ok(format!("faketcp.source_port: {}", cfg.faketcp.source_port));
        if let Ok((_, server_port)) = crate::config::parse_host_port(&cfg.server) {
            if cfg.faketcp.source_port == server_port {
                r.warn("faketcp.source_port 与服务端端口相同，NAT 场景下易与真实流量混淆");
            }
        }
    }

    check_faketcp(cfg.faketcp.ip_id_magic, &cfg.faketcp.handshake, r);

    if cfg.faketcp.handshake == "none" {
        r.warn(
            "handshake=none：要求客户端直接持有公网 IP，\
             否则严格 NAT 会丢弃握手完成前的数据包",
        );
    }

    check_net(&cfg.net.mode, cfg.net.max_cwnd, r);

    // 伪装用 SNI：客户端连 IP 时不发 SNI 扩展（与真实浏览器一致），
    // 但配一个真实域名会让握手外观更接近浏览器（也能配合真实证书站点）。
    let sni = cfg.effective_sni();
    if sni.is_empty() {
        r.warn("未配置 sni，且无法从 server 推导");
    } else if sni.parse::<std::net::IpAddr>().is_ok() {
        r.warn(format!(
            "sni 是 IP 地址 ({sni})：伪 ClientHello 会自动省略 SNI 扩展\
             （与真实浏览器用 IP 直连时一致）。想更接近浏览器可配一个真实域名"
        ));
    } else {
        r.ok(format!("伪装 SNI: {sni}"));
    }

    // 入口至少要有可用的
    if cfg.socks5.is_none() && cfg.http.is_none() && cfg.https.is_none() {
        r.warn("没有配置任何本地入口（socks5 / http / https 全为空），客户端起来也没法用");
    }

    // UDP 转发：SOCKS5 是唯一的 UDP 入口（HTTP/HTTPS 代理协议本身不支持 UDP），
    // 所以没配 socks5 时开不开 udp 都没用，必须提醒。
    if cfg.udp.enabled {
        if cfg.socks5.is_some() {
            r.ok(format!(
                "UDP 转发已启用（会话上限 {}，空闲回收 {}s），入口为 SOCKS5 UDP ASSOCIATE",
                cfg.udp.max_sessions, cfg.udp.timeout_secs
            ));
        } else {
            r.warn(
                "udp.enabled=true 但没有配置 socks5 入口：\
                 HTTP/HTTPS 代理协议不支持 UDP，UDP 实际上用不了",
            );
        }
    } else {
        r.warn("udp.enabled=false：SOCKS5 的 UDP ASSOCIATE 会被拒绝（返回命令不支持）");
    }
    if cfg.udp.max_sessions == 0 {
        r.error("udp.max_sessions 不能为 0（会拒绝所有 UDP 会话）");
    }
    if cfg.udp.timeout_secs == 0 {
        r.warn("udp.timeout_secs=0 会被钳到 10 秒，低频 UDP 会话会被过早回收");
    }
    for (name, inb) in [
        ("socks5", cfg.socks5.as_ref()),
        ("http", cfg.http.as_ref()),
        ("https", cfg.https.as_ref()),
    ] {
        if let Some(i) = inb {
            if let Err(e) = crate::config::parse_listen(&i.listen) {
                r.error(format!("{name}.listen 无法解析 ({}): {e:#}", i.listen));
            }
            if i.username.is_empty() || i.password.is_empty() {
                r.warn(format!("{name} 没有配置用户名密码，本机任何进程都能使用该代理"));
            }
        }
    }

    if cfg.net.mode == "auto" {
        let has = crate::rules::check_client(cfg.faketcp.source_port);
        if has {
            r.ok("客户端 iptables 规则已安装（屏蔽内核 RST）");
        } else {
            r.warn("客户端 iptables 规则缺失：内核可能为回包产生 RST 噪音");
        }
    }
}

/// 两端一致性：这两项不一致时现象都很隐蔽，是 check 的核心价值
fn check_pair(s: &ServerFile, c: &ClientFile, r: &mut Report) {
    // 密码必须命中服务端的某个用户（外层 AEAD 密钥由它派生）。
    //
    // 多用户下不能再用「两个 password 字段相等」来判断：
    // 服务端可能只写了 users，顶层 password 为空。
    let users = s.effective_users();
    if users.iter().any(|(_, p)| p == &c.password) {
        if users.len() > 1 {
            r.ok(format!(
                "客户端 password 命中服务端 {} 个用户之一",
                users.len()
            ));
        } else {
            r.ok("两端 password 一致");
        }
    } else {
        r.error(format!(
            "客户端 password 不在服务端用户表里（服务端 {} 个用户）：\
             外层 AEAD 会全部解密失败，\
             服务端只表现为「收到 raw 包但 conns=0」",
            users.len()
        ));
    }

    // 分流标记高字节必须一致（iptables 与伪包判别都依赖它）
    let sm = s.faketcp.ip_id_magic & 0xFF00;
    let cm = c.faketcp.ip_id_magic & 0xFF00;
    if sm == cm {
        r.ok(format!("两端 ip_id_magic 高字节一致: 0x{sm:04x}"));
        if sm == 0 {
            r.error("ip_id_magic 高字节为 0：与大量真实流量重合，规则会误伤");
        }
    } else {
        r.error(format!(
            "两端 ip_id_magic 高字节不一致（服务端 0x{sm:04x} / 客户端 0x{cm:04x}）：\
             服务端 iptables 打不中伪包，内核回 RST，连接建不起来"
        ));
    }

    // 服务端端口与客户端指向的端口
    if let (Ok(sp), Ok((_, cp))) = (
        crate::config::parse_listen(&s.listen),
        crate::config::parse_host_port(&c.server),
    ) {
        if sp.port() == cp {
            r.ok(format!("端口一致: {cp}"));
        } else {
            r.error(format!(
                "端口不一致（服务端 listen {} / 客户端指向 {cp}）",
                sp.port()
            ));
        }
    }

    // UDP 开关必须两端一致：QUIC DATAGRAM 是双向协商的，
    // 但两端配置不一致时**不会报错**（不像密码不一致会解密失败），
    // 只会表现为「UDP 包发出去石沉大海」，非常难排查。
    if s.udp.enabled == c.udp.enabled {
        r.ok(format!(
            "两端 udp.enabled 一致: {}",
            if s.udp.enabled { "启用" } else { "关闭" }
        ));
    } else {
        r.error(format!(
            "两端 udp.enabled 不一致（服务端 {} / 客户端 {}）：\
             UDP 包会单向消失，且没有任何错误日志",
            s.udp.enabled, c.udp.enabled
        ));
    }
}

/// 服务端用户表校验。
///
/// 多用户是 2026-11-13 引入的（wire format v2），这里的每一条都对应
/// 一个「配错了不报错、只是连不上」的坑。
fn check_server_users(cfg: &ServerFile, r: &mut Report) {
    if cfg.users.is_empty() {
        // 单用户模式：顶层 password 就是唯一凭证
        check_password(&cfg.password, "服务端", r);
        if !cfg.password.is_empty() {
            r.ok("单用户模式（未配置 users）");
        }
        return;
    }

    r.ok(format!("多用户模式: {} 个用户", cfg.users.len()));

    // 顶层 password 在多用户模式下是多余的，容易让人误以为它仍生效
    if !cfg.password.is_empty() {
        r.warn("已配置 users，顶层 password 会被忽略；建议删掉避免误会");
    }

    // 用 auth id（密码派生值）查重，而不是比较 name：
    // 真正决定「能不能分别鉴权」的是密码，name 只是日志标签。
    let mut seen: std::collections::HashMap<[u8; crate::faketcp::codec::AUTH_ID_LEN], String> =
        std::collections::HashMap::new();
    let mut seen_names: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    let mut ok_count = 0usize;
    for (i, u) in cfg.users.iter().enumerate() {
        let label = if u.name.is_empty() {
            format!("user[{i}]")
        } else {
            u.name.clone()
        };
        if u.password.is_empty() {
            r.error(format!("{label} 的 password 为空"));
            continue;
        }
        ok_count += 1;
        if u.password.len() < 8 {
            r.warn(format!(
                "{label} 的 password 只有 {} 个字符，建议 16 位以上",
                u.password.len()
            ));
        }
        let id = crate::faketcp::codec::Obfs::new_server(&u.password).auth_id();
        if let Some(other) = seen.insert(id, label.clone()) {
            r.error(format!(
                "{label} 与 {other} 的 password 相同：auth id 冲突，\
                 后一个用户会被静默覆盖（配置改了但登录失败就是这个）"
            ));
        }
        // name 重复不影响鉴权，但日志里会分不清是谁，属于该修的配置问题
        *seen_names.entry(u.name.as_str()).or_insert(0) += 1;
    }
    for (name, count) in seen_names {
        if count > 1 {
            let label = if name.is_empty() { "(空名字)" } else { name };
            r.warn(format!("{label} 出现了 {count} 次，日志里无法区分"));
        }
    }
    // 所有用户都填了密码时给一条正反馈，方便确认检查确实跑到了
    if ok_count == cfg.users.len() {
        r.ok(format!("{ok_count} 个用户均配置了 password"));
    }
}

fn check_password(p: &str, who: &str, r: &mut Report) {
    if p.is_empty() {
        r.error(format!("{who} password 为空"));
    } else if p.len() < 8 {
        r.warn(format!(
            "{who} password 只有 {} 个字符，建议 16 位以上（它是外层 AEAD 的密钥来源）",
            p.len()
        ));
    } else {
        r.ok(format!("{who} password 长度: {}", p.len()));
    }
}

fn check_faketcp(magic: u16, handshake: &str, r: &mut Report) {
    let mark = magic & 0xFF00;
    if mark == 0 {
        r.error("ip_id_magic 高字节不能为 0");
    } else if mark == crate::faketcp::packet::IPID_MARK {
        // 编译默认值：所有没改过配置的部署都用它，等于共用同一个线上特征
        r.warn(format!(
            "ip_id_magic 仍是编译默认值 0x{magic:04x}：\
             所有未改配置的部署特征相同，建议按部署改成不同值（DEVTIPS 38）"
        ));
    } else if mark == 0xFF00 {
        r.warn("ip_id_magic 高字节为 0xFF，建议换成不显眼的值");
    } else {
        r.ok(format!("伪包标记高字节: 0x{mark:04x}"));
    }
    if !matches!(handshake, "symbolic" | "none") {
        r.error(format!(
            "faketcp.handshake 只能是 symbolic 或 none，实际是 {handshake}"
        ));
    }
}

fn check_net(mode: &str, max_cwnd: u64, r: &mut Report) {
    if !matches!(mode, "auto" | "none") {
        r.error(format!("net.mode 只能是 auto 或 none，实际是 {mode}"));
    }
    // 窗口低于 512KB 跑不满 100Mbps；高于 40MB 会触发 quinn 的
    // MAX_CHUNKS 空洞上限（见 quic/config.rs 的说明）
    if max_cwnd < 512 * 1024 {
        r.warn(format!(
            "net.max_cwnd 偏小 ({})，100ms RTT 下跑不满 100Mbps",
            max_cwnd
        ));
    } else if max_cwnd > 40 * 1024 * 1024 {
        r.warn(format!(
            "net.max_cwnd 偏大 ({} > 40MB)：高丢包时会超出 quinn 的空洞上限导致断连",
            max_cwnd
        ));
    }
}

/// 证书/私钥：存在性 + PEM 可解析性
fn check_cert_pair(cert: &Path, key: &Path, r: &mut Report) {
    let cert_ok = read_pem_certs(cert).map(|v| !v.is_empty());
    match cert_ok {
        Ok(true) => r.ok(format!("证书可解析: {}", cert.display())),
        Ok(false) => r.error(format!("证书文件里没有证书: {}", cert.display())),
        Err(e) => r.error(format!("证书无法读取/解析 {}: {e}", cert.display())),
    }

    match std::fs::read(key) {
        Ok(bytes) => match rustls_pemfile::private_key(&mut bytes.as_slice()) {
            Ok(Some(_)) => r.ok(format!("私钥可解析: {}", key.display())),
            Ok(None) => r.error(format!("私钥文件里没有私钥: {}", key.display())),
            Err(e) => r.error(format!("私钥格式错误 {}: {e}", key.display())),
        },
        Err(e) => r.error(format!("私钥无法读取 {}: {e}", key.display())),
    }
}

fn read_pem_certs(path: &Path) -> std::io::Result<Vec<Vec<u8>>> {
    let data = std::fs::read(path)?;
    let mut out = Vec::new();
    for item in rustls_pemfile::certs(&mut data.as_slice()) {
        match item {
            Ok(c) => out.push(c.to_vec()),
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e.to_string(),
                ))
            }
        }
    }
    Ok(out)
}
