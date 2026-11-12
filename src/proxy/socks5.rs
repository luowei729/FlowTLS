//! SOCKS5 入口，支持 RFC1929 用户名密码认证。
//!
//! 支持两个命令：
//! - `CONNECT`（CMD=1）：浏览器的 HTTPS 流量、绝大多数代理客户端都走这个；
//! - `UDP ASSOCIATE`（CMD=3）：UDP relay，DNS/语音/游戏/QUIC 都依赖它。
//!
//! 不实现 `BIND`（CMD=2）：它早已被 CONNECT 完全取代，实际没有客户端在用。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::client::{pipe_stream, ProxyClient};
use crate::proxy;

/// UDP relay 参数（从客户端配置 `udp` 节传进来）
#[derive(Debug, Clone, Copy)]
pub struct UdpOptions {
    pub enabled: bool,
    pub max_sessions: usize,
    pub timeout_secs: u64,
}

/// 启动 SOCKS5 监听。
pub async fn run(
    addr: SocketAddr,
    auth: (String, String),
    client: ProxyClient,
    udp: UdpOptions,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("SOCKS5 监听失败: {addr}"))?;
    loop {
        let (stream, peer) = listener.accept().await?;
        let auth = auth.clone();
        let client = client.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, auth, client, udp).await {
                tracing::debug!(%peer, error = %e, "SOCKS5 会话结束");
            }
        });
    }
}

async fn handle(
    mut s: TcpStream,
    auth: (String, String),
    client: ProxyClient,
    udp: UdpOptions,
) -> Result<()> {
    let _ = s.set_nodelay(true);

    // ---- 方法协商 ----
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Ok(());
    }
    let mut methods = vec![0u8; head[1] as usize];
    s.read_exact(&mut methods).await?;

    let need_auth = !auth.0.is_empty();
    if need_auth {
        // 配置了用户名密码时，只接受用户名密码认证
        if !methods.contains(&0x02) {
            s.write_all(&[5, 0xff]).await?;
            return Ok(());
        }
        s.write_all(&[5, 0x02]).await?;
        // RFC1929：VER ULEN UNAME PLEN PASSWD
        let mut v = [0u8; 2];
        s.read_exact(&mut v).await?;
        let mut uname = vec![0u8; v[1] as usize];
        s.read_exact(&mut uname).await?;
        let mut plen = [0u8; 1];
        s.read_exact(&mut plen).await?;
        let mut passwd = vec![0u8; plen[0] as usize];
        s.read_exact(&mut passwd).await?;
        if uname != auth.0.as_bytes() || passwd != auth.1.as_bytes() {
            // 认证失败：回复失败并断开
            s.write_all(&[1, 1]).await?;
            return Ok(());
        }
        s.write_all(&[1, 0]).await?;
    } else {
        s.write_all(&[5, 0]).await?;
    }

    // ---- 请求：VER CMD RSV ATYP ----
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[0] != 5 {
        return Ok(());
    }

    // 两种命令的地址都要先读完再分流：
    // CONNECT 是目的地址；UDP ASSOCIATE 是「客户端将从哪发 UDP」的提示地址
    // （RFC 1928 允许填 0.0.0.0:0，我们同样不校验——客户端换个网卡就变了，
    //  真正的准入靠这条 TCP 控制连接本身）。
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        4 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            s.read_exact(&mut d).await?;
            String::from_utf8(d)?
        }
        _ => return Ok(()),
    };
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await?;
    let port = u16::from_be_bytes(p);

    match req[1] {
        1 => {
            // ---- CONNECT 隧道 ----
            // 先回复成功，再建立远端流：浏览器对 CONNECT 的响应很敏感
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;

            let target = proxy::encode_target(&host, port);
            let Some((epoch, id, rx)) = client.open(target).await else {
                return Ok(());
            };
            tracing::debug!(%host, port, "SOCKS5 已打开流");
            pipe_stream(s, epoch, id, rx, client).await;
        }
        3 => {
            // ---- UDP ASSOCIATE ----
            tracing::debug!(%host, port, "SOCKS5 请求 UDP ASSOCIATE");
            // 记下控制连接的来源 IP：UDP relay 靠它做准入。
            // relay socket 本身没有认证（UDP 无连接，RFC 1928 也不要求），
            // 如果接受任意来源，同网段的任何人都能在猜到端口后白嫖这个代理。
            let peer_ip = s.peer_addr().ok().map(|a| a.ip());
            handle_udp_associate(s, client, udp, peer_ip).await?;
        }
        _ => {
            // 只支持 CONNECT / UDP ASSOCIATE；BIND 返回「命令不支持」
            let _ = s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        }
    }
    Ok(())
}

/// 一个 UDP 会话的本地元信息。
struct UdpPeer {
    /// 发来这个会话第一个包的本地应用地址（回程往这里发）
    peer: SocketAddr,
    /// 目标地址帧 `[ATYP][ADDR][PORT]`，回程要原样填进 SOCKS5 UDP 头
    target: Vec<u8>,
    /// 最后一次活动时间，用于超时回收
    last_active: Instant,
}

/// SOCKS5 UDP ASSOCIATE（RFC 1928 §7）。
///
/// 控制连接（这条 TCP）只用于**保活**：它一断，整个 UDP relay 立刻结束、
/// 所有 session 注销。这是 RFC 要求的行为，也是客户端唯一能正确感知
/// 「代理侧 UDP 已经不可用」的机制。
///
/// 数据面在独立的 UDP socket 上跑：
/// - 上行：本地应用 → relay socket → 按 `(peer, target)` 查/建 session
///   → `client.send_udp`（QUIC DATAGRAM，不重传、满即丢）；
/// - 下行：QUIC DATAGRAM → `ProxyClient` 按 session 投到这个 relay 的通道
///   → 组装 `RSV|FRAG|地址帧|载荷` → `send_to(peer)`。
async fn handle_udp_associate(
    mut s: TcpStream,
    client: ProxyClient,
    opts: UdpOptions,
    peer_ip: Option<std::net::IpAddr>,
) -> Result<()> {
    if !opts.enabled {
        // 配置里关了 UDP：按 RFC 回「命令不支持」，客户端会自动回退到 TCP
        s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        tracing::debug!("UDP 转发已关闭，拒绝 UDP ASSOCIATE");
        return Ok(());
    }

    // 绑 0.0.0.0 而不是 127.0.0.1：允许局域网里其它设备把本机当代理用
    // （与 SOCKS5 TCP 入口的语义保持一致）。
    let sock = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .context("UDP relay 监听失败")?,
    );
    let bnd = sock.local_addr()?;
    // 回复 BND.ADDR / BND.PORT：客户端拿到后会往这里发 UDP
    s.write_all(&socks5_reply(0x00, bnd)).await?;
    tracing::debug!(%bnd, "UDP relay 已就绪");

    // 下行通道：这个 relay 的所有 session 共用一个。
    // 通道里带 session id，回程要靠它查 UdpPeer 拿 peer 和 target。
    let (down_tx, mut down_rx) = mpsc::unbounded_channel::<(u32, Vec<u8>)>();

    // relay 的本地表：session → 元信息
    let mut peers: HashMap<u32, UdpPeer> = HashMap::new();
    // 反向索引：(peer, target) → session，同一个目标不必重复建会话
    let mut index: HashMap<(SocketAddr, Vec<u8>), u32> = HashMap::new();

    let mut buf = vec![0u8; 65536];
    let mut pkt = Vec::with_capacity(2048);
    // 每 30 秒顺手回收一次空闲 session（UDP 无连接，只能靠超时感知对端消失）
    let mut reap = tokio::time::interval(Duration::from_secs(30));
    reap.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // 下限 10 秒：配成 0 或 1 会让 DNS 这种低频会话刚建就被回收
    let idle = Duration::from_secs(opts.timeout_secs.max(10));

    // 控制连接上不该再有数据；读到 EOF 或错误就说明客户端关了 relay。
    // 用 1 字节缓冲：RFC 里 UDP ASSOCIATE 之后这条 TCP 是纯保活，
    // 万一有数据也只可能是不合规的客户端，忽略即可。
    let mut ctrl = [0u8; 1];

    loop {
        tokio::select! {
            // 1. 上行：本地应用发来的 UDP
            r = sock.recv_from(&mut buf) => {
                let Ok((n, from)) = r else { break };
                // 准入检查：只接受与控制连接同源 IP 的包。
                // 端口没法校验（本地应用用的是随机源端口），但 IP 足以挡住
                // 同网段其它机器——它们本来也没有这个代理的密码。
                if let Some(want) = peer_ip {
                    if from.ip() != want {
                        tracing::debug!(%from, %want, "UDP relay 拒绝非控制连接同源 IP 的包");
                        continue;
                    }
                }
                // RFC 1928 的 UDP 头；解析失败（分片包/畸形包）直接丢
                let Some((target, off)) = proxy::parse_socks5_udp(&buf[..n]) else {
                    continue;
                };
                if target.is_empty() {
                    continue;
                }
                let payload = &buf[off..n];
                let key = (from, target.to_vec());
                // 查/建 session。会话数上限按配置截断：
                // 单个应用疯狂开目标（比如 P2P）时不能把内存撑爆。
                let session = match index.get(&key) {
                    Some(id) => *id,
                    None => {
                        if peers.len() >= opts.max_sessions {
                            tracing::trace!(
                                %from,
                                limit = opts.max_sessions,
                                "UDP 会话数已达上限，丢弃新会话"
                            );
                            continue;
                        }
                        let id = client.register_udp(down_tx.clone());
                        index.insert(key.clone(), id);
                        peers.insert(id, UdpPeer {
                            peer: from,
                            target: target.to_vec(),
                            last_active: Instant::now(),
                        });
                        tracing::debug!(%from, session = id, "新建 UDP 会话");
                        id
                    }
                };
                if let Some(p) = peers.get_mut(&session) {
                    p.last_active = Instant::now();
                }
                // 非阻塞投递：QUIC 侧跟不上就丢，绝不反压本地收包循环
                client.send_udp(session, target.to_vec(), payload.to_vec());
            }
            // 2. 下行：QUIC datagram 回来了
            maybe = down_rx.recv() => {
                let Some((session, payload)) = maybe else { break };
                let Some(p) = peers.get_mut(&session) else { continue };
                p.last_active = Instant::now();
                // 组 SOCKS5 UDP 响应：RSV(2) FRAG(1) + 地址帧 + 载荷
                proxy::build_socks5_udp(&p.target, &payload, &mut pkt);
                // 本地应用可能已经退出，send_to 失败直接忽略
                let _ = sock.send_to(&pkt, p.peer).await;
            }
            // 3. 控制连接关闭 = relay 结束（RFC 1928 要求）
            r = s.read(&mut ctrl) => {
                match r {
                    Ok(0) => tracing::debug!("UDP relay 控制连接已关闭"),
                    Ok(_) => continue, // 不该有数据，忽略并继续
                    Err(_) => {}
                }
                break;
            }
            // 4. 定期回收空闲 session
            _ = reap.tick() => {
                let now = Instant::now();
                let before = peers.len();
                peers.retain(|id, p| {
                    let keep = now.duration_since(p.last_active) < idle;
                    if !keep {
                        index.remove(&(p.peer, p.target.clone()));
                        client.unregister_udp(*id);
                    }
                    keep
                });
                if peers.len() != before {
                    tracing::debug!(
                        closed = before - peers.len(),
                        active = peers.len(),
                        "UDP 会话空闲超时回收"
                    );
                }
            }
        }
    }

    // relay 结束：注销所有 session，避免 ProxyClient 里留下收不到东西的路由
    for id in peers.keys() {
        client.unregister_udp(*id);
    }
    tracing::debug!(sessions = peers.len(), "UDP relay 已结束");
    Ok(())
}

/// 组装 SOCKS5 应答：`VER REP RSV ATYP + BND.ADDR + BND.PORT`
fn socks5_reply(rep: u8, bnd: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(22);
    out.push(5);
    out.push(rep);
    out.push(0);
    match bnd {
        SocketAddr::V4(a) => {
            out.push(1);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            out.push(4);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    out
}
