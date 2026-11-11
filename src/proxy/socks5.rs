//! SOCKS5 入口，支持 RFC1929 用户名密码认证。
//!
//! 只实现 CONNECT 命令：浏览器的 HTTPS 流量、以及绝大多数代理客户端
//! 都走 CONNECT，足够覆盖实际使用。

use std::net::SocketAddr;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::client::{pipe_stream, ProxyClient};
use crate::proxy::encode_target;

/// 启动 SOCKS5 监听。
pub async fn run(
    addr: SocketAddr,
    auth: (String, String),
    client: ProxyClient,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("SOCKS5 监听失败: {addr}"))?;
    loop {
        let (stream, peer) = listener.accept().await?;
        let auth = auth.clone();
        let client = client.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, auth, client).await {
                tracing::debug!(%peer, error = %e, "SOCKS5 会话结束");
            }
        });
    }
}

async fn handle(
    mut s: TcpStream,
    auth: (String, String),
    client: ProxyClient,
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
    if req[0] != 5 || req[1] != 1 {
        // 只支持 CONNECT
        let _ = s
            .write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0])
            .await;
        return Ok(());
    }

    // 解析目标地址
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

    // 先回复成功，再建立远端流：浏览器对 CONNECT 的响应很敏感
    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;

    let target = encode_target(&host, port);
    let Some((id, rx)) = client.open(target).await else {
        return Ok(());
    };
    tracing::debug!(%host, port, "SOCKS5 已打开流");
    pipe_stream(s, id, rx, client).await;
    Ok(())
}
