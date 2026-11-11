//! HTTP / HTTPS 入口。
//!
//! 支持 CONNECT 隧道和普通 HTTP 绝对 URI 请求，带 Basic 认证。
//! HTTPS 入口是「本地 TLS + 同一套 HTTP 代理逻辑」，用自签证书，
//! 只用于浏览器把代理地址填成 https:// 的场景。

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::client::{pipe_stream, ProxyClient};
use crate::proxy::encode_target;

/// 明文 HTTP 代理监听
pub async fn run(addr: SocketAddr, auth: (String, String), client: ProxyClient) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("HTTP 监听失败: {addr}"))?;
    loop {
        let (stream, peer) = listener.accept().await?;
        let auth = auth.clone();
        let client = client.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, auth, client, peer).await {
                tracing::debug!(%peer, error = %e, "HTTP 会话结束");
            }
        });
    }
}

/// 本地 TLS 代理监听
pub async fn run_tls(addr: SocketAddr, auth: (String, String), client: ProxyClient) -> Result<()> {
    // 本地入口用运行时自签证书，浏览器首次访问需要手动信任
    let cert = rcgen::generate_simple_self_signed(vec!["flowtls-local".to_string()])
        .context("生成本地自签证书失败")?;
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key),
        )
        .context("本地 TLS 配置失败")?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("HTTPS 入口监听失败: {addr}"))?;
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let auth = auth.clone();
        let client = client.clone();
        tokio::spawn(async move {
            let Ok(tls_stream) = acceptor.accept(stream).await else {
                return;
            };
            if let Err(e) = handle(tls_stream, auth, client, peer).await {
                tracing::debug!(%peer, error = %e, "HTTPS 会话结束");
            }
        });
    }
}

async fn handle<S>(
    mut s: S,
    auth: (String, String),
    client: ProxyClient,
    peer: SocketAddr,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // ---- 读完整请求头 ----
    let mut buf = Vec::with_capacity(4096);
    let head_end = loop {
        let mut chunk = [0u8; 4096];
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(p) = find_headers_end(&buf) {
            break p;
        }
        if buf.len() > 16384 {
            return Ok(());
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let first = lines.next().unwrap_or_default().to_string();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let uri = parts.next().unwrap_or("").to_string();

    // ---- Basic 认证 ----
    if !auth.0.is_empty() {
        let expected = format!("{}:{}", auth.0, auth.1);
        let ok = head.lines().any(|l| {
            // 只对头名做大小写不敏感比较；Base64 值本身大小写敏感，不能一起转小写
            let Some((name, value)) = l.split_once(':') else {
                return false;
            };
            if !name.trim().eq_ignore_ascii_case("proxy-authorization") {
                return false;
            }
            let v = value.trim();
            let Some(encoded) = v
                .strip_prefix("Basic ")
                .or_else(|| v.strip_prefix("basic "))
            else {
                return false;
            };
            b64_decode(encoded)
                .map(|d| d == expected.as_bytes())
                .unwrap_or(false)
        });
        if !ok {
            s.write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"flowtls\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await?;
            return Ok(());
        }
    }

    if method == "CONNECT" {
        // ---- CONNECT 隧道 ----
        let Some((host, port)) = split_host_port(&uri) else {
            s.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Ok(());
        };
        s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        let target = encode_target(&host, port);
        let Some((id, rx)) = client.open(target).await else {
            return Ok(());
        };
        tracing::debug!(%peer, %host, port, "HTTP CONNECT 已打开流");
        // CONNECT 之后可能已经有粘包数据，先补发
        let extra = buf[head_end..].to_vec();
        if !extra.is_empty() {
            client.send(id, extra);
        }
        pipe_stream(s, id, rx, client).await;
        return Ok(());
    }

    // ---- 普通 HTTP 代理请求：绝对 URI ----
    let Some((host, port, path)) = parse_absolute_uri(&uri) else {
        s.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    };
    // 重写为 origin-form，去掉代理专用头
    let mut out = format!("{method} {path} HTTP/1.1\r\n");
    let mut has_host = false;
    for line in head.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("proxy-authorization:")
            || lower.starts_with("proxy-connection:")
            || lower.starts_with("connection:")
        {
            continue;
        }
        if lower.starts_with("host:") {
            has_host = true;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !has_host {
        out.push_str(&format!("Host: {host}\r\n"));
    }
    // 简化处理：单次请求，不做连接复用
    out.push_str("Connection: close\r\n\r\n");

    let mut payload = out.into_bytes();
    // 请求体（如果有）跟在头后面
    payload.extend_from_slice(&buf[head_end..]);

    let target = encode_target(&host, port);
    let Some((id, rx)) = client.open(target).await else {
        return Ok(());
    };
    client.send(id, payload);
    // 请求体由上面的 payload 发出，这里不再从本地读，只把响应写回
    let mut r = s;
    let mut resp = rx;
    while let Some(data) = resp.recv().await {
        if data.is_empty() {
            break;
        }
        if r.write_all(&data).await.is_err() {
            break;
        }
    }
    let _ = r.flush().await;
    Ok(())
}

/// 解析 "host:port"，支持 [IPv6]:port。
fn split_host_port(s: &str) -> Option<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?.parse().ok()?;
        return Some((host.to_string(), port));
    }
    let (host, port) = s.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

/// 解析 http://host[:port]/path 形式的绝对 URI。
fn parse_absolute_uri(uri: &str) -> Option<(String, u16, String)> {
    let rest = uri.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (authority.to_string(), 80),
    };
    Some((host, port, path.to_string()))
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// 极简 Base64 解码，只用于校验 Basic 认证头，避免额外依赖。
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = TABLE.iter().position(|&x| x == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}
