//! 同端口真网站。
//!
//! 内核 TCP 监听与 FakeTCP 使用同一个端口：
//! 普通浏览器/扫描器的 SYN 不带魔数，走内核 TCP，命中这里；
//! 我们的客户端数据包被 iptables 挡在内核之外，只有 raw socket 能收到。
//! 这样 443/8443 的主动探测看到的是一个带真实证书的完整站点。

use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::config::parse_listen;

/// 编译期内置的首页，保证离线也能正常响应
const INDEX_HTML: &str = include_str!("../../web/index.html");
const ROBOTS_TXT: &str = "User-agent: *\nAllow: /\n";

/// 加载证书并构造只支持 http/1.1 的 TLS 配置。
pub fn load_tls(cert: &PathBuf, key: &PathBuf) -> Result<rustls::ServerConfig> {
    let mut cert_reader = BufReader::new(
        std::fs::File::open(cert).with_context(|| format!("打开证书失败: {}", cert.display()))?,
    );
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("解析证书失败")?;
    if certs.is_empty() {
        anyhow::bail!("证书文件为空: {}", cert.display());
    }
    let mut key_reader = BufReader::new(
        std::fs::File::open(key).with_context(|| format!("打开私钥失败: {}", key.display()))?,
    );
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("解析私钥失败")?
        .context("私钥文件为空")?;

    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("证书与私钥不匹配")?;
    // 只宣告 http/1.1：实现简单，且真实世界大量站点如此，不会成为指纹特征
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

/// 启动网站监听。
pub async fn run(listen: &str, cert: PathBuf, key: PathBuf, site_dir: String) -> Result<()> {
    let addr: SocketAddr = parse_listen(listen)?;
    let tls = load_tls(&cert, &key)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("网站监听失败: {addr}"))?;
    tracing::info!(%addr, "伪装网站已启动 (TLS 1.3, ALPN http/1.1)");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "accept 失败");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let dir = site_dir.clone();
        tokio::spawn(async move {
            // TLS 握手失败通常说明对方不是浏览器（或指纹异常），直接断开即可
            let mut tls = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                acceptor.accept(stream),
            )
            .await
            {
                Ok(Ok(s)) => s,
                _ => return,
            };
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                serve(&mut tls, &dir),
            )
            .await;
            tracing::debug!(%peer, "网站连接结束");
        });
    }
}

/// 处理一条 TLS 连接上的 HTTP/1.1 请求，支持 keep-alive。
async fn serve<S>(stream: &mut S, site_dir: &str) -> std::io::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    loop {
        // 每次请求最多读 16KB 头部，防止被恶意超长请求拖垮
        let header_end = loop {
            let mut chunk = [0u8; 4096];
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = find_headers_end(&buf) {
                break pos;
            }
            if buf.len() > 16384 {
                return Ok(());
            }
        };

        let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let mut lines = head.lines();
        let request_line = lines.next().unwrap_or_default();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("GET");
        let path = parts.next().unwrap_or("/");

        // 只允许常规只读方法，异常方法返回 405，避免看起来像可写的业务系统
        let (status, body, ctype) = match method {
            "GET" | "HEAD" => {
                if path == "/robots.txt" {
                    ("200 OK", ROBOTS_TXT.as_bytes().to_vec(), "text/plain; charset=utf-8")
                } else if path == "/favicon.ico" {
                    // 返回 204 比返回 404 更像正常站点
                    ("204 No Content", Vec::new(), "image/x-icon")
                } else {
                    // 静态文件优先：用于带宽对比测试和放置真实资源
                    let rel = path.trim_start_matches('/');
                    let mut file_body = None;
                    if !site_dir.is_empty() && !rel.contains("..") && !rel.is_empty() {
                        let fp = format!("{site_dir}/{rel}");
                        if let Ok(data) = std::fs::read(&fp) {
                            let ctype = if rel.ends_with(".bin") {
                                "application/octet-stream"
                            } else if rel.ends_with(".png") {
                                "image/png"
                            } else if rel.ends_with(".jpg") {
                                "image/jpeg"
                            } else if rel.ends_with(".css") {
                                "text/css"
                            } else if rel.ends_with(".js") {
                                "application/javascript"
                            } else {
                                "application/octet-stream"
                            };
                            file_body = Some((data, ctype));
                        }
                    }
                    if let Some((data, ctype)) = file_body {
                        ("200 OK", data, ctype)
                    } else {
                        let page = if !site_dir.is_empty() {
                            std::fs::read(format!("{site_dir}/index.html"))
                                .unwrap_or_else(|_| INDEX_HTML.as_bytes().to_vec())
                        } else {
                            INDEX_HTML.as_bytes().to_vec()
                        };
                        ("200 OK", page, "text/html; charset=utf-8")
                    }
                }
            }
            _ => ("405 Method Not Allowed", b"Method Not Allowed".to_vec(), "text/plain; charset=utf-8"),
        };

        // 保持连接，除非客户端明确要求关闭
        let keep_alive = !head.to_ascii_lowercase().contains("connection: close");
        let conn = if keep_alive { "keep-alive" } else { "close" };
        let mut resp = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: {conn}\r\nServer: nginx\r\nCache-Control: public, max-age=300\r\n\r\n",
            body.len()
        )
        .into_bytes();
        if method != "HEAD" {
            resp.extend_from_slice(&body);
        }
        stream.write_all(&resp).await?;
        stream.flush().await?;

        // 丢掉已处理的请求，保留可能粘在后面的下一请求
        buf.drain(..header_end);
        if !keep_alive {
            return Ok(());
        }
    }
}

/// 找到 HTTP 头结束位置（\r\n\r\n），返回结束后的偏移。
fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}
