//! YAML 配置加载。
//!
//! 配置结构刻意贴近 hysteria2 的写法，方便直接迁移使用习惯。

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

/// 服务端配置文件
#[derive(Debug, Clone, Deserialize)]
pub struct ServerFile {
    /// 监听地址，例如 ":8443" 或 "0.0.0.0:8443"
    pub listen: String,
    /// 代理密码，同时也是外层 AEAD 的密钥来源
    pub password: String,
    pub tls: TlsFile,
    #[serde(default)]
    pub site: SiteFile,
    #[serde(default)]
    pub faketcp: FakeTcpFile,
    #[serde(default)]
    pub net: NetFile,
}

/// 证书配置
#[derive(Debug, Clone, Deserialize)]
pub struct TlsFile {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// 伪装网站配置
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SiteFile {
    /// 为空时使用编译进二进制的内置页面
    #[serde(default)]
    pub dir: String,
}

/// FakeTCP 参数
#[derive(Debug, Clone, Deserialize)]
pub struct FakeTcpFile {
    /// 用来标记「这是我们自己的 SYN」的 IP ID，避开内核协议栈
    #[serde(default = "default_magic")]
    pub ip_id_magic: u16,
    /// symbolic：发裸 SYN 表演；none：不发 SYN（要求客户端有公网 IP）
    #[serde(default = "default_handshake")]
    pub handshake: String,
    /// 服务端对外公网 IP。
    /// 云主机在 NAT 后面时，路由探测只能拿到内网地址（如 10.x），
    /// 但发给客户端的包源 IP 必须是公网 IP，否则客户端会丢弃。
    #[serde(default)]
    pub local_ip: Option<String>,
}

fn default_magic() -> u16 {
    0xF107
}
fn default_handshake() -> String {
    "symbolic".to_string()
}
impl Default for FakeTcpFile {
    fn default() -> Self {
        Self {
            ip_id_magic: default_magic(),
            handshake: default_handshake(),
            local_ip: None,
        }
    }
}

/// 防火墙规则模式与传输参数
#[derive(Debug, Clone, Deserialize)]
pub struct NetFile {
    /// auto：启动时自动写入 iptables；none：不写规则
    #[serde(default = "default_net_mode")]
    pub mode: String,
    /// QUIC 拥塞窗口上限（字节）。
    /// 默认 8MB：对齐 hysteria2 的千兆配置，千兆机器直接可用。
    /// 小带宽跨境链路（实际 20~50Mbps）建议调到 1MB 左右，否则丢包会明显变多。
    #[serde(default = "default_max_cwnd")]
    pub max_cwnd: u64,
}
fn default_net_mode() -> String {
    "auto".to_string()
}
fn default_max_cwnd() -> u64 {
    // 与 hysteria2 默认流窗口（8MB）对齐，按 1000Mbps × 70ms 的 BDP 留足余量
    8 * 1024 * 1024
}
impl Default for NetFile {
    fn default() -> Self {
        Self {
            mode: default_net_mode(),
            max_cwnd: default_max_cwnd(),
        }
    }
}

/// 客户端配置文件
#[derive(Debug, Clone, Deserialize)]
pub struct ClientFile {
    /// 服务端地址，例如 "example.com:8443"
    pub server: String,
    pub password: String,
    /// 伪装用的 SNI，默认从 server 里取域名部分
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub faketcp: FakeTcpClientFile,
    #[serde(default)]
    pub socks5: Option<InboundFile>,
    #[serde(default)]
    pub http: Option<InboundFile>,
    #[serde(default)]
    pub https: Option<InboundFile>,
    #[serde(default)]
    pub net: NetFile,
}

/// 客户端 FakeTCP 参数
#[derive(Debug, Clone, Deserialize)]
pub struct FakeTcpClientFile {
    /// 客户端固定源端口，iptables 用它精确匹配内核 RST
    #[serde(default = "default_source_port")]
    pub source_port: u16,
    #[serde(default = "default_handshake")]
    pub handshake: String,
    #[serde(default = "default_magic")]
    pub ip_id_magic: u16,
}
fn default_source_port() -> u16 {
    44300
}
impl Default for FakeTcpClientFile {
    fn default() -> Self {
        Self {
            source_port: default_source_port(),
            handshake: default_handshake(),
            ip_id_magic: default_magic(),
        }
    }
}

/// 本地代理入口配置
#[derive(Debug, Clone, Deserialize)]
pub struct InboundFile {
    pub listen: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

impl ServerFile {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("读取配置失败: {}", path.display()))?;
        let cfg: Self = serde_yaml::from_str(&text).context("解析服务端配置失败")?;
        Ok(cfg)
    }
}

impl ClientFile {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("读取配置失败: {}", path.display()))?;
        let cfg: Self = serde_yaml::from_str(&text).context("解析客户端配置失败")?;
        Ok(cfg)
    }

    /// 推导 SNI：优先用配置值，否则取 server 的域名部分。
    pub fn effective_sni(&self) -> String {
        if !self.sni.is_empty() {
            return self.sni.clone();
        }
        self.server
            .rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| self.server.clone())
    }
}

/// 把 ":8443" 这种简写解析成 SocketAddr。
pub fn parse_listen(s: &str) -> Result<SocketAddr> {
    let full = if let Some(rest) = s.strip_prefix(':') {
        format!("0.0.0.0:{rest}")
    } else {
        s.to_string()
    };
    full.parse()
        .with_context(|| format!("监听地址格式错误: {s}"))
}

/// 把 "host:port" 解析成 (host, port)。
pub fn parse_host_port(s: &str) -> Result<(String, u16)> {
    let (host, port) = s
        .rsplit_once(':')
        .with_context(|| format!("地址缺少端口: {s}"))?;
    let port: u16 = port.parse().with_context(|| format!("端口错误: {s}"))?;
    Ok((host.to_string(), port))
}
