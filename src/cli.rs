//! 命令行定义。子命令和参数尽量与 hysteria2 保持一致。

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "flowtls", version, about = "FakeTCP + QUIC 伪装成 HTTPS 的代理")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// 启动服务端
    Server(ServerArgs),
    /// 启动客户端
    Client(ClientArgs),
    /// 安装防火墙规则
    InstallRules(RuleArgs),
    /// 检查防火墙规则
    CheckRules,
    /// 打印版本
    Version,
}

#[derive(Args)]
pub struct ServerArgs {
    /// 配置文件路径
    #[arg(short, long, default_value = "server.yaml")]
    pub config: PathBuf,
    /// 覆盖监听地址
    #[arg(long)]
    pub listen: Option<String>,
    /// 覆盖证书路径
    #[arg(long)]
    pub cert: Option<PathBuf>,
    /// 覆盖私钥路径
    #[arg(long)]
    pub key: Option<PathBuf>,
    /// 覆盖密码
    #[arg(long)]
    pub password: Option<String>,
    /// 覆盖防火墙模式：auto / none
    #[arg(long)]
    pub net_mode: Option<String>,
}

#[derive(Args)]
pub struct ClientArgs {
    /// 配置文件路径
    #[arg(short, long, default_value = "client.yaml")]
    pub config: PathBuf,
    /// 覆盖服务端地址
    #[arg(long)]
    pub server: Option<String>,
    /// 覆盖密码
    #[arg(long)]
    pub password: Option<String>,
    /// 覆盖 SOCKS5 监听地址
    #[arg(long)]
    pub socks5: Option<String>,
    /// 覆盖 HTTP 代理监听地址
    #[arg(long)]
    pub http: Option<String>,
    /// 覆盖 HTTPS 代理监听地址
    #[arg(long)]
    pub https: Option<String>,
}

#[derive(Args)]
pub struct RuleArgs {
    /// 按哪一端安装规则
    #[arg(value_enum)]
    pub role: Role,
    /// FakeTCP 端口
    #[arg(long, default_value_t = 8443)]
    pub port: u16,
    /// 客户端固定源端口
    #[arg(long, default_value_t = 44300)]
    pub source_port: u16,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Role {
    Server,
    Client,
}
