//! FlowTLS：外观是 TCP + TLS，内部是 QUIC 数据报的代理。
//!
//! 子命令与 hysteria2 保持一致：server / client / install-rules / version。

mod cli;
mod client;
mod config;
mod faketcp;
mod proxy;
mod quic;
mod rules;
mod server;
mod site;

use anyhow::{Context, Result};
use clap::Parser;

use cli::{Cli, Commands, Role};

fn main() -> Result<()> {
    // rustls 0.23 要求显式安装 crypto provider，否则 QUIC/网站初始化会 panic
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    match cli.command {
        Commands::Server(args) => {
            init_logging();
            let cfg = build_server_config(args)?;
            run_async(server::run(cfg))
        }
        Commands::Client(args) => {
            init_logging();
            let cfg = build_client_config(args)?;
            run_async(client::run(cfg))
        }
        Commands::InstallRules(args) => {
            init_logging();
            match args.role {
                Role::Server => rules::ensure_server(args.port, 0xF107)?,
                Role::Client => rules::ensure_client(args.source_port, args.port, 0xF107)?,
            }
            println!("规则已安装");
            Ok(())
        }
        Commands::CheckRules => {
            init_logging();
            let server = rules::check_server(8443, 0xF107);
            let client = rules::check_client(44300);
            println!("server 规则: {}", if server { "已存在" } else { "缺失" });
            println!("client 规则: {}", if client { "已存在" } else { "缺失" });
            Ok(())
        }
        Commands::Version => {
            println!("flowtls {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

/// 初始化日志。默认 info，可用 RUST_LOG 覆盖。
fn init_logging() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

/// 把同步的 main 和异步运行时隔开，避免在运行时里再建运行时。
fn run_async<F>(fut: F) -> Result<()>
where
    F: std::future::Future<Output = Result<()>>,
{
    tokio::runtime::Builder::new_multi_thread()
        // 服务端 1 核也可能同时有几十条出站流（Twitch 网页会开 40+ 连接），
        // 单 worker 会让 IO 任务互相饥饿，4 个 worker 让调度更平滑。
        .worker_threads(4)
        .enable_all()
        .build()
        .context("创建 tokio 运行时失败")?
        .block_on(fut)
}

/// 加载服务端配置并应用命令行覆盖。
fn build_server_config(args: cli::ServerArgs) -> Result<config::ServerFile> {
    let mut cfg = config::ServerFile::load(&args.config)?;
    if let Some(v) = args.listen {
        cfg.listen = v;
    }
    if let Some(v) = args.cert {
        cfg.tls.cert = v;
    }
    if let Some(v) = args.key {
        cfg.tls.key = v;
    }
    if let Some(v) = args.password {
        cfg.password = v;
    }
    if let Some(v) = args.net_mode {
        cfg.net.mode = v;
    }
    Ok(cfg)
}

/// 加载客户端配置并应用命令行覆盖。
fn build_client_config(args: cli::ClientArgs) -> Result<config::ClientFile> {
    let mut cfg = config::ClientFile::load(&args.config)?;
    if let Some(v) = args.server {
        cfg.server = v;
    }
    if let Some(v) = args.password {
        cfg.password = v;
    }
    if let Some(v) = args.socks5 {
        cfg.socks5 = Some(config::InboundFile {
            listen: v,
            username: cfg.socks5.as_ref().map(|i| i.username.clone()).unwrap_or_default(),
            password: cfg.socks5.as_ref().map(|i| i.password.clone()).unwrap_or_default(),
            // SOCKS5 不需要证书
            cert: None,
            key: None,
        });
    }
    if let Some(v) = args.http {
        cfg.http = Some(config::InboundFile {
            listen: v,
            username: cfg.http.as_ref().map(|i| i.username.clone()).unwrap_or_default(),
            password: cfg.http.as_ref().map(|i| i.password.clone()).unwrap_or_default(),
            cert: None,
            key: None,
        });
    }
    if let Some(v) = args.https {
        cfg.https = Some(config::InboundFile {
            listen: v,
            username: cfg.https.as_ref().map(|i| i.username.clone()).unwrap_or_default(),
            password: cfg.https.as_ref().map(|i| i.password.clone()).unwrap_or_default(),
            // 只改监听地址时保留配置里已有的证书路径
            cert: cfg.https.as_ref().and_then(|i| i.cert.clone()),
            key: cfg.https.as_ref().and_then(|i| i.key.clone()),
        });
    }
    Ok(cfg)
}
