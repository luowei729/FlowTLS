//! FlowTLS：外观是 TCP + TLS，内部是 QUIC 数据报的代理。
//!
//! 子命令与 hysteria2 保持一致：server / client / install-rules / version。

mod check;
mod cli;
mod client;
mod config;
mod faketcp;
mod proxy;
mod quic;
mod rules;
mod server;
mod site;

use std::path::PathBuf;

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
            let (port, source_port, magic) = resolve_rule_args(&args)?;
            match args.role {
                Role::Server => rules::ensure_server(port, magic)?,
                Role::Client => rules::ensure_client(source_port, port, magic)?,
            }
            println!("规则已安装（端口 {port}, 标记 0x{:04x}）", magic & 0xFF00);
            Ok(())
        }
        Commands::CheckRules(args) => {
            init_logging();
            let (port, source_port, magic) = resolve_rule_args(&args)?;
            let ok = match args.role {
                Role::Server => rules::check_server(port, magic),
                Role::Client => rules::check_client(source_port),
            };
            println!(
                "{} 规则（端口 {port}, 标记 0x{:04x}）: {}",
                match args.role {
                    Role::Server => "server",
                    Role::Client => "client",
                },
                magic & 0xFF00,
                if ok { "已存在" } else { "缺失" }
            );
            Ok(())
        }
        Commands::Check(args) => {
            // 不初始化日志：check 直接 println 人类可读报告，
            // 混入带时间戳的日志反而难读
            let ok = check::run(args.server.as_deref(), args.client.as_deref())?;
            if !ok {
                std::process::exit(1);
            }
            Ok(())
        }
        Commands::Version => {
            println!("flowtls {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

/// 解析 install-rules / check-rules 的参数。
///
/// 优先级：命令行 → 配置文件 → 内置默认值。
/// **不能只写内置默认值**：分流标记现在是配置派生的（DEVTIPS 38），
/// 写死 `0xF107` 会让规则与实际标记不匹配，规则静默失效。
/// 这是之前真实踩过的坑，所以让两个 rules 子命令都从配置读。
fn resolve_rule_args(args: &cli::RuleArgs) -> Result<(u16, u16, u16)> {
    // 按角色选默认配置文件名
    let default_name = match args.role {
        Role::Server => "server.yaml",
        Role::Client => "client.yaml",
    };
    let path = args
        .config
        .clone()
        .or_else(|| Some(default_name.into()).filter(|p: &PathBuf| p.exists()));

    let mut port = if matches!(args.role, Role::Server) { 8443 } else { 8443 };
    let mut source_port = 44300u16;
    let mut magic = crate::faketcp::packet::IPID_MARK | 0x07;

    if let Some(p) = path {
        match args.role {
            Role::Server => {
                let cfg = config::ServerFile::load(&p)?;
                port = config::parse_listen(&cfg.listen)?.port();
                magic = cfg.faketcp.ip_id_magic;
            }
            Role::Client => {
                let cfg = config::ClientFile::load(&p)?;
                let (_, sp) = config::parse_host_port(&cfg.server)?;
                port = sp;
                source_port = cfg.faketcp.source_port;
                magic = cfg.faketcp.ip_id_magic;
            }
        }
        println!("从 {} 读取：端口 {port}, 标记 0x{:04x}", p.display(), magic & 0xFF00);
    }

    if let Some(v) = args.port {
        port = v;
    }
    if let Some(v) = args.source_port {
        source_port = v;
    }
    if let Some(v) = args.magic {
        magic = v;
    }
    Ok((port, source_port, magic))
}

/// 初始化日志。默认 info，可用 RUST_LOG 覆盖。
fn init_logging() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        // 关闭 ANSI 颜色码：日志重定向到文件后，颜色码会把字段名包成
        // `\033[3mrtt_ms\033[0m=`，导致 grep 'rtt_ms=' 一条都匹配不到，
        // 排查时只能肉眼翻几十 MB 日志。服务端和客户端都输出到文件，统一关掉。
        .with_ansi(false)
        .try_init();
}

/// 把同步的 main 和异步运行时隔开，避免在运行时里再建运行时。
fn run_async<F>(fut: F) -> Result<()>
where
    F: std::future::Future<Output = Result<()>>,
{
    // worker 数量跟着 CPU 核数走。
    // 之前写死 4：服务端机型常是 1 核（如 Oracle A1 最小规格），
    // 4 个 worker 线程加收包线程、主循环一起抢同一个核，
    // 上下文切换和 cache 失效反而拖慢热路径。
    // 上限 4 是经验值：更多 worker 对「单连接多流」没有额外收益。
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 4);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
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
