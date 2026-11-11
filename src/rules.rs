//! iptables 规则检测与安装。
//!
//! 规则的作用不是代理协议需要，而是阻止内核协议栈处理我们的伪造包：
//! - 服务端：把带魔数 IP ID 的 SYN 和无 conntrack 的包在 raw 表丢弃，
//!   内核看不到就不会回 SYN-ACK / RST，NAT 映射不会被拆掉，
//!   同端口的真网站也不受干扰。
//! - 客户端：屏蔽内核对伪造连接回包（SYN-ACK）产生的 RST。

use std::process::Command;

use anyhow::{bail, Context, Result};

/// 执行一条 iptables 命令，返回是否成功。
fn iptables(args: &[String]) -> Result<bool> {
    let out = Command::new("iptables")
        .args(args)
        .output()
        .context("无法执行 iptables，请确认已安装并具备 root 权限")?;
    if out.status.success() {
        return Ok(true);
    }
    let err = String::from_utf8_lossy(&out.stderr);
    // 规则已存在时 -A 会报错，这里视为成功，保证幂等
    if err.contains("already exists") {
        return Ok(true);
    }
    Ok(false)
}

/// 构造服务端规则。
/// 只保留一条：用 IP ID 魔数匹配我们自己的所有伪造包。
/// 不能用 conntrack INVALID 规则：它会在 raw 表早期误伤正常 SYN，
/// 导致同端口的真网站无法完成 TCP 握手。
fn server_rules(port: u16, magic: u16) -> Vec<Vec<String>> {
    let port = port.to_string();
    let _ = magic; // 保留参数兼容旧调用；识别特征已改为 TCP 选项
    // 用 TCP 选项里的窗口缩放因子（wscale=12）识别伪包。
    // 实跟踪发现：客户端的 NAT 会把 IP ID 改写成 0x0000，
    // 旧版按 IP ID 匹配的 u32 规则在真实链路上根本不命中。
    // 偏移：IP 头 20 + TCP 头 26（MSS 4 字节 + SACK 2 字节之后）= 46，
    // WS 选项固定为 03 03 0c 01（shift=12）。
    let magic_expr = "46&0xFFFFFFFF=0x03030C01".to_string();
    vec![vec![
        "-t".into(), "raw".into(), "-A".into(), "PREROUTING".into(),
        "-p".into(), "tcp".into(), "--dport".into(), port,
        "-m".into(), "u32".into(), "--u32".into(), magic_expr,
        "-j".into(), "DROP".into(),
    ]]
}

/// 服务端规则：用 IP ID 魔数把我们的伪造包挡在内核之外。
pub fn ensure_server(port: u16, magic: u16) -> Result<()> {
    for mut rule in server_rules(port, magic) {
        // 先检查是否已存在，避免重复添加
        let mut check = rule.clone();
        check[2] = "-C".into();
        if iptables(&check)? {
            continue;
        }
        rule[2] = "-A".into();
        if !iptables(&rule)? {
            bail!("写入 iptables 规则失败: {}", rule.join(" "));
        }
    }
    Ok(())
}

/// 客户端规则：
/// 1. 屏蔽内核对伪造连接回包产生的 RST；
/// 2. 直接 DROP 服务端发来的魔数包，避免内核为每个包回一个 RST。
///    AF_PACKET 在 netfilter 之前收包，DROP 不影响 raw 层。
pub fn ensure_client(source_port: u16, server_port: u16, magic: u16) -> Result<()> {
    let _ = magic; // 识别特征改为五元组，不再依赖会被 NAT 改写的 IP ID
    // OUTPUT：屏蔽 RST
    let mut out_rule: Vec<String> = vec![
        "-A".into(), "OUTPUT".into(),
        "-p".into(), "tcp".into(),
        "--sport".into(), source_port.to_string(),
        "--tcp-flags".into(), "RST".into(), "RST".into(),
        "-j".into(), "DROP".into(),
    ];
    let mut out_check = out_rule.clone();
    out_check[0] = "-C".into();
    if !iptables(&out_check)? {
        if !iptables(&out_rule)? {
            bail!("写入 iptables 规则失败: {}", out_rule.join(" "));
        }
    }

    // INPUT：服务端发来的包交给 raw 层，内核不要处理。
    // 按源/目标端口匹配（服务端端口 → 客户端伪源端口），
    // 不再用 IP ID：NAT 回程同样可能改写它。
    let mut in_rule: Vec<String> = vec![
        "-A".into(), "INPUT".into(),
        "-p".into(), "tcp".into(),
        "--sport".into(), server_port.to_string(),
        "--dport".into(), source_port.to_string(),
        "-j".into(), "DROP".into(),
    ];
    let mut in_check = in_rule.clone();
    in_check[0] = "-C".into();
    if !iptables(&in_check)? {
        in_rule[0] = "-A".into();
        if !iptables(&in_rule)? {
            bail!("写入 iptables 规则失败: {}", in_rule.join(" "));
        }
    }
    Ok(())
}

/// 只检查规则是否存在，不修改。
pub fn check_server(port: u16, magic: u16) -> bool {
    server_rules(port, magic).into_iter().all(|mut r| {
        r[2] = "-C".into();
        iptables(&r).unwrap_or(false)
    })
}

/// 只检查客户端规则是否存在。
pub fn check_client(source_port: u16) -> bool {
    let mut rule: Vec<String> = vec![
        "-C".into(), "OUTPUT".into(),
        "-p".into(), "tcp".into(),
        "--sport".into(), source_port.to_string(),
        "--tcp-flags".into(), "RST".into(), "RST".into(),
        "-j".into(), "DROP".into(),
    ];
    iptables(&rule).unwrap_or(false)
}
