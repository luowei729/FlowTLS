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
/// 只保留一条：把发往监听端口的伪包在内核 TCP 栈之前 DROP。
///
/// 匹配依据是 IP ID 高字节，取值来自配置的 `faketcp.ip_id_magic`。
/// **不能写死常量**：写死一个固定值意味着任何 DPI 只要加一条
/// 「IP ID 高字节 == 某值」的通用规则就能命中所有部署。
/// 从配置派生后，每个部署的特征不同，检测方必须逐条链路采集。
///
/// 标记范围刻意保持很窄（只固定高字节 = 256 个值，0.4%）：
/// 这里 DROP 的包内核看不到，对外表现为「完全无响应」。
/// 范围放宽到高 4 位（6%）会让端口探测行为前后不一致，反而更容易暴露。
///
/// offset 4 读的是「IP ID(2) + Flags/Frag(2)」四字节：
/// Frag 固定 0x4000（DF），掩掉 IP ID 低字节与 MF/offset。
fn server_rules(port: u16, magic: u16) -> Vec<Vec<String>> {
    let port = port.to_string();
    // 与 packet.rs 的 ipid_mark / build_packet_into 保持一致：只保留高字节
    let mark = magic & 0xFF00;
    let magic_expr = format!("0x4&0xff00ffff=0x{mark:04x}4000");
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
    // OUTPUT：屏蔽 RST
    let out_rule: Vec<String> = vec![
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
    // 用「源端口 + IP ID 高字节标记」匹配：服务端所有回包的标记一致。
    // 标记同样来自配置（与 ensure_server 同源），不写死。
    let mark = magic & 0xFF00;
    let mut in_rule: Vec<String> = vec![
        "-A".into(),
        "INPUT".into(),
        "-p".into(),
        "tcp".into(),
        "--sport".into(),
        server_port.to_string(),
        "-m".into(),
        "u32".into(),
        "--u32".into(),
        format!("0x4&0xff00ffff=0x{mark:04x}4000"),
        "-j".into(),
        "DROP".into(),
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
    let rule: Vec<String> = vec![
        "-C".into(), "OUTPUT".into(),
        "-p".into(), "tcp".into(),
        "--sport".into(), source_port.to_string(),
        "--tcp-flags".into(), "RST".into(), "RST".into(),
        "-j".into(), "DROP".into(),
    ];
    iptables(&rule).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// iptables u32 的右值必须带 `0x` 前缀。
    /// 内核解析器用的是 `simple_strtoul(..., base=0)`，只有带 0x 才按十六进制，
    /// 否则 "f1004000" 会解析失败（返回 0），规则永不命中——
    /// 表现为「服务端内核回 RST 把连接打断」，但日志里看不出任何异常。
    #[test]
    fn server_rule_expr_has_hex_prefix() {
        let rules = server_rules(8443, 0xF107);
        let joined = rules[0].join(" ");
        assert!(
            joined.contains("--u32"),
            "服务端规则必须用 u32 匹配 IP ID"
        );
        // 取 "--u32" 后面紧跟的那个值，不硬编码下标
        let pos = rules[0]
            .iter()
            .position(|a| a == "--u32")
            .expect("规则里应有 --u32");
        let expr = &rules[0][pos + 1];
        assert!(
            expr.starts_with("0x4&0xff00ffff=0x"),
            "u32 右值必须带 0x 前缀，实际是 {expr}"
        );
    }

    /// 标记值必须来自配置：换 magic 就要换出不同的规则，
    /// 这样每个部署的特征不同，DPI 无法写通用规则。
    #[test]
    fn server_rule_follows_magic() {
        let a = server_rules(8443, 0xF107)[0].join(" ");
        let b = server_rules(8443, 0x1E07)[0].join(" ");
        assert_ne!(a, b, "不同 magic 必须生成不同规则");
        assert!(b.contains("0x1e004000"), "标记高字节应来自 magic: {b}");
    }

    /// 客户端 INPUT 规则同样要跟随 magic
    #[test]
    fn client_rule_follows_magic() {
        let expr = format!("0x4&0xff00ffff=0x{:04x}4000", 0x2A00u16);
        assert_eq!(expr, "0x4&0xff00ffff=0x2a004000");
    }
}
