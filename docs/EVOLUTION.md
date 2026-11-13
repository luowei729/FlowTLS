# 实现演进史

## 一句话

FlowTLS 的 wire format 最早由 **Rust** 实现并验证；主分支现在只保留 **Go** 实现，
Rust 代码冻结在 `legacy-rust` 分支里，仅作为参考实现与历史记录。

---

## 为什么要换语言

| 维度 | Rust 实现 | Go 实现 |
|---|---|---|
| 生态位置 | 独立进程，自己实现 SOCKS5/HTTP/HTTPS 入口 | 直接作为 sing-box 的一个协议库，与 hy2/anytls 平级 |
| 用户获得的能力 | 只能用它自带的入口 | 全部 sing-box 能力：路由规则、DNS 策略、TUN、Clash API、订阅、面板 |
| 维护成本 | 每加一个功能都要重写一遍 sing-box 已有的东西 | 只维护协议本身 |
| 发布方式 | 独立二进制 | `sing-box 1.14.4-rev.N`（同仓库构建，版本号区分官方版） |

结论：协议本身是资产，**外围功能不是**。继续用 Rust 意味着永远在追 sing-box 的功能。
所以把权威实现换成 Go，Rust 冻结成参考实现。

---

## 冻结点的位置

| 引用 | 内容 |
|---|---|
| 分支 `legacy-rust` | Rust 源码、`Cargo.toml`、`Cargo.lock`、Rust 时代的测试脚本 |
| 标签 `rust-frozen-2026-11-13` | 同一提交，带说明的永久锚点 |

查看历史：

```bash
# 方式一：直接切过去看（看完记得切回来）
git switch legacy-rust

# 方式二：worktree，两个分支同时可见（推荐）
git worktree add /tmp/flowtls-rust legacy-rust
cd /tmp/flowtls-rust && cargo test        # 25 个单测
cargo build --release                     # 需要跑 Rust 端到端时用它

# 用完清理
git worktree remove /tmp/flowtls-rust
```

如果还想跑「Rust × Go」的互通矩阵：

```bash
git worktree add /tmp/flowtls-rust legacy-rust
(cd /tmp/flowtls-rust && cargo build)
RUST_FLOWTLS=/tmp/flowtls-rust/target/debug/flowtls bash docs/e2e_matrix.sh
```

`docs/e2e_matrix.sh` 在未设置 `RUST_FLOWTLS` 时只跑 Go↔Go 并明确报告跳过的 3 格，
不会静默假装全绿。

---

## 为什么删掉 Rust 之后互通性不会被破坏

删代码最大的风险是**丢基线**：以后 Go 侧悄悄改了 HKDF 参数，
两端（现在只有 Go 一端）都跟着改，测试依旧全绿，但已经和老版本不兼容。

解决办法是冻结前把「绝对字节」导出成黄金向量，入库到主分支：

| 文件 | 内容 |
|---|---|
| `flowtls/testdata/wire_v2_rust.bin` | 用密码 `interop-password` 加密的两条记录（120 字节） |
| `flowtls/testdata/wire_v2_rust_authid.txt` | 同一密码派生出的 authID（32 字节 hex） |

`flowtls/interop_test.go` 里的 `TestInteropRustToGo` 直接消费它们：

- authID 必须逐字节相同 → 锁死 HKDF 的 `salt` / `info`
- 两条记录必须能解出 `first-datagram` / `second-datagram` → 锁死记录头布局、
  nonce 位置、AAD 组成、AEAD 参数

换句话说：**Rust 代码可以删，Rust 产出的字节删不掉**。这才是真正的兼容性契约。

门禁：`bash docs/interop_check.sh`（不需要 Rust，不需要 root）。

---

## 这次演进留下的经验

1. **先冻结参考实现，再换权威实现**。
   不要反过来——一旦主分支已经改完才发现没有基线，历史实现只能靠回忆重建。

2. **跨语言测试脚本要向「向量文件」演化**。
   原来的 `docs/interop_check.sh` 靠 `cargo test` 实时生成向量，
   Rust 一删脚本就废。改成「向量入库 + 单向消费」后，脚本的生命周期不再依赖对方语言。

3. **删源码时要同步删掉「只对那条路有意义」的工具**。
   `docs/test_udp_recover.py` / `test_udp_stale.py` 断言的是 Rust 实现内部的重连语义，
   Go 侧不存在同样状态机，留着只会误导。

4. **配置格式不兼容必须明说**。
   Rust 用 YAML（`server.yaml` / `client.yaml`），sing-box 用 JSON。
   字段对照见 `docs/MIGRATION.md`。
