package flowtls

import _ "embed"

// embeddedIndexHTML 是编译期内置的首页，与 Rust 版
// `include_str!("../../web/index.html")` 完全对应。
//
// 为什么要内置而不是只靠 site_dir：
// 伪装站的第一要务是「任何情况下都不露馅」。site_dir 为空、被清空、
// 运维忘了放 index.html——这些在真实部署里都发生过。
// 没有内置兜底的话，`http.FileServer` 会返回**目录列表**，
// 一个只有几个下载链接的页面比 404 更像靶子。
//
// 文件来源：仓库根目录的 web/index.html（与 Rust 版是同一个文件）。
// 放在 sing-box/protocol/flowtls/web/ 下是因为 embed 指令**不能跨模块**
// 引用上级目录（go:embed 只认当前 package 目录及其子目录）。
//
//go:embed web/index.html
var embeddedIndexHTML []byte
