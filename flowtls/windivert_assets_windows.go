//go:build windows && (amd64 || 386)

package flowtls

// 嵌入 WinDivert 驱动二进制，让部署只需要一个 exe。
//
// 上游 sing-box 也是同样做法（`common/windivert/assets/*.sys`）：
// 驱动不在运行时下载，避免网络依赖与供应链风险；SHA256 在发布流程里
// 由 `windivert_assets/SHA256SUMS` 记录，便于人工核对。
//
// 许可：WinDivert 官方发行版，按 LGPL v3 再分发。
// 许可证全文见 `windivert_assets/LICENSE.txt`，随二进制一起分发。

import _ "embed"

//go:embed windivert_assets/WinDivert64.sys
var wdivSysBytes64 []byte

//go:embed windivert_assets/WinDivert32.sys
var wdivSysBytes32 []byte
