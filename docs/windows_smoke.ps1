# windows_smoke.ps1 —— Windows 首次部署验证脚本
#
# 用途：在没有真机验证过的前提下，把 PROJECT_PLAN.md §W9 的手工清单变成
#       一条命令能跑完的检查，并输出一份可直接贴回 issue 的报告。
#
# 为什么需要这个脚本：
#   flowtls 的 Windows 路径（WinDivert）从未在真机上运行过。交叉编译通过、
#   过滤器编码的字节级单测通过，都不能证明驱动能装、包能收发。
#   逐条手工敲不但慢，还容易漏掉「驱动落盘路径」「服务名」这类细节。
#
# 用法（**管理员** PowerShell）：
#   $env:FLOWTLS_SERVER = '203.0.113.10:8443'     # 服务端地址，不要写进仓库
#   $env:FLOWTLS_SOCKS  = '127.0.0.1:1080'
#   .\windows_smoke.ps1 -Bin .\sing-box.exe -Config .\client.json
#
# 全部 PASS 才算 Windows 路径可用。任何一项 FAIL 都会打印排查提示。
#
# 注意：本脚本只做**读取和调用**，不修改系统状态。唯一会动系统的是
#       sing-box 自己加载驱动（`sc query WinDivert` 只是查询）。
#       清理见文末提示。

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Bin,
    [Parameter(Mandatory = $true)][string]$Config,

    # 探测目标（用于判断隧道是否真的通）。用 Cloudflare trace，
    # 它回显客户端 IP，能直接看出流量是从服务端出去的。
    [string]$Probe = 'https://www.cloudflare.com/cdn-cgi/trace',

    # 观察多久（秒）。期间会采样 sing-box 的 CPU / 内存。
    [int]$WatchSeconds = 20
)

$ErrorActionPreference = 'Stop'

# 结果收集：最后统一打印，方便一次看到全貌
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    $results.Add([pscustomobject]@{ Check = $Name; Result = if ($Ok) { 'PASS' } else { 'FAIL' }; Detail = $Detail })
    $tag = if ($Ok) { 'PASS' } else { 'FAIL' }
    $color = if ($Ok) { 'Green' } else { 'Red' }
    Write-Host ("[{0}] {1}" -f $tag, $Name) -ForegroundColor $color
    if ($Detail) { Write-Host ("        {0}" -f $Detail) -ForegroundColor DarkGray }
}

function Add-Skip {
    param([string]$Name, [string]$Why)
    $results.Add([pscustomobject]@{ Check = $Name; Result = 'SKIP'; Detail = $Why })
    Write-Host ("[SKIP] {0}" -f $Name) -ForegroundColor Yellow
    if ($Why) { Write-Host ("        {0}" -f $Why) -ForegroundColor DarkGray }
}

Write-Host ''
Write-Host '=== FlowTLS Windows 冒烟测试 ===' -ForegroundColor Cyan
Write-Host ''

# ---------------------------------------------------------------- 0. 前置检查

# 管理员权限：加载 WinDivert 驱动必须有 SeLoadDriverPrivilege。
# 不是管理员时 CreateFile("\\.\WinDivert") 返回 ERROR_ACCESS_DENIED(5)，
# 而 sing-box 会把这条错误归类成 ErrWindivertUnsupported —— 很容易被误读成
# 「驱动不支持本平台」。所以先单独检查。
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Add-Result '管理员权限' $isAdmin $(if (-not $isAdmin) { '右键 PowerShell → 以管理员身份运行' } else { '' })

if (-not (Test-Path $Bin)) { throw "找不到二进制: $Bin" }
if (-not (Test-Path $Config)) { throw "找不到配置: $Config" }
Add-Result '二进制与配置存在' $true ("{0} ({1:N0} 字节)" -f $Bin, (Get-Item $Bin).Length)

# ARM64 目前没有驱动资产（上游只有 x64 / x86 的 .sys）。
$arch = $env:PROCESSOR_ARCHITECTURE
Add-Result 'CPU 架构受支持' ($arch -eq 'AMD64' -or $arch -eq 'x86') "当前 $arch（WinDivert 资产只有 x64/x86）"

# ---------------------------------------------------------------- 1. 启动

# 端口占用会让启动失败但报错在别处，先查。
$socks = $env:FLOWTLS_SOCKS
if ($socks) {
    $port = [int]($socks -split ':')[-1]
    $busy = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    Add-Result "本地端口 $port 空闲" (-not $busy) $(if ($busy) { '有进程已监听，先关掉或换端口' } else { '' })
} else {
    Add-Skip '本地端口检查' '未设置 FLOWTLS_SOCKS'
}

$logFile = Join-Path $env:TEMP ("flowtls-smoke-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
Write-Host ("启动: {0} run -c {1}" -f $Bin, $Config) -ForegroundColor DarkGray
Write-Host ("日志: {0}" -f $logFile) -ForegroundColor DarkGray

# 用 -Output 让 PowerShell 把 stdout/stderr 一起收进日志。
$proc = Start-Process -FilePath $Bin -ArgumentList @('run', '-c', $Config) `
    -PassThru -NoNewWindow -RedirectStandardOutput $logFile -RedirectStandardError "$logFile.err"

# 等日志出现「发送路径」那一行。启动到写出它通常 < 3 秒，
# 但首次要落盘并注册驱动，给 25 秒余量。
$deadline = (Get-Date).AddSeconds(25)
$sendMode = $null
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
    if ($proc.HasExited) { break }
    $all = ''
    foreach ($f in @($logFile, "$logFile.err")) {
        if (Test-Path $f) { $all += (Get-Content $f -Raw -ErrorAction SilentlyContinue) }
    }
    if ($all -match '发送路径[:：]\s*(.+)') { $sendMode = $Matches[1].Trim(); break }
}

if ($proc.HasExited) {
    $all = ''
    foreach ($f in @($logFile, "$logFile.err")) {
        if (Test-Path $f) { $all += (Get-Content $f -Raw -ErrorAction SilentlyContinue) }
    }
    Add-Result 'sing-box 启动' $false ("进程已退出，退出码 {0}" -f $proc.ExitCode)
    Write-Host '--- 日志 ---' -ForegroundColor DarkGray
    Write-Host $all -ForegroundColor DarkGray

    # 把常见错误码直接翻译成结论，省掉一轮来回。
    $hint = if ($all -match 'ACCESS_DENIED|拒绝访问') {
        '管理员权限不足 —— 用管理员 PowerShell 重跑'
    } elseif ($all -match '1275|DRIVER_BLOCKED|驱动.*(阻止|拦截)') {
        '杀软拦截 WinDivert 驱动（360/Defender/火绒常见）—— 需加白名单后重试'
    } elseif ($all -match '577|INVALID_IMAGE_HASH|签名') {
        '驱动数字签名被拒 —— 检查系统是否禁用签名、或驱动文件被篡改'
    } elseif ($all -match 'windivert') {
        'WinDivert 相关错误，见上方日志'
    } else {
        '见上方日志'
    }
    Add-Skip '后续检查' '未能启动'
    Write-Host ''
    Write-Host ("排查方向: {0}" -f $hint) -ForegroundColor Yellow
    exit 1
}

Add-Result 'sing-box 启动' $true
Add-Result '发送路径 = windivert' ($sendMode -match 'windivert') ("实际: {0}" -f $sendMode)

# ---------------------------------------------------------------- 2. 驱动状态

# 驱动与我们的 exe 是分开的：exe 里 embed 了 .sys 字节，运行时落盘并注册服务。
$drvDir = Join-Path $env:LOCALAPPDATA 'flowtls\windivert'
if (Test-Path $drvDir) {
    $sys = Get-ChildItem -Path $drvDir -Recurse -Filter 'WinDivert*.sys' -ErrorAction SilentlyContinue
    Add-Result '驱动落盘' ($sys.Count -gt 0) (($sys | ForEach-Object { $_.FullName }) -join '; ')
} else {
    # 若官方 sing-box 已装过驱动，这里是空的但服务仍可用 —— 不算失败。
    Add-Skip '驱动落盘（我们自己的目录）' "未找到 $drvDir（可能复用了官方 sing-box 已安装的驱动）"
}

$svc = Get-Service -Name 'WinDivert*' -ErrorAction SilentlyContinue
if ($svc) {
    $names = ($svc | ForEach-Object { "$($_.Name)=$($_.Status)" }) -join '; '
    Add-Result 'WinDivert 服务已注册' ($svc | Where-Object { $_.Status -eq 'Running' } | Measure-Object).Count -gt 0 $names
} else {
    Add-Result 'WinDivert 服务已注册' $false 'Get-Service 找不到 WinDivert，驱动未成功加载'
}

# ---------------------------------------------------------------- 3. 端到端

if ($socks) {
    try {
        $trace = curl.exe -s --max-time 25 -x "http://$socks" $Probe 2>&1
        # trace 里 ip= 那一行是从「对端看到的地址」，能证明流量真的从服务端出去。
        $egress = ($trace | Select-String -Pattern '^ip=(.+)$').Matches.Groups[1].Value
        Add-Result 'SOCKS5 出口可用' ([bool]$egress) ("出口 IP: {0}" -f $(if ($egress) { $egress } else { '(未取到)' }))
    } catch {
        Add-Result 'SOCKS5 出口可用' $false $_.Exception.Message
    }

    # 大流量压一下：WinDivert 每个包都要进出用户态，MTU/分片问题只在高负载暴露。
    try {
        $mb = 8
        $t0 = Get-Date
        curl.exe -s --max-time 60 -x "http://$socks" -o NUL `
            "https://speed.cloudflare.com/__down?bytes=$($mb * 1024 * 1024)" | Out-Null
        $sec = ((Get-Date) - $t0).TotalSeconds
        $ok = $sec -gt 0.5
        Add-Result "下载 ${mb}MB" $ok ("{0:N2}s → {1:N2} MB/s" -f $sec, ($(if ($sec -gt 0) { $mb / $sec } else { 0 })))
    } catch {
        Add-Result '下载 8MB' $false $_.Exception.Message
    }
} else {
    Add-Skip '端到端连通' '未设置 FLOWTLS_SOCKS'
}

# 伪装站：同一个端口上真实网站必须仍可访问。
# 这条专门验证「未消费的包被重新注入给内核」（DEVTIPS 133/136）。
# 过滤器的判据是 IP ID 标记，浏览器流量不带标记 → 必须走内核 TCP。
$srv = $env:FLOWTLS_SERVER
if ($srv) {
    $host_ = ($srv -split ':')[0]
    $port_ = ($srv -split ':')[-1]
    try {
        $code = curl.exe -s -o NUL -w '%{http_code}' --max-time 20 -k "https://${host_}:${port_}/"
        # 任何非 000 的响应都说明内核 TCP 拿到了这个包（000 = 完全没响应）。
        Add-Result '同端口伪装站可达（验证重新注入）' ($code -ne '000') ("HTTP {0}" -f $code)
    } catch {
        Add-Result '同端口伪装站可达（验证重新注入）' $false $_.Exception.Message
    }
} else {
    Add-Skip '同端口伪装站' '未设置 FLOWTLS_SERVER'
}

# ---------------------------------------------------------------- 4. 资源占用

# Windows 路径的 CPU 开销是未知数（每包一次内核↔用户拷贝）。
# 这里在隧道跑着的情况下采样，给出一个可比较的量级。
$cpu0 = $proc.TotalProcessorTime
Start-Sleep -Seconds $WatchSeconds
$proc.Refresh()
$cpu1 = $proc.TotalProcessorTime
$usedSec = ($cpu1 - $cpu0).TotalSeconds
$cores = [Environment]::ProcessorCount
$pct = if ($WatchSeconds -gt 0 -and $cores -gt 0) { $usedSec / $WatchSeconds / $cores * 100 } else { 0 }
Write-Host ("[INFO] {0}s 内 CPU {1:N2}s（占整机 {2:N1}%），工作集 {3:N1} MB" -f `
    $WatchSeconds, $usedSec, $pct, ($proc.WorkingSet64 / 1MB)) -ForegroundColor Cyan

# ---------------------------------------------------------------- 5. 收尾

$proc | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500
Add-Result '进程可正常退出' $proc.HasExited

Write-Host ''
Write-Host '=== 汇总 ===' -ForegroundColor Cyan
$results | Format-Table -AutoSize | Out-String | Write-Host

$failed = ($results | Where-Object { $_.Result -eq 'FAIL' }).Count
Write-Host ("通过 {0} / 失败 {1} / 跳过 {2}" -f `
    ($results | Where-Object { $_.Result -eq 'PASS' }).Count, $failed,
    ($results | Where-Object { $_.Result -eq 'SKIP' }).Count)
Write-Host ''
Write-Host '清理（需要时手工执行）：' -ForegroundColor DarkGray
# 服务名就是 `WinDivert`（不带版本后缀），与 sing-box 官方版共用同一个服务名。
# 驱动可以留在系统里，卸载 sing-box 不会自动删除（与 Linux 的 iptables 规则同理：
# 升级/重启期间保留比删错更安全）。
Write-Host '  sc stop WinDivert ; sc delete WinDivert' -ForegroundColor DarkGray
Write-Host ("  驱动文件: {0}" -f $drvDir) -ForegroundColor DarkGray
Write-Host ("  日志:     {0}" -f $logFile) -ForegroundColor DarkGray

if ($failed -gt 0) { exit 1 }
exit 0
