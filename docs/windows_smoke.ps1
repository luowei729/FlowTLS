# windows_smoke.ps1 -- first-run verification for FlowTLS on Windows.
#
# ============================================================================
# THIS FILE IS DELIBERATELY ASCII-ONLY (English messages, no CJK).
#
# Windows PowerShell 5.1 decodes a .ps1 WITHOUT a UTF-8 BOM using the system
# ANSI code page. CJK comments then decode into multi-byte garbage and the
# script fails to PARSE -- before a single line runs. The errors point at
# random places ("missing expression after ','" inside the param block) and
# look like a syntax bug that does not exist.
#
# It is NOT a runtime problem and NOT fixable by "running it again".
# Two valid fixes exist: (a) save as UTF-8 WITH BOM, or (b) keep it ASCII.
# We chose (b): an editor, a git filter or a zip tool can silently strip a BOM
# and then the script breaks again for the next person. The Chinese
# documentation for this script lives in PROJECT_PLAN.md section W9.
#
# If you edit this file, keep every byte below 0x80. Verify with:
#   python -c "d=open('windows_smoke.ps1','rb').read(); print(max(d))"
# ============================================================================
#
# Usage (Administrator PowerShell):
#   .\windows_smoke.ps1 -Bin .\sing-box.exe -Config .\client.json
#
# Server address, local listen port and credentials are all read from the
# config file, so no environment variables are needed.
#
# Exit code: 0 = all checks passed, 1 = at least one failure, 2 = cannot start.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Bin,

    [Parameter(Mandatory = $true)]
    [string]$Config,

    # Probe target. The cloudflare trace echoes back the egress IP, which
    # proves traffic really leaves from the server side.
    [string]$Probe = 'https://www.cloudflare.com/cdn-cgi/trace',

    # How long to sample CPU / memory while the tunnel is up.
    [int]$WatchSeconds = 20
)

$ErrorActionPreference = 'Stop'

$script:PassCount = 0
$script:FailCount = 0
$script:SkipCount = 0

function Write-Result {
    param(
        [string]$Name,
        [bool]$Ok,
        [string]$Detail = ''
    )
    if ($Ok) {
        $script:PassCount = $script:PassCount + 1
        Write-Host ('[PASS] ' + $Name) -ForegroundColor Green
    } else {
        $script:FailCount = $script:FailCount + 1
        Write-Host ('[FAIL] ' + $Name) -ForegroundColor Red
    }
    if ($Detail) {
        Write-Host ('       ' + $Detail) -ForegroundColor DarkGray
    }
}

function Write-Skip {
    param(
        [string]$Name,
        [string]$Why = ''
    )
    $script:SkipCount = $script:SkipCount + 1
    Write-Host ('[SKIP] ' + $Name) -ForegroundColor Yellow
    if ($Why) {
        Write-Host ('       ' + $Why) -ForegroundColor DarkGray
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('--- ' + $Title + ' ---') -ForegroundColor Cyan
}

function Read-Logs {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    $t = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    if ($null -eq $t) { return '' }
    return [string]$t
}

Write-Host ''
Write-Host '=== FlowTLS Windows smoke test ===' -ForegroundColor Cyan

# ---------------------------------------------------------------- 0. preflight

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$detail = ''
if (-not $isAdmin) {
    $detail = 'Run PowerShell as Administrator -- the WinDivert driver cannot load otherwise'
}
Write-Result 'Administrator privileges' $isAdmin $detail

if (-not (Test-Path -LiteralPath $Bin)) {
    Write-Host ('FATAL: binary not found: ' + $Bin) -ForegroundColor Red
    exit 2
}
if (-not (Test-Path -LiteralPath $Config)) {
    Write-Host ('FATAL: config not found: ' + $Config) -ForegroundColor Red
    exit 2
}
$binItem = Get-Item -LiteralPath $Bin
Write-Result 'Binary and config present' $true ($binItem.Name + ' (' + [string]$binItem.Length + ' bytes)')

# WinDivert ships x64 and x86 drivers only; ARM64 Windows is not supported.
$arch = [string]$env:PROCESSOR_ARCHITECTURE
$archOk = ($arch -eq 'AMD64') -or ($arch -eq 'x86')
$detail = ''
if (-not $archOk) { $detail = 'WinDivert assets exist for x64/x86 only; ARM64 is not supported' }
Write-Result ('CPU architecture supported (' + $arch + ')') $archOk $detail

# curl.exe ships with Windows 10 1803+ and Server 2019+. Without it the two
# network checks cannot run, and "command not found" would be reported as a
# tunnel failure -- the most misleading outcome possible.
$curlCmd = Get-Command -Name 'curl.exe' -ErrorAction SilentlyContinue
$curlOk = ($null -ne $curlCmd)
$detail = ''
if (-not $curlOk) { $detail = 'curl.exe not found; network checks will be skipped (Windows 10 1803+ ships it)' }
Write-Result 'curl.exe available' $curlOk $detail

# -------------------------------------------------------------- read settings

$srvHost = ''
$srvPort = 0
$socksAddr = ''
$proxyCred = ''

try {
    $rawCfg = Get-Content -LiteralPath $Config -Raw
    $cfg = $rawCfg | ConvertFrom-Json
} catch {
    Write-Host ('FATAL: cannot parse config: ' + $_.Exception.Message) -ForegroundColor Red
    exit 2
}

$ob = @($cfg.outbounds) | Where-Object { $_.type -eq 'flowtls' } | Select-Object -First 1
if ($ob) {
    $srvHost = [string]$ob.server
    $srvPort = [int]$ob.server_port
}

$ib = @($cfg.inbounds) | Where-Object { $_.listen_port } | Select-Object -First 1
if ($ib) {
    $lh = [string]$ib.listen
    if (($lh -eq '') -or ($lh -eq '0.0.0.0') -or ($lh -eq '::') -or ($lh -eq '[::]')) {
        $lh = '127.0.0.1'
    }
    $socksAddr = $lh + ':' + [string]$ib.listen_port
    $u = @($ib.users) | Select-Object -First 1
    if ($u) {
        $proxyCred = [string]$u.username + ':' + [string]$u.password
    }
}

$server = ''
if (($srvHost -ne '') -and ($srvPort -gt 0)) {
    $server = $srvHost + ':' + [string]$srvPort
}

# Secrets are never printed; only presence is reported.
if ($server -ne '') {
    Write-Result 'Config: server parsed' $true ('port ' + [string]$srvPort)
} else {
    Write-Result 'Config: server parsed' $false 'no flowtls outbound with server/server_port'
}

if ($socksAddr -ne '') {
    Write-Result 'Config: local listener parsed' $true $socksAddr
} else {
    Write-Result 'Config: local listener parsed' $false 'no inbound with listen_port'
}

# curl through the local proxy: -x for the endpoint, --proxy-user for auth.
# The mixed inbound has a users list, so an unauthenticated request would just
# return 407 and look like a broken tunnel.
#
# Plain string array (not ArrayList): @splat only guarantees expansion for
# arrays, and an empty array must expand to nothing.
[string[]]$proxyArgs = @()
if ($socksAddr -ne '') {
    $proxyArgs += '-x'
    $proxyArgs += ('http://' + $socksAddr)
    if ($proxyCred -ne '') {
        $proxyArgs += '--proxy-user'
        $proxyArgs += $proxyCred
    }
}

if ($socksAddr -ne '') {
    $lp = [int]($socksAddr.Split(':')[-1])
    $busy = Get-NetTCPConnection -LocalPort $lp -State Listen -ErrorAction SilentlyContinue
    $detail = ''
    if ($busy) { $detail = 'another process is already listening; stop it or change listen_port' }
    Write-Result ('Local port ' + [string]$lp + ' free') (-not [bool]$busy) $detail
}

# --------------------------------------------------------------- start binary

Write-Section 'start'

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logOut = Join-Path $env:TEMP ('flowtls-' + $stamp + '.out.log')
$logErr = Join-Path $env:TEMP ('flowtls-' + $stamp + '.err.log')
Write-Host ('log: ' + $logOut) -ForegroundColor DarkGray

$proc = $null
try {
    $proc = Start-Process -FilePath $Bin -ArgumentList @('run', '-c', $Config) -PassThru -NoNewWindow -RedirectStandardOutput $logOut -RedirectStandardError $logErr
} catch {
    Write-Result 'Start sing-box' $false $_.Exception.Message
    exit 2
}

try {
    # Wait for the send-path log line. The first run also writes the driver to
    # disk and registers the service, so allow a generous 25s.
    $deadline = (Get-Date).AddSeconds(25)
    $sendMode = ''
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        if ($proc.HasExited) { break }
        $txt = (Read-Logs $logOut) + (Read-Logs $logErr)
        if ($txt -match 'windivert') { $sendMode = 'windivert'; break }
    }

    if ($proc.HasExited) {
        $txt = (Read-Logs $logOut) + (Read-Logs $logErr)
        Write-Result 'Start sing-box' $false ('process exited with code ' + [string]$proc.ExitCode)
        Write-Host ''
        Write-Host '--- log ---' -ForegroundColor DarkGray
        Write-Host $txt -ForegroundColor DarkGray

        $hint = 'see the log above'
        if ($txt -match 'ACCESS_DENIED|Access is denied') {
            $hint = 'not running as Administrator (ERROR_ACCESS_DENIED)'
        } elseif ($txt -match '1275|DRIVER_BLOCKED') {
            $hint = 'antivirus blocked the WinDivert driver (ERROR_DRIVER_BLOCKED=1275); whitelist and retry'
        } elseif ($txt -match '577|INVALID_IMAGE_HASH') {
            $hint = 'driver signature rejected (ERROR_INVALID_IMAGE_HASH=577)'
        } elseif ($txt -match 'windivert') {
            $hint = 'WinDivert related, see the log above'
        }
        Write-Host ''
        Write-Host ('hint: ' + $hint) -ForegroundColor Yellow
        exit 1
    }

    Write-Result 'Start sing-box' $true
    Write-Result 'Send path is windivert' ($sendMode -eq 'windivert') 'expected the log to contain "windivert"'

    # ------------------------------------------------------------ driver state

    Write-Section 'driver'

    $drvDir = Join-Path $env:LOCALAPPDATA 'flowtls\windivert'
    if (Test-Path -LiteralPath $drvDir) {
        $sys = @(Get-ChildItem -LiteralPath $drvDir -Recurse -Filter 'WinDivert*.sys' -ErrorAction SilentlyContinue)
        $detail = ''
        if ($sys.Count -eq 0) { $detail = 'directory exists but contains no .sys file' }
        Write-Result 'Driver written to disk' ($sys.Count -gt 0) $detail
    } else {
        # Not a failure: an official sing-box install may already have the
        # service registered, in which case CreateFile reuses it.
        Write-Skip 'Driver written to disk' ('no ' + $drvDir + ' (an existing WinDivert service may be reused)')
    }

    # Get-Service only lists services (win32 services), NOT kernel drivers, so it
    # would always report "not found" here. Query the driver store instead.
    $drv = @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'WinDivert*' })
    if ($drv.Count -gt 0) {
        $names = @()
        $running = $false
        foreach ($d in $drv) {
            $names += ($d.Name + '=' + [string]$d.State)
            if ($d.State -eq 'Running') { $running = $true }
        }
        Write-Result 'WinDivert driver registered' $running ($names -join '; ')
    } else {
        # Not a hard failure: the driver node may not exist until the first
        # CreateFile, and an official sing-box install may share it.
        Write-Skip 'WinDivert driver registered' 'no WinDivert* entry in Win32_SystemDriver yet'
    }

    # ------------------------------------------------------------- end to end

    Write-Section 'end to end'

    if (($socksAddr -ne '') -and $curlOk) {
        $egress = ''
        $err = ''
        try {
            $out = & curl.exe -s --max-time 25 @proxyArgs $Probe 2>&1
            foreach ($line in @($out)) {
                $s = [string]$line
                if ($s -match '^ip=(.+)$') { $egress = $Matches[1].Trim() }
            }
        } catch {
            $err = $_.Exception.Message
        }
        if ($egress -ne '') {
            $detail = 'egress IP ' + $egress
            if (($srvHost -ne '') -and ($egress -ne $srvHost)) {
                $detail = $detail + ' (differs from the configured server address)'
            }
            Write-Result 'Proxy egress works' $true $detail
        } else {
            if ($err -eq '') { $err = 'no ip= line in the trace output; tunnel or proxy auth failed' }
            Write-Result 'Proxy egress works' $false $err
        }

        # A larger transfer: MTU / fragmentation problems only show under load.
        # Judge on curl's own numbers, not on elapsed time: a failed curl also
        # returns quickly (or after the timeout), which would make a timing-only
        # check report PASS for a dead tunnel.
        $mb = 8
        $url = 'https://speed.cloudflare.com/__down?bytes=' + [string]($mb * 1024 * 1024)
        $fmt = '%{http_code} %{size_download} %{time_total} %{speed_download}'
        $out = ''
        try { $out = [string](& curl.exe -s --max-time 60 @proxyArgs -o NUL -w $fmt $url 2>$null) } catch { }
        $code = 0
        $got = 0
        $sec = 0.0
        $bps = 0.0
        $parts = @($out -split ' ')
        if ($parts.Count -ge 4) {
            $code = [int]$parts[0]
            $got = [double]$parts[1]
            $sec = [double]$parts[2]
            $bps = [double]$parts[3]
        }
        $want = $mb * 1024 * 1024
        $ok = ($code -eq 200) -and ($got -ge ($want * 0.99))
        $detail = ''
        if ($ok) {
            $detail = [string]::Format('{0:N2}s -> {1:N2} MB/s', $sec, ($bps / 1MB))
        } else {
            $detail = 'http=' + [string]$code + ' bytes=' + [string]$got + ' (want 200 and ' + [string]$want + ')'
        }
        Write-Result ('Download ' + [string]$mb + 'MB') $ok $detail
    } else {
        $why = 'local listener could not be determined'
        if (-not $curlOk) { $why = 'curl.exe is not available' }
        Write-Skip 'Proxy egress works' $why
        Write-Skip 'Download 8MB' $why
    }

    # The same TCP port must still serve the real website. This is the check
    # that exercises "unconsumed packets are reinjected into the kernel":
    # browser traffic carries no ip_id mark, so it has to reach the kernel TCP
    # stack. 000 means no response at all.
    if (($server -ne '') -and $curlOk) {
        $code = ''
        try {
            $out = & curl.exe -s -o NUL -w '%{http_code}' --max-time 20 -k ('https://' + $server + '/') 2>&1
            $last = @($out) | Select-Object -Last 1
            $code = [string]$last
        } catch { }
        $ok = ($code -ne '') -and ($code -ne '000')
        $detail = ''
        if (-not $ok) {
            $detail = 'no HTTP response, reinjection may be broken; '
        }
        Write-Result 'Decoy site reachable on the same port' $ok ($detail + 'HTTP ' + $code)
    } else {
        $why = 'server address unknown'
        if (-not $curlOk) { $why = 'curl.exe is not available' }
        Write-Skip 'Decoy site reachable on the same port' $why
    }

    # ------------------------------------------------------------------ load

    Write-Section 'resource usage'

    $proc.Refresh()
    $cpu0 = $proc.TotalProcessorTime
    Start-Sleep -Seconds $WatchSeconds
    $proc.Refresh()
    $cpu1 = $proc.TotalProcessorTime
    $used = ($cpu1 - $cpu0).TotalSeconds
    $cores = [Environment]::ProcessorCount
    $pct = 0.0
    if (($WatchSeconds -gt 0) -and ($cores -gt 0)) {
        $pct = $used / $WatchSeconds / $cores * 100
    }
    $rss = $proc.WorkingSet64 / 1MB
    Write-Host ('[INFO] ' + [string]$WatchSeconds + 's: cpu ' + [string]::Format('{0:N2}s ({1:N1}% of machine), working set {2:N1} MB', $used, $pct, $rss)) -ForegroundColor Cyan
}
catch {
    # Record it as a FAIL instead of dying half way: a crash that exits with
    # code 0 looks like success to whoever reads the output later.
    Write-Result 'Unhandled error during checks' $false $_.Exception.Message
}
finally {
    # Always stop the child, even if a check above threw. Leaving a tunnel and
    # a loaded driver behind is how the next run starts from a stale state.
    if ($null -ne $proc) {
        if (-not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
            $proc.Refresh()
        }
        $detail = ''
        if (-not $proc.HasExited) { $detail = 'process is still alive' }
        Write-Result 'Process stopped cleanly' $proc.HasExited $detail
    }
}

# ------------------------------------------------------------------- summary

Write-Section 'summary'
Write-Host ('pass=' + [string]$script:PassCount + '  fail=' + [string]$script:FailCount + '  skip=' + [string]$script:SkipCount)
Write-Host ''
Write-Host 'cleanup (only if you want to remove the driver):' -ForegroundColor DarkGray
Write-Host '  sc stop WinDivert ; sc delete WinDivert' -ForegroundColor DarkGray
Write-Host ('  driver dir: ' + (Join-Path $env:LOCALAPPDATA 'flowtls\windivert')) -ForegroundColor DarkGray
Write-Host ('  logs:       ' + $logOut) -ForegroundColor DarkGray

if ($script:FailCount -gt 0) { exit 1 }
exit 0
