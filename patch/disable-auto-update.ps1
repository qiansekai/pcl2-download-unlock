<#
.SYNOPSIS
    关闭 / 恢复 PCL 的自动更新（防止补丁被新版本覆盖）。

.DESCRIPTION
    PCL 的自动更新策略写在 <PCL目录>\PCL\Setup.ini 的 SystemSystemUpdate 键：
        0 = 有新版本时自动下载（缺省行为）
        1 = 有新版本时显示提示
        2 = 仅在有重大漏洞更新时显示提示
        3 = 关闭更新提示
    缺省（键不存在）等价于 0，即"自动下载"——补丁会被覆盖。

    PCL 退出时会把内存中的配置回写 Setup.ini，所以必须先关闭 PCL 再改，
    否则本次修改会被覆盖。

.PARAMETER PclDir
    PCL 所在目录（含 exe 与 PCL 子目录）。

.PARAMETER Value
    要写入 SystemSystemUpdate 的值，默认 3（关闭更新提示）。

.PARAMETER ProcessName
    用来判定 PCL 是否在运行的进程名，默认 'Plain Craft Launcher 2'。

.EXAMPLE
    .\disable-auto-update.ps1 -PclDir 'C:\PCL2'

.EXAMPLE
    # 恢复缺省自动更新
    .\disable-auto-update.ps1 -PclDir 'C:\PCL2' -Value 0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PclDir,
    [ValidateSet(0, 1, 2, 3)][int]$Value = 3,
    [string]$ProcessName = 'Plain Craft Launcher 2'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ini = Join-Path (Join-Path $PclDir 'PCL') 'Setup.ini'
if (-not (Test-Path -LiteralPath $ini)) { throw "Setup.ini not found: $ini" }

# 1) 关闭运行中的 PCL（避免退出时回写覆盖）
$procs = @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
if ($procs.Count -gt 0) {
    foreach ($p in $procs) {
        Write-Output ("closing PCL PID {0} ..." -f $p.Id)
        $null = $p.CloseMainWindow()
        if (-not $p.WaitForExit(8000)) {
            Write-Output "  graceful close timed out, forcing"
            Stop-Process -Id $p.Id -Force
            Start-Sleep -Milliseconds 1200
        }
    }
    Start-Sleep -Milliseconds 600
}
$left = @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
if ($left.Count -gt 0) { throw "PCL 仍在运行，无法安全写配置" }

# 2) 改写 SystemSystemUpdate
$lines = @(Get-Content -LiteralPath $ini)
Write-Output ""
Write-Output "--- before ---"
$lines | ForEach-Object { Write-Output $_ }

$pattern = '^\s*SystemSystemUpdate\s*:'
$newLine = "SystemSystemUpdate:$Value"
if ($lines | Where-Object { $_ -match $pattern }) {
    $lines = @($lines | ForEach-Object {
        if ($_ -match $pattern) { $newLine } else { $_ }
    })
} else {
    $lines = $lines + $newLine
}

Set-Content -LiteralPath $ini -Value $lines -Encoding UTF8

Write-Output ""
Write-Output "--- after ---"
$lines | ForEach-Object { Write-Output $_ }
Write-Output ""
Write-Output ("SystemSystemUpdate = {0} 写入完成" -f $Value)

# 3) 重新启动 PCL
$exe = Get-ChildItem -LiteralPath $PclDir -Filter '*.exe' | Where-Object { $_.Name -like 'Plain Craft Launcher*' } | Select-Object -First 1
if ($exe) {
    $proc = Start-Process -FilePath $exe.FullName -WorkingDirectory $PclDir -PassThru
    Write-Output ("relaunched: {0} (PID {1})" -f $exe.Name, $proc.Id)
} else {
    Write-Warning "未找到 PCL exe，跳过重启"
}
