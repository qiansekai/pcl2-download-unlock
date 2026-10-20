<#
.SYNOPSIS
    对 PCL2 可执行文件应用 IL 字节补丁。补丁定义见 patch-def.json。

.DESCRIPTION
    只做"查找-校验-等长替换"，不重写 PE、不触碰元数据表以外的任何结构。
    因为 find/replace 等长，节表、RVА、元数据堆偏移全部保持不变。

.PARAMETER In
    输入 exe（原始未修改文件）。

.PARAMETER Out
    输出 exe（补丁后）。

.PARAMETER DefFile
    补丁定义 JSON，默认同目录 patch-def.json。

.PARAMETER DryRun
    只做查找与校验，不写文件。

.EXAMPLE
    .\apply-patch.ps1 -In ..\_work\orig\Plain Craft Launcher 2.exe.orig -Out .\Plain Craft Launcher 2.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$In,
    [Parameter(Mandatory = $true)][string]$Out,
    [string]$DefFile = (Join-Path $PSScriptRoot 'patch-def.json'),
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $In)) { throw "input not found: $In" }
if (-not (Test-Path -LiteralPath $DefFile)) { throw "def not found: $DefFile" }

$def = Get-Content -LiteralPath $DefFile -Raw -Encoding UTF8 | ConvertFrom-Json

$bytes = [System.IO.File]::ReadAllBytes($In)
$inHash = (Get-FileHash -LiteralPath $In -Algorithm SHA256).Hash

Write-Output ("input    : {0}" -f $In)
Write-Output ("size     : {0:N0} B" -f $bytes.Length)
Write-Output ("sha256   : {0}" -f $inHash)

$expectedHash = $def.target.sha256
if ($expectedHash) {
    if ($inHash -ne $expectedHash) {
        Write-Warning ("sha256 与 patch-def 期望不符（目标版本可能不是 {0}）" -f $def.target.version)
        Write-Warning ("  expected: {0}" -f $expectedHash)
        Write-Warning ("  actual  : {0}" -f $inHash)
    } else {
        Write-Output ("version  : {0} {1} (sha256 匹配)" -f $def.target.product, $def.target.version)
    }
}

function ConvertTo-ByteArray([string]$hex) {
    $parts = $hex -split '-'
    [byte[]]$out = New-Object byte[] $parts.Length
    for ($i = 0; $i -lt $parts.Length; $i++) { $out[$i] = [Convert]::ToByte($parts[$i], 16) }
    return $out
}

# 用十六进制整串 + regex 定位（比逐字节循环快一个数量级）
$fileHex = [System.BitConverter]::ToString($bytes)
$work = $bytes.Clone()

$appliedCount = 0
foreach ($p in $def.patches) {
    $find = ConvertTo-ByteArray $p.find
    $repl = ConvertTo-ByteArray $p.replace
    if ($find.Length -ne $repl.Length) {
        throw ("patch '{0}': find/replace 长度不一致 ({1} vs {2})" -f $p.name, $find.Length, $repl.Length)
    }

    $script:workHex = [System.BitConverter]::ToString($work)
    $matches = [regex]::Matches($script:workHex, [regex]::Escape($p.find))
    $occ = $matches.Count
    Write-Output ""
    Write-Output ("patch    : {0}" -f $p.name)
    Write-Output ("  at     : {0}" -f $p.location)
    Write-Output ("  length : {0} bytes" -f $find.Length)
    Write-Output ("  hits   : {0} (expect {1})" -f $occ, $p.expectOccurrences)

    if ($occ -ne [int]$p.expectOccurrences) {
        throw ("patch '{0}' 命中数不符：实际 {1}，期望 {2}，中止（不做任何写入）" -f $p.name, $occ, $p.expectOccurrences)
    }

    foreach ($m in $matches) {
        # hex 串中每字节占 2 字符 + 1 个分隔符 => byteIndex = (charIndex + 1) / 3
        $byteIndex = [int](($m.Index + 1) / 3)
        Write-Output ("  offset : 0x{0:X}  (IL_+0x{1:X})" -f $byteIndex, ($byteIndex - 0x2C0C0))
        for ($k = 0; $k -lt $repl.Length; $k++) { $work[$byteIndex + $k] = $repl[$k] }
        $appliedCount++
    }
}

if ($DryRun) {
    Write-Output ""
    Write-Output "DRY RUN — 未写入任何文件"
    return
}

$changed = 0
for ($i = 0; $i -lt $bytes.Length; $i++) { if ($bytes[$i] -ne $work[$i]) { $changed++ } }
Write-Output ""
Write-Output ("diff bytes : {0} / {1}" -f $changed, $bytes.Length)
if ($changed -eq 0) { throw "没有任何字节被修改" }

[System.IO.File]::WriteAllBytes($Out, $work)

$outHash = (Get-FileHash -LiteralPath $Out -Algorithm SHA256).Hash
Write-Output ("output     : {0}" -f $Out)
Write-Output ("out sha256 : {0}" -f $outHash)
Write-Output ("out size   : {0:N0} B" -f (Get-Item -LiteralPath $Out).Length)

# 自检：find 必须消失，replace 必须存在
$outHex = [System.BitConverter]::ToString([System.IO.File]::ReadAllBytes($Out))
foreach ($p in $def.patches) {
    $stillFind = ([regex]::Matches($outHex, [regex]::Escape($p.find))).Count
    $hasRepl = ([regex]::Matches($outHex, [regex]::Escape($p.replace))).Count
    Write-Output ("verify     : {0} 残留={1} 已注入={2}" -f $p.name, $stillFind, $hasRepl)
    if ($stillFind -ne 0) { throw ("自检失败：patch '{0}' 目标仍存在" -f $p.name) }
    if ($hasRepl -lt 1) { throw ("自检失败：patch '{0}' 替换内容未出现" -f $p.name) }
}
Write-Output "OK"
