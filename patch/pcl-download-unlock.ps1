<#
.SYNOPSIS
    PCL2 下载封锁解除 —— 一键分析与补丁（零依赖）。

.DESCRIPTION
    2026-10-20 起，PCL2 2.99.x 把「原版游戏」页的版本清单加载器替换成了一个只抛异常的假
    LoaderTask，导致下载页报「为遵守相关法律法规…」。

    本脚本不依赖任何硬编码字节串，而是：
      1. 用 System.Reflection.Metadata（pwsh 自带 BCL，无需编译/装包）
         定位 PCL.PageDownloadInstall::LoaderInit() 的方法体；
      2. 在该方法的 IL 里按语义查找 newobj LoaderTask<TIn,TOut>::.ctor（假加载器构造），
         向前回溯到 ldstr（方法名字符串）确定待替换区间；
      3. 生成与原区间等长的替换字节：ldsfld PCL.ModDownload::DlClientListLoader + nop 填充
         （等长 => 节表/元数据堆/RVA 全不变；nop 填充 => 栈平衡与原逻辑一致）；
      4. 校验仅目标区间被改动、文件长度不变。

    因为按语义定位，PCL 发新版时只要埋点结构不变，脚本无需修改即可适配；
    若结构变了则安全失败（不写文件）。重复运行可识别「已打过补丁」。

.PARAMETER In
    待处理的 PCL 可执行文件。

.PARAMETER Out
    输出文件。省略时在原文件旁生成 <name>.patched.exe。

.PARAMETER PclDir
    PCL 所在目录。给出时自动在目录内查找 Plain Craft Launcher*.exe 作为 -In，
    且作为 -Deploy / -RestorePclDir 的部署目录。

.PARAMETER Deploy
    部署模式：关闭正在运行的 PCL -> 备份 -> 写入补丁 -> 关闭自动更新 -> 重新启动 PCL。

.PARAMETER RestorePclDir
    从最近的 .bak-* 备份恢复 exe。

.PARAMETER DryRun
    只分析并打印将要做的事，不写任何文件。

.PARAMETER Force
    允许对已打过补丁的文件重复处理（默认跳过）。

.EXAMPLE
    # 只生成补丁产物，不动现场
    .\pcl-download-unlock.ps1 -PclDir 'C:\PCL2'

.EXAMPLE
    # 一键打补丁并部署（会重启 PCL）
    .\pcl-download-unlock.ps1 -PclDir 'C:\PCL2' -Deploy

.EXAMPLE
    # 回滚
    .\pcl-download-unlock.ps1 -RestorePclDir 'C:\PCL2'
#>
[CmdletBinding(DefaultParameterSetName = 'Patch')]
param(
    [Parameter(ParameterSetName = 'Patch')][string]$In,
    [Parameter(ParameterSetName = 'Patch')][string]$Out,
    [Parameter(ParameterSetName = 'Patch')][string]$PclDir,
    [Parameter(ParameterSetName = 'Patch')][switch]$Deploy,
    [Parameter(Mandatory = $true, ParameterSetName = 'Restore')][string]$RestorePclDir,
    [switch]$DryRun,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName 'System.Reflection.Metadata' -ErrorAction Stop | Out-Null
# 注意：PowerShell 变量名大小写不敏感。类型别名统一加 Type 前缀，
# 否则 $pe（PEReader 实例）会与 $PE（类型）撞成同一个变量。
$TypePE  = [System.Reflection.PortableExecutable.PEReader]
$TypeTok = [System.Reflection.Metadata.Ecma335.MetadataTokens]
$TypeHS  = [System.Reflection.Metadata.HandleKind]

$TargetType   = 'PCL.PageDownloadInstall'
$TargetMethod = 'LoaderInit'
$LoaderType   = 'LoaderTask'
$LoaderField  = 'DlClientListLoader'
$FieldOwner   = 'PCL.ModDownload'
$ProcName     = 'Plain Craft Launcher 2'

function Find-PclExe([string]$dir) {
    if (-not (Test-Path -LiteralPath $dir)) { throw "目录不存在: $dir" }
    $hit = Get-ChildItem -LiteralPath $dir -Filter '*.exe' -File |
           Where-Object { $_.Name -like 'Plain Craft Launcher*' } |
           Sort-Object Length -Descending | Select-Object -First 1
    if (-not $hit) { throw "在 $dir 下没找到 Plain Craft Launcher*.exe" }
    return $hit.FullName
}

function Get-RvaOffset($peHeaders, [int]$rva) {
    foreach ($s in $peHeaders.SectionHeaders) {
        $size = [Math]::Max($s.VirtualSize, $s.SizeOfRawData)
        if ($rva -ge $s.VirtualAddress -and $rva -lt ($s.VirtualAddress + $size)) {
            return $s.PointerToRawData + ($rva - $s.VirtualAddress)
        }
    }
    return -1
}

# IL opcode -> 操作数长度（ECMA-335）。未列出者视为无操作数。
$ILSize = @{}
foreach ($op in 0x0E,0x0F,0x10,0x11,0x12,0x13,0x1F,0xDE,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37) { $ILSize[$op] = 1 }
foreach ($op in 0x20,0x22,0x27,0x28,0x29,0x6F,0x70,0x71,0x72,0x73,0x74,0x75,0x79,0x7B,0x7C,0x7D,0x7E,0x7F,0x80,0x81) { $ILSize[$op] = 4 }
foreach ($op in 0x8C,0x8D,0x8F,0xA3,0xA4,0xA5,0xC2,0xC6,0xD0,0xDD,0x38,0x39,0x3A,0x3B) { $ILSize[$op] = 4 }
foreach ($op in 0x3C,0x3D,0x3E,0x3F,0x40,0x41,0x42,0x43,0x44) { $ILSize[$op] = 4 }
$ILSize[0x21] = 8; $ILSize[0x23] = 8; $ILSize[0x45] = -1
$ILSize[0xFE06] = 4; $ILSize[0xFE07] = 4; $ILSize[0xFE15] = 4; $ILSize[0xFE16] = 4; $ILSize[0xFE1C] = 4
$ILSize[0xFE09] = 2; $ILSize[0xFE0A] = 2; $ILSize[0xFE0B] = 2
$ILSize[0xFE0C] = 2; $ILSize[0xFE0D] = 2; $ILSize[0xFE0E] = 2
$ILSize[0xFE12] = 1; $ILSize[0xFE19] = 1

function Get-ILInstructions([byte[]]$il) {
    $list = New-Object System.Collections.Generic.List[object]
    $i = 0
    while ($i -lt $il.Length) {
        $start = $i
        $b = $il[$i]; $i++
        $code = [int]$b
        if ($b -eq 0xFE) {
            if ($i -ge $il.Length) { throw "IL 截断于 0xFE 前缀 (offset $start)" }
            $code = 0xFE00 -bor [int]$il[$i]; $i++
        }
        # 表里只登记"带操作数"的 opcode；未登记的按无操作数处理（ECMA-335 里其余确实都不带操作数）
        $osz = 0
        if ($ILSize.ContainsKey($code)) { $osz = [int]$ILSize[$code] }
        if ($osz -eq -1) {
            $cnt = [BitConverter]::ToInt32($il, $i); $i += 4
            $osz = $cnt * 4
        }
        $operand = 0
        if ($osz -eq 1) { $operand = [int]$il[$i] }
        elseif ($osz -eq 2) { $operand = [int][BitConverter]::ToUInt16($il, $i) }
        elseif ($osz -eq 4) { $operand = [int][BitConverter]::ToInt32($il, $i) }
        elseif ($osz -eq 8) { $operand = [int64][BitConverter]::ToInt64($il, $i) }
        $i += $osz
        $list.Add([pscustomobject]@{ Offset = $start; Length = $i - $start; Code = $code; Operand = $operand })
    }
    return $list
}

function Resolve-TokenName($mr, [int]$token) {
    if ((([uint32]$token) -shr 24) -eq 0x70) {
        try { return 'ldstr "' + $mr.GetUserString($TypeTok::UserStringHandle($token -band 0x00FFFFFF)) + '"' }
        catch { return '<userstring>' }
    }
    try {
        $h = $TypeTok::EntityHandle($token)
        switch ($h.Kind) {
            ($TypeHS::MemberReference) {
                $m = $mr.GetMemberReference([System.Reflection.Metadata.MemberReferenceHandle]$h)
                return $mr.GetString($m.Name) + '  [' + $h.Parent.Kind.ToString() + ']'
            }
            ($TypeHS::MethodDefinition) {
                $m = $mr.GetMethodDefinition([System.Reflection.Metadata.MethodDefinitionHandle]$h)
                return $mr.GetString($m.Name)
            }
            ($TypeHS::FieldDefinition) {
                $f = $mr.GetFieldDefinition([System.Reflection.Metadata.FieldDefinitionHandle]$h)
                return $mr.GetString($f.Name)
            }
            default { return '<' + $h.Kind.ToString() + '>' }
        }
    } catch { return '<unresolved>' }
}

function Get-TypeSpecOuterName($mr, $typeSpecHandle) {
    $ts = $mr.GetTypeSpecification($typeSpecHandle)
    $br = $mr.GetBlobReader($ts.Signature)
    if ($br.ReadByte() -ne 0x15) { return $null }
    $null = $br.ReadByte()
    $th = $br.ReadTypeHandle()
    switch ($th.Kind) {
        ($TypeHS::TypeDefinition) {
            return $mr.GetString($mr.GetTypeDefinition([System.Reflection.Metadata.TypeDefinitionHandle]$th).Name)
        }
        ($TypeHS::TypeReference) {
            return $mr.GetString($mr.GetTypeReference([System.Reflection.Metadata.TypeReferenceHandle]$th).Name)
        }
        default { return $null }
    }
}

function Find-TypeByFullName($mr, [string]$fullName) {
    foreach ($th in $mr.TypeDefinitions) {
        $td = $mr.GetTypeDefinition($th)
        $ns = $mr.GetString($td.Namespace); $nm = $mr.GetString($td.Name)
        $fq = $(if ($ns) { $ns + '.' + $nm } else { $nm })
        if ($fq -eq $fullName) { return @{ Handle = $th; Def = $td } }
    }
    return $null
}

# ======================================================== 恢复模式
if ($PSCmdlet.ParameterSetName -eq 'Restore') {
    $exe = Find-PclExe $RestorePclDir
    $baks = @(Get-ChildItem -LiteralPath $RestorePclDir -Filter '*.bak-*' -File |
              Where-Object { $_.Name -like 'Plain Craft Launcher*' } |
              Sort-Object LastWriteTime -Descending)
    if ($baks.Count -eq 0) { throw "在 $RestorePclDir 下没有找到备份文件" }
    $bak = $baks[0]
    Write-Output ("恢复来源: {0}  ({1})" -f $bak.Name, $bak.LastWriteTime)
    Write-Output ("目标    : {0}" -f $exe)
    if ($DryRun) { Write-Output 'DRY RUN - 未做任何修改'; return }
    foreach ($p in @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)) {
        $null = $p.CloseMainWindow()
        if (-not $p.WaitForExit(8000)) { Stop-Process -Id $p.Id -Force }
        Start-Sleep -Milliseconds 600
    }
    Copy-Item -LiteralPath $bak.FullName -Destination $exe -Force
    Write-Output ("已恢复，sha256 = {0}" -f (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash)
    return
}

# ======================================================== 定位输入
if (-not $In) {
    if (-not $PclDir) { throw '必须提供 -PclDir 或 -In' }
    $In = Find-PclExe $PclDir
}
if (-not (Test-Path -LiteralPath $In)) { throw "输入不存在: $In" }
$outIsTemp = $false
if (-not $Out) {
    if ($Deploy) {
        # 部署模式不往现场甩产物：先写临时文件，装完即清理
        $outIsTemp = $true
        $Out = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ('pcl-patched-' + [guid]::NewGuid().ToString('N') + '.exe'))
    } else {
        $Out = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($In), 'Plain Craft Launcher 2.patched.exe')
    }
}

$inFull = (Resolve-Path -LiteralPath $In).Path
$bytes  = [System.IO.File]::ReadAllBytes($inFull)
$hash   = (Get-FileHash -LiteralPath $inFull -Algorithm SHA256).Hash

Write-Output '========================================'
Write-Output ' PCL2 下载封锁解除 · 自动定位与补丁'
Write-Output '========================================'
Write-Output ("输入     : {0}" -f $inFull)
Write-Output ("大小     : {0:N0} B" -f $bytes.Length)
Write-Output ("SHA256   : {0}" -f $hash)
Write-Output ("文件版本 : {0}" -f (Get-Item -LiteralPath $inFull).VersionInfo.FileVersion)

$fs = $null; $pe = $null
try {
    $fs = [System.IO.File]::OpenRead($inFull)
    $pe = $TypePE::new($fs)
    if (-not $pe.HasMetadata) { throw '不是 .NET 程序集（无 CLR 元数据）' }
    $mr = [System.Reflection.Metadata.PEReaderExtensions]::GetMetadataReader($pe)
    $cor = $pe.PEHeaders.CorHeader
    Write-Output ("强名签名 : {0}" -f $(if ($cor.StrongNameSignatureDirectory.Size -gt 0) { '有（改动会失效）' } else { '无' }))
    Write-Output ("AuthCode : {0}" -f $(if ($pe.PEHeaders.PEHeader.CertificateTableDirectory.Size -gt 0) { '有' } else { '无' }))

    $t = Find-TypeByFullName $mr $TargetType
    if (-not $t) { throw ("未找到类型 {0}" -f $TargetType) }
    $methodHandle = $null
    foreach ($mh in $t.Def.GetMethods()) {
        $md0 = $mr.GetMethodDefinition($mh)
        if ($mr.GetString($md0.Name) -eq $TargetMethod) { $methodHandle = $mh; break }
    }
    if ($null -eq $methodHandle) { throw ("未找到 {0}::{1}()" -f $TargetType, $TargetMethod) }

    $md = $mr.GetMethodDefinition($methodHandle)
    $rva = $md.RelativeVirtualAddress
    if ($rva -eq 0) { throw '目标方法没有方法体' }
    $body = [System.Reflection.Metadata.PEReaderExtensions]::GetMethodBody($pe, $rva)
    $il = $body.GetILBytes()

    $bodyOff = Get-RvaOffset $pe.PEHeaders $rva
    if ($bodyOff -lt 0) { throw '无法把方法体 RVA 映射到文件偏移' }
    $hb = $bytes[$bodyOff]
    if (($hb -band 3) -eq 3) { $hdrSize = 12 }
    elseif (($hb -band 3) -eq 2) { $hdrSize = 1 }
    else { throw '未知方法体头格式' }
    $ilBase = $bodyOff + $hdrSize

    Write-Output ''
    $methodToken = $TypeTok::GetToken([System.Reflection.Metadata.EntityHandle]$methodHandle)
    Write-Output ("目标方法 : {0}::{1}()  MethodDef=0x{2:X8}" -f $TargetType, $TargetMethod, $methodToken)
    Write-Output ("方法体   : RVA=0x{0:X} 文件偏移=0x{1:X} header={2}B IL={3}B 基点=0x{4:X}" -f $rva, $bodyOff, $hdrSize, $il.Length, $ilBase)

    $ins = Get-ILInstructions $il

    $ft = Find-TypeByFullName $mr $FieldOwner
    if (-not $ft) { throw ("未找到类型 {0}" -f $FieldOwner) }
    $fieldToken = $null
    foreach ($fh in $ft.Def.GetFields()) {
        $fd = $mr.GetFieldDefinition($fh)
        if ($mr.GetString($fd.Name) -eq $LoaderField) {
            $fieldToken = $TypeTok::GetToken([System.Reflection.Metadata.EntityHandle]$fh)
            break
        }
    }
    if ($null -eq $fieldToken) { throw ("未找到字段 {0}::{1}" -f $FieldOwner, $LoaderField) }
    Write-Output ("目标字段 : {0}::{1}  token=0x{2:X8}" -f $FieldOwner, $LoaderField, $fieldToken)

    $alreadyPatched = $false
    foreach ($i in $ins) { if ($i.Code -eq 0x7E -and $i.Operand -eq $fieldToken) { $alreadyPatched = $true; break } }
    if ($alreadyPatched -and -not $Force) {
        Write-Output ''
        Write-Output '[跳过] 该方法已是 ldsfld DlClientListLoader —— 补丁已存在。'
        Write-Output '       如需强制重做请加 -Force；只调整自动更新开关请用 patch/disable-auto-update.ps1。'
        return
    }

    $newobjIdx = -1
    for ($k = 0; $k -lt $ins.Count; $k++) {
        $i = $ins[$k]
        if ($i.Code -ne 0x73) { continue }
        try {
            $h = $TypeTok::EntityHandle($i.Operand)
            if ($h.Kind -ne $TypeHS::MemberReference) { continue }
            $mref = $mr.GetMemberReference([System.Reflection.Metadata.MemberReferenceHandle]$h)
            if ($mr.GetString($mref.Name) -ne '.ctor') { continue }
            if ($mref.Parent.Kind -ne $TypeHS::TypeSpecification) { continue }
            $outer = Get-TypeSpecOuterName $mr $mref.Parent
            if ($outer -and $outer.StartsWith($LoaderType)) { $newobjIdx = $k; break }
        } catch { continue }
    }
    if ($newobjIdx -lt 0) {
        throw ('未在 {0} 中找到 newobj {1}::.ctor —— 此版本可能无该封锁，或封锁方式已变（安全中止，未写入）' -f $TargetMethod, $LoaderType)
    }

    $startIdx = -1
    for ($k = $newobjIdx - 1; $k -ge 0; $k--) { if ($ins[$k].Code -eq 0x72) { $startIdx = $k; break } }
    if ($startIdx -lt 0) { throw 'newobj 之前没找到 ldstr，无法确定安全替换区间（安全中止）' }

    $segStart = $ins[$startIdx].Offset
    $segEnd   = $ins[$newobjIdx].Offset + $ins[$newobjIdx].Length
    $segLen   = $segEnd - $segStart

    for ($k = $startIdx; $k -lt $newobjIdx; $k++) {
        $c = $ins[$k].Code
        if ($c -eq 0x28 -or $c -eq 0x6F -or $c -eq 0x2A -or $c -eq 0x7A -or $c -eq 0xDD -or $c -eq 0xDE) {
            throw ('替换区间内出现控制流/调用指令 0x{0:X} @IL_{1:X4}，语义不安全（安全中止）' -f $c, $ins[$k].Offset)
        }
    }

    Write-Output ''
    Write-Output ("封锁点   : IL_{0:X4}..IL_{1:X4}  ({2} 字节, {3} 条指令)" -f $segStart, $segEnd, $segLen, ($newobjIdx - $startIdx + 1))
    Write-Output ("文件偏移 : 0x{0:X} .. 0x{1:X}" -f ($ilBase + $segStart), ($ilBase + $segEnd - 1))
    Write-Output '原指令:'
    for ($k = $startIdx; $k -le $newobjIdx; $k++) {
        $i = $ins[$k]
        Write-Output ("  IL_{0:X4}  op=0x{1:X2}  arg=0x{2:X}  {3}" -f $i.Offset, $i.Code, $i.Operand, (Resolve-TokenName $mr $i.Operand))
    }

    if ($segLen -lt 5) { throw ("替换区间仅 {0} 字节，容不下 ldsfld(5B)（安全中止）" -f $segLen) }
    $repl = New-Object byte[] $segLen
    $repl[0] = 0x7E
    [Array]::Copy([BitConverter]::GetBytes([int32]$fieldToken), 0, $repl, 1, 4)
    for ($k = 5; $k -lt $segLen; $k++) { $repl[$k] = 0x00 }
    Write-Output ''
    Write-Output ("替换为   : ldsfld 0x{0:X8} + {1} 个 nop  ({2} 字节, 等长)" -f $fieldToken, ($segLen - 5), $segLen)

    $fileSegStart = $ilBase + $segStart
    $outBytes = [byte[]]$bytes.Clone()
    [Array]::Copy($repl, 0, $outBytes, $fileSegStart, $segLen)

    $diffCount = 0; $diffFirst = -1; $diffLast = -1
    for ($k = 0; $k -lt $bytes.Length; $k++) {
        if ($bytes[$k] -ne $outBytes[$k]) {
            $diffCount++
            if ($diffFirst -lt 0) { $diffFirst = $k }
            $diffLast = $k
        }
    }
    Write-Output ("字节差异 : {0} 字节, 范围 0x{1:X}..0x{2:X}（应落在 0x{3:X}..0x{4:X}）" -f $diffCount, $diffFirst, $diffLast, $fileSegStart, ($fileSegStart + $segLen - 1))
    if ($diffFirst -lt $fileSegStart -or $diffLast -gt ($fileSegStart + $segLen - 1)) {
        throw '差异越出目标区间，定位有误（已中止，未写文件）'
    }

    if ($DryRun) { Write-Output ''; Write-Output 'DRY RUN - 未写入任何文件'; return }

    $tmp = $Out + '.tmp'
    [System.IO.File]::WriteAllBytes($tmp, $outBytes)

    $fs2 = [System.IO.File]::OpenRead($tmp)
    try {
        $pe2 = $TypePE::new($fs2)
        $mr2 = [System.Reflection.Metadata.PEReaderExtensions]::GetMetadataReader($pe2)
        $md2 = $mr2.GetMethodDefinition($methodHandle)
        $body2 = [System.Reflection.Metadata.PEReaderExtensions]::GetMethodBody($pe2, $md2.RelativeVirtualAddress)
        $il2 = $body2.GetILBytes()
        if ($il2.Length -ne $il.Length) { throw ("产物 IL 长度异常: {0} vs {1}" -f $il2.Length, $il.Length) }
        $ok = $false
        foreach ($i in (Get-ILInstructions $il2)) { if ($i.Code -eq 0x7E -and $i.Operand -eq $fieldToken) { $ok = $true; break } }
        if (-not $ok) { throw '产物复核失败：未找到注入的 ldsfld' }
    } finally { $fs2.Dispose() }

    Move-Item -LiteralPath $tmp -Destination $Out -Force
    Write-Output ''
    Write-Output ("产物     : {0}" -f $Out)
    Write-Output ("产物大小 : {0:N0} B（应与原文件一致）" -f (Get-Item -LiteralPath $Out).Length)
    Write-Output ("产物SHA  : {0}" -f (Get-FileHash -LiteralPath $Out -Algorithm SHA256).Hash)
    Write-Output '复核     : 元数据可解析 / IL 长度不变 / ldsfld 已注入'
}
finally {
    if ($pe) { $pe.Dispose() }
    if ($fs) { $fs.Dispose() }
}

# ======================================================== 部署
if (-not $Deploy) {
    Write-Output ''
    Write-Output '（未指定 -Deploy，未改动现场。加 -Deploy 会自动关闭/备份/替换/关闭自动更新/重启。）'
    return
}

if (-not $PclDir) { throw '-Deploy 需要 -PclDir 指定 PCL 目录' }

Write-Output ''
Write-Output '---------------- 部署 ----------------'
foreach ($p in @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)) {
    Write-Output ("关闭运行中的 PCL (PID {0})" -f $p.Id)
    $null = $p.CloseMainWindow()
    if (-not $p.WaitForExit(8000)) { Stop-Process -Id $p.Id -Force; Start-Sleep -Milliseconds 1200 }
}
Start-Sleep -Milliseconds 600
if (@(Get-Process -Name $ProcName -ErrorAction SilentlyContinue).Count -gt 0) { throw 'PCL 仍在运行，无法安全替换' }

$stamp       = Get-Date -Format 'yyyyMMdd-HHmmss'
$liveExe     = Find-PclExe $PclDir
$liveHash    = (Get-FileHash -LiteralPath $liveExe -Algorithm SHA256).Hash
$patchedHash = (Get-FileHash -LiteralPath $Out -Algorithm SHA256).Hash

if ($liveHash -eq $patchedHash) {
    Write-Output '现场已是补丁版，跳过替换'
} else {
    $bak = $liveExe + '.bak-' + $stamp
    Copy-Item -LiteralPath $liveExe -Destination $bak -Force
    Write-Output ("已备份原文件 -> {0}" -f $bak)
    Copy-Item -LiteralPath $Out -Destination $liveExe -Force
    Write-Output ("已写入补丁   -> {0}" -f $liveExe)
}

$ini = Join-Path (Join-Path $PclDir 'PCL') 'Setup.ini'
if (Test-Path -LiteralPath $ini) {
    $lines = @(Get-Content -LiteralPath $ini)
    $pat = '^\s*SystemSystemUpdate\s*:'
    if ($lines | Where-Object { $_ -match $pat }) {
        $lines = @($lines | ForEach-Object { if ($_ -match $pat) { 'SystemSystemUpdate:3' } else { $_ } })
    } else {
        $lines = $lines + 'SystemSystemUpdate:3'
    }
    Set-Content -LiteralPath $ini -Value $lines -Encoding UTF8
    Write-Output '已设置 SystemSystemUpdate:3（关闭自动更新，防止补丁被覆盖）'
}

$exeToStart = Find-PclExe $PclDir
$proc = Start-Process -FilePath $exeToStart -WorkingDirectory $PclDir -PassThru
Write-Output ("已重新启动 PCL (PID {0})" -f $proc.Id)
if ($outIsTemp -and (Test-Path -LiteralPath $Out)) {
    Remove-Item -LiteralPath $Out -Force
    Write-Output '已清理临时产物（部署模式不往现场留副本）'
}

Write-Output ''
Write-Output '完成。打开 PCL 的「下载」页即可看到版本列表。'
Write-Output ("回滚： .\pcl-download-unlock.ps1 -RestorePclDir '{0}'" -f $PclDir)
