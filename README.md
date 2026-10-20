# PCL2 下载限制解锁（RestrictMcDownload patch）

针对 Plain Craft Launcher 2 **2.99.0.0** 的离线分析与补丁：绕开 2026-10-20 起加入的硬封锁，
恢复「原版游戏」页的 Minecraft 本体下载。**已在实机验证通过。**

## 结果

| | 补丁前 | 补丁后 |
|---|---|---|
| 下载 / 原版游戏页 | 为遵守相关法律法规… 报错卡 | 「最新版本」26.3 / 26.4-snapshot-5 + 正式版/预览版/远古版/愚人节版完整列表 |
| LoaderTask | `关闭下载` → Failed | `DlClientList Main` → Finished |
| 网络 | 无 | `GET launchermeta.mojang.com/mc/game/version_manifest.json` |

## 背景（2026-10-20 事件）

境内第三方启动器 PCL2 / HMCL 于 2026-10-20 下午同时下线内置 Minecraft 本体下载入口。
PCL 主线由 2.13.1.1 直接跳到 **2.99.0.0**（合规切割版）。

**但下载通道本身没被封**：本项目实测 BMCLAPI / Mojang piston-meta / Modrinth 全部 HTTP 200 存活
（见 `docs/notes.md`）。被砍掉的只是启动器内的入口 UI 与加载器绑定。

## 关键发现

官方源码里 `PageDownloadInstall.LoaderInit()` 是个 `If RestrictMcDownload` 二选一：真分支用
`ModDownload.DlClientListLoader`，假分支用一个只抛异常的 `LoaderTask`。

但这个常量声明为 `Const`，**编译期就地内联成字面量**，二进制里没有任何对该字段的引用 ——
**改常量值对已编译的 exe 无效**。而且 2.99.0.0 的发布二进制里 `LoaderInit()` 只剩 throw 那一条分支，
Else 分支的 IL 根本不在文件里。

所以只能改 IL：把构造假加载器的那段等长替换回 `ldsfld DlClientListLoader`。详见 `docs/notes.md`。

## 用法：一键脚本（推荐）

`patch/pcl-download-unlock.ps1` 是**零依赖单文件脚本**：不需要编译、不需要装 NuGet/工具包，
只要 PowerShell 7（自带 `System.Reflection.Metadata`）。它**不依赖任何硬编码字节串**，
而是按语义定位 `LoaderInit()` 里的 `newobj LoaderTask::.ctor`，因此 PCL 换版本时大概率仍能自适应。

```powershell
# 只分析 + 生成补丁，不动现场
.\patch\pcl-download-unlock.ps1 -PclDir 'C:\PCL2'

# 一键：关闭 PCL -> 备份 -> 打补丁 -> 关闭自动更新 -> 重启
.\patch\pcl-download-unlock.ps1 -PclDir 'C:\PCL2' -Deploy

# 先看它打算做什么（不写任何文件）
.\patch\pcl-download-unlock.ps1 -PclDir 'C:\PCL2' -DryRun

# 回滚
.\patch\pcl-download-unlock.ps1 -RestorePclDir 'C:\PCL2'
```

脚本自带的安全约束：

- **幂等**：已打过补丁会直接跳过（`-Force` 可强制重做）。
- **安全失败**：定位不到 `newobj LoaderTask`、替换区间里混进 `call/ret/throw`、
  或字节差异越出目标区间 —— 任一情况都中止且**不写文件**，而不是写坏。
- **产物复核**：写盘后重新打开产物验证元数据可解析、IL 长度不变、`ldsfld` 已注入。
- **先备份再替换**：部署时自动生成 `<exe>.bak-<时间戳>`。

> 本仓库的自动脚本与早期手工补丁产物 SHA256 完全一致（`BA7585…2A9`），可交叉验证。

## 用法：手工（可选）

`patch/patch-def.json` + `patch/apply-patch.ps1` 是**字节模式版**，把要找的 48 字节段和目标字节写死在
定义文件里，适合复现/审计（能一眼看出改的是哪 48 个字节），但**只对 2.99.0.0 成立**。

```powershell
.\patch\apply-patch.ps1 -In '<原版 exe>' -Out '.\patch\Plain Craft Launcher 2.patched.exe'
```

补丁按字节模式匹配，只对 **2.99.0.0（SHA256 `6B6E1260CB5A1D6A303855F1C60CAB3D0BC1AEBBA7E40A964180188B271E7386`）** 成立；
版本一变匹配失败，脚本会中止而不是写坏文件。

## 注意

- **自动更新会覆盖补丁**：建议在 `PCL/Setup.ini` 加 `SystemSystemUpdate:3` 关闭更新提示（删掉该行即恢复自动更新）。
- 已知限制：整合包安装链路未处理。缺的是约 330 条指令的分发逻辑，超出字节补丁能力范围，需方法体移植；社区已有实现（PCL-Uncut-Patcher / PCL2.UnrestrictLauncher），见 `docs/notes.md`。
- PCL 有单实例 Mutex，替换 exe 前必须先退出启动器。

## 结构

```
patch/
  pcl-download-unlock.ps1   一键脚本（零依赖，按语义自动定位）
  apply-patch.ps1           字节模式版补丁器（配合 patch-def.json）
  patch-def.json            48 字节补丁定义，可逐字节审计
  disable-auto-update.ps1   单独开关 PCL 自动更新
tools/
  ilprobe/                  零依赖 IL 探针（System.Reflection.Metadata）
  pclpatch/                 Cecil 版分析实验（写回受 Costura 内嵌程序集限制，留档）
docs/
  notes.md                  事件 + 封锁点 + 补丁原理 + 验证与限制
```

## 范围与版权

- 本项目**不含** Plain Craft Launcher 的任何二进制或源码副本。PCL 版权归其作者**龙腾猫跃**所有，以 LGPL-3.0 发布；
  本项目是独立的第三方分析工具，与 PCL 作者无隶属关系，也未获其背书。
- 本项目**不分发**任何 Minecraft 游戏文件，也不涉及账号验证或授权体系；补丁只把启动器内**原有的**下载器重新接线。
- 修改是可逆的：部署前自动备份，随时可用 `-RestorePclDir` 回滚，或直接换回 `*.bak-*`。
- 按 **AS IS** 提供，请自行备份后再操作。

## 致谢

- **龙腾猫跃 / LTCatt** —— Plain Craft Launcher 2
- **bangbang93 / BMCLAPI** —— 境内 Minecraft 镜像源

## License

[MIT](LICENSE)
