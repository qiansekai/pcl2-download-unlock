# 事件与补丁

## 事件

2026-10-20 下午，PCL2 与 HMCL 几乎同时下线内置 Minecraft 本体下载入口；PCL 当天由 2.13.1.1
直接跳到 **2.99.0.0**（合规切割版）。启动器内统一提示「为遵守相关法律法规…」。

- **被关停**：PCL2 / HMCL 的游戏本体下载；网易代理版的应用商店渠道服。
- **未受影响**：Mojang 官方启动器、网易代理版官服、境外启动器、**境内镜像源 BMCLAPI**。
- **PCL 内实际封锁面**：只有「原版游戏」一个 LoaderTask；Mod / 整合包 / 数据包 / 资源包 / 光影包 /
  各加载器全部正常。

下载源实测（2026-10-21）：BMCLAPI、Mojang launchermeta / piston-meta、Modrinth 全部 HTTP 200；
CurseForge 403 是缺 API key 的正常响应。**通道没被封，被封的是启动器内的入口与加载器绑定。**

社区已有的做法：改 `SystemSystemUpdate:3` 只防未来升级（救不了已升到 2.99 的）；换 PCL2-CE 也同步了
下游代码；网上流传的「恢复下载插件 / 修改版 PCL」已出现被植入病毒的样本。

## 为什么不能改 RestrictMcDownload

官方源码里 `LoaderInit()` 确实是二选一，这个常量**在源码层面就是开关**：

```vb
If RestrictMcDownload Then
    PageLoaderInit(..., New LoaderTask(Of String, DlClientListResult)("关闭下载", Sub() Throw New Exception(...)), ...)
Else
    PageLoaderInit(..., DlClientListLoader, ...)
End If
```

但它声明为 `Const`，VB.NET 编译期直接内联成字面量 —— 二进制里**没有任何对该字段的引用**
（全量反编译 164 个 .cs，grep 名字只命中定义处）。改字段值对已编译的 exe 无效。

且 2.99.0.0 的发布二进制里，`LoaderInit()` 只剩 throw 那一条分支（`PageLoaderInit` 只被调用一次），
Else 分支的 IL 根本不在文件里。所以只能改 IL，改常量没用。

## 真正的封锁点

`PCL.PageDownloadInstall::LoaderInit()` 把原本传入的真实加载器换成了只抛异常的假 LoaderTask：

```csharp
PageLoaderInit(LoadMinecraft, PanLoad, PanAllBack, null,
    new LoaderTask<string, DlClientListResult>("关闭下载",
        a0 => { throw new Exception("为遵守相关法律法规…"); }),
    a0 => LoadMinecraft_OnFinish());
```

底层加载器毫发无损（`ModDownload.cs:270`），且 `LoadMinecraft_OnFinish()` 读的是**静态字段**
`ModDownload.DlClientListLoader.Output` —— 消费端没改，只换了传入参数。原始接线只可能是：

```csharp
PageLoaderInit(LoadMinecraft, PanLoad, PanAllBack, null, ModDownload.DlClientListLoader,
    a0 => LoadMinecraft_OnFinish());
```

## 补丁

把构造假加载器的那段 IL **等长**替换为一条 `ldsfld DlClientListLoader`：

| 项 | 值 |
|---|---|
| 位置 | `IL_001A..IL_004A`（48 字节），文件偏移 `0x2C0DA` |
| 原内容 | `ldstr` + 委托构造 + `newobj LoaderTask`（净 -3 栈） |
| 替换为 | `ldsfld 0x0400040F` + 43 个 `nop`（净 +1 栈） |

必须整段替换、不能只改 opcode，因为两个约束同时成立：

1. **等长** —— 节表、元数据堆、所有 RVA 全不变，PE 其余部分零改动。
2. **栈平衡** —— `newobj` 消耗 4 值压 1 值，`ldsfld` 不消耗栈；只换 5 字节会多出 3 个残值，
   直接 `InvalidProgramException`。整段 nop 后栈净变化与原逻辑一致。

## 验证与限制

- 字节 diff 收敛在 48 字节内，文件大小不变（5,980,160 B）；程序集无强名、无 Authenticode。
- 运行时：LoaderTask 由 `关闭下载` -> Failed 变为 `DlClientList Main` -> Finished，
  下载页恢复完整版本列表（26.3 / 26.4-snapshot-5 + 正式版/预览版/远古版/愚人节版）。
- 整合包安装链路未处理，且**不是字节补丁能解决的**：`ModpackInstall()` 只剩 7 条指令（一句 Hint），
  `ModpackInstall(File, …)` 在解析完压缩包类型后无条件 throw。缺的是 `Select Case PackType` 的 7 路分发
  加 7 个 `InstallPack*` 调用，约 330 条指令；而那条 throw 只占 11 字节，方法体塞不下，必须做方法体移植
  （dnlib/Cecil 级工具），不是原地改字节。
- 同类工作社区已完成，可参考其路线：`snake-aabb-wtf/PCL-Uncut-Patcher`（静态方法体移植，此外还涉及
  `PageDownloadResourceDetail.InitializeStackResourceVersions()` 与 `PageDownloadModify.LoadInstanceFinished()` 两处界面绑定）、
  `LingYi0110/PCL2.UnrestrictLauncher`（Harmony 运行时 IL Transpiler，不动磁盘文件）。
- PCL 有单实例 Mutex，替换 exe 前必须先退出；自动更新会覆盖补丁。
