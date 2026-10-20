using Mono.Cecil;
using Mono.Cecil.Cil;

// pclpatch — PCL2 RestrictMcDownload 封锁点重接线
//
// 背景：PCL 2.99.0.0 把 PageDownloadInstall.LoaderInit 里的
//   PageLoaderInit(..., ModDownload.DlClientListLoader, ...)
// 换成了
//   PageLoaderInit(..., New LoaderTask("关闭下载", Sub() Throw ...), ...)
// 底层 ModDownload.DlClientListLoader（真实版本清单拉取器）完好无损。
//
// 本工具把假的 throw loader 换回 ModDownload.DlClientListLoader。
//
// 用法: pclpatch <in.exe> <out.exe> [--dry-run]

string inPath = args.ElementAtOrDefault(0) ?? throw new ArgumentException("missing in.exe");
string outPath = args.ElementAtOrDefault(1) ?? throw new ArgumentException("missing out.exe");
bool dryRun = args.Contains("--dry-run");

Console.WriteLine($"in  : {inPath}");
Console.WriteLine($"out : {outPath}");
Console.WriteLine($"dry : {dryRun}");

// PCL 是 .NET Framework 4.8 程序集，自定义属性里带 WPF 枚举类型。
// 必须提供解析目录，否则 Cecil 读 attribute 时 AssemblyResolutionException。
var resolver = new DefaultAssemblyResolver();
foreach (var dir in ResolverDirs())
{
    if (Directory.Exists(dir)) { resolver.AddSearchDirectory(dir); }
}

var asm = AssemblyDefinition.ReadAssembly(inPath, new ReaderParameters
{
    ReadWrite = false,
    InMemory = true,
    ReadingMode = ReadingMode.Deferred,
    AssemblyResolver = resolver,
});

IEnumerable<string> ResolverDirs()
{
    var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
    var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    // .NET Framework 引用程序集（编译期）
    foreach (var v in new[] { "v4.8", "v4.7.2", "v4.7.1", "v4.7", "v4.6.2", "v4.6.1", "v4.6", "v4.5.2", "v4.5.1", "v4.5" })
        yield return Path.Combine(pf86, "Reference Assemblies", "Microsoft", "Framework", ".NETFramework", v);
    // 运行时 GAC
    yield return Path.Combine(win, "Microsoft.NET", "assembly", "GAC_MSIL");
    yield return Path.Combine(win, "Microsoft.NET", "assembly", "GAC_32");
    yield return Path.Combine(win, "Microsoft.NET", "assembly", "GAC_64");
    yield return Path.Combine(win, "Microsoft.NET", "Framework", "v4.0.30319");
    yield return Path.Combine(win, "Microsoft.NET", "Framework64", "v4.0.30319");
    // WPF 运行目录
    yield return Path.Combine(win, "Microsoft.NET", "Framework", "v4.0.30319", "WPF");
}
var mod = asm.MainModule;
Console.WriteLine($"module: {mod.Name}  runtime={mod.Runtime}  arch={mod.Architecture}");
Console.WriteLine($"resources: {mod.Resources.Count}");

// ---- 目标字段 ----
var dlType = mod.GetType("PCL.ModDownload") ?? throw new Exception("PCL.ModDownload not found");
var dlLoaderField = dlType.Fields.FirstOrDefault(f => f.Name == "DlClientListLoader")
    ?? throw new Exception("DlClientListLoader not found");
Console.WriteLine($"field: {dlLoaderField.FullName}  static={dlLoaderField.IsStatic}  type={dlLoaderField.FieldType.FullName}");

// ---- 目标方法 ----
var pageType = mod.GetType("PCL.PageDownloadInstall") ?? throw new Exception("PCL.PageDownloadInstall not found");
var loaderInit = pageType.Methods.FirstOrDefault(m => m.Name == "LoaderInit")
    ?? throw new Exception("LoaderInit not found");

Console.WriteLine($"method: {loaderInit.FullName}  ILSize={loaderInit.Body?.CodeSize}");

if (loaderInit.Body == null) throw new Exception("no body");
var body = loaderInit.Body;
var il = body.GetILProcessor();
var ins = body.Instructions;

// ---- 定位 ldstr "关闭下载" 与 newobj LoaderTask ----
const string Marker = "关闭下载";
Instruction ldstrIns = null, newobjIns = null;
foreach (var i in ins)
{
    if (i.OpCode == OpCodes.Ldstr && (string)i.Operand == Marker) ldstrIns = i;
    if (i.OpCode == OpCodes.Newobj && i.Operand is MethodReference mr
        && mr.DeclaringType.Name.StartsWith("LoaderTask"))
        newobjIns = i;
}
if (ldstrIns == null) throw new Exception($"未找到 ldstr \"{Marker}\"");
if (newobjIns == null) throw new Exception("未找到 newobj LoaderTask");

int from = ins.IndexOf(ldstrIns);
int to = ins.IndexOf(newobjIns);
Console.WriteLine($"range: IL_{ldstrIns.Offset:X4} .. IL_{newobjIns.Offset:X4}  (index {from}..{to}, {to - from + 1} instructions)");

Console.WriteLine("--- 将被移除的指令 ---");
for (int k = from; k <= to; k++)
{
    var i = ins[k];
    string op = i.Operand is null ? "" : i.Operand is string s ? "\"" + s + "\"" :
        i.Operand is MethodReference m2 ? m2.FullName : i.Operand.ToString();
    Console.WriteLine($"  IL_{i.Offset:X4}  {i.OpCode,-12} {op}");
}

// 安全检查：范围外不得有分支指向范围内
for (int k = 0; k < ins.Count; k++)
{
    if (k >= from && k <= to) continue;
    var i = ins[k];
    if (i.Operand is Instruction tgt)
    {
        int ti = ins.IndexOf(tgt);
        if (ti >= from && ti <= to)
            throw new Exception($"范围外指令 IL_{i.Offset:X4} 分支进入删除范围 -> IL_{tgt.Offset:X4}，中止");
    }
    if (i.Operand is Instruction[] arr)
        foreach (var t in arr)
        {
            int ti = ins.IndexOf(t);
            if (ti >= from && ti <= to)
                throw new Exception($"switch IL_{i.Offset:X4} 分支进入删除范围，中止");
        }
}
Console.WriteLine("safety: 无外部分支进入删除范围 OK");

if (dryRun)
{
    Console.WriteLine("DRY RUN — 不做修改");
    return 0;
}

// ---- 执行替换：移除 [from..to]，在原位置插入 ldsfld ----
var anchor = ins[from];
var prev = anchor.Previous;   // IL_0019 的 ldnull (PanAlways)
for (int k = to; k >= from; k--) il.Remove(ins[k]);
var ldsfld = il.Create(OpCodes.Ldsfld, dlLoaderField);
if (prev != null) il.InsertAfter(prev, ldsfld);
else il.InsertBefore(ins[0], ldsfld);

Console.WriteLine($"injected: ldsfld {dlLoaderField.Name}");

// ---- 自检：重扫确认 ----
bool ok = body.Instructions.Any(i => i.OpCode == OpCodes.Ldsfld && (i.Operand as FieldReference)?.Name == "DlClientListLoader");
bool gone = body.Instructions.All(i => !(i.OpCode == OpCodes.Ldstr && (string)i.Operand == Marker));
Console.WriteLine($"verify: ldsfld插入={ok} throwLoader已移除={gone} newILSize={body.CodeSize}");
if (!ok || !gone) throw new Exception("自检失败");

// 简化宏：去掉可能的 MaxStack 不足
if (body.MaxStackSize < 9) body.MaxStackSize = 9;

asm.Write(outPath, new WriterParameters { WriteSymbols = false });
Console.WriteLine($"written: {outPath}");
return 0;
