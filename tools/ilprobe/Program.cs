using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

// ilprobe — 零依赖 .NET 元数据 / IL 探针
// 用法:
//   ilprobe <exe> type <TypeFullName> method <MethodName>      # dump 方法 IL + newobj 目标
//   ilprobe <exe> field <TypeFullName> name <FieldName>        # 查字段 token
//   ilprobe <exe> info                                         # PE/强名/头信息

if (args.Length < 2) { Usage(); return 2; }

string exePath = args[0];
using var fs = File.OpenRead(exePath);
using var pe = new PEReader(fs);
if (!pe.HasMetadata) { Console.Error.WriteLine("ERR: 无 CLR 元数据"); return 3; }
var mr = pe.GetMetadataReader();

string mode = args[1];
switch (mode)
{
    case "info": Info(); break;
    case "field": DoField(args[2], args[4]); break;
    case "memberref": DoMemberRef(Convert.ToInt32(args[2], 16)); break;
    case "method": DoMethod(args[2], args[4]); break;
    default: Usage(); return 2;
}
return 0;

string TypeName(TypeSpecificationHandle h)
{
    var ts = mr.GetTypeSpecification(h);
    var br = mr.GetBlobReader(ts.Signature);
    return DecodeType(ref br);
}

string DecodeType(ref BlobReader br)
{
    byte code = br.ReadByte();
    switch (code)
    {
        case 0x01: return "void"; case 0x02: return "bool"; case 0x03: return "char";
        case 0x04: return "int8"; case 0x05: return "uint8"; case 0x06: return "int16";
        case 0x07: return "uint16"; case 0x08: return "int32"; case 0x09: return "uint32";
        case 0x0A: return "int64"; case 0x0B: return "uint64"; case 0x0C: return "float32";
        case 0x0D: return "float64"; case 0x0E: return "string"; case 0x16: return "typedref";
        case 0x18: return "native int"; case 0x19: return "native uint"; case 0x1C: return "object";
        case 0x10: return DecodeType(ref br) + "&";
        case 0x0F: return DecodeType(ref br) + "*";
        case 0x1D: return DecodeType(ref br) + "[]";
        case 0x12: case 0x11:
            return TypeHandleName(br.ReadTypeHandle());
        case 0x15:
            {
                byte cls = br.ReadByte(); // 0x12 class / 0x11 valuetype
                string outer = TypeHandleName(br.ReadTypeHandle());
                int n = br.ReadCompressedInteger();
                var parts = new List<string>();
                for (int k = 0; k < n; k++) parts.Add(DecodeType(ref br));
                return outer + "<" + string.Join(", ", parts) + ">";
            }
        case 0x13: return "!" + br.ReadCompressedInteger();
        case 0x1E: return "!!" + br.ReadCompressedInteger();
        default: return $"<elem 0x{code:X2}>";
    }
}

string TypeHandleName(EntityHandle th)
{
    if (th.IsNil) return "<nil>";
    switch (th.Kind)
    {
        case HandleKind.TypeDefinition:
            {
                var td = mr.GetTypeDefinition((TypeDefinitionHandle)th);
                string ns = mr.GetString(td.Namespace);
                return (ns.Length > 0 ? ns + "." : "") + mr.GetString(td.Name);
            }
        case HandleKind.TypeReference:
            {
                var tr = mr.GetTypeReference((TypeReferenceHandle)th);
                string ns = mr.GetString(tr.Namespace);
                return (ns.Length > 0 ? ns + "." : "") + mr.GetString(tr.Name);
            }
        case HandleKind.TypeSpecification:
            return TypeName((TypeSpecificationHandle)th);
        default: return th.Kind.ToString();
    }
}

void DoMemberRef(int token)
{
    var h = MetadataTokens.MemberReferenceHandle(token & 0x00FFFFFF);
    var m = mr.GetMemberReference(h);
    Console.WriteLine($"MEMBERREF 0x{token:X8}");
    Console.WriteLine($"  name   = {mr.GetString(m.Name)}");
    Console.WriteLine($"  parent = {TypeHandleName(m.Parent)}  (kind={m.Parent.Kind})");
    if (m.GetKind() == MemberReferenceKind.Method)
    {
        var sig = m.DecodeMethodSignature(new DummyProvider(mr), null);
        Console.WriteLine($"  params = {sig.ParameterTypes.Length}  return={sig.ReturnType}");
        for (int i = 0; i < sig.ParameterTypes.Length; i++) Console.WriteLine($"    p{i}: {sig.ParameterTypes[i]}");
    }
}

void Usage()
{
    Console.Error.WriteLine("usage:");
    Console.Error.WriteLine("  ilprobe <exe> info");
    Console.Error.WriteLine("  ilprobe <exe> method <TypeFullName> method <MethodName>");
    Console.Error.WriteLine("  ilprobe <exe> field  <TypeFullName> name <FieldName>");
}

// RVA -> 文件偏移
int RvaToOffset(int rva)
{
    foreach (var s in pe.PEHeaders.SectionHeaders)
    {
        int size = Math.Max(s.VirtualSize, s.SizeOfRawData);
        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + size)
            return s.PointerToRawData + (rva - s.VirtualAddress);
    }
    return -1;
}

void Info()
{
    var h = pe.PEHeaders;
    var cor = h.CorHeader!;
    Console.WriteLine($"Machine            : {h.CoffHeader.Machine}");
    Console.WriteLine($"FileSize           : {fs.Length:N0} B");
    Console.WriteLine($"ImageBase          : 0x{h.PEHeader!.ImageBase:X}");
    Console.WriteLine($"EntryPointToken    : 0x{cor.EntryPointTokenOrRelativeVirtualAddress:X8}");
    Console.WriteLine($"Metadata RVA/Size  : 0x{cor.MetadataDirectory.RelativeVirtualAddress:X} / {cor.MetadataDirectory.Size:N0}");
    Console.WriteLine($"StrongNameSigned   : {cor.Flags.HasFlag(CorFlags.StrongNameSigned)}");
    Console.WriteLine($"Flags              : {cor.Flags}");
    int snRva = cor.StrongNameSignatureDirectory.RelativeVirtualAddress;
    int snSize = cor.StrongNameSignatureDirectory.Size;
    Console.WriteLine($"StrongName SigDir  : rva=0x{snRva:X} size={snSize}  (0 = 无强名签名)");
    int certRva = h.PEHeader.CertificateTableDirectory.RelativeVirtualAddress;
    Console.WriteLine($"AuthentiCode Dir   : rva=0x{certRva:X} size={h.PEHeader.CertificateTableDirectory.Size} (0 = 未 Authenticode 签名)");
    Console.WriteLine($"PE Checksum (hdr)  : 0x{h.PEHeader.CheckSum:X8}");
    Console.WriteLine($"Sections           :");
    foreach (var s in h.SectionHeaders)
        Console.WriteLine($"   {s.Name,-10} VA=0x{s.VirtualAddress:X8} VSize=0x{s.VirtualSize:X6} RawPtr=0x{s.PointerToRawData:X8} RawSize=0x{s.SizeOfRawData:X6}");
    Console.WriteLine($"AssemblyRefs ({mr.AssemblyReferences.Count}):");
    foreach (var rh in mr.AssemblyReferences)
    {
        var ar = mr.GetAssemblyReference(rh);
        Console.WriteLine($"   {mr.GetString(ar.Name)} {ar.Version}");
    }
}

TypeDefinitionHandle FindType(string fullName)
{
    foreach (var th in mr.TypeDefinitions)
    {
        var td = mr.GetTypeDefinition(th);
        string ns = mr.GetString(td.Namespace);
        string nm = mr.GetString(td.Name);
        string fq = string.IsNullOrEmpty(ns) ? nm : ns + "." + nm;
        if (fq == fullName) return th;
    }
    throw new Exception("type not found: " + fullName);
}

void DoField(string typeName, string fieldName)
{
    var th = FindType(typeName);
    var td = mr.GetTypeDefinition(th);
    foreach (var fh in td.GetFields())
    {
        var fd = mr.GetFieldDefinition(fh);
        if (mr.GetString(fd.Name) == fieldName)
        {
            var tok = MetadataTokens.GetToken(fh);
            Console.WriteLine($"FIELD {typeName}::{fieldName}");
            Console.WriteLine($"  token          = 0x{tok:X8}");
            Console.WriteLine($"  attributes     = {fd.Attributes}");
            Console.WriteLine($"  little endian  = {BitConverter.ToString(BitConverter.GetBytes(tok))}");
            return;
        }
    }
    Console.Error.WriteLine("field not found: " + fieldName);
}

void DoMethod(string typeName, string methodName)
{
    var th = FindType(typeName);
    var td = mr.GetTypeDefinition(th);
    foreach (var mh in td.GetMethods())
    {
        var md = mr.GetMethodDefinition(mh);
        if (mr.GetString(md.Name) != methodName) continue;

        int rva = md.RelativeVirtualAddress;
        Console.WriteLine($"METHOD {typeName}::{methodName}");
        Console.WriteLine($"  MethodDef token = 0x{MetadataTokens.GetToken(mh):X8}");
        Console.WriteLine($"  RVA             = 0x{rva:X}");
        if (rva == 0) { Console.WriteLine("  (无方法体)"); return; }

        var body = pe.GetMethodBody(rva);
        int bodyOffset = RvaToOffset(rva);
        var il = body.GetILBytes();

        Console.WriteLine($"  BodyFileOffset  = 0x{bodyOffset:X}");
        Console.WriteLine($"  MaxStack={body.MaxStack} LocalSig={body.LocalSignature} ILSize={il.Length}");
        Console.WriteLine($"  IL bytes        = {BitConverter.ToString(il)}");
        Console.WriteLine("  --- IL ---");

        // 手工解析指令流（含双字节 opcode）
        int i = 0;
        while (i < il.Length)
        {
            int start = i;
            byte b = il[i++];
            ushort code = b;
            if (b == 0xFE) code = (ushort)(0xFE00 | il[i++]);
            string name = OpCodes.NameOf(code, out int operandSize);
            string operand = "";
            if (operandSize > 0)
            {
                long val = 0;
                for (int k = 0; k < operandSize; k++) val |= (long)il[i + k] << (8 * k);
                operand = $"0x{val:X}";
                if (code == 0x73 || code == 0x7E || code == 0x28 || code == 0x6F || code == 0x72 || code == 0x7B || code == 0x7D || code == 0x8C || code == 0xD0)
                    operand += "  " + ResolveToken((int)val);
                i += operandSize;
                if (operandSize == 1)
                {
                    sbyte sb = (sbyte)il[i - 1];
                    operand = $"{sb}";
                }
            }
            var raw = string.Join("-", il.Skip(start).Take(i - start).Select(x => x.ToString("X2")));
            Console.WriteLine($"    IL_{start:X4}  file=0x{bodyOffset + 1 + start:X}  {name,-14} {operand,-58} [{raw}]");
        }
        return;
    }
    Console.Error.WriteLine("method not found: " + methodName);
}

string ResolveToken(int token)
{
    try
    {
        // 0x70 前缀 = UserString 堆（不是 EntityHandle）
        if (((uint)token >> 24) == 0x70)
            return "=> \"" + mr.GetUserString(MetadataTokens.UserStringHandle(token & 0x00FFFFFF)) + "\"";
        var h = MetadataTokens.EntityHandle(token);
        switch (h.Kind)
        {
            case HandleKind.MethodDefinition:
                { var m = mr.GetMethodDefinition((MethodDefinitionHandle)h); return "=> [methoddef] " + mr.GetString(m.Name); }
            case HandleKind.MemberReference:
                {
                    var m = mr.GetMemberReference((MemberReferenceHandle)h);
                    string parent = m.Parent.Kind switch
                    {
                        HandleKind.TypeReference => mr.GetString(mr.GetTypeReference((TypeReferenceHandle)m.Parent).Name),
                        HandleKind.TypeDefinition => mr.GetString(mr.GetTypeDefinition((TypeDefinitionHandle)m.Parent).Name),
                        HandleKind.TypeSpecification => "<typespec>",
                        _ => m.Parent.Kind.ToString()
                    };
                    return $"=> [memberref] {parent}::{mr.GetString(m.Name)}";
                }
            case HandleKind.FieldDefinition:
                { var f = mr.GetFieldDefinition((FieldDefinitionHandle)h); return "=> [fielddef] " + mr.GetString(f.Name); }
            case HandleKind.MethodSpecification:
                {
                    var ms = mr.GetMethodSpecification((MethodSpecificationHandle)h);
                    return "=> [methodspec] " + ResolveToken(MetadataTokens.GetToken(ms.Method));
                }
            case HandleKind.TypeReference:
                return "=> [typeref] " + mr.GetString(mr.GetTypeReference((TypeReferenceHandle)h).Name);
            case HandleKind.TypeDefinition:
                return "=> [typedef] " + mr.GetString(mr.GetTypeDefinition((TypeDefinitionHandle)h).Name);
            default:
                return "=> " + h.Kind;
        }
    }
    catch (Exception e) { return "=> <" + e.Message + ">"; }
}

sealed class DummyProvider : ISignatureTypeProvider<string, object>
{
    readonly MetadataReader _mr;
    public DummyProvider(MetadataReader mr) { _mr = mr; }
    public string GetPrimitiveType(PrimitiveTypeCode c) => c.ToString();
    public string GetTypeFromDefinition(MetadataReader r, TypeDefinitionHandle h, byte raw) =>
        r.GetString(r.GetTypeDefinition(h).Namespace) + "." + r.GetString(r.GetTypeDefinition(h).Name);
    public string GetTypeFromReference(MetadataReader r, TypeReferenceHandle h, byte raw) =>
        r.GetString(r.GetTypeReference(h).Namespace) + "." + r.GetString(r.GetTypeReference(h).Name);
    public string GetTypeFromSpecification(MetadataReader r, object ctx, TypeSpecificationHandle h, byte raw) => "<spec>";
    public string GetSZArrayType(string e) => e + "[]";
    public string GetArrayType(string e, ArrayShape s) => e + "[,]";
    public string GetByReferenceType(string e) => e + "&";
    public string GetPointerType(string e) => e + "*";
    public string GetGenericInstantiation(string g, System.Collections.Immutable.ImmutableArray<string> a) => g + "<" + string.Join(",", a) + ">";
    public string GetGenericMethodParameter(object ctx, int i) => "!!" + i;
    public string GetGenericTypeParameter(object ctx, int i) => "!" + i;
    public string GetFunctionPointerType(MethodSignature<string> s) => "fnptr";
    public string GetModifiedType(string m, string u, bool req) => u;
    public string GetPinnedType(string e) => e;
}

// 极简 opcode 表：覆盖 PCL 方法体里会出现的指令，含操作数长度
static class OpCodes
{
    // 操作数长度：0/1/2/4/8/-1(switch)
    static readonly Dictionary<ushort, (string name, int size)> Table = new()
    {
        [0x00] = ("nop", 0), [0x01] = ("break", 0), [0x02] = ("ldarg.0", 0), [0x03] = ("ldarg.1", 0),
        [0x04] = ("ldarg.2", 0), [0x05] = ("ldarg.3", 0), [0x06] = ("ldloc.0", 0), [0x07] = ("ldloc.1", 0),
        [0x08] = ("ldloc.2", 0), [0x09] = ("ldloc.3", 0), [0x0A] = ("stloc.0", 0), [0x0B] = ("stloc.1", 0),
        [0x0C] = ("stloc.2", 0), [0x0D] = ("stloc.3", 0), [0x0E] = ("ldarg.s", 1), [0x0F] = ("ldarga.s", 1),
        [0x10] = ("starg.s", 1), [0x11] = ("ldloc.s", 1), [0x12] = ("ldloca.s", 1), [0x13] = ("stloc.s", 1),
        [0x14] = ("ldnull", 0), [0x15] = ("ldc.i4.m1", 0), [0x16] = ("ldc.i4.0", 0), [0x17] = ("ldc.i4.1", 0),
        [0x18] = ("ldc.i4.2", 0), [0x19] = ("ldc.i4.3", 0), [0x1A] = ("ldc.i4.4", 0), [0x1B] = ("ldc.i4.5", 0),
        [0x1C] = ("ldc.i4.6", 0), [0x1D] = ("ldc.i4.7", 0), [0x1E] = ("ldc.i4.8", 0), [0x1F] = ("ldc.i4.s", 1),
        [0x20] = ("ldc.i4", 4), [0x21] = ("ldc.i8", 8), [0x22] = ("ldc.r4", 4), [0x23] = ("ldc.r8", 8),
        [0x25] = ("dup", 0), [0x26] = ("pop", 0), [0x27] = ("jmp", 4), [0x28] = ("call", 4),
        [0x29] = ("calli", 4), [0x2A] = ("ret", 0), [0x2B] = ("br.s", 1), [0x2C] = ("brfalse.s", 1),
        [0x2D] = ("brtrue.s", 1), [0x2E] = ("beq.s", 1), [0x2F] = ("bge.s", 1), [0x30] = ("bgt.s", 1),
        [0x31] = ("ble.s", 1), [0x32] = ("blt.s", 1), [0x33] = ("bne.un.s", 1), [0x34] = ("bge.un.s", 1),
        [0x35] = ("bgt.un.s", 1), [0x36] = ("ble.un.s", 1), [0x37] = ("blt.un.s", 1), [0x38] = ("br", 4),
        [0x39] = ("brfalse", 4), [0x3A] = ("brtrue", 4), [0x3B] = ("beq", 4), [0x3C] = ("bge", 4),
        [0x3D] = ("bgt", 4), [0x3E] = ("ble", 4), [0x3F] = ("blt", 4), [0x40] = ("bne.un", 4),
        [0x41] = ("bge.un", 4), [0x42] = ("bgt.un", 4), [0x43] = ("ble.un", 4), [0x44] = ("blt.un", 4),
        [0x45] = ("switch", -1), [0x46] = ("ldind.i1", 0), [0x47] = ("ldind.u1", 0), [0x48] = ("ldind.i2", 0),
        [0x49] = ("ldind.u2", 0), [0x4A] = ("ldind.i4", 0), [0x4B] = ("ldind.u4", 0), [0x4C] = ("ldind.i8", 0),
        [0x4D] = ("ldind.i", 0), [0x4E] = ("ldind.r4", 0), [0x4F] = ("ldind.r8", 0), [0x50] = ("ldind.ref", 0),
        [0x51] = ("stind.ref", 0), [0x52] = ("stind.i1", 0), [0x53] = ("stind.i2", 0), [0x54] = ("stind.i4", 0),
        [0x55] = ("stind.i8", 0), [0x56] = ("stind.r4", 0), [0x57] = ("stind.r8", 0), [0x58] = ("add", 0),
        [0x59] = ("sub", 0), [0x5A] = ("mul", 0), [0x5B] = ("div", 0), [0x5C] = ("div.un", 0),
        [0x5D] = ("rem", 0), [0x5E] = ("rem.un", 0), [0x5F] = ("and", 0), [0x60] = ("or", 0),
        [0x61] = ("xor", 0), [0x62] = ("shl", 0), [0x63] = ("shr", 0), [0x64] = ("shr.un", 0),
        [0x65] = ("neg", 0), [0x66] = ("not", 0), [0x67] = ("conv.i1", 0), [0x68] = ("conv.i2", 0),
        [0x69] = ("conv.i4", 0), [0x6A] = ("conv.i8", 0), [0x6B] = ("conv.r4", 0), [0x6C] = ("conv.r8", 0),
        [0x6D] = ("conv.u4", 0), [0x6E] = ("conv.u8", 0), [0x6F] = ("callvirt", 4), [0x70] = ("cpobj", 4),
        [0x71] = ("ldobj", 4), [0x72] = ("ldstr", 4), [0x73] = ("newobj", 4), [0x74] = ("castclass", 4),
        [0x75] = ("isinst", 4), [0x76] = ("conv.r.un", 0), [0x79] = ("unbox", 4), [0x7A] = ("throw", 0),
        [0x7B] = ("ldfld", 4), [0x7C] = ("ldflda", 4), [0x7D] = ("stfld", 4), [0x7E] = ("ldsfld", 4),
        [0x7F] = ("ldsflda", 4), [0x80] = ("stsfld", 4), [0x81] = ("stobj", 4), [0x8C] = ("box", 4),
        [0x8D] = ("newarr", 4), [0x8E] = ("ldlen", 0), [0x8F] = ("ldelema", 4), [0x90] = ("ldelem.i1", 0),
        [0x91] = ("ldelem.u1", 0), [0x92] = ("ldelem.i2", 0), [0x93] = ("ldelem.u2", 0), [0x94] = ("ldelem.i4", 0),
        [0x95] = ("ldelem.u4", 0), [0x96] = ("ldelem.i8", 0), [0x97] = ("ldelem.i", 0), [0x98] = ("ldelem.r4", 0),
        [0x99] = ("ldelem.r8", 0), [0x9A] = ("ldelem.ref", 0), [0x9B] = ("stelem.i", 0), [0x9C] = ("stelem.i1", 0),
        [0x9D] = ("stelem.i2", 0), [0x9E] = ("stelem.i4", 0), [0x9F] = ("stelem.i8", 0), [0xA0] = ("stelem.r4", 0),
        [0xA1] = ("stelem.r8", 0), [0xA2] = ("stelem.ref", 0), [0xA3] = ("ldelem", 4), [0xA4] = ("stelem", 4),
        [0xA5] = ("unbox.any", 4), [0xB3] = ("conv.ovf.i1", 0), [0xB4] = ("conv.ovf.u1", 0),
        [0xB5] = ("conv.ovf.i2", 0), [0xB6] = ("conv.ovf.u2", 0), [0xB7] = ("conv.ovf.i4", 0),
        [0xB8] = ("conv.ovf.u4", 0), [0xB9] = ("conv.ovf.i8", 0), [0xBA] = ("conv.ovf.u8", 0),
        [0xC2] = ("refanyval", 4), [0xC3] = ("ckfinite", 0), [0xC6] = ("mkrefany", 4),
        [0xD0] = ("ldtoken", 4), [0xD1] = ("conv.u2", 0), [0xD2] = ("conv.u1", 0), [0xD3] = ("conv.i", 0),
        [0xD4] = ("conv.ovf.i", 0), [0xD5] = ("conv.ovf.u", 0), [0xD6] = ("add.ovf", 0),
        [0xD7] = ("add.ovf.un", 0), [0xD8] = ("mul.ovf", 0), [0xD9] = ("mul.ovf.un", 0),
        [0xDA] = ("sub.ovf", 0), [0xDB] = ("sub.ovf.un", 0), [0xDC] = ("endfinally", 0),
        [0xDD] = ("leave", 4), [0xDE] = ("leave.s", 1), [0xDF] = ("stind.i", 0), [0xE0] = ("conv.u", 0),
        // 0xFE 前缀
        [0xFE01] = ("arglist", 0), [0xFE02] = ("ceq", 0), [0xFE03] = ("cgt", 0), [0xFE04] = ("cgt.un", 0),
        [0xFE05] = ("clt", 0), [0xFE06] = ("clt.un", 0), [0xFE07] = ("ldftn", 4), [0xFE08] = ("ldvirtftn", 4),
        [0xFE09] = ("ldarg", 2), [0xFE0A] = ("ldarga", 2),
        [0xFE0B] = ("starg", 2), [0xFE0C] = ("ldloc", 2), [0xFE0D] = ("ldloca", 2), [0xFE0E] = ("stloc", 2),
        [0xFE0F] = ("localloc", 0), [0xFE11] = ("endfilter", 0), [0xFE12] = ("unaligned.", 1),
        [0xFE13] = ("volatile.", 0), [0xFE14] = ("tail.", 0), [0xFE15] = ("initobj", 4),
        [0xFE16] = ("constrained.", 4), [0xFE17] = ("cpblk", 0), [0xFE18] = ("initblk", 0),
        [0xFE19] = ("no.", 1), [0xFE1A] = ("rethrow", 0), [0xFE1C] = ("sizeof", 4),
        [0xFE1D] = ("refanytype", 0), [0xFE1E] = ("readonly.", 0),
    };

    public static string NameOf(ushort code, out int operandSize)
    {
        if (Table.TryGetValue(code, out var t)) { operandSize = t.size; return t.name; }
        operandSize = 0;
        return $"0x{code:X2}?";
    }
}
