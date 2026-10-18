---
name: rev-windows-pe
description: Windows PE/DLL/SYS 静态分析。PE header 与节区解析、导入导出表、PEB/TEB、PDB 符号路径、资源与清单、异常目录、TLS 回调、.NET 判定、驱动结构。适用于 exe/dll/sys 的结构分析、找入口、判壳、定位关键函数。
enabled: true
---

# Windows PE 静态分析

## 基础信息

```bash
# 用 pefile（Python）
python3 -c "
import pefile
pe = pefile.PE('SAMPLE.exe')
print('Machine      :', hex(pe.FILE_HEADER.Machine))
print('TimeDateStamp:', pe.FILE_HEADER.TimeDateStamp)
print('Subsystem    :', pe.OPTIONAL_HEADER.Subsystem)
print('ImageBase    :', hex(pe.OPTIONAL_HEADER.ImageBase))
print('EntryPoint   :', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
print('Characteristics:', hex(pe.FILE_HEADER.Characteristics))
print()
print('Sections:')
for s in pe.sections:
    name = s.Name.decode(errors='replace').strip(chr(0))
    print(f'  {name:10} VA={hex(s.VirtualAddress):10} raw={s.SizeOfRawData:8} '
          f'entropy={s.get_entropy():.3f} flags={hex(s.Characteristics)}')
"
```

| Machine | 架构 |
| --- | --- |
| 0x14c | x86 |
| 0x8664 | x64 |
| 0xaa64 | ARM64 |
| 0x1c0 | ARM |

| Subsystem | 类型 |
| --- | --- |
| 2 | GUI |
| 3 | Console |
| 1 | Native（驱动） |

## 节区分析（判壳核心）

```bash
python3 -c "
import pefile
pe = pefile.PE('SAMPLE.exe')
for s in pe.sections:
    n = s.Name.decode(errors='replace').strip(chr(0))
    e = s.get_entropy()
    flag = ' <== 可疑' if e > 7.0 else ''
    print(f'{n:10} entropy={e:.3f}{flag}')
"
```

| 节区名 | 壳 / 含义 |
| --- | --- |
| `UPX0` `UPX1` | UPX |
| `.vmp0` `.vmp1` | VMProtect |
| `.themida` `.winlice` | Themida / WinLicence |
| `.aspack` `.adata` | ASPack |
| `.enigma1` `.enigma2` | Enigma |
| `.petite` | Petite |
| `.MPRESS1` | MPRESS |
| `.nsp0` `.nsp1` | NsPack |
| `.tElock` | tElock |
| `.perplex` | Perplex |
| `.ccg` | CCG |
| `.RLPack` | RLPack |

**异常信号：**
- 熵 > 7.0 → 压缩或加密
- 节区名乱码 / 非标准 → 自定义壳
- 可写可执行（`W` + `X`）→ 自修改代码
- `SizeOfRawData = 0` 但有 `VirtualSize` → 运行时解压

## 导入导出表

### 导入表（看它用什么 API）

```bash
python3 -c "
import pefile
pe = pefile.PE('SAMPLE.exe')
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for e in pe.DIRECTORY_ENTRY_IMPORT:
        print(f'== {e.dll.decode()}')
        for imp in e.imports[:20]:
            print(f'   {imp.name.decode() if imp.name else hex(imp.ordinal)}')
"
```

**导入表极小时的判断：**

```
只有 LoadLibraryA/ExW + GetProcAddress  -> 动态解析 API（多半有壳或恶意）
只有 VirtualAlloc + VirtualProtect      -> 运行时解密
导入表完全为空                          -> 加壳
```

### 导出表（DLL 才有）

```bash
python3 -c "
import pefile
pe = pefile.PE('SAMPLE.dll')
if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        print(f'{e.ordinal:5} {e.name.decode() if e.name else \"(no name)\"} @ {hex(e.address)}')
"
```

```bash
# 或直接用 dumpbin（需 VS 环境）
dumpbin /exports SAMPLE.dll
dumpbin /imports SAMPLE.exe
```

## 找入口与关键函数

### 入口点

```bash
python3 -c "
import pefile
pe = pefile.PE('SAMPLE.exe')
ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
ib = pe.OPTIONAL_HEADER.ImageBase
print('EP RVA:', hex(ep))
print('EP VA :', hex(ib + ep))
# 找 EP 在哪个节区
for s in pe.sections:
    if s.VirtualAddress <= ep < s.VirtualAddress + s.Misc_VirtualSize:
        print('EP in section:', s.Name.decode(errors='replace').strip(chr(0)))
"
```

**EP 不在第一个节区 = 很可能有壳。**

### TLS 回调（常见隐蔽执行点）

```bash
python3 -c "
import pefile
pe = pefile.PE('SAMPLE.exe')
if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS:
    tls = pe.DIRECTORY_ENTRY_TLS.struct
    print('TLS callbacks:', hex(tls.AddressOfCallBacks))
    # 回调会在 main 之前执行，是恶意代码常用藏身处
else:
    print('no TLS')
"
```

### 异常目录（SEH）

```bash
python3 -c "
import pefile
pe = pefile.PE('SAMPLE.exe')
d = pe.OPTIONAL_HEADER.DATA_DIRECTORY
names = ['EXPORT','IMPORT','RESOURCE','EXCEPTION','SECURITY','BASERELOC',
         'DEBUG','ARCHITECTURE','GLOBALPTR','TLS','LOAD_CONFIG',
         'BOUND_IMPORT','IAT','DELAY_IMPORT','COM_DESCRIPTOR']
for i, n in enumerate(names):
    if d[i].VirtualAddress:
        print(f'{n:16} RVA={hex(d[i].VirtualAddress):10} size={d[i].Size}')
"
```

## PDB 路径（调试符号）

```bash
python3 -c "
import pefile
pe = pefile.PE('SAMPLE.exe')
if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
    for dbg in pe.DIRECTORY_ENTRY_DEBUG:
        if dbg.struct.Type == 2:  # CODEVIEW
            data = pe.get_data(dbg.struct.AddressOfRawData, dbg.struct.SizeOfData)
            print('PDB:', data[24:].split(b'\0')[0].decode(errors='replace'))
"
```

**PDB 路径能泄露：**
- 开发者用户名
- 项目路径结构
- 编译环境
- 有时能直接下载到符号

## .NET 判定

```bash
python3 -c "
import pefile
pe = pefile.PE('SAMPLE.exe')
d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]  # COM_DESCRIPTOR
if d.VirtualAddress:
    print('.NET assembly! COR20 header at', hex(d.VirtualAddress))
else:
    print('native')
"
```

.NET 程序用 **dnSpy / ILSpy** 打开，能直接反编译成 C#：

```bash
# dnSpy 命令行（如果有）
dnSpy.Console.exe SAMPLE.exe -o OUT_DIR
```

## 资源与清单

```bash
# 资源
wrestool -l SAMPLE.exe
wrestool -x -t 24 SAMPLE.exe > manifest.xml    # 24 = RT_MANIFEST

# 清单重点看
cat manifest.xml
# requestedExecutionLevel: asInvoker / requireAdministrator / highestAvailable
```

```python
# pefile 读资源
import pefile
pe = pefile.PE('SAMPLE.exe')
if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
    for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        print('type', t.id, t.name)
```

## 驱动（.sys）

```bash
# 驱动特征
python3 -c "
import pefile
pe = pefile.PE('SAMPLE.sys')
print('Subsystem:', pe.OPTIONAL_HEADER.Subsystem)   # 1 = native (driver)
print('EntryPoint:', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
# 导入表通常只有 ntoskrnl.exe
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for e in pe.DIRECTORY_ENTRY_IMPORT:
        print('imports from:', e.dll.decode())
"
```

**驱动入口是 `DriverEntry`**（不是 main）。导入表通常只有 `ntoskrnl.exe` 和 `HAL.dll`。

关键导入：

```
IoCreateDevice       创建设备
IoCreateSymbolicLink 创建符号链接（用户态可见名）
IRP_MJ_*             分发表（DeviceIoControl 的处理函数在这）
PsCreateSystemThread 创建系统线程
MmMapIoSpace         映射物理内存（危险）
ZwOpenProcess        操作进程（可用来杀 AV）
```

## 地址计算

```
文件偏移 = RVA - VirtualAddress(节区) + PointerToRawData(节区)

例：
  某函数 RVA = 0x1234
  .text 节 VirtualAddress = 0x1000, PointerToRawData = 0x400
  文件偏移 = 0x1234 - 0x1000 + 0x400 = 0x634
```

```python
# 用 pefile 直接算
import pefile
pe = pefile.PE('SAMPLE.exe')
print(hex(pe.get_offset_from_rva(0x1234)))
```

## 输出规范

```
[静态-PE] 样本=SHA256 架构=x64 类型=GUI
入口: 0x140001000 in .text (无壳)
节区: .text(6.2) .rdata(5.1) .data(3.4) .rsrc(4.8)  <- 熵正常
导入: kernel32/user32/advapi32/ws2_32
可疑: 有 ws2_32（网络）+ advapi32（注册表）
PDB: C:\Users\dev\proj\x64\Release\app.pdb    <- 泄露开发者路径
关键函数: 
  - sub_140001234 -> 调用 CryptEncrypt
  - sub_140002000 -> 调用 InternetOpenUrlA
下一步: 建议 dynamic 角色在 CryptEncrypt 下断抓密钥
```

## 常见坑

| 症状 | 原因 | 处理 |
| --- | --- | --- |
| 节区熵都 > 7 | 加壳 | rev-unpack-windows |
| 导入表只有两个函数 | 动态解析 | 分析壳或找 API 解析循环 |
| pefile 报错 | 文件损坏/非标准 | 用 010 Editor + PE 模板手工看 |
| 找不到 main | 是 DLL/驱动 | 看 filetype 与导出表 |
| dnSpy 打不开 | 不是 .NET | 检查 COM_DESCRIPTOR |
