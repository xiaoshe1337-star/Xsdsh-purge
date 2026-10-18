---
name: rev-unpack-windows
description: Windows PE 脱壳。UPX/ASPack/VMProtect/Themida/Enigma 等壳识别、ESP 定律定位 OEP、Scylla dump 与 IAT 修复、重定位处理、自解压与安装包解包、.NET 混淆还原。适用于节区熵高、导入表极小、EP 异常、IDA 打不开的 PE 文件。
enabled: true
---

# Windows PE 脱壳

## 壳识别

```bash
diec SAMPLE.exe           # Detect It Easy（最准）
```

或手工看节区：

```python
import pefile
pe = pefile.PE('SAMPLE.exe')
for s in pe.sections:
    print(s.Name.decode(errors='replace').strip(chr(0)),
          hex(s.VirtualAddress), round(s.get_entropy(), 3))
```

| 节区名 | 壳 | 难度 |
| --- | --- | --- |
| `UPX0` `UPX1` | UPX | ★☆☆ |
| `.aspack` `.adata` | ASPack | ★★☆ |
| `.MPRESS1` `.MPRESS2` | MPRESS | ★★☆ |
| `.nsp0` `.nsp1` | NsPack | ★★☆ |
| `.petite` | Petite | ★★☆ |
| `.themida` `.winlice` | Themida / WinLicense | ★★★★ |
| `.vmp0` `.vmp1` | VMProtect | ★★★★★ |
| `.enigma1` `.enigma2` | Enigma | ★★★☆ |
| `.tElock` | tElock | ★★★☆ |
| `.perplex` | Perplex | ★★★★ |

**判断依据补充：**
- 熵 > 7.0 → 压缩/加密
- 导入表 < 10 个函数 → 运行时解析
- EP 在最后一个节区 → 壳的初始化代码
- `SizeOfRawData` 远小于 `VirtualSize` → 运行时解压

## UPX（最简单）

```bash
# 一行搞定
upx -d SAMPLE.exe -o UNPACKED.exe

# 验证
python3 -c "
import pefile
pe=pefile.PE('UNPACKED.exe')
for s in pe.sections:
    print(s.Name.decode().strip(chr(0)), round(s.get_entropy(),3))
"
```

**UPX 被改过（magic 被改）：**

```
1. 用 010 Editor 打开，找 UPX! magic
2. 把 UPX0/UPX1 节名改回标准
   或在 UPX 源码里改 magic 后重编译 upx
3. 常见修改点：UPX! -> 自定义 4 字节
```

## 通用脱壳流程（ESP 定律）

适用于大多数非虚拟化壳。

### 步骤

```
1. x64dbg 打开样本（勾选 "Entry Breakpoint"）
2. F9 到 EP（此时停在壳代码，不是真实入口）
3. 在寄存器窗口对 ESP 右键 -> "Follow in Dump"
4. 在 Dump 窗口对 ESP 指向的地址选中 4 字节 -> 右键 -> 断点 -> 硬件访问 -> 写入
5. F9 运行
6. 命中断点时，看栈顶的返回地址 —— 那附近就是 OEP
7. 在 OEP 处 dump + 修 IAT
```

### 为什么有效

壳解压完会 `push 真实入口; ret` 或者 `jmp 真实入口`。无论哪种，**栈上都会出现真实入口的地址**，硬件断点能抓到。

### 命令快捷方式（x64dbg 命令行）

```
# 到 EP
bp ep
run

# 设 ESP 硬件断点（脚本）
esp
hr esp

# 或者用 Scylla 的一键功能
```

## Scylla 修 IAT

```
1. 在 OEP 处（确认是真实入口，能看到正常代码）
2. 打开 Scylla（x64dbg 插件 -> Scylla）
3. 填 OEP（Scylla 会自动读当前 EIP）
4. 点 "IAT Autosearch" -> 等待
5. 点 "Get Imports"
6. 检查列表：
   - 白色 = 有效
   - 红色 = 无效（需要手工修）
   - 无效项通常是壳的跳转表，指向壳区域
7. 对红色项右键 -> "Cut thunk" 或手工填正确的 API 地址
8. 点 "Fix Dump"，选择刚才 dump 的文件
9. 得到 SAMPLE_dump_SCY.exe
```

### 验证

```bash
# 导入表是否正常
python3 -c "
import pefile
pe=pefile.PE('SAMPLE_dump_SCY.exe')
if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
    for e in pe.DIRECTORY_ENTRY_IMPORT:
        n = len(e.imports)
        print(f'{e.dll.decode():20} {n} imports')
"

# 跑一下（虚拟机里！）
```

## 重定位处理

**DLL 被 dump 后，如果 ImageBase 变了，重定位表必须修。**

```
1. Scylla 里有 "Fix Dump" 时自动处理
2. 或手工：
   - 确认 .reloc 节还在
   - 用 CFF Explorer / pe-bear 检查 Relocation Directory
   - 如果被抹了，用 IDA 的 "Rebase program" 
```

**x64 的 DLL 通常不强依赖重定位**（RIP-relative 寻址），x86 的相对跳转则必须修。

## VMProtect / Themida（虚拟化保护）

**重要认知：这两种不是"壳"，是虚拟机保护。**

### VMProtect 的两种模式

| 模式 | 特征 | 可还原程度 |
| --- | --- | --- |
| **Mutation** | 代码等价变换（MBA、常量展开、指令替换） | 可做**语义还原**（不等价字节还原） |
| **Virtualization** | 关键函数转成 VM 字节码 + 解释器 | 只能**行为级还原**，完整还原需大量手工 |

### 识别

```bash
# 找 VM 入口特征（VMProtect）
# - 大量 pushad/popad（x86）
# - 有巨大的 switch 跳转表
# - 调用一个 "dispatcher" 函数反复执行
# - 有 VM handler 表（一组小函数，每个处理一条 VM 指令）
```

### 分析路径

```
1. 确认哪部分被虚拟化（不是整个程序）
   - 通常只有关键校验函数被 VM 化
   - 找 VM enter（保存上下文）与 VM exit（恢复）
2. 定位 VM handler 表
   - 在 VM enter 里，通常能看到一个大的跳转表
   - 每个 handler 处理一种 VM 操作（moval/addv/jmpv...）
3. 记录 handler 语义
   - 逐个分析 handler，标注它做什么
4. 上层的 VM 字节码解释
   - 写脚本把字节码翻译成伪代码
5. 语义还原
   - 得到的是"等价逻辑"，不是原始汇编
```

**如实报告：** "已定位 VM handler 表，还原了 N 个 handler 语义，被虚拟化函数 X 的逻辑已还原为伪代码，无法还原原始指令。"

### Themida

特征：
- 多层加密（代码段 + 数据段分开加密）
- 强反调试 + 反虚拟机
- 有 `SecureEngine` 节

处理：
```
1. 先过反调试（ScyllaHide 全勾）
2. 过反虚拟机（改配置 / 物理机）
3. ESP 定律找 OEP（可能要多跟几次）
4. dump + 修 IAT
5. 静态分析还原后代码（可能仍是虚拟机化）
```

## 自解压 / 安装包

```bash
# 自解压 exe（7z 打的开）
7z x SAMPLE_installer.exe -oOUT

# InstallShield
unshield x SAMPLE.cab

# NSIS
7z x SAMPLE_installer.exe -oOUT
# 或
nsisunz SAMPLE_installer.exe

# Inno Setup
innoextract SAMPLE_installer.exe -d OUT

# MSI
msiexec /a SAMPLE.msi /qb TARGETDIR=OUT
# 或
7z x SAMPLE.msi -oOUT
```

## .NET 混淆还原

### 识别

```python
import pefile
pe = pefile.PE('SAMPLE.exe')
if pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress:
    print('.NET assembly')
```

### 工具链

```bash
# 1. 先 dnSpy 打开看（能直接反编译 C#）
# 2. 如果混淆了：
#    - de4dot 自动反混淆
de4dot SAMPLE.exe -o CLEAN.exe

# 3. 再用 dnSpy 打开 CLEAN.exe
```

**常见 .NET 混淆器：**

| 混淆器 | 特征 | 处理 |
| --- | --- | --- |
| ConfuserEx | 控制流混淆 + 常量加密 | de4dot + 手工 |
| .NET Reactor | 原生壳 + IL 加密 | 需专门脱壳 |
| Dotfuscator | 重命名 + 字符串加密 | de4dot 部分有效 |
| SmartAssembly | 字符串加密 + 控制流 | de4dot |
| Babel | 控制流 + 虚拟机 | 难 |

## 驱动（.sys）分析

```bash
# 驱动不需要"脱壳"，通常是分析
python3 -c "
import pefile
pe = pefile.PE('SAMPLE.sys')
print('Subsystem:', pe.OPTIONAL_HEADER.Subsystem)  # 1 = native
print('EP:', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))  # DriverEntry
"
```

**若有壳（少见），脱壳后 DriverEntry 才能正常分析。**

## 验证

```bash
# 1. PE 结构完整
python3 -c "
import pefile
pe = pefile.PE('UNPACKED.exe')
print('sections:', len(pe.sections))
print('imports:', sum(len(e.imports) for e in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])))
"

# 2. 熵值正常（< 7）
# 3. IDA 能识别函数
# 4. 在隔离虚拟机里能运行
```

**成功标准：**
```
✅ 节区熵 < 7.0
✅ 导入表完整（>20 个 API）
✅ IDA 打开后函数识别正常（不是一大片 sub_xxx 无内容）
✅ 在 VM 里能运行
```

## 输出规范

```
[脱壳-Windows] 样本=SHA256 壳=UPX 3.96
原状态: .text 熵 7.92, 导入表 3 项, EP 在 UPX1
方法: upx -d
产物: /path/UNPACKED.exe  sha256=xxx  size=1.2MB
验证: 节区熵 6.2, 导入表 87 项, IDA 反编译正常
结论: 脱壳成功
```

## 边界

- 只做脱壳。**不做业务逻辑分析**。
- VMProtect/Themida 这种虚拟化保护，**能还原多少报多少，不夸大**。
- 所有运行验证**必须在隔离虚拟机里**做。
