---
name: rev-ios-macho
description: iOS IPA/Mach-O 静态分析。Mach-O header 与 load commands 解析、架构判定、class-dump 导出 ObjC 类与方法、Swift 符号 demangle、FairPlay 加密状态判定、依赖库分析、 entitlements 与签名信息。适用于 IPA 解包后的结构分析与找关键逻辑。
enabled: true
---

# iOS Mach-O 静态分析

## 解包 IPA

```bash
# IPA 就是个 zip
unzip -o SAMPLE.ipa -d OUT
ls OUT/Payload/
# 主二进制
BIN="OUT/Payload/$(ls OUT/Payload)/$(ls OUT/Payload/*.app | head -1 | xargs basename .app)"
```

## Mach-O 基础

### Header

```bash
otool -h BINARY
```

输出解读：

```
magic       cputype    cpusubtype  filetype    ncmds  sizeofcmds  flags
feedfacf    0100000c   00000000    2           120    14000       00200085
```

| 字段 | 含义 |
| --- | --- |
| `magic` | `feedfacf` = 64 位小端 |
| `cputype` | `0c` = ARM64, `07` = x86, `12` = ARM |
| `filetype` | `2` = MH_EXECUTE, `6` = MH_DYLIB, `8` = MH_BUNDLE |
| `flags` | 含 `PIE`（0x200000）表示位置无关 |

### 架构

```bash
lipo -info BINARY
# 输出 "Architectures in the fat file: BINARY are: arm64" -> 单架构
# 输出多个 -> FAT 二进制，可以用 lipo 拆
lipo -thin arm64 BINARY -output BINARY_arm64
```

### 加载命令

```bash
otool -l BINARY
```

**重点找这几个 LC：**

```bash
# 加密信息（FairPlay）
otool -l BINARY | grep -A4 LC_ENCRYPTION_INFO

# 主程序段（找 __TEXT 的 vmaddr 与 fileoff，算地址偏移）
otool -l BINARY | grep -A6 "segname __TEXT"

# 依赖库
otool -L BINARY

# RPATH
otool -l BINARY | grep -A2 LC_RPATH

# 代码签名
codesign -dvvv BINARY

# entitlements
codesign -d --entitlements - BINARY
```

## FairPlay 判定（最关键的检查）

```bash
otool -l BINARY | grep -A4 LC_ENCRYPTION_INFO
```

```
cmd LC_ENCRYPTION_INFO
cmdsize 32
cryptoff 16384
cryptsize 8388608
cryptid 1          <- 1 = 已加密，必须先脱壳
```

| cryptid | 含义 | 行动 |
| --- | --- | --- |
| `0` | 未加密 | 直接分析 |
| `1` | FairPlay 加密 | **必须先脱壳**，转 rev-unpack-ios |

**从 App Store 下载的 IPA 一定是 `1`。** IDA 打开时加密段是乱码。

## ObjC 分析

### class-dump 导出头文件

```bash
class-dump -H BINARY -o OUT_HEADERS
ls OUT_HEADERS | head -20
```

导出的是 `.h` 文件，包含：
- 类名、父类名
- 协议（protocol）
- 属性（property）
- 方法声明（instance / class method）

```objc
// OUT_HEADERS/TargetClass.h
@interface TargetClass : NSObject <NSCoding>
@property (nonatomic, strong) NSString *apiKey;
- (NSString *)encrypt:(NSString *)plain;
- (void)loginWithUser:(NSString *)user pass:(NSString *)pass;
@end
```

### 找关键类

```bash
# 按名字猜
ls OUT_HEADERS | grep -iE 'crypto|encrypt|sign|auth|login|pay|net'

# 按方法内容搜
grep -rn -iE 'encrypt|decrypt|sign|token' OUT_HEADERS/ | head -30

# 类的数量（判断复杂度）
ls OUT_HEADERS | wc -l
```

### 看字符串常量

```bash
strings -a BINARY | grep -iE 'https?://|api|key|secret|token' | head -30
strings -a -el BINARY | head -30     # UTF-16
```

ObjC 的方法名与类名会在二进制里以明文出现，`strings` 就能看到大量线索。

## Swift 分析

Swift 符号是 mangled 的，需要 demangle：

```bash
# 看 demangled 符号表
nm -g BINARY | swift-demangle | head -50

# 只找特定类
nm -g BINARY | swift-demangle | grep -i 'TargetClass'

# 完整 demangle（含私有符号）
nm BINARY | swift-demangle | grep 'TargetModule'
```

**Mangling 前缀速查：**

| 前缀 | 含义 |
| --- | --- |
| `_$s` | Swift 4+ |
| `_$S` | Swift 5+ |
| `_T` | Swift 3 及更早 |
| `_TtC` | ObjC 运行时里的 Swift 类 |
| `_TtP` | Swift protocol |

`_$s10TargetModule9TargetClassC` = `TargetModule.TargetClass` (C = class)

### Swift 特有结构

```bash
# 找 Swift 元数据
nm BINARY | swift-demangle | grep -E 'metadata|witness|vtable'

# Swift 的 vtable 在 __swift5_proto / __swift5_types 段
otool -l BINARY | grep -E '__swift5'
```

## 依赖库分析

```bash
otool -L BINARY
```

**重点看：**

```
/System/Library/Frameworks/...        系统库（不用管）
@rpath/Framework.framework/Framework  内嵌框架（要一起分析）
@executable_path/...                  同目录
/usr/lib/libsubstrate.dylib           越狱插件注入痕迹
```

内嵌框架位置：

```bash
ls OUT/Payload/*.app/Frameworks/
```

## 找入口点

```
1. main 函数（otool -l 找 LC_MAIN 的 entryoff）
2. AppDelegate 的 application:didFinishLaunchingWithOptions:
3. SceneDelegate
4. 自定义 UIViewController 的 viewDidLoad
5. 网络请求发起处（NSURLSession / Alamofire）
6. 加密调用（CCCrypt / SecKeyEncrypt / CryptoKit）
```

```bash
# 找 CryptoKit / CommonCrypto 调用
nm -u BINARY | grep -iE 'CCCrypt|SecKey|CC_MD5|CC_SHA'

# 找网络
nm -u BINARY | grep -iE 'NSURLSession|CFNetwork'
```

## 地址计算（写 hook / patch 时必需）

```
IDA 里的地址 = Mach-O 的 vmaddr + 偏移

例：
  __TEXT segment vmaddr = 0x100000000
  IDA 显示 0x100004a2c
  实际文件偏移 = 0x100004a2c - 0x100000000 + __TEXT.fileoff
```

```bash
# 精确算
otool -l BINARY | grep -A6 "segname __TEXT"
# 记下 vmaddr 与 fileoff
```

## entitlements 与签名

```bash
codesign -d --entitlements - BINARY
codesign -dvvv BINARY
```

**重点看 entitlements：**

```xml
<key>get-task-allow</key><true/>        <- 允许调试（开发版）
<key>application-identifier</key>       <- Bundle ID
<key>keychain-access-groups</key>       <- 钥匙串访问组
<key>com.apple.developer.team-identifier</key>
```

`get-task-allow = true` 意味着**可以直接 lldb 附加**（不需要脱壳机权限）。

## 输出规范

```
[静态-iOS] 样本=SHA256 Bundle=com.example.app 版本=1.2.3
架构: arm64 (FAT: arm64 + arm64e)
FairPlay: cryptid=1 -> 需脱壳
入口: main @ 0x100004a2c
关键类: 42 个 ObjC 类，其中:
  - CryptoHelper: encrypt: / decrypt: / generateKey
  - LoginManager: loginWithUser:pass:
关键字符串: https://api.example.com/v1 (offset 0x1a2b3)
依赖: 内嵌 Framework: NetworkKit.framework
签名: get-task-allow=true -> 可直接 lldb
下一步: 先 rev-unpack-ios 脱壳，再 rev-dynamic-frida hook CryptoHelper
```

## 常见坑

| 症状 | 原因 | 处理 |
| --- | --- | --- |
| IDA 打开是乱码 | cryptid=1 未脱壳 | rev-unpack-ios |
| class-dump 只导出部分类 | Swift 类不在 ObjC runtime | 用 swift-demangle 看符号 |
| strings 看不到明文 | 字符串被加密/混淆 | 转 rev-deobfuscate |
| otool -l 输出太长 | 加载命令很多 | `\| grep -A4 LC_` 过滤 |
| 找不到 main | 不是 MH_EXECUTE | 检查 filetype，可能是 dylib |
