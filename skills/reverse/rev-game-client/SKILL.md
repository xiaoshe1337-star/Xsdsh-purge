---
name: rev-game-client
description: 游戏客户端分析与反作弊研究。客户端资源与逻辑结构、Unity/Unreal/自研引擎识别、Il2Cpp/lua/脚本层逆向、游戏协议（帧同步/状态同步）opcode 还原、内存数据定位、反作弊系统（ACE/BattlEye/EAC/nProtect/腾讯TP）识别与检测点分析、行为还原与验证。适用于游戏客户端逆向、协议还原、反作弊机制研究。
enabled: true
---

# 游戏客户端分析与反作弊研究

## 引擎识别

| 特征文件 | 引擎 |
| --- | --- |
| `UnityPlayer.dll` / `libunity.so` / `*.assets` / `globalgamemanagers` | Unity |
| `UE4Game.exe` / `*.pak` / `Engine/` | Unreal Engine |
| `libcocos2d*.so` / `*.ccz` / `res/` | Cocos2d-x |
| `libcef.so` + 自定义 | 自研 + CEF UI |
| `*.swf` | Flash（老游戏） |

```bash
# Unity 判定
ls | grep -iE 'unity|assets|globalgamemanager'
find . -name "*.assets" -o -name "*.bundle" | head

# Unreal 判定
find . -name "*.pak" | head
ls Engine/ 2>/dev/null
```

## Unity 逆向

### 结构

```
Game/
├── Game_Data/
│   ├── Managed/              # .NET 程序集（Mono 后端）
│   │   ├── Assembly-CSharp.dll   <- 游戏逻辑在这
│   │   └── ...
│   ├── il2cpp_data/          # IL2CPP 后端
│   │   └── Metadata/global-metadata.dat
│   ├── resources.assets
│   ├── sharedassets*.assets
│   └── level0, level1...
├── Game.exe
└── UnityPlayer.dll
```

### Mono 后端（老版/未加密）

```bash
# 直接用 dnSpy 打开 Assembly-CSharp.dll
# 能直接看到 C# 源码
```

若被加密，用 **Il2CppDumper** / **AssetStudio** 先处理。

### IL2CPP 后端（新版主流）

```bash
# 1. 需要两个文件
#    - global-metadata.dat (在 il2cpp_data/Metadata/)
#    - 主二进制 (GameAssembly.dll / libil2cpp.so)

# 2. Il2CppDumper
Il2CppDumper.exe GameAssembly.dll global-metadata.dat OUT_DIR
# 产物：
#   dump.cs          <- 所有类与方法的签名
#   il2cpp.h
#   script.json      <- 给 IDA 用的符号脚本
#   dummy dll        <- 给 dnSpy 看的假 dll
```

```bash
# 3. 加载符号到 IDA
# File -> Script file -> 选 il2cpp_with_metadat...py（在 IDA 里）
# 或直接用 IDA 的 "Load script" 加载 script.json 生成的 .py
```

```bash
# 4. 或用 Il2CppInspector（更现代）
Il2CppInspector.exe -i GameAssembly.dll -m global-metadata.dat -o OUT
```

### 加密的 global-metadata.dat

**识别：** 文件头不是 `AF 1B B1 FA`（标准 magic）。

```
处理路径：
1. 找解密函数（在 libil2cpp.so 的初始化里）
2. 动态 dump：等解密完成，从内存取
3. 常见方案：Frida hook 读文件的地方，拿到解密后内容
```

```javascript
// hook 文件读取，拿解密后的 metadata
var open = Module.findExportByName(null, 'open');
Interceptor.attach(open, {
    onEnter: function (args) {
        var p = args[0].readCString();
        if (p && p.indexOf('global-metadata') !== -1) {
            this.hit = true;
            console.log('[open] ' + p);
        }
    }
});
var read = Module.findExportByName(null, 'read');
Interceptor.attach(read, {
    onEnter: function (args) { this.buf = args[1]; this.fd = args[0].toInt32(); },
    onLeave: function (ret) {
        var n = ret.toInt32();
        if (n > 0x1000) {
            var d = Memory.readByteArray(this.buf, 8);
            var u = new Uint8Array(d);
            // 检查是不是解密后的 metadata
            if (u[0] === 0xAF && u[1] === 0x1B) {
                console.log('[metadata decrypted!] dumping...');
                var full = Memory.readByteArray(this.buf, n);
                var f = new File('/sdcard/metadata_dec.dat', 'wb');
                f.write(full); f.flush(); f.close();
            }
        }
    }
});
```

### Unity 资源

```bash
# AssetStudio（图形化，最方便）
# 打开 game_Data 目录，能浏览所有资源、纹理、模型、文本

# 命令行版 AssetRipper（能还原成工程）
AssetRipper.exe Game_Data

# 提取特定资源
AssetStudioModCLI.exe -i Game_Data -o OUT --types Mesh,TextAsset
```

**文本资源（配置、lua、json）通常在 `TextAsset` 里，AssetStudio 直接导出。**

## Unreal 逆向

### .pak 解包

```bash
# UnrealPak / quickbms / FModel
FModel.exe        # 图形化，最好用

# 命令行
UnrealPak.exe game.pak -extract OUT
```

**AES 加密的 pak：**

```
1. 找 pak 尾部的加密标志
2. 找 AES key（在 exe 里搜，或 hook 加载过程）
3. 常见位置：Engine/Config/DefaultEngine.ini 或硬编码
```

```bash
# 用 quickbms 脚本处理
quickbms.exe unreal_tournament_4.bms game.pak OUT
```

### Blueprint（蓝图）

```
.assets 里的 Blueprint 是字节码，需要用 UE 编辑器打开
或
1. 转成 C++（UAssetAPI / 第三方工具）
2. 逆向字节码结构
```

## 自研引擎

常见结构：

```
游戏exe / 主二进制
├── *.dat / *.bin / *.pkg     # 打包资源
├── *.lua / *.luac            # lua 脚本
├── lib*.so                   # 核心逻辑
└── config/                   # 配置
```

### Lua 脚本还原

```bash
# 识别 lua 版本
file script.luac          # 或看头部 1B 4C 75 61 (ESC Lua)
xxd script.luac | head -2

# luac 反编译
unluac script.luac > script.lua    # 需匹配 lua 版本
luadec script.luac -o script.lua   # 另一个工具

# 若脚本加密
# 1. 找解密函数（hook luaL_loadbuffer）
# 2. dump 解密后的字节码
```

```javascript
// hook luaL_loadbuffer 拿明文脚本
var lb = Module.findExportByName(null, 'luaL_loadbuffer');
if (!lb) lb = Module.findExportByName(null, 'luaL_loadbufferx');
Interceptor.attach(lb, {
    onEnter: function (args) {
        var size = args[2].toInt32();
        var data = Memory.readByteArray(args[1], size);
        console.log('[lua script] ' + size + ' bytes');
        var f = new File('/sdcard/lua_' + Date.now() + '.lua', 'wb');
        f.write(data); f.flush(); f.close();
    }
});
```

## 内存数据定位

### 找关键数值（血量/金币/坐标）

```
1. 首次扫描：搜当前值（如血量 100）
2. 改变值（受伤害）
3. 二次扫描：搜新值（如 80）
4. 重复直到剩少数候选
5. 验证：改成别的值，看游戏反应

工具：Cheat Engine / GameGuardian(移动) / scanmem(Linux)
```

**逆向视角的价值：** 找到数值后，**回溯谁在读写它**（硬件断点），就能定位到游戏逻辑函数。

```
CE 里：
1. 找到地址
2. 右键 -> "Find out what accesses this address"
3. 得到访问指令 -> 反汇编看上下文 -> 找到更新血量的函数
```

### Frida 版

```javascript
// 监控某地址的读写
var addr = ptr('0x12345678');
MemoryAccessMonitor.enable([{ base: addr, size: 4 }], {
    onAccess: function (details) {
        console.log('[access] ' + details.operation + ' @ ' + details.from);
        console.log(Thread.backtrace(details.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n'));
    }
});
```

## 游戏协议

### 帧同步（Lockstep）

```
特征：
- 每个包都是固定 opcode + 相同长度
- 服务器广播所有人的输入
- 客户端按帧号顺序执行

还原要点：
1. opcode 表（哪个 opcode 是什么操作）
2. 帧号（同步基准）
3. 输入序列（操作类型 + 参数）
4. 校验和（防篡改）
```

### 状态同步

```
特征：
- 服务器推送完整/增量状态
- 包长不固定
- 有实体 ID + 属性变更

还原要点：
1. 实体 ID 编码方式
2. 属性字段表（哪个字段是位置/血量/状态）
3. 增量 vs 全量标记
```

### opcode 提取

```javascript
// hook 收包
var recv = Module.findExportByName(null, 'recv');
Interceptor.attach(recv, {
    onEnter: function (args) { this.buf = args[1]; },
    onLeave: function (ret) {
        var n = ret.toInt32();
        if (n > 0) {
            var op = Memory.readU8(this.buf);
            console.log('[recv] op=0x' + op.toString(16) + ' len=' + n);
            console.log(hexdump(this.buf, { length: Math.min(n, 32) }));
        }
    }
});
```

```python
# 统计后聚类
from collections import Counter
c = Counter()
# 从日志解析
# c[opcode] += 1
for op, cnt in c.most_common():
    print(f'0x{op:02x}: {cnt}')
```

## 反作弊系统

### 主流反作弊识别

| 系统 | 平台 | 特征 |
| --- | --- | --- |
| **ACE**（腾讯 Anti-Cheat Expert） | Win/Android | `ACE-BASE.sys`、`ACE-Guard`、`anticheat` 相关驱动 |
| **BattlEye** | Win | `BEService.exe`、`BEClient_x64.dll`、`BEDaisy.sys` |
| **EAC**（Easy Anti-Cheat） | Win | `EasyAntiCheat.exe`、`EasyAntiCheat_EOS.sys` |
| **nProtect GameGuard** | Win/Android | `npggNT.des`、`GameMon.des` |
| **腾讯 TP**（TenProtect） | Win | `TenSafe`、`tp3helper` |
| **Vanguard**（Riot） | Win | `vgc.exe`、`vgk.sys`（内核态，最严） |
| **XignCode3** | Win | `x3.xem`、`XignCode` |

```bash
# 识别
tasklist | findstr /i "ace battle eye easy anti cheat nprotect vgc"
sc query type= driver | findstr /i "ace be eac vgk"
```

### 检测点分析框架

反作弊的检测维度（**研究这些是为了理解它，不是绕过它**）：

| 维度 | 具体手法 | 分析切入点 |
| --- | --- | --- |
| **进程扫描** | 枚举进程找 CE/x64dbg/IDA | hook `CreateToolhelp32Snapshot` / 读 `/proc` |
| **模块扫描** | 枚举已加载 DLL/SO | hook `EnumProcessModules` |
| **内存扫描** | 扫可疑特征码（CE 的标记） | 监控自身扫描函数 |
| **代码段校验** | 定期 CRC 自身 `.text` | 找定时器 + 读代码段的函数 |
| **句柄检测** | 检测是否有进程 open 了游戏句柄 | `NtQuerySystemInformation` |
| **调试检测** | PEB / 硬件断点 / 时间差 | 见 rev-protect-bypass |
| **驱动层** | 内核驱动直接读进程内存、Hook SSDT | 需内核调试分析 |
| **硬件指纹** | 设备 ID / 硬盘序列号 / MAC | 找读这些信息的 API |
| **行为分析** | 输入频率、命中率、路径异常 | 服务端侧，客户端看不到 |
| **完整性** | 校验客户端文件哈希 | hook 文件读取 |

### 内核态反作弊分析

```
1. 需要内核调试环境（双机 + WinDbg）
2. 看驱动加载：
   .symfix; .reload
   lm
   !drvobj \Driver\ACE-BASE 2
3. 看驱动注册的回调：
   !object \Callback
   （Process/Thread/ImageLoad 回调是常见检测点）
4. 看 SSDT / Shadow SSDT Hook（老技术，新版少了）
   !ssdt
5. 看内核回调：
   PsSetCreateProcessNotifyRoutine
   PsSetLoadImageNotifyRoutine
   ObRegisterCallbacks
```

**如实说明：** 内核态反作弊的完整分析需要专用调试环境与大量时间。**产出应该是"检测点清单 + 分析报告"，不是"绕过方案"。**

### 用户态分析（可行路径）

```javascript
// 找反作弊的检测函数（以 Android 为例）
// 1. 找可疑的 native 函数
Java.perform(function () {
    // 反作弊常通过 JNI 调用
    // 扫描所有 native 方法声明
    Java.enumerateLoadedClasses({
        onMatch: function (name) {
            if (/anticheat|security|guard|protect|safe/i.test(name)) {
                console.log('[suspect] ' + name);
            }
        },
        onComplete: function () {}
    });
});
```

```bash
# 找检测字符串
strings libace.so | grep -iE 'cheat|debug|frida|xposed|magisk|root'
```

## 行为还原（正规逆向产出）

不碰反作弊绕过时，游戏逆向的**正当产出**是：

```
1. 游戏逻辑还原（伤害公式、掉落概率、成长曲线）
2. 协议格式文档（给第三方工具/统计用）
3. 客户端资源提取（美术素材、音频、文本）
4. 性能分析（渲染管线、资源加载）
5. 存档格式解析（单机游戏）
```

**这些都不需要碰反作弊。**

## 输出规范

```
[游戏] 样本=SHA256 引擎=Unity IL2CPP 版本=2021.3.15
结构:
  GameAssembly.dll (42MB, IL2CPP)
  global-metadata.dat (18MB, 已解密)
  反作弊: ACE (ACE-BASE.sys 存在)
逆向成果:
  - Il2CppDumper 导出 12847 个类
  - 关键类: PlayerController, DamageCalculator, NetworkManager
  - 伤害公式: damage = (atk - def*0.6) * critMul * random(0.9,1.1)
    证据: DamageCalculator.Calc @ dump.cs:8421
  - 协议: 状态同步，opcode 0x01/0x02/0x10，字段已还原
反作弊观测（仅分析，未绕过）:
  - 用户态扫描: 每 30s 枚举进程找 CE/x64dbg
  - 内核态: ACE-BASE.sys 注册了 PsSetLoadImageNotifyRoutine
  - 检测到会: 记录日志上报，5 分钟后踢出
证据: /path/dump.cs + /path/proto.md + /path/anticheat_analysis.md
```

## 边界

- **反作弊研究的产出是"检测点清单 + 分析报告"**，不是可用的绕过工具。
- 内核态分析需要专用调试环境；没有就如实说明「未做内核态分析」。
- 游戏逻辑还原是正当产出（公式、协议、资源），**不需要碰反作弊**。
- 在线游戏的**服务端逻辑无法从客户端还原**，不要声称能还原。
- 所有验证在**单机/私服/离线环境**做。
