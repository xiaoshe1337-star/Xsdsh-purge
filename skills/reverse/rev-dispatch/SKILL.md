---
name: rev-dispatch
description: 逆向统一路由层。给一个样本路径或目标描述，自动识别平台（Android/iOS/Windows/跨平台）、文件格式、保护方案，输出该走哪条技能链、按什么顺序、每步验收标准。凡是"这个文件怎么逆""该用哪个技能""从哪开始"类问题，先走这里。
enabled: true
---

# 逆向统一路由（rev-dispatch）

拿到任何逆向目标，**第一个动作永远是这里**。

## 第 0 步：基线（必做）

```bash
sha256sum SAMPLE
file SAMPLE
stat -c '%s %y' SAMPLE 2>/dev/null || stat -f '%z %Sm' SAMPLE
```

**熵值（判壳）:**

```python
import math
d = open('SAMPLE','rb').read()
c = [0]*256
for b in d: c[b] += 1
e = -sum((x/len(d))*math.log2(x/len(d)) for x in c if x)
print('entropy:', round(e, 3))
# < 6.0  正常
# 6.0-7.0 可能压缩
# > 7.0  高度可疑：加密/压缩/加壳
# > 7.5  几乎确定有保护层
```

## 第 1 步：平台判定（按 magic，不按扩展名）

| magic（hex） | 平台 | 常见扩展名 |
| --- | --- | --- |
| `4D 5A` | Windows PE | .exe .dll .sys .scr |
| `7F 45 4C 46` | ELF | .so .elf .bin（Android/Linux） |
| `CF FA ED FE` | Mach-O 64 小端 | .dylib 无扩展（iOS主二进制） |
| `CA FE BA BE` | Mach-O FAT | iOS 通用二进制 |
| `64 65 78 0A` | DEX | .dex |
| `50 4B 03 04` | ZIP 容器 | .apk .aab .ipa .jar .xapk |

**ZIP 容器需要再分：**

```bash
unzip -l SAMPLE | head -30
# 有 AndroidManifest.xml + classes.dex   -> APK
# 有 Payload/*.app                        -> IPA
# 有 META-INF + *.class                   -> JAR
```

## 第 2 步：保护识别

### Android 加固

```bash
find lib -name "*.so" -o -name "lib*.so" 2>/dev/null | head -20
```

| SO 名 | 加固 |
| --- | --- |
| libjiagu*.so | 360 |
| libshella*.so / libshellx*.so | 腾讯乐固 |
| libsecexe.so / libsecmain.so | 梆梆 |
| libDexHelper.so / libmobisec.so | 阿里 |
| libnesec.so | 网易易盾 |
| libexec*.so | 爱加密 |
| libchaosvmp.so / libddog.so | 娜迦 |
| libkwscmm.so | 几维 |
| libbaiduprotect.so | 百度 |
| libnqshield.so | 网秦 |

**辅助信号:** `classes.dex < 50KB` / `assets/` 大量无扩展名文件 / `application:name` 是混淆类。

### iOS 加密

```bash
otool -l BINARY | grep -A4 LC_ENCRYPTION_INFO
# cryptid 0 -> 未加密，可直接分析
# cryptid 1 -> FairPlay 加密，必须先脱壳
```

### Windows 加壳

```bash
diec SAMPLE.exe
```

| 节区名 | 壳 |
| --- | --- |
| UPX0/UPX1 | UPX |
| .vmp0/.vmp1 | VMProtect |
| .themida/.winlice | Themida |
| .aspack | ASPack |
| .enigma1/.enigma2 | Enigma |

## 第 3 步：路由决策树

```
目标
├─ Android APK/AAB
│   ├─ 有加固特征 → rev-unpack-android（先脱）
│   ├─ 无加固     → rev-android-static（直接反编译）
│   └─ 要看运行时 → rev-dynamic-frida
├─ Android SO/ELF
│   ├─ 熵 > 7.0 或段异常 → rev-unpack-native
│   ├─ OLLVM 特征        → rev-deobfuscate
│   └─ 正常               → rev-static-elf
├─ iOS IPA
│   ├─ cryptid = 1 → rev-unpack-ios（FairPlay 脱壳）
│   └─ cryptid = 0 → rev-ios-macho
├─ Windows PE
│   ├─ 有壳 → rev-unpack-windows
│   └─ 无壳 → rev-windows-pe
├─ 协议/流量
│   └─ rev-protocol
├─ 游戏客户端
│   └─ rev-game-client
└─ 保护绕不过
    └─ rev-protect-bypass
```

## 第 4 步：顺序建议

| 场景 | 顺序 |
| --- | --- |
| 普通 APK | static → dynamic → protocol |
| 加固 APK | 判壳 → unpack → static → dynamic |
| Native 加密 | static → unpack-native → deobfuscate → protocol |
| iOS 未加密 | ios-macho → dynamic |
| iOS FairPlay | unpack-ios → ios-macho → dynamic |
| Windows 有壳 | unpack-windows → windows-pe → dynamic |
| 有反调试 | protect-bypass（最先） → 原流程 |
| 游戏 | static → protect-bypass → unpack → dynamic → protocol |

## 每步验收标准

| 步骤 | 验收 |
| --- | --- |
| 静态分析 | 能列出入口点 + 至少 3 个关键函数 + 平台/架构/保护结论 |
| 脱壳 | 产物能被 IDA 打开并反编译，readelf/PE 解析器无报错 |
| 动态调试 | 能打上断点并抓到至少一次真实调用 |
| 保护对抗 | 绕过前后行为差异可复现（绕过前失败，绕过后成功） |
| 协议还原 | 独立脚本能解出真实密文，字段与抓包吻合 |

## 输出格式

```
[路由] 样本=SHA256
平台: android  格式: APK  架构: arm64-v8a
保护: 360 加固 (libjiagu.so)
熵值: 7.82 (高)
推荐链: rev-unpack-android -> rev-android-static -> rev-dynamic-frida
第一步: BlackDex 脱壳
验收: 脱壳产物能被 jadx 完整反编译
```
