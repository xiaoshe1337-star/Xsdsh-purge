---
name: rev-unpack-android
description: Android 加固脱壳。识别 20+ 种加固方案（360/腾讯乐固/梆梆/阿里聚安全/网易易盾/爱加密/娜迦VMP/几维/百度/网秦等），按 root 状态选择 BlackDex / FRIDA-DEXDump / youpk / dumpDex / FART 方案，脱壳后修复 dex 头与验证。适用于 classes.dex 异常小、反编译不出来、assets 有加密载荷的场景。
enabled: true
---

# Android 脱壳

## 加固识别

### SO 特征表

```bash
find OUT/lib -name "*.so" | while read f; do echo "== $f"; done
```

| SO 文件名 | 加固方案 | 强度 |
| --- | --- | --- |
| `libjiagu.so` `libjiagu_art.so` `libjiagu_x86.so` | 360 加固 | 中 |
| `libshella.so` `libshellx.so` | 腾讯乐固 | 中 |
| `libsecexe.so` `libsecmain.so` | 梆梆加固 | 中 |
| `libDexHelper.so` | 阿里聚安全 | 中 |
| `libmobisec.so` | 阿里 | 中 |
| `libnesec.so` | 网易易盾 | 高 |
| `libexec.so` `libexecmain.so` | 爱加密 | 中 |
| `libchaosvmp.so` `libddog.so` | 娜迦 VMP | 高 |
| `libkwscmm.so` | 几维安全 | 中 |
| `libbaiduprotect.so` | 百度加固 | 中 |
| `libnqshield.so` | 网秦 | 中 |
| `libapp.so` (Flutter) | Flutter（不是壳） | — |

### 辅助信号

```bash
# classes.dex 大小（加固后通常 < 50KB）
unzip -l SAMPLE.apk | grep 'classes.*dex'

# assets 里的可疑文件
unzip -l SAMPLE.apk | grep assets/ | head -30

# Manifest 里的 Application 类名（加固会改）
apktool d -f -s SAMPLE.apk -o OUT_MANIFEST
grep 'android:name' OUT_MANIFEST/AndroidManifest.xml | head -15
```

**典型加固特征：**
- `android:name="com.stub.StubApp"` → 360
- `android:name="com.tencent.StubShell.TxAppEntry"` → 腾讯
- `android:name="s.h.e.l.l.S"` → 梆梆
- `android:name="com.ali.mobisecenhance.ld.RecordShellApp"` → 阿里

## 方案选择

| 条件 | 方案 | 说明 |
| --- | --- | --- |
| 有 root，优先简单 | **BlackDex** | 免 root 也能跑，兼容广 |
| 有 root + Frida | **FRIDA-DEXDump** | 批量 dump 内存 dex |
| 需要完整方法体 | **youpk** | 需刷定制 ROM，最强 |
| 无 root | **dumpDex**(Xposed) | 需 LSPosed |
| 抽取型壳 | **FART** | 需定制 ROM |

## BlackDex

```bash
# 1. 装
adb install BlackDex.apk

# 2. 打开 App，选目标，点"脱壳"
#    等待完成（30s-2min，看 App 大小）

# 3. 取产物
adb pull /sdcard/Android/data/com.wrbug.dexdump/files/dexdump/ OUT_DEX
ls -la OUT_DEX/
```

**BlackDex 的优点：** 自动修复 dex 头，产物通常能直接反编译。

**限制：** 对某些强壳（网易易盾、娜迦 VMP）效果差。

## FRIDA-DEXDump

```bash
# 1. 起 App
adb shell am start -n PACKAGE_NAME/.MainActivity
sleep 3

# 2. dump
python3 frida_dexdump.py -n PACKAGE_NAME -o OUT_DEX

# 3. 修复（关键）
python3 dexfixer.py OUT_DEX/*.dex
```

**dump 出来的 dex 常见问题：**

| 问题 | 原因 | 修法 |
| --- | --- | --- |
| 打不开，magic 错 | header 被抹 | 填回 `64 65 78 0A 30 33 35 00` |
| `file_size` 错 | 字段被改 | 用实际文件大小填 `0x20` 偏移的 u32 |
| `header_size` 错 | 同上 | 填 `0x70`（标准值） |
| checksum/signature 错 | 内存里被改 | 重算（`dexfixer` 会做） |
| 只有部分类 | 动态加载未触发 | 多点几下 App 的功能页，再 dump |

**手工修 header（用 Python）：**

```python
import struct

def fix_dex_header(path, size):
    d = bytearray(open(path, 'rb').read())
    # magic
    d[0:8] = b'dex\n035\x00'
    # checksum (adler32 of [12:])
    import zlib
    struct.pack_into('<I', d, 8, zlib.adler32(bytes(d[12:])))
    # signature (sha1 of [32:])
    import hashlib
    d[12:32] = hashlib.sha1(bytes(d[32:])).digest()
    # file_size
    struct.pack_into('<I', d, 32, len(d))
    # header_size
    struct.pack_into('<I', d, 36, 0x70)
    open(path, 'wb').write(d)
    print('fixed', path, len(d))
```

## youpk / FART（抽典型壳）

需要刷定制 ROM。流程简述：

```
1. 刷 youpk/FART 定制 ROM 到测试机
2. 装目标 App
3. 运行 App，走到需要分析的功能
4. 从 /data/youpk/ 或类似目录取完整 dump
5. 产物包含 method 级完整字节码，不受抽取影响
```

**适用于：** 网易易盾、娜迦、某些企业定制壳。

## 验证脱壳成功

```bash
# 1. 能被标准工具打开
baksmali d OUT_DEX/classes.dex -o OUT_SMALI
echo "baksmali exit: $?"

# 2. jadx 能反编译
jadx -d OUT_JADX_V OUT_DEX/classes.dex
grep -r "not decompiled" OUT_JADX_V/ | wc -l   # 越少越好

# 3. 类数量合理（原 App 应该几千到几万）
find OUT_SMALI -name "*.smali" | wc -l

# 4. 方法体非空
grep -c "\.method" OUT_SMALI/**/*.smali 2>/dev/null | head
```

**脱壳成功的标准：**

```
✅ baksmali 无报错
✅ jadx 反编译成功率 > 90%
✅ 能找到业务逻辑的真实代码（不是空方法）
✅ 类数量与原 App 规模相符
```

**脱壳失败的表现：**

```
❌ 类存在但方法体全是 throw / return null  -> 抽取型壳，方法体在别处
❌ magic 修复后仍打不开                    -> 结构被破坏，dump 时机不对
❌ 只有壳自己的类                          -> dump 时机太早，真实 dex 还没解密
```

## 常见问题排查

| 症状 | 原因 | 处理 |
| --- | --- | --- |
| dump 出来全是很小的 dex | dump 时机太早 | App 多跑一会儿再 dump |
| 类数量远少于预期 | 只 dump 了主 dex | 用 BlackDex 全量模式 |
| 方法体是空的 | 抽取型壳 | 换 youpk / FART |
| 反编译报 "invalid dex" | header 损坏 | dexfixer / 手工修 |
| 打开 App 就闪退 | 有反调试/反 root | 先 rev-protect-bypass |
| BlackDex 列不出目标 | 目标未运行 | 先启动目标 App |

## 输出规范

```
[脱壳] 样本=SHA256 加固=360 (libjiagu.so) 方法=BlackDex v9.0
设备: Pixel7 / Android 14 / Magisk 26
产物:
  /path/OUT_DEX/classes.dex      sha256=xxx  size=8.2MB
  /path/OUT_DEX/classes2.dex     sha256=xxx  size=5.1MB
验证:
  baksmali: PASS (无报错)
  jadx: PASS (反编译率 96%)
  类数量: 12483 (合理)
结论: 加固已脱，真实业务代码完整
下一步: rev-android-static 分析真实代码
```

## 边界

- 只做脱壳。**不做协议还原、不写完整破解**。
- 脱壳失败要**如实报告卡在哪**，不要谎报成功。
- 强壳（易盾/娜迦）处理不了时，报告需要什么条件（定制 ROM / 特定工具）。
