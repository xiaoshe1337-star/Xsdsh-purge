---
name: rev-unpack-ios
description: iOS FairPlay 脱壳。cryptid 判定、越狱机环境准备、frida-ios-dump / dumpdecrypted / bagbak 脱壳流程、产物验证（cryptid 归零）、内嵌 Framework 一并脱壳。适用于 App Store 下载的 IPA（cryptid=1）无法直接静态分析的场景。
enabled: true
---

# iOS FairPlay 脱壳

## 先判定是否加密

```bash
otool -l BINARY | grep -A4 LC_ENCRYPTION_INFO
```

```
cmd LC_ENCRYPTION_INFO
cryptoff 16384
cryptsize 8388608
cryptid 1          <== 1 = 加密，必须脱壳
```

| cryptid | 含义 | 行动 |
| --- | --- | --- |
| `0` | 未加密 | 直接分析，不需要本技能 |
| `1` | FairPlay 加密 | 走下面的流程 |

**App Store 下载的一定是 1。** 从越狱源/第三方装的可能是 0。

## 环境要求

```
✅ 越狱设备（checkra1n / palera1n / unc0ver / Dopamine 等）
✅ 设备已安装 OpenSSH
✅ 设备能装 Frida（Cydia/Sileo 源）
✅ 电脑能 SSH 到设备
```

### 检查

```bash
# SSH 连通
ssh root@DEVICE_IP 'uname -a'

# frida 在设备上
ssh root@DEVICE_IP 'which frida-server || ls /usr/sbin/frida*'

# 设备 frida 版本
ssh root@DEVICE_IP '/usr/sbin/frida-server --version'

# 本地 frida 版本（必须一致）
frida --version
```

## 方法一：frida-ios-dump（推荐）

```bash
# 1. 克隆
git clone https://github.com/AloneMonkey/frida-ios-dump
cd frida-ios-dump

# 2. 装依赖
pip3 install -r requirements.txt

# 3. 改配置（dump.py 里）
#    Password = 'alpine'        设备 SSH 密码
#    Host = 'DEVICE_IP'         设备 IP
#    Port = 22
#    User = 'root'

# 4. 列应用
python3 dump.py -l

# 5. 脱壳
python3 dump.py com.example.app
# 产物：com.example.app.ipa 在当前目录
```

**原理：** 从内存里 dump 已解密的 __TEXT 段，重新组装成 IPA。

### 常见问题

| 错误 | 原因 | 处理 |
| --- | --- | --- |
| `Unable to connect to device` | SSH 不通 | 检查 IP / 端口 / 密码 |
| `No such process` | App 没运行 | 先手动打开 App 再脱 |
| 产物打不开 | dump 时机不对 | App 打开后等 3-5 秒再脱 |
| 只脱了主二进制 | 内嵌 Framework 没脱 | 见下面"内嵌 Framework" |

## 方法二：bagbak（Frida 现代版）

```bash
# 支持 iOS 12+ 与 arm64e
npm install -g bagbak

# 列应用
bagbak --list

# 脱壳
bagbak com.example.app -o OUT.ipa
```

**优点：** 对 arm64e 与新版 iOS 支持更好。

## 方法三：dumpdecrypted（老方法，iOS 9-12）

```bash
# 编译
git clone https://github.com/stefanesser/dumpdecrypted
cd dumpdecrypted
make

# 推到设备
scp dumpdecrypted.dylib root@DEVICE_IP:/var/mobile/

# 在设备上运行
ssh root@DEVICE_IP
cd /var/mobile
DYLD_INSERT_LIBRARIES=dumpdecrypted.dylib \
  /var/containers/Bundle/Application/XXXX/App.app/App

# 产物在 /var/mobile/*.decrypted
```

## 内嵌 Framework 一并脱壳

主二进制脱了，`Frameworks/` 下的库可能还是加密的。

```bash
# 1. 列出所有 Mach-O
find Payload -type f -exec file {} \; | grep Mach-O

# 2. 逐个检查 cryptid
for f in $(find Payload -type f -exec file {} \; | grep Mach-O | cut -d: -f1); do
    echo "== $f"
    otool -l "$f" 2>/dev/null | grep -A3 LC_ENCRYPTION_INFO | grep cryptid
done

# 3. 有 cryptid 1 的，逐个脱
python3 dump.py -o FrameworkName Payload/App.app/Frameworks/X.framework/X
```

**frida-ios-dump 支持 `--framework` 参数批处理。**

## 验证脱壳成功

```bash
# 1. 解包新 IPA
unzip -o OUT.ipa -d OUT_UNPACKED

# 2. 检查 cryptid 归零
otool -l OUT_UNPACKED/Payload/*.app/AppBinary | grep -A4 LC_ENCRYPTION_INFO
# cryptid 0  <== 成功

# 3. 检查段内容不是乱码
otool -s __TEXT __text OUT_UNPACKED/Payload/*.app/AppBinary | head -20
# 应该看到正常的 ARM64 指令，而不是一堆 00 或随机字节

# 4. class-dump 能导出类
class-dump -H OUT_UNPACKED/Payload/*.app/AppBinary -o OUT_HEADERS
ls OUT_HEADERS | head

# 5. IDA 打开能反编译
```

**成功标准：**

```
✅ cryptid = 0
✅ __text 段是正常指令
✅ class-dump 能导出（ObjC 应用）
✅ IDA 能正常反编译关键函数
```

**失败标准：**

```
❌ cryptid 仍是 1           -> dump 时机不对 / 权限不足
❌ __text 全是 0xFF         -> 读到了未解密页
❌ class-dump 报错          -> 二进制不完整
❌ IDA 打开一段乱码         -> 只脱了部分页
```

## 重新打包（需要时）

```bash
# 把脱壳后的二进制放回
cp DECRYPTED_BINARY OUT_UNPACKED/Payload/App.app/AppBinary
chmod +x OUT_UNPACKED/Payload/App.app/AppBinary

# 重新签名（需要证书）
codesign -f -s "iPhone Developer: XXX (TEAMID)" \
    --entitlements ent.plist \
    OUT_UNPACKED/Payload/App.app

# 打包
cd OUT_UNPACKED
zip -r ../OUT_resigned.ipa Payload
```

**注意：** 脱壳 + 重签后的 App 装到设备上会失去部分能力（推送、Keychain 共享等），因为签名变了。

## 常见坑

| 症状 | 原因 | 处理 |
| --- | --- | --- |
| SSH 连不上 | 越狱后 SSH 未启动 | 装 OpenSSH，或 checkra1n 里开启 |
| 密码错 | 默认 alpine | 如果改过就是改后的 |
| frida 连不上 | 版本不匹配 | 设备与本地 frida 版本必须一致 |
| 设备重启后失效 | 越狱是半持久化 | 重新越狱 |
| dump 出的 IPA 装不上 | 签名无效 | 重签 |
| 脱壳后某些功能异常 | 完整性校验 | 分析校验逻辑（rev-protect-bypass） |

## 输出规范

```
[脱壳-iOS] 样本=SHA256 Bundle=com.example.app 版本=1.2.3
设备: iPhone12,3 / iOS 15.7 / palera1n 越狱
原状态: cryptid=1 (FairPlay 加密)
方法: frida-ios-dump (frida 16.2.1)
产物: /path/com.example.app.ipa  sha256=xxx  size=45MB
验证:
  cryptid: 0 (PASS)
  __text 段: 正常 ARM64 指令 (PASS)
  class-dump: 导出 312 个类 (PASS)
结论: FairPlay 已脱，可进行完整静态分析
```

## 边界

- 只做脱壳。**不做业务分析、不改功能**。
- 脱壳失败要**如实报告**，说明是 SSH / frida / 时机哪一环出的问题。
- 需要重签时说明会失去哪些能力。
