---
name: rev-protocol
description: 协议还原与算法提取。抓包（mitmproxy/Wireshark/r0capture）、密文特征反推算法、定位加解密函数、提取密钥与 IV、Protobuf 与自定义二进制解析、游戏协议 opcode 表还原、独立脚本验证。适用于 App/客户端/游戏通信加密、签名参数、二进制协议的场景。
enabled: true
---

# 协议还原与算法提取

## 第 1 步：抓包

### TLS 层选择

| 场景 | 方案 |
| --- | --- |
| 普通 HTTPS | mitmproxy + 系统证书 |
| 有 SSL Pinning | Frida 绕过 + mitmproxy |
| 自研 TCP 协议 | Wireshark 抓原始字节 |
| 双向认证（mTLS） | 需要客户端证书，hook 提取 |

### mitmproxy

```bash
# 起代理
mitmproxy -p 8080
# 或带 UI
mitmweb -p 8080

# Android 装证书（7.0+ 需系统证书）
# 方案 A：Magisk 模块 "Move Certificates"
# 方案 B：手工
adb root 2>/dev/null
adb remount
adb push ~/.mitmproxy/mitmproxy-ca-cert.pem /system/etc/security/cacerts/
adb shell "chmod 644 /system/etc/security/cacerts/$(openssl x509 -inform PEM -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.pem | head -1).0"
adb reboot

# 设备设代理指向 电脑IP:8080
adb shell settings put global http_proxy COMPUTER_IP:8080
```

### r0capture（绕 pinning 抓包）

```bash
# https://github.com/r0ysue/r0capture
python3 r0capture.py -U -f PACKAGE_NAME -v
# 产物：PACKAGE_NAME.pcap
```

原理：hook `SSL_write`/`SSL_read`，直接拿明文，不经过代理。

### Wireshark（自研协议）

```
1. 抓包：选网卡，过滤 tcp.port == 目标端口
2. 跟流：右键 -> Follow -> TCP Stream
3. 看原始字节（选 "Show data as: Hex Dump"）
```

## 第 2 步：从密文反推算法

| 密文特征 | 算法 |
| --- | --- |
| 长度 = 16 的整数倍 | AES / SM4 |
| 长度 = 8 的整数倍 | DES / 3DES / Blowfish |
| 长度 = 明文长度（流式） | RC4 / XOR / 流密码 |
| 末尾 `=` 或 `==` | Base64（外层编码） |
| 32 位 hex | MD5 |
| 40 位 hex | SHA1 |
| 64 位 hex | SHA256 |
| 64 位 base64url | HMAC / JWT segment |

### 快速判定脚本

```python
def guess(s):
    import base64, re
    raw = s
    if s.endswith('=') or re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', s):
        try:
            raw = base64.b64decode(s)
            print('base64 ->', len(raw), 'bytes')
        except Exception:
            pass
    if re.fullmatch(r'[0-9a-fA-F]{32}', s):
        print('可能是 MD5')
    elif re.fullmatch(r'[0-9a-fA-F]{40}', s):
        print('可能是 SHA1')
    elif re.fullmatch(r'[0-9a-fA-F]{64}', s):
        print('可能是 SHA256')
    if len(raw) % 16 == 0:
        print('块长 16 -> AES/SM4')
    if len(raw) % 8 == 0 and len(raw) % 16 != 0:
        print('块长 8 -> DES/3DES')
    print('raw hex:', raw[:32].hex())
```

### Entropy 检查

```python
import math
def ent(b):
    if not b: return 0
    c = [0]*256
    for x in b: c[x] += 1
    return -sum((y/len(b))*math.log2(y/len(b)) for y in c if y)

print('entropy:', round(ent(raw), 3))
# > 7.8  几乎确定加密
# 6-7.8  压缩或部分加密
# < 6    可能是明文/编码
```

## 第 3 步：定位加解密函数

### 特征字节扫描（最可靠）

```javascript
// 找 AES S-box
var SBOX = '63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76';
Process.enumerateRanges('r--').forEach(function (r) {
    try {
        var hits = Memory.scanSync(r.base, r.size, SBOX);
        hits.forEach(function (h) {
            console.log('AES S-box @', h.address, 'in', r.file ? r.file.path : 'anon');
        });
    } catch (e) {}
});
```

```javascript
// 找 MD5 初始值 (67452301 efcdab89 98badcfe 10325476)
var MD5_INIT = '01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10';
```

```javascript
// 找 SHA256 初始值 (6a09e667 bb67ae85 ...)
var SHA256_INIT = '67 e6 09 6a 85 ae 67 bb';
```

### Java 层 hook

```javascript
Java.perform(function () {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.getInstance.overload('java.lang.String').implementation = function (alg) {
        console.log('[Cipher] ' + alg);
        return this.getInstance(alg);
    };
    Cipher.doFinal.overload('[B').implementation = function (input) {
        var out = this.doFinal(input);
        console.log('[AES IN ] ' + bytesToHex(input));
        console.log('[AES OUT] ' + bytesToHex(out));
        return out;
    };
    var MD = Java.use('java.security.MessageDigest');
    MD.getInstance.overload('java.lang.String').implementation = function (alg) {
        console.log('[Digest] ' + alg);
        return this.getInstance(alg);
    };
});
```

```javascript
// 第三方库
// OkHttp 的签名拦截器
Java.perform(function () {
    var Interceptor = Java.use('okhttp3.Interceptor');
    // 或直接 hook 具体实现类
    // 常见：com.xxx.SignInterceptor
});
```

### Native 层

```javascript
// hook 常见加密库导出
['AES_encrypt', 'AES_cbc_encrypt', 'MD5', 'SHA256', 'EVP_EncryptUpdate']
    .forEach(function (name) {
        var p = Module.findExportByName(null, name);
        if (p) {
            console.log('[found]', name, '@', p);
            Interceptor.attach(p, {
                onEnter: function (args) {
                    console.log('[' + name + '] in', args[0]);
                }
            });
        }
    });
```

**找不到导出符号时（静态链接）：** 用特征字节扫描定位 S-box，再在附近下断点。

## 第 4 步：提取密钥与 IV

密钥可能的来源，按优先级：

| 来源 | 找法 |
| --- | --- |
| 硬编码字符串 | `strings` + `grep -iE 'key\|secret\|aes'` |
| 硬编码字节数组 | 找长度 16/24/32 的字节序列，在加密调用前加载 |
| Native 常量 | hook so 里的 key 加载函数 |
| 服务端下发 | 抓握手包，找 key 字段 |
| 设备指纹派生 | hook 派生函数（IMEI/AndroidID/MAC + 固定盐） |
| 白盒密码学 | 无显式密钥，算法被融进查表 —— 只能整体复制函数 |

### Hook 密钥构造

```javascript
// Android
Java.perform(function () {
    var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
    SKS.$init.overload('[B', 'java.lang.String').implementation = function (k, a) {
        console.log('[KEY] ' + a + ' = ' + bytesToHex(k));
        return this.$init(k, a);
    };
    var IVP = Java.use('javax.crypto.spec.IvParameterSpec');
    IVP.$init.overload('[B').implementation = function (iv) {
        console.log('[IV ] ' + bytesToHex(iv));
        return this.$init(iv);
    };
    var GCMP = Java.use('javax.crypto.spec.GCMParameterSpec');
    GCMP.$init.overload('int', '[B').implementation = function (t, iv) {
        console.log('[GCM iv] ' + bytesToHex(iv));
        return this.$init(t, iv);
    };
});
```

```javascript
// iOS
ObjC.choose(ObjC.classes.NSData, {
    onMatch: function (inst) {
        var len = inst.length();
        if (len === 16 || len === 24 || len === 32) {
            // 可能是密钥，记录
        }
    },
    onComplete: function () {}
});
```

## 第 5 步：还原数据结构

### Protobuf

```bash
# 从二进制反推字段
protoc --decode_raw < payload.bin

# 输出形如：
# 1 { 1: "hello" 2: 123 }
# 对应 .proto:
# message Foo { string field1 = 1; int64 field2 = 2; }
```

```python
# 或用 python 库
from google.protobuf.internal.decoder import _DecodeVarint
```

### 自定义二进制

```python
import struct

d = open('payload.bin', 'rb').read()
print('total', len(d))
print('hex', d[:64].hex())

# 试探 1：长度前缀（小端 u32）
off = 0
while off < len(d) - 4:
    ln = struct.unpack_from('<I', d, off)[0]
    if 0 < ln < len(d):
        print(f'@{off}: len={ln}')
        off += 4 + ln
    else:
        break

# 试探 2：TLV（Type-Length-Value）
off = 0
while off < len(d) - 5:
    t, ln = struct.unpack_from('<BH', d, off)
    print(f'@{off}: type={t} len={ln}')
    off += 3 + ln

# 试探 3：分隔符
for sep in (b'\x00', b'\n', b'|', b','):
    parts = d.split(sep)
    if 3 < len(parts) < 1000:
        print(f'sep={sep}: {len(parts)} parts')
```

### JSON / 加密 JSON

```
外层 base64 -> 解出 JSON -> 找加密字段 -> 回到第 3 步
```

```python
import base64, json
raw = base64.b64decode(b64str)
print(raw[:200])
try:
    print(json.loads(raw))
except:
    print('not json, try decrypt')
```

## 第 6 步：游戏协议专项

### 同步模式识别

| 模式 | 特征 | 还原要点 |
| --- | --- | --- |
| 帧同步 Lockstep | 每帧固定 opcode + 玩家输入 | opcode 表、帧号、输入序列、校验 |
| 状态同步 | 服务器广播全量/增量 | 状态字段、增量编码、序列化格式 |
| 客户端预测 | 本地先演算再校验 | 预测公式、回滚条件、容差 |

### opcode 表还原

```javascript
// 在收包处记录 opcode 频率
var recv = Module.findExportByName(null, 'recv');
Interceptor.attach(recv, {
    onEnter: function (args) { this.buf = args[1]; this.len = args[2].toInt32(); },
    onLeave: function (ret) {
        var n = ret.toInt32();
        if (n > 0) {
            var op = Memory.readU8(this.buf);
            console.log('opcode=0x' + op.toString(16) + ' len=' + n);
        }
    }
});
```

```
统计后按频率排序：
  高频 opcode -> 心跳/移动同步
  低频但固定周期 -> 状态更新
  特定时机出现 -> 技能/交易/登录
```

### 静态找 dispatcher

```
IDA 里找：
1. 大 switch（>50 case）
2. 或 jump table（jmp [rax*8+offset]）
3. case 值就是 opcode
4. 每个 case 的目标函数就是 handler
```

## 验证（必须做）

**协议还原的验收标准：写独立脚本，用还原的算法和密钥，把真实密文解成明文。**

```python
# verify.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64, json

KEY = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
IV  = bytes.fromhex('000102030405060708090a0b0c0d0e0f')

def decrypt(b64):
    raw = base64.b64decode(b64)
    c = AES.new(KEY, AES.MODE_CBC, IV)
    return unpad(c.decrypt(raw), 16)

# 用抓到的真实包测
samples = [
    "抓到的密文1",
    "抓到的密文2",
]

for s in samples:
    try:
        pt = decrypt(s)
        print('[PASS]', json.loads(pt))
    except Exception as e:
        print('[FAIL]', e)
```

**验收：**

```
✅ 3 个以上真实包能解出可读明文
✅ 字段名与抓包时的业务逻辑吻合
✅ 解密后重新加密能还原原密文（验证算法完整）
✅ 边界情况（空串/超长/特殊字符）也能处理
```

## 输出规范

```
[协议] 样本=SHA256 端点=https://api.example.com/v1/login 方法=POST
抓包: mitmproxy + Frida SSL bypass
密文样本: 8f3a2b... (base64, 64 bytes -> 48 bytes raw)
算法: AES-128-CBC + PKCS7 + base64
密钥: 2b7e151628aed2a6abf7158809cf4f3c
  来源: hook SecretKeySpec，来自 Constants.KEY 硬编码
IV: 固定 000102030405060708090a0b0c0d0e0f
  来源: 硬编码在 CryptoHelper.java:18
明文结构: {"user":str,"pass":str,"ts":long,"sign":str}
签名: sign = MD5(user + pass + ts + SALT)[:16]
验证: verify.py 解开 5 个真实包，字段全部吻合 PASS
证据: /path/capture.log + /path/verify.py + /path/hook.js
```

## 边界

- 只做协议。**不脱壳、不做完整破解**。
- 需要脱壳才能看算法时，交回指挥派 `unpack`。
- **算法必须能被独立脚本复现才算还原**，不要只写"看到了 AES"。
- 抓到的用户凭据**只记录结构，不原文照抄**。
