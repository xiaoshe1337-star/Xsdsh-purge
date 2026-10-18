---
name: rev-dynamic-frida
description: 跨平台动态调试与 Hook。Frida 环境搭建（Android/iOS）、objection 一键探索、通用 Hook 模板、抓加解密前后明文、SSL Pinning 绕过、Root/越狱检测绕过、内存 dump、调用栈追踪。适用于需要看运行时行为、抓参数与返回值、绕过检测的场景。
enabled: true
---

# 动态调试与 Frida Hook

## Android 环境

### 准备

```bash
# 1. 确认设备
adb devices
adb shell getprop ro.product.cpu.abi    # arm64-v8a
adb shell getprop ro.build.version.release

# 2. root 检查
adb shell su -c 'id'     # uid=0(root) 才行

# 3. frida 版本必须一致
frida --version                      # 本地
# 下载对应版本 frida-server
# https://github.com/frida/frida/releases

# 4. 推上去并起
adb push frida-server-16.x.x-android-arm64 /data/local/tmp/fs
adb shell "su -c 'chmod 755 /data/local/tmp/fs'"
adb shell "su -c '/data/local/tmp/fs &'"

# 5. 验证
frida-ps -U
```

### 对抗进程名检测

```bash
# frida-server 改名
adb shell "su -c 'mv /data/local/tmp/fs /data/local/tmp/frida-helper'"
adb shell "su -c '/data/local/tmp/frida-helper &'"
frida -U -n frida-helper
```

## iOS 环境

```bash
# 越狱设备
ssh root@DEVICE_IP          # 默认密码 alpine

# 装 frida
# Cydia/Sileo 搜 Frida
# 或手动：
dpkg -i frida_16.x.x_iphoneos-arm.deb

# 验证
frida-ps -U
frida-ps -Ua     # 只看应用
```

## objection 快速探索

```bash
objection -g PACKAGE_NAME explore
```

**进去后的高频命令：**

```
# Android
android hooking list activities
android hooking list services
android hooking list receivers
android hooking search classes KEYWORD
android hooking watch class com.example.Target
android hooking watch method com.example.Target.method
android root detection disable
android sslpinning disable
android keystore list

# iOS
ios info binary
ios sslpinning disable
ios jailbreak simulate         # 模拟非越狱环境
ios hooking list classes
ios hooking watch class TargetClass
```

## 通用 Hook 模板

### 1. 抓方法入参与返回值（Java）

```javascript
// hook_java.js
Java.perform(function () {
    var Target = Java.use('com.example.Target');
    
    // 有多个重载时必须用 overload 明确指定
    Target.targetMethod.overload('java.lang.String', 'int').implementation = function (a, b) {
        console.log('[IN ] a=' + a + ' b=' + b);
        var ret = this.targetMethod(a, b);
        console.log('[OUT] ' + ret);
        return ret;
    };
});
```

```bash
frida -U -f PACKAGE_NAME -l hook_java.js --no-pause
```

### 2. 抓调用栈（定位谁调的）

```javascript
Java.perform(function () {
    var Target = Java.use('com.example.Target');
    Target.targetMethod.implementation = function () {
        console.log('=== called ===');
        console.log(Java.use('android.util.Log').getStackTraceString(
            Java.use('java.lang.Throwable').$new()));
        return this.targetMethod.apply(this, arguments);
    };
});
```

### 3. 抓加解密（最重要）

```javascript
// hook_crypto.js
function bytesToHex(b) {
    var arr = new Uint8Array(b);
    var s = '';
    for (var i = 0; i < arr.length; i++) {
        s += ('0' + arr[i].toString(16)).slice(-2);
    }
    return s;
}

Java.perform(function () {
    // Cipher
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.doFinal.overload('[B').implementation = function (input) {
            console.log('[Cipher.doFinal IN ] ' + bytesToHex(input));
            var out = this.doFinal(input);
            console.log('[Cipher.doFinal OUT] ' + bytesToHex(out));
            return out;
        };
        Cipher.getInstance.overload('java.lang.String').implementation = function (alg) {
            console.log('[Cipher alg] ' + alg);
            return this.getInstance(alg);
        };
    } catch (e) { console.log('Cipher hook fail: ' + e); }

    // MessageDigest
    try {
        var MD = Java.use('java.security.MessageDigest');
        MD.digest.overload('[B').implementation = function (input) {
            console.log('[Digest IN ] ' + bytesToHex(input));
            var out = this.digest(input);
            console.log('[Digest OUT] ' + bytesToHex(out));
            return out;
        };
    } catch (e) {}

    // 密钥与 IV
    try {
        var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
        SKS.$init.overload('[B', 'java.lang.String').implementation = function (k, a) {
            console.log('[KEY] alg=' + a + ' key=' + bytesToHex(k));
            return this.$init(k, a);
        };
    } catch (e) {}
    try {
        var IVP = Java.use('javax.crypto.spec.IvParameterSpec');
        IVP.$init.overload('[B').implementation = function (iv) {
            console.log('[IV] ' + bytesToHex(iv));
            return this.$init(iv);
        };
    } catch (e) {}
});
```

### 4. Native 层 Hook

```javascript
// hook_native.js
var target = 'libnative.so';
var fn = 'nativeEncrypt';

var addr = Module.findExportByName(target, fn);
console.log('[' + target + '!' + fn + '] @ ' + addr);

if (addr) {
    Interceptor.attach(addr, {
        onEnter: function (args) {
            // 假设签名: char* f(char* input, int len)
            var len = args[1].toInt32();
            this.inPtr = args[0];
            this.len = len;
            console.log('[IN ] ' + Memory.readUtf8String(args[0]));
            console.log('[IN hex] ' + hexdump(args[0], { length: Math.min(len, 64) }));
        },
        onLeave: function (ret) {
            console.log('[OUT] ' + ret);
            if (ret && !ret.isNull()) {
                try {
                    console.log('[OUT str] ' + Memory.readUtf8String(ret));
                } catch (e) {}
            }
        }
    });
}
```

**找不到导出符号时（常见于静态链接/去符号）：**

```javascript
// 按偏移 hook
var base = Module.findBaseAddress('libnative.so');
var offset = 0x1234;
Interceptor.attach(base.add(offset), { ... });

// 或扫描特征字节
var m = Memory.scanSync(base, 0x100000, 'F0 4F 2D E9 ?? ?? ?? ??');
```

### 5. 追踪所有方法调用（重型，慎用）

```javascript
// trace_all.js
Java.perform(function () {
    var cls = 'com.example.Target';
    var methods = Java.use(cls).class.getDeclaredMethods();
    methods.forEach(function (m) {
        var name = m.getName();
        try {
            var overloads = Java.use(cls)[name].overloads;
            overloads.forEach(function (o) {
                o.implementation = function () {
                    console.log('[' + cls + '.' + name + ']');
                    return o.apply(this, arguments);
                };
            });
        } catch (e) {}
    });
});
```

### 6. 内存搜索明文

```javascript
// search_mem.js
Java.perform(function () {
    var ranges = Process.enumerateRanges('rw-');
    ranges.forEach(function (r) {
        try {
            var hits = Memory.scanSync(r.base, r.size, hexpattern);
            hits.forEach(function (h) {
                console.log('hit @ ' + h.address + ' in ' + (r.file ? r.file.path : 'anon'));
                console.log(hexdump(h.address, { length: 64 }));
            });
        } catch (e) {}
    });
});

// 搜 ASCII 字符串
function scanString(s) {
    var pat = '';
    for (var i = 0; i < s.length; i++) {
        pat += ('0' + s.charCodeAt(i).toString(16)).slice(-2) + ' ';
    }
    return pat.trim();
}
```

## SSL Pinning 绕过

```javascript
// ssl_bypass.js
Java.perform(function () {
    // 通用：TrustManager
    try {
        var TM = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'com.custom.TM',
            implements: [TM],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var ctx = SSLContext.getInstance('TLS');
        ctx.init(null, [TrustManager.$new()], null);
        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        ).implementation = function (km, tm, sr) {
            this.init(km, [TrustManager.$new()], sr);
        };
    } catch (e) {}

    // OkHttp CertificatePinner
    try {
        var CP = Java.use('okhttp3.CertificatePinner');
        CP.check.overload('java.lang.String', 'java.util.List').implementation = function () {
            return;
        };
    } catch (e) {}

    // TrustManagerImpl（Android 7+ 系统级）
    try {
        var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TMI.verifyChain.implementation = function (untrusted, chain, authType, host, clientAuth, ocspData, tlsSctData) {
            return chain;
        };
    } catch (e) {}
});
```

## Root 检测绕过

```javascript
// root_bypass.js
Java.perform(function () {
    // 常见检测点
    var checks = [
        'android.os.Build$TAGS',       // test-keys
        'java.io.File',                // exists()
        'android.app.ActivityManager', // isRunningAppProcess
    ];

    // File.exists 伪造
    var File = Java.use('java.io.File');
    var origExists = File.exists;
    File.exists.implementation = function () {
        var p = this.getAbsolutePath();
        if (p.indexOf('su') !== -1 || p.indexOf('magisk') !== -1 ||
            p.indexOf('superuser') !== -1 || p.indexOf('busybox') !== -1) {
            console.log('[File.exists] hide ' + p);
            return false;
        }
        return origExists.call(this);
    };

    // Runtime.exec 伪造
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
        if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1) {
            console.log('[Runtime.exec] hide ' + cmd);
            throw Java.use('java.io.IOException').$new('broken pipe');
        }
        return this.exec(cmd);
    };
});
```

## 反调试绕过（Native）

```javascript
// antidebug.js
// ptrace
var ptrace = Module.findExportByName(null, 'ptrace');
if (ptrace) {
    Interceptor.replace(ptrace, new NativeCallback(function () {
        console.log('[ptrace] blocked');
        return 0;
    }, 'long', ['int', 'int', 'pointer', 'pointer']));
}

// fork 检测
var fork = Module.findExportByName(null, 'fork');
if (fork) {
    Interceptor.attach(fork, {
        onLeave: function (ret) {
            // 有些反调试会用 fork 让父进程退出
        }
    });
}

// 时间差检测
var clock_gettime = Module.findExportByName(null, 'clock_gettime');
if (clock_gettime) {
    Interceptor.attach(clock_gettime, {
        onEnter: function (args) {
            args[1] = ptr(0);  // 危险：可能破坏正常逻辑
        }
    });
}
```

## 输出规范

```
[动态] 样本=SHA256 设备=Pixel7/Android14 时间=2026-10-18T03:20:00Z
框架: Frida 16.2.1 + frida-server (改名 frida-helper)
Hook: /path/hook_crypto.js
目标: com.example.CryptoHelper.encrypt
抓到:
  IN : {"user":"admin","pass":"P@ssw0rd"}
  KEY: 2b7e151628aed2a6abf7158809cf4f3c
  IV : 000102030405060708090a0b0c0d0e0f
  OUT: 8f3a... (base64)
调用栈: CryptoHelper.encrypt(CryptoHelper.java:42) <- ApiClient.login(ApiClient.java:88)
结论: 登录参数明文构造，AES-128-CBC 加密后 base64 上送
证据: /path/hook_crypto.js + /path/session.log
```

## 边界与纪律

- **先过反调试再下断点**，否则看到的是假象。
- Hook 失败先看：类名/方法名/spawn 还是 attach（`-f` 比 `-n` 更早）。
- **内存 dump 产物动辄数 GB**，落盘前确认磁盘空间。
- 抓到的明文含用户凭据时，**只记录结构与算法，不原文照抄到报告**。
- 需要脱壳才能 hook 到真实方法时，交回指挥派 `unpack`。
