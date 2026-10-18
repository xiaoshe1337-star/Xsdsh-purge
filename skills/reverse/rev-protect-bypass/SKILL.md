---
name: rev-protect-bypass
description: 保护对抗与检测绕过。反调试（ptrace/IsDebuggerPresent/PEB）、反虚拟机（CPUID/注册表/设备指纹）、反 Frida 检测、完整性校验（CRC/签名）、Root/越狱检测、平台级保护（FairPlay/Play Integrity/驱动签名）的分析与绕过。适用于样本附加不上、一跑就退、行为异常的场合。
enabled: true
---

# 保护对抗与检测绕过

## 诊断：先确认被什么拦住

| 症状 | 可能检测 |
| --- | --- |
| Frida 一附加进程就退 | 反调试 / 反 Frida |
| 在虚拟机里闪退 | 反虚拟机 |
| 附加后行为不同（不弹窗/不联网） | 反调试（静默降级） |
| patch 后校验失败 | 完整性校验 |
| 越狱/Root 机上拒绝运行 | Root/越狱检测 |
| 调试器断点不命中 | 反调试（改代码段 / 硬件断点检测） |

## 反调试

### Android

| 手法 | 位置 | 绕过 |
| --- | --- | --- |
| `ptrace(PTRACE_TRACEME)` | `.init_array` / `JNI_OnLoad` | hook ptrace 返 0 |
| `/proc/self/status` 的 `TracerPid` | 读文件 | hook fopen/open 伪造 |
| `Debug.isDebuggerConnected()` | Java | hook 返 false |
| 扫 23946 端口（IDA） | Native | hook connect |
| 扫进程名 `frida` / `gdb` | 读 `/proc` | 改 frida-server 名 + hook opendir |
| `Process.killProcess` 自毁 | Java/Native | hook kill |
| 时间差（clock_gettime） | Native | hook 返回固定值 |

```javascript
// antidebug.js —— 一键过大部分
Java.perform(function () {
    // Java 层
    try {
        Java.use('android.os.Debug').isDebuggerConnected.implementation = function () { return false; };
    } catch (e) {}
    try {
        Java.use('android.os.Debug').waitForDebugger.implementation = function () {};
    } catch (e) {}

    // ptrace
    var ptrace = Module.findExportByName(null, 'ptrace');
    if (ptrace) {
        Interceptor.replace(ptrace, new NativeCallback(function () {
            console.log('[ptrace] blocked');
            return 0;
        }, 'long', ['int', 'int', 'pointer', 'pointer']));
    }

    // kill（阻止自毁）
    var kill = Module.findExportByName(null, 'kill');
    if (kill) {
        Interceptor.attach(kill, {
            onEnter: function (args) {
                console.log('[kill] pid=' + args[0].toInt32() + ' sig=' + args[1].toInt32());
                // 不实际调用（阻断）
                args[0] = ptr(-1);
            }
        });
    }

    // exit（阻止退出）
    var exit = Module.findExportByName(null, 'exit');
    if (exit) {
        Interceptor.replace(exit, new NativeCallback(function (code) {
            console.log('[exit] blocked, code=' + code);
        }, 'void', ['int']));
    }

    // fopen 伪造 TracerPid
    var fopen = Module.findExportByName(null, 'fopen');
    if (fopen) {
        Interceptor.attach(fopen, {
            onEnter: function (args) {
                this.path = args[0].readCString();
            },
            onLeave: function (ret) {
                if (this.path && this.path.indexOf('status') !== -1) {
                    console.log('[fopen] ' + this.path + ' (需伪造 TracerPid:0)');
                }
            }
        });
    }
});
```

```bash
# 更强的方案：改名 + 改端口
adb shell "su -c 'cp /data/local/tmp/frida-server /data/local/tmp/f'"
adb shell "su -c '/data/local/tmp/f -l 127.0.0.1:12345 &'"
frida -H 127.0.0.1:12345 -f PACKAGE
```

### 反 Frida 检测专项

```javascript
// 常见检测点与绕过
Java.perform(function () {
    // 1. 扫 /proc/self/maps 找 frida
    var File = Java.use('java.io.File');
    // hook readLine / 或 hook BufferedReader

    // 2. 扫线程名（gum-js-loop / pool-frida）
    var Thread = Java.use('java.lang.Thread');
    Thread.getAllStackTraces.implementation = function () {
        var r = this.getAllStackTraces();
        return r;
    };

    // 3. 检测 27042 端口
    var Socket = Java.use('java.net.Socket');
    Socket.connect.implementation = function (addr) {
        var h = addr.toString();
        if (h.indexOf('27042') !== -1) {
            console.log('[Socket] block frida port');
            throw Java.use('java.io.IOException').$new('refused');
        }
        return this.connect(addr);
    };
});
```

### iOS

| 手法 | 绕过 |
| --- | --- |
| `ptrace(PT_DENY_ATTACH)` | hook ptrace 返 0 |
| `sysctl` 查 `P_TRACED` | hook sysctl 清 flag |
| 直接 `syscall(26)` | hook syscall |
| 检测 `/Applications/Cydia.app` | hook `fileExistsAtPath:` |
| 检测 `FridaGadget` | 用非默认名 gadget |

```javascript
// ios_antidebug.js
var ptrace = Module.findExportByName(null, 'ptrace');
if (ptrace) {
    Interceptor.replace(ptrace, new NativeCallback(function () {
        console.log('[ptrace] blocked');
        return 0;
    }, 'int', ['int', 'int', 'pointer', 'pointer']));
}

var sysctl = Module.findExportByName(null, 'sysctl');
if (sysctl) {
    Interceptor.attach(sysctl, {
        onLeave: function (ret) {
            // 清 P_TRACED (0x800)
        }
    });
}

// 文件存在性伪造
var NSFileManager = ObjC.classes.NSFileManager;
Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
    onEnter: function (args) {
        var p = new ObjC.Object(args[2]).toString();
        if (p.indexOf('Cydia') !== -1 || p.indexOf('Sileo') !== -1 ||
            p.indexOf('substrate') !== -1) {
            console.log('[NSFileManager] hide ' + p);
        }
    }
});
```

### Windows

| 手法 | 绕过 |
| --- | --- |
| `IsDebuggerPresent` | 改返回值 / 清 `PEB.BeingDebugged` |
| `CheckRemoteDebuggerPresent` | 同上 |
| `NtQueryInformationProcess(ProcessDebugPort)` | hook 返 0 |
| `PEB.NtGlobalFlag`（0x70） | 清标志 |
| `HeapFlags`（0x2） | 清 |
| 硬件断点检测（Dr0-Dr7） | 清调试寄存器 |
| `NtSetInformationThread(HideFromDebugger)` | hook |
| `rdtsc` 时间差 | hook 时间函数 |
| 代码段 CRC 自校验 | 见下节 |

```
x64dbg + ScyllaHide：
1. 插件 -> ScyllaHide -> Options -> 全勾
   - PEB.BeingDebugged
   - PEB.NtGlobalFlag
   - PEB.HeapFlags
   - NtQueryInformationProcess
   - NtSetInformationThread
   - NtQuerySystemInformation
   - NtQueryObject
   - 硬件断点清空
2. 应用后重新附加
```

## 反虚拟机

### 检测手段与伪造

| 类别 | 检测 | 绕过 |
| --- | --- | --- |
| **CPUID** | hypervisor bit（ECX bit31）、`0x40000000` 厂商串 | hook cpuid 或改 VM 配置 |
| **注册表** | `HKLM\SOFTWARE\VMware, Inc.`、`HKLM\HARDWARE\DEVICEMAP\Scsi` | 删键 / 改 VM 配置 |
| **设备文件** | `\\.\VBoxGuest`、`\\.\pipe\VBoxTrayIPCFlags` | 删驱动 / 换 VM |
| **MAC 前缀** | `00:05:69` `00:0C:29` `00:1C:14`(VMware) `08:00:27`(VBox) | 改 MAC |
| **进程名** | `vmtoolsd.exe` `VBoxService.exe` | 改名 / 结束 |
| **硬件型号** | 磁盘 `VMware Virtual` | 改 VM 配置 |
| **传感器** | 无电池、无温度 | 见下（Android） |
| **时间** | `rdtsc` 差异常、启动时间短 | 调 VM 时钟 |
| **用户行为** | 无鼠标移动、无焦点切换 | 脚本模拟 |

### Android 设备指纹伪造

```javascript
// fake_device.js
Java.perform(function () {
    var Build = Java.use('android.os.Build');
    Build.MODEL.value = 'Pixel 7 Pro';
    Build.MANUFACTURER.value = 'Google';
    Build.BRAND.value = 'google';
    Build.DEVICE.value = 'cheetah';
    Build.PRODUCT.value = 'cheetah';
    Build.FINGERPRINT.value = 'google/cheetah/cheetah:13/TQ3A.230805.001/10316531:user/release-keys';
    Build.HARDWARE.value = 'cheetah';
    Build.TAGS.value = 'release-keys';

    // 传感器数量（虚拟机常为 0）
    var SensorManager = Java.use('android.hardware.SensorManager');
    var origGetSensorList = SensorManager.getSensorList;
    SensorManager.getSensorList.implementation = function (type) {
        var real = origGetSensorList.call(this, type);
        if (real.size() === 0) {
            console.log('[Sensor] fake non-empty list');
            // 返回一个假列表（需要构造 Sensor 对象，实际很难）
            // 更简单的方案：hook 检测函数返回值
        }
        return real;
    };

    // 电池（模拟器常为固定值）
    var BatteryManager = Java.use('android.os.BatteryManager');
    // hook 相关 getter
});
```

### Windows 虚拟机伪装

```
VMware:
1. 关 vmx 里的 hypervisor 暴露：
   hypervisor.cpuid.v0 = "FALSE"
   monitor_control.restrict_backdoor = "TRUE"
2. 改 MAC：ethernet0.address = "00:11:22:33:44:55"
   ethernet0.addressType = "static"
3. 改硬件型号：
   SCSI 型号改成真实硬盘
   SMBIOS 改厂商

VirtualBox:
VBoxManage modifyvm VMNAME --paravirtprovider none
VBoxManage setextradata VMNAME "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor" "Dell Inc."
```

## 完整性校验

### 类型识别

```python
# 静态找 CRC/哈希常量
# 特征：一个函数遍历某段内存，算出一个值，与硬编码值比较
```

| 类型 | 特征 | 定位 |
| --- | --- | --- |
| 代码段 CRC | 遍历 `.text` 范围 | 看有多少循环指向 `.text` |
| 全文件哈希 | 读自身路径再 hash | hook CreateFile + ReadFile |
| 签名校验 | `WinVerifyTrust` / `SecStaticCodeCheckValidity` | hook 该 API |
| 服务端校验 | 上报 hash | 抓包看是否有 hash 字段 |

### 中和方式（按侵入性排序）

```
1. 最轻：hook 校验函数返回恒定"通过"
2. 中等：patch 校验分支（jz -> jmp / nop）
3. 最重：重算校验值填回（每次改动都要重算）
```

```javascript
// hook 校验函数
var check = Module.findExportByName('libtarget.so', 'checkIntegrity');
if (check) {
    Interceptor.replace(check, new NativeCallback(function () {
        return 1;  // 恒定通过
    }, 'int', []));
}
```

## Root / 越狱检测

### Android

```javascript
// root_bypass.js
Java.perform(function () {
    var File = Java.use('java.io.File');
    var origExists = File.exists;
    File.exists.implementation = function () {
        var p = this.getAbsolutePath();
        var bad = ['su', 'magisk', 'superuser', 'busybox', 'xposed',
                   'frida', 'substrate', 'supersu', 'daemonsu'];
        for (var i = 0; i < bad.length; i++) {
            if (p.indexOf(bad[i]) !== -1) {
                console.log('[File.exists] hide ' + p);
                return false;
            }
        }
        return origExists.call(this);
    };

    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
        if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1) {
            throw Java.use('java.io.IOException').$new('no such file');
        }
        return this.exec(cmd);
    };

    // Build.TAGS（test-keys 表示非官方）
    try {
        var Build = Java.use('android.os.Build');
        Build.TAGS.value = 'release-keys';
    } catch (e) {}

    // 包管理器检测 Magisk
    var PM = Java.use('android.app.ApplicationPackageManager');
    PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (n, f) {
        if (n.indexOf('magisk') !== -1 || n.indexOf('supersu') !== -1) {
            throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(n);
        }
        return this.getPackageInfo(n, f);
    };
});
```

**更强的方案：Magisk + Zygisk + DenyList + Shamiko**

```
1. Magisk 设置里开启 Zygisk
2. 配置 DenyList，把目标 App 加进去（"屏蔽"模式）
3. 装 Shamiko 模块（更强的隐藏，需关闭 Enforce DenyList）
4. 装 Play Integrity Fix（过完整性检测）
```

### iOS

```javascript
// ios_jb_bypass.js
var NSFileManager = ObjC.classes.NSFileManager;
Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
    onEnter: function (args) {
        var p = new ObjC.Object(args[2]).toString();
        this.hide = /Cydia|Sileo|substrate|jailbreak|apt|ssh/i.test(p);
    },
    onLeave: function (ret) {
        if (this.hide) {
            ret.replace(0);
            console.log('[hide] fileExistsAtPath -> 0');
        }
    }
});

// fork 检测
var fork = Module.findExportByName(null, 'fork');
if (fork) {
    Interceptor.attach(fork, {
        onLeave: function (ret) {
            // 越狱机 fork 成功，非越狱失败（返回 -1）
            if (ret.toInt32() !== -1) {
                ret.replace(-1);
            }
        }
    });
}
```

## 平台级保护

### iOS FairPlay

```
cryptid = 1 -> 必须先脱壳（rev-unpack-ios）
没有任何 hook 能绕过 FairPlay —— 那是内核层加密
```

### Android Play Integrity

```
检测链：
1. Play Integrity API -> Google 服务器验证
2. 返回 MEETS_DEVICE_INTEGRITY / MEETS_STRONG_INTEGRITY
3. App 根据结果决定行为

绕过路径（按可行性）：
1. Play Integrity Fix 模块（伪造 attestation，对新版 Android 效果下降）
2. hook 校验回调直接返回通过
3. hook 网络层伪造服务器响应
```

### Windows 驱动签名（DSE）

```
分析用（不改目标）：
1. bcdedit /set testsigning on     (测试模式，重启)
2. 或 bcdedit /set nointegritychecks on
3. 或用 WinDbg 内核调试，在加载前断点

注意：这些是改测试机配置，不是改目标。
```

## 验证绕过成功

```bash
# 必须能证明"绕过了"，不是"看起来能跑"
```

```
✅ 绕过前：Frida 附加 -> 3 秒内进程退出（记录 PID 与退出时间）
✅ 绕过后：Frida 附加 -> 进程存活，hook 成功命中（有日志）
✅ 绕过前：虚拟机里弹窗"检测到虚拟机"
✅ 绕过后：无弹窗，功能正常
✅ 绕过前：patch 后卡死
✅ 绕过后：patch 后正常执行到目标代码
```

**证据：前后两次的日志 + 时间戳。没有对比就不算验证。**

## 输出规范

```
[保护] 样本=SHA256 平台=android 保护类型=反调试+反root
检测点:
  - ptrace(PTRACE_TRACEME) @ libnative.so+0x1234
  - /proc/self/status TracerPid 读取 @ libnative.so+0x1560
  - Debug.isDebuggerConnected @ com.x.Utils.check (Utils.java:88)
  - File.exists 扫 su/magisk @ com.x.Utils.isRoot (Utils.java:120)
绕过: bypass.js (ptrace 替换 + File.exists 伪造 + File 隐藏)
验证:
  绕过前: frida -f 附加后 2.3s 进程退出 (PID 12345)
  绕过后: frida -f 附加成功, hook 命中 47 次, 进程存活 300s+
残余风险: 有一处时间差检测未处理，长时间运行可能触发
证据: /path/bypass.js + /path/before.log + /path/after.log
```

## 边界

- 只做保护对抗。**不做业务逻辑分析、不脱壳**。
- **绕过不了就如实报告**：说明试了什么、卡在哪、需要什么条件。
- **不要谎报"已绕过"**。有前后对比证据才算。
- 所有验证在**隔离环境**做，不要在主工作机跑可疑样本。
