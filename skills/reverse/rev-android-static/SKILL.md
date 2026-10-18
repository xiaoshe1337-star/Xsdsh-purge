---
name: rev-android-static
description: Android APK/AAB/DEX 静态分析。apktool 拆包、jadx 反编译、dex2jar、smali 阅读、AndroidManifest 分析、JNI 符号表、资源与 assets 提取。适用于未加壳 APK 的结构分析、找入口、找关键逻辑、找硬编码密钥。
enabled: true
---

# Android 静态分析

## 拆包与反编译

```bash
# 1. 包结构总览
unzip -l SAMPLE.apk | head -40

# 2. apktool 拆（保留资源与 smali）
apktool d -f -o OUT_APK SAMPLE.apk

# 3. jadx 反编译（可读性最好，优先看这个）
jadx -d OUT_JADX --show-bad-code SAMPLE.apk

# 4. dex2jar + jd-gui（jadx 失败时备用）
d2j-dex2jar.sh SAMPLE.apk -o out.jar

# 5. 纯 smali
baksmali d classes.dex -o OUT_SMALI
```

## 先看这四个文件

### 1. AndroidManifest.xml

```bash
cat OUT_APK/AndroidManifest.xml
```

**重点看：**

```xml
<!-- 入口 Activity -->
<activity android:name=".MainActivity">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>

<!-- 自定义 Application（加固常改这里） -->
<application android:name="com.stub.StubApp" ...>

<!-- 权限（判断 App 干什么） -->
<uses-permission android:name="android.permission.READ_SMS"/>

<!-- ContentProvider（攻击面） -->
<provider android:name=".DataProvider" android:exported="true"/>

<!-- 网络安全配置（判断是否允许明文） -->
<application android:networkSecurityConfig="@xml/network_security_config">

<!-- debuggable（是否可调试） -->
<application android:debuggable="true">
```

### 2. build.gradle / 版本信息

```bash
cat OUT_APK/apktool.yml
```

### 3. assets/ 目录

```bash
ls -la OUT_APK/assets/
find OUT_APK/assets -type f | head -30
```

**看到这些要提高警惕：**
- `.dat` / `.bak` / 无扩展名大文件 → 加固载荷
- `.js` / `.html` → WebView 混合开发（逻辑可能在 JS 里）
- `.dex` → 动态加载
- `.so` 不在 lib/ 而在 assets/ → 运行时释放

### 4. lib/ 目录

```bash
find OUT_APK/lib -name "*.so" | sort
```

## 找关键逻辑

### 搜敏感字符串

```bash
# 硬编码密钥/URL/API
grep -rn --include="*.smali" -E 'https?://|api[_-]?key|secret|token|password' OUT_APK/ | head -40

# 在 jadx 输出里搜（更可读）
grep -rn --include="*.java" -iE 'aes|rsa|md5|sha|encrypt|decrypt|sign' OUT_JADX/ | head -40
```

### 找加密调用

```bash
grep -rn "Ljavax/crypto/Cipher;" OUT_APK/ | head -20
grep -rn "Ljavax/crypto/spec/SecretKeySpec;" OUT_APK/ | head -20
grep -rn "Ljava/security/MessageDigest;" OUT_APK/ | head -20
```

### 找网络请求

```bash
grep -rn "Lokhttp3/" OUT_APK/ | head -20
grep -rn "Ljava/net/HttpURLConnection;" OUT_APK/ | head -20
grep -rn "WebView" OUT_APK/ | head -20
```

### 找 JNI 调用

```bash
# smali 里的 native 方法声明
grep -rn "native " OUT_APK/smali*/ | head -30

# 对应的 so 导出符号
for so in OUT_APK/lib/arm64-v8a/*.so; do
  echo "== $so"
  readelf -Ws "$so" 2>/dev/null | grep -E 'Java_|JNI_OnLoad'
done
```

`Java_com_example_MainActivity_nativeEncrypt` 这种符号名直接告诉你：**哪个类的哪个方法调用了它**。

## jadx 使用技巧

```bash
# 只反编译指定包（大 App 提速）
jadx -d OUT --include-pkg com.target SAMPLE.apk

# 显示反混淆后的名字（如果 App 用了 proguard 且保留 mapping）
jadx -d OUT --deobf SAMPLE.apk

# 导出为 gradle 工程（能直接看资源与代码）
jadx -d OUT --export-gradle SAMPLE.apk

# 搜索（jadx-gui 里更快）
# 命令行没有搜索，用 grep 代替
```

**jadx-gui 快捷键：**
- `Ctrl+Shift+F` 全局搜索
- `Ctrl+点击` 跳转定义
- `F` 找用法（Find usages）
- `Ctrl+B` 反编译为 Java

## smali 阅读要点

| 指令 | 含义 |
| --- | --- |
| `invoke-virtual` | 调用实例方法 |
| `invoke-static` | 调用静态方法 |
| `invoke-direct` | 调构造/私有方法 |
| `const-string v0, "xxx"` | 字符串常量 |
| `iget/iput` | 读/写实例字段 |
| `sget/sput` | 读/写静态字段 |
| `.method ... .end method` | 方法边界 |
| `if-eq / if-ne / if-eqz` | 条件跳转 |

**改 smali 的常见手法：**

```smali
# 原始：if (check()) { fail(); }
invoke-virtual {v0}, Lcom/x/Util;->check()Z
move-result v1
if-eqz v1, :cond_0
# 改法：把 if-eqz 改成 if-nez（条件取反），或直接 nop 掉判断
```

## 找入口点

```
1. Manifest 里的 LAUNCHER Activity  -> onCreate
2. Application.onCreate            -> 初始化、加固入口
3. 网络请求的发起处                 -> 业务逻辑
4. native 方法声明处                -> 核心算法
5. 加解密调用点                     -> 算法实现
```

## 输出规范

```
[静态-Android] 样本=SHA256 包名=com.example 版本=1.2.3
入口: com.example.MainActivity.onCreate (OUT_JADX/.../MainActivity.java:42)
保护: 无 / 或 libjiagu.so -> 360
关键发现:
  - API endpoint: https://api.example.com/v1/login (Constants.java:15)
  - 加密: AES/CBC/PKCS5Padding，密钥在 Constants.KEY (Constants.java:22)
  - JNI: nativeSign(String) -> libnative.so: Java_com_example_Sign_nativeSign
下一步: 建议 dynamic 角色 hook nativeSign 抓入参与返回值
```

## 常见坑

| 症状 | 原因 | 处理 |
| --- | --- | --- |
| classes.dex 很小 | 加固 | 转 rev-unpack-android |
| jadx 报错一堆 | 代码被混淆/损坏 | 用 smali 看，或 dex2jar |
| 反编译全是空方法 | 加固（抽取型） | 必须脱壳 |
| 找不到 native 库 | 运行时释放 | 装到设备上后从 `/data/app/.../lib/` 取 |
| manifest 是乱码 | 二进制 XML | apktool 已自动处理，确认用的是 apktool 输出 |
