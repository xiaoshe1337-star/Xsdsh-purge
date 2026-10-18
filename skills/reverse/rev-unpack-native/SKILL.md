---
name: rev-unpack-native
description: Native ELF/SO 脱壳与重建。内存 dump、ELF carve、段重排、IAT/重定位修复、fake PT_LOAD 识别、入口搬移还原、嵌套 ELF 提取、mprotect/memfd 执行链分析。适用于 libxxx.so 熵值高、readelf 解析异常、IDA 打不开、入口不在 LOAD 段的场景。
enabled: true
---

# Native ELF/SO 脱壳重建

## 识别保护类型

### 静态检查

```bash
# 1. 基本信息
readelf -h TARGET.so
file TARGET.so

# 2. 节区是否被抹
readelf -S TARGET.so | head -20
# e_shoff = 0 或节区名全是空 -> section 表被抹

# 3. 段信息
readelf -l TARGET.so

# 4. 熵值分布
python3 -c "
d=open('TARGET.so','rb').read()
import math
def ent(b):
    if not b: return 0
    c=[0]*256
    for x in b: c[x]+=1
    return -sum((y/len(b))*math.log2(y/len(b)) for y in c if y)
print('file entropy:', round(ent(d),3))
# 按 4KB 分块看熵分布
for i in range(0, min(len(d), 0x100000), 0x1000):
    e = ent(d[i:i+0x1000])
    if e > 7.5:
        print(f'  block @{hex(i)} entropy={e:.2f} <== 加密/压缩')
"
```

### 保护类型判定

| 特征 | 类型 | 处理难度 |
| --- | --- | --- |
| `e_shoff = 0`，节区全无 | section 剥离 | 易 |
| `PT_LOAD` 的 `p_vaddr` 是离谱高地址（如 `0x7ffff000`） | fake PT_LOAD 包装 | 中 |
| `e_entry` 不在任何 LOAD 段范围内 | 入口被搬走 | 中 |
| 段内嵌 `7F 45 4C 46` | 嵌套 ELF / 多阶段 | 中 |
| 段熵 > 7.5 | 内层加密 | 中 |
| `DT_INIT_ARRAY` 指向异常地址 | 构造函数劫持 | 中 |
| 有 `mprotect` + `mmap` 但没有对应解密 | 运行时解密 | 中 |
| `memfd_create` 调用痕迹 | 内存执行链 | 高 |

## 静态还原路径

### 1. 判断 entry 合法性

```python
import struct

d = open('TARGET.so', 'rb').read()
is64 = d[4] == 2
e_entry = struct.unpack_from('<Q' if is64 else '<I', d, 0x18)[0]
e_phoff = struct.unpack_from('<Q' if is64 else '<I', d, 0x20)[0]
e_phnum = struct.unpack_from('<H', d, 0x38)[0]
e_shoff = struct.unpack_from('<Q' if is64 else '<I', d, 0x28)[0]

print(f'entry = {hex(e_entry)}')
print(f'phoff = {hex(e_phoff)}, phnum = {e_phnum}')
print(f'shoff = {hex(e_shoff)}  {"(抹掉了)" if e_shoff == 0 else ""}')

loads = []
for i in range(e_phnum):
    off = e_phoff + i * (56 if is64 else 32)
    p_type = struct.unpack_from('<I', d, off)[0]
    if is64:
        p_flags = struct.unpack_from('<I', d, off+4)[0]
        p_offset = struct.unpack_from('<Q', d, off+8)[0]
        p_vaddr = struct.unpack_from('<Q', d, off+16)[0]
        p_filesz = struct.unpack_from('<Q', d, off+32)[0]
        p_memsz = struct.unpack_from('<Q', d, off+40)[0]
    else:
        p_offset = struct.unpack_from('<I', d, off+4)[0]
        p_vaddr = struct.unpack_from('<I', d, off+8)[0]
        p_filesz = struct.unpack_from('<I', d, off+16)[0]
        p_memsz = struct.unpack_from('<I', d, off+20)[0]
    if p_type == 1:
        loads.append((p_offset, p_vaddr, p_filesz, p_memsz))
        print(f'  LOAD off={hex(p_offset):>10} vaddr={hex(p_vaddr):>12} filesz={hex(p_filesz):>10} memsz={hex(p_memsz):>10}')

# 检查 entry 是否落在某个 LOAD 段
in_load = any(v <= e_entry < v + m for (_, v, _, m) in loads)
print(f'\nentry in LOAD: {in_load}')
if not in_load and loads:
    # 尝试 e_entry - 第一个 LOAD 的 p_vaddr
    for (o, v, f, m) in loads:
        cand = e_entry - v
        print(f'  尝试 entry - vaddr({hex(v)}) = {hex(cand)}  {"<== 可能" if 0 <= cand < 0x1000 else ""}')
```

**如果 `entry in LOAD: False`**，说明入口被搬走。常见还原公式：

```
真实入口偏移 = e_entry - fake_p_vaddr
```

## 内存 dump（动态）

### 找真实 ELF 位置

```javascript
// find_elf.js
var target = 'libtarget.so';

// 1. 看 base
var base = Module.findBaseAddress(target);
console.log('base =', base);

// 2. 遍历内存找 ELF magic
Process.enumerateRanges('r-x').forEach(function (r) {
    try {
        var hits = Memory.scanSync(r.base, r.size, '7f 45 4c 46');
        hits.forEach(function (h) {
            console.log('ELF @', h.address, 'range:', r.base, 'size:', r.size,
                        'file:', r.file ? r.file.path : 'anon');
        });
    } catch (e) {}
});
```

```bash
frida -U -f PACKAGE -l find_elf.js --no-pause
```

### dump 指定内存段

```javascript
// dump_range.js
var addr = ptr('0x7000000000');   // 从上面找到的地址
var size = 0x200000;

var data = Memory.readByteArray(addr, size);
var f = new File('/sdcard/dump.bin', 'wb');
f.write(data);
f.flush();
f.close();
console.log('dumped', size, 'bytes');
```

```bash
frida -U -f PACKAGE -l dump_range.js --no-pause
adb pull /sdcard/dump.bin .
```

### 等解密完成再 dump

**关键：dump 时机。**

```javascript
// 等到关键函数执行后再 dump
var decryptFn = Module.findExportByName('libtarget.so', 'init');
if (!decryptFn) {
    // 找不到就在库加载后延迟
    var mod = Process.findModuleByName('libtarget.so');
    if (mod) decryptFn = mod.base;
}

Interceptor.attach(decryptFn, {
    onLeave: function () {
        console.log('[-] decrypt done, dumping...');
        var base = Module.findBaseAddress('libtarget.so');
        var size = Process.findModuleByName('libtarget.so').size;
        var d = Memory.readByteArray(base, size);
        var f = new File('/sdcard/libtarget_dump.so', 'wb');
        f.write(d); f.flush(); f.close();
        console.log('[+] dumped', size);
    }
});
```

## 重建 ELF

dump 出来的通常是**内存视图**，`p_offset` 与 `p_vaddr` 已不对应。

```python
# rebuild_elf.py
import struct
import sys

def rebuild(raw_path, out_path):
    raw = open(raw_path, 'rb').read()

    if raw[:4] != b'\x7fELF':
        print('not ELF magic, trying to find it...')
        idx = raw.find(b'\x7fELF')
        if idx < 0:
            print('no ELF found')
            return False
        print(f'found ELF at offset {hex(idx)}')
        raw = raw[idx:]

    is64 = raw[4] == 2
    e_phoff = struct.unpack_from('<Q' if is64 else '<I', raw, 0x20)[0]
    e_phnum = struct.unpack_from('<H', raw, 0x38)[0]

    print(f'is64={is64} phoff={hex(e_phoff)} phnum={e_phnum}')

    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * (56 if is64 else 32)
        if off + (56 if is64 else 32) > len(raw):
            break
        p_type = struct.unpack_from('<I', raw, off)[0]
        if p_type != 1:
            continue
        if is64:
            p_offset = struct.unpack_from('<Q', raw, off + 8)[0]
            p_vaddr = struct.unpack_from('<Q', raw, off + 16)[0]
            p_filesz = struct.unpack_from('<Q', raw, off + 32)[0]
        else:
            p_offset = struct.unpack_from('<I', raw, off + 4)[0]
            p_vaddr = struct.unpack_from('<I', raw, off + 8)[0]
            p_filesz = struct.unpack_from('<I', raw, off + 16)[0]
        loads.append({'off': p_offset, 'vaddr': p_vaddr, 'filesz': p_filesz})

    print(f'{len(loads)} LOAD segments')

    # 按 vaddr 排序，构造新的文件布局
    loads.sort(key=lambda x: x['vaddr'])

    if not loads:
        print('no LOAD segments')
        return False

    base_vaddr = loads[0]['vaddr']
    out = bytearray()
    new_offsets = []

    for seg in loads:
        # 内存 dump 里的数据位置 = vaddr - base_vaddr（假设 dump 从 base 开始）
        src_off = seg['vaddr'] - base_vaddr
        src_end = src_off + seg['filesz']

        if src_off >= len(raw):
            print(f'  WARN: segment vaddr={hex(seg["vaddr"])} beyond dump')
            continue

        data = raw[src_off:min(src_end, len(raw))]
        new_offsets.append({'vaddr': seg['vaddr'], 'new_off': len(out), 'filesz': len(data)})
        out += data
        # 按页对齐
        while len(out) % 0x1000:
            out.append(0)

    # 回填新的 p_offset
    out = bytearray(out)
    for i in range(e_phnum):
        off = e_phoff + i * (56 if is64 else 32)
        p_type = struct.unpack_from('<I', out, off)[0]
        if p_type != 1:
            continue
        p_vaddr = struct.unpack_from('<Q' if is64 else '<I', out, off + 16 if is64 else off + 8)[0]
        for seg in new_offsets:
            if seg['vaddr'] == p_vaddr:
                struct.pack_into('<Q' if is64 else '<I', out,
                                 off + 8 if is64 else off + 4,
                                 seg['new_off'])
                struct.pack_into('<Q' if is64 else '<I', out,
                                 off + 32 if is64 else off + 16,
                                 seg['filesz'])
                break

    open(out_path, 'wb').write(out)
    print(f'rebuilt -> {out_path} ({len(out)} bytes)')

    # 验证
    import subprocess
    r = subprocess.run(['readelf', '-l', out_path], capture_output=True, text=True)
    print('readelf check:', 'OK' if r.returncode == 0 else 'FAIL')
    if r.returncode != 0:
        print(r.stderr[:500])
    return True

if __name__ == '__main__':
    rebuild(sys.argv[1], sys.argv[2])
```

## 修 section header（如果被抹）

```python
# 用 readelf 的段信息重建最小 section 表
# 大部分场景其实不需要 section，IDA 靠 segment 就能工作
# 但加回去能让 readelf -S / objdump 正常工作

import struct

def add_section_headers(path):
    d = bytearray(open(path, 'rb').read())
    is64 = d[4] == 2
    e_shoff_off = 0x28 if is64 else 0x20
    e_shentsize_off = 0x3A if is64 else 0x2E
    e_shnum_off = 0x3C if is64 else 0x30
    e_shstrndx_off = 0x3E if is64 else 0x32

    # 简单方案：不重建完整 section 表，只把 e_shoff 保持 0
    # IDA/Ghidra 对无 section 的 ELF 处理得很好
    print('IDA/Ghidra 不需要 section header，跳过')
    return
```

**实际经验：IDA 和 Ghidra 靠 PT_LOAD 就能正常分析，section 表被抹不影响。**

## 嵌套 ELF / 多阶段加载

```bash
# 找所有 ELF magic
python3 -c "
d=open('TARGET.so','rb').read()
i=0
n=0
while True:
    i=d.find(b'\x7fELF', i)
    if i<0: break
    print(f'ELF @ {hex(i)}')
    i+=4
    n+=1
print(f'total {n}')
"
```

```bash
# 用 binwalk 自动切
binwalk -e TARGET.so
ls _TARGET.so.extracted/
```

## memfd / mprotect 执行链

**特征：**
- 导入 `memfd_create`、`fexecve`
- 调用 `mmap(PROT_EXEC)` 后 `mprotect`
- `/proc/self/exe` 被替换

```javascript
// 拦截 memfd_create
var mfd = Module.findExportByName(null, 'memfd_create');
if (mfd) {
    Interceptor.attach(mfd, {
        onEnter: function (args) {
            console.log('[memfd_create]', args[0].readCString());
        },
        onLeave: function (ret) {
            console.log('  -> fd', ret);
            this.fd = ret;
        }
    });
}

// 拦截写入 memfd 的 write
var write = Module.findExportByName(null, 'write');
Interceptor.attach(write, {
    onEnter: function (args) {
        var fd = args[0].toInt32();
        if (fd > 2 && fd < 100) {
            var buf = args[1];
            var len = args[2].toInt32();
            // 检查是否是 ELF
            if (len > 4) {
                var m = Memory.readByteArray(buf, 4);
                var u = new Uint8Array(m);
                if (u[0] === 0x7f && u[1] === 0x45) {
                    console.log('[write to fd ' + fd + '] ELF! len=' + len);
                    console.log(hexdump(buf, { length: Math.min(len, 64) }));
                }
            }
        }
    }
});
```

## 验证

```bash
# 1. readelf 能完整解析
readelf -h rebuilt.so
readelf -l rebuilt.so

# 2. 动态符号
readelf -Ws rebuilt.so | head -20

# 3. 重定位
readelf -r rebuilt.so | head -10

# 4. IDA 打开后能反编译（人工确认）

# 5. 如果能独立运行，跑一下
chmod +x rebuilt.so 2>/dev/null
./rebuilt.so 2>&1 | head
```

**成功标准：**
```
✅ readelf -h/-l 无报错
✅ 能看到真实的代码段（不是全零或全 FF）
✅ IDA 打开后函数识别正常
✅ 关键字符串能找到
```

## 输出规范

```
[脱壳-Native] 样本=SHA256 保护=fake PT_LOAD + XOR 解密
原文件: entry=0x1a3c0 不在 LOAD[0] 0x10000~0x11000, shoff=0
方法: Frida 在 libtarget.so 的 init 后 dump 0x200000 字节
产物: /path/libtarget_dump.so  sha256=xxx
重建: 按 vaddr 排序重排 3 个 LOAD 段，回填 p_offset
验证: readelf -h/-l PASS, 函数可识别, 关键字符串命中
结论: 真实 ELF 已还原，入口 0x10000，代码段完整
```

## 边界

- 只做 ELF 重建。**不做业务逻辑分析**。
- 重建失败要**说清哪一步失败**（dump 时机 / 段排序 / 重定位）。
- 内层还有加密时，**如实报告**需要继续解一层。
