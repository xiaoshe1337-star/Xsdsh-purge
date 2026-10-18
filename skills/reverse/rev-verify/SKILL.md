---
name: rev-verify
description: 逆向结果可执行验收器。对还原后的算法模块、脱壳产物、Hook 脚本、协议实现自动跑断言检查，输出 PASS/FAIL 清单。消除"看起来对但跑不起来"的隐患。任何还原动作完成后必须走这里。
enabled: true
---

# 逆向结果验收

## 为什么要这一步

逆向最常见的失败不是"没做出来"，而是**"看起来做出来了但实际是错的"**：

```
❌ 算法写出来了，但边界情况对不上
❌ 脱壳产物 readelf 能过，但 IDA 反编译是乱码
❌ Hook 抓到数据了，但抓的是错误位置
❌ 协议解密成功一次，换个包就失败
```

**每个结论都要能被独立复现。**

## 验收矩阵

| 产物类型 | L1 能跑 | L2 结果对 | L3 可复现 |
| --- | --- | --- | --- |
| 还原的算法 | 脚本能执行 | 输出与真实样本吻合 | 换一批样本也吻合 |
| 脱壳产物 | 能被解析器打开 | 反编译出正常代码 | 关键函数能定位 |
| Hook 脚本 | Frida 能加载 | 抓到真实数据 | 重复跑结果一致 |
| 协议实现 | 能解一个包 | 字段全部对应 | 3+ 包都成功 |
| 反混淆结果 | 反编译无报错 | 控制流线性 | 行为与动态观测一致 |

## L1：能跑

### 算法模块

```bash
python3 -c "import target_algo; print('import OK')"
# 或
python3 target_algo.py --selftest
```

### 脱壳产物

```bash
# ELF
readelf -h unpacked.so && echo "readelf OK"
readelf -l unpacked.so > /dev/null && echo "segments OK"

# PE
python3 -c "import pefile; pe=pefile.PE('unpacked.exe'); print('pefile OK')"

# DEX
baksmali d unpacked.dex -o /tmp/test_smali && echo "baksmali OK"

# Mach-O
otool -h unpacked_binary && echo "otool OK"
```

### Hook 脚本

```bash
frida -U -f PACKAGE -l hook.js --no-pause --runtime=v8 -e "console.log('load OK')" 2>&1 | grep "load OK"
```

### 协议实现

```bash
python3 -c "import proto_impl; print('import OK')"
```

## L2：结果对

### 算法：与真实样本比对

```python
# verify_algo.py
import sys
import json

from target_algo import encrypt, decrypt

# 真实样本（从抓包/Hook 得到）
CASES = [
    # (明文, 期望密文, key, iv)
    (b'{"user":"admin"}', bytes.fromhex('8f3a2b1c...'), KEY, IV),
    (b'{"user":"test"}',  bytes.fromhex('7e1d4c9a...'), KEY, IV),
    (b'',                bytes.fromhex('...'),         KEY, IV),   # 边界：空
    (b'\x00' * 1000,     bytes.fromhex('...'),         KEY, IV),   # 边界：超长
]

fails = 0
for i, (pt, expected, k, iv) in enumerate(CASES):
    got = encrypt(pt, k, iv)
    if got == expected:
        print(f'[PASS] case {i}')
    else:
        print(f'[FAIL] case {i}')
        print(f'  expect: {expected.hex()}')
        print(f'  got   : {got.hex()}')
        fails += 1

# 反向验证：解回来
for i, (pt, expected, k, iv) in enumerate(CASES):
    if expected:
        back = decrypt(expected, k, iv)
        if back == pt:
            print(f'[PASS] roundtrip {i}')
        else:
            print(f'[FAIL] roundtrip {i}: {back} != {pt}')
            fails += 1

print()
print('RESULT:', 'PASS' if fails == 0 else f'FAIL ({fails} failures)')
sys.exit(0 if fails == 0 else 1)
```

**边界情况必测：**
- 空输入
- 超长输入（> 1MB）
- 特殊字符（`\x00`、UTF-8 多字节、emoji）
- 非法输入（错误 key / 截断密文）应该抛明确异常

### 脱壳：反编译质量

```python
# verify_unpack.py
import subprocess
import os
import sys

def check_elf(path):
    r = subprocess.run(['readelf', '-h', path], capture_output=True, text=True)
    assert r.returncode == 0, f'readelf -h failed: {r.stderr}'
    print('[PASS] readelf -h')

    r = subprocess.run(['readelf', '-l', path], capture_output=True, text=True)
    assert r.returncode == 0, f'readelf -l failed: {r.stderr}'
    print('[PASS] readelf -l')

    # 段内容不能全零
    data = open(path, 'rb').read()
    text_off = None
    # 简单检查：文件里至少有 1KB 非零非FF数据
    nonzero = sum(1 for b in data[:0x10000] if b not in (0, 0xff))
    assert nonzero > 1024, f'too little real data: {nonzero}'
    print(f'[PASS] real data present ({nonzero} non-trivial bytes)')

def check_dex(path):
    r = subprocess.run(['baksmali', 'd', path, '-o', '/tmp/_v_smali'],
                       capture_output=True, text=True)
    assert r.returncode == 0, f'baksmali failed: {r.stderr[:300]}'
    print('[PASS] baksmali')

    # 方法体非空
    n_methods = 0
    for root, _, files in os.walk('/tmp/_v_smali'):
        for f in files:
            if f.endswith('.smali'):
                with open(os.path.join(root, f), encoding='utf-8', errors='replace') as fh:
                    n_methods += fh.read().count('.method')
    assert n_methods > 100, f'too few methods: {n_methods}'
    print(f'[PASS] {n_methods} methods found')

def check_pe(path):
    import pefile
    pe = pefile.PE(path)
    assert len(pe.sections) >= 2, 'too few sections'
    print(f'[PASS] {len(pe.sections)} sections')
    imports = sum(len(e.imports) for e in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []))
    assert imports >= 5, f'too few imports: {imports}'
    print(f'[PASS] {imports} imports')

if __name__ == '__main__':
    p = sys.argv[1]
    if p.endswith('.dex'):
        check_dex(p)
    elif p.endswith(('.exe', '.dll', '.sys')):
        check_pe(p)
    else:
        check_elf(p)
    print('\nRESULT: PASS')
```

### Hook：抓到真实数据

```python
# verify_hook.py —— 检查 hook 日志是否有真实数据
import json
import sys
import re

LOG = sys.argv[1]
text = open(LOG, encoding='utf-8', errors='replace').read()

checks = {
    'hook 已加载':      'Script loaded' in text or 'loaded' in text.lower(),
    '至少一次命中':      text.count('[IN ') > 0 or text.count('called') > 0,
    '抓到参数':         bool(re.search(r'\[IN .{5,}', text)),
    '抓到返回值':       bool(re.search(r'\[OUT .{1,}', text)),
    '无异常退出':       'Error' not in text or text.count('Error') < 3,
}

fails = 0
for k, v in checks.items():
    print(('[PASS] ' if v else '[FAIL] ') + k)
    if not v:
        fails += 1

print()
print('RESULT:', 'PASS' if fails == 0 else f'FAIL ({fails})')
sys.exit(0 if fails == 0 else 1)
```

### 协议：多包验证

```python
# verify_proto.py
import sys
sys.path.insert(0, '.')
from proto_impl import decrypt, parse

CASES = [
    # (密文, 期望字段)
    ("8f3a2b...",  {"user": "admin", "act": "login"}),
    ("7e1d4c...",  {"user": "test",  "act": "query"}),
    ("9a2b5e...",  {"user": "guest", "act": "ping"}),
]

fails = 0
for i, (ct, expect) in enumerate(CASES):
    try:
        pt = decrypt(ct)
        obj = parse(pt)
        ok = all(obj.get(k) == v for k, v in expect.items())
        if ok:
            print(f'[PASS] case {i}: {obj}')
        else:
            print(f'[FAIL] case {i}')
            print(f'  expect: {expect}')
            print(f'  got   : {obj}')
            fails += 1
    except Exception as e:
        print(f'[FAIL] case {i}: exception {e}')
        fails += 1

print()
print('RESULT:', 'PASS' if fails == 0 else f'FAIL ({fails})')
sys.exit(0 if fails == 0 else 1)
```

## L3：可复现

**换一批样本再跑一次。**

```
算法：用另外 5 个抓到的包验证
脱壳：换一个同壳的样本，走同样流程
Hook：重启 App 再跑一次，结果应一致
协议：用不同时间/不同账号的包验证
```

```bash
# 幂等性检查
python3 verify_algo.py && python3 verify_algo.py && python3 verify_algo.py
# 三次都 PASS 才算稳定
```

## 自动生成验收脚本

```python
# gen_verify.py —— 根据产物类型生成对应验证脚本
import os
import sys

TEMPLATES = {
    'algo': '''#!/usr/bin/env python3
# 自动生成的算法验收脚本
import sys
from MODULE import FUNC

CASES = [
    # (输入, 期望输出)
]

fails = 0
for i, (inp, exp) in enumerate(CASES):
    got = FUNC(inp)
    ok = got == exp
    print(f"[{'PASS' if ok else 'FAIL'}] case {i}")
    if not ok:
        print(f"  expect: {exp!r}")
        print(f"  got   : {got!r}")
        fails += 1

print()
print("RESULT:", "PASS" if fails == 0 else f"FAIL ({fails})")
sys.exit(0 if fails == 0 else 1)
''',

    'unpack': '''#!/usr/bin/env python3
# 自动生成的脱壳验收脚本
import subprocess, sys

PATH = sys.argv[1]
checks = []

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode == 0, r.stderr

ok, err = run(['readelf', '-h', PATH])
checks.append(('readelf -h', ok, err[:200]))

ok, err = run(['readelf', '-l', PATH])
checks.append(('readelf -l', ok, err[:200]))

data = open(PATH, 'rb').read()
nonzero = sum(1 for b in data[:0x10000] if b not in (0, 0xff))
checks.append(('real data', nonzero > 1024, f'{nonzero} bytes'))

fails = 0
for name, ok, detail in checks:
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail if not ok else ''}")
    if not ok: fails += 1

print()
print('RESULT:', 'PASS' if fails == 0 else f'FAIL ({fails})')
sys.exit(0 if fails == 0 else 1)
''',
}

def gen(kind, out_path, module=None, func=None):
    tpl = TEMPLATES.get(kind)
    if not tpl:
        print('unknown kind:', kind)
        return False
    if module:
        tpl = tpl.replace('MODULE', module)
    if func:
        tpl = tpl.replace('FUNC', func)
    open(out_path, 'w', encoding='utf-8').write(tpl)
    os.chmod(out_path, 0o755)
    print('generated:', out_path)
    return True

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('usage: gen_verify.py <algo|unpack> <out.py> [module] [func]')
        sys.exit(1)
    gen(sys.argv[1], sys.argv[2],
        sys.argv[3] if len(sys.argv) > 3 else None,
        sys.argv[4] if len(sys.argv) > 4 else None)
```

## 一键验收（把所有检查串起来）

```bash
#!/usr/bin/env bash
# verify-all.sh
set -u

FAILS=0
run() {
    local name="$1"; shift
    echo "=== $name ==="
    if "$@"; then
        echo "[PASS] $name"
    else
        echo "[FAIL] $name"
        FAILS=$((FAILS+1))
    fi
    echo
}

run "算法" python3 verify_algo.py
run "脱壳" python3 verify_unpack.py unpacked.so
run "Hook" python3 verify_hook.py hook.log
run "协议" python3 verify_proto.py

echo "===================="
if [ $FAILS -eq 0 ]; then
    echo "ALL PASS"
    exit 0
else
    echo "FAILURES: $FAILS"
    exit 1
fi
```

## 输出规范

```
[验收] 目标=SHA256 产物=target_algo.py
L1 能跑: PASS (import OK, selftest OK)
L2 结果对:
  [PASS] case 0 (明文->密文 吻合)
  [PASS] case 1
  [PASS] roundtrip 0
  [FAIL] case 2 (空输入): 期望 d41d8cd9, 实际 0
L3 可复现: 3 次运行结果一致
结论: FAIL — 空输入边界未处理
修复建议: 空输入应返回空串，不是抛异常也不是返回 0
```

## 边界

- 只做验收。**不修 bug**（发现问题交回原角色）。
- **L2 必须有真实样本比对**，不能自己造期望值。
- 三项全过才算完成；只过 L1 就报"完成"是最常见的谎报。
