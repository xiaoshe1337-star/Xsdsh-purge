---
name: rev-deobfuscate
description: 代码混淆还原。OLLVM/Hikari 控制流平坦化、虚假控制流、指令替换、MBA 表达式化简、字符串加密还原、常量加密、间接跳转还原、IDA/Ghidra 脚本编写。适用于反编译出来结构混乱、跳转满天飞、字符串全是乱码的场景。
enabled: true
---

# 代码混淆还原

## 混淆类型识别

| 症状 | 混淆类型 | 难度 |
| --- | --- | --- |
| 大量 `switch` / `if-else` 指向同一批块 | 控制流平坦化（FCO） | ★★★ |
| 大量恒假条件（`x*x>=0`、`(x|1)!=0`） | 虚假控制流（BCF） | ★★ |
| 简单运算变成一长串位运算 | 指令替换（SUB/MBA） | ★★ |
| 字符串全是乱码，运行时才解 | 字符串加密 | ★★ |
| 大量间接跳转（`jmp [table+idx*8]`） | 间接跳转/BR dispatch | ★★★★ |
| 函数被拆成很多小函数互相调用 | 函数拆分（FLA） | ★★★ |
| 有 VM 解释器 + 字节码表 | 虚拟化（VMProtect 类） | ★★★★★ |

## OLLVM 控制流平坦化（FCO）

### 识别

```c
// 反编译出来长这样：
while (1) {
    switch (state) {
    case 0: a = 1; state = 3; break;
    case 1: b = 2; state = 7; break;
    case 2: c = 3; state = 5; break;
    ...
    case 8: return result;
    }
}
```

真实逻辑 = 按 `state` 赋值链串起来的顺序。

### 手工还原

```
1. 找到 dispatcher（那个大 switch）
2. 找到 state 变量
3. 从入口点的 state 开始，跟着赋值链走：
   state = 0 -> 执行 case 0 -> 最后 state = 3
   state = 3 -> 执行 case 3 -> 最后 state = 7
   ...
4. 按这个顺序把块排出来就是真实逻辑
```

### 脚本化还原（IDAPython）

```python
# ollvm_deflat.py —— IDA 里跑
import idaapi
import idautils
import idc
import ida_funcs
import ida_xref

def find_dispatcher(func_ea):
    """找控制流平坦化的 dispatcher（switch 所在处）"""
    blocks = [b for b in idaapi.FlowChart(ida_funcs.get_func(func_ea))]
    # dispatcher 是后继最多的块
    best = None
    best_n = 0
    for b in blocks:
        succ = len(list(b.succs()))
        if succ > best_n:
            best_n = succ
            best = b
    return best, best_n

def trace_state_chain(dispatcher_ea):
    """从 dispatcher 出发，追踪 state 赋值链"""
    chain = []
    visited = set()
    cur = dispatcher_ea
    while cur and cur not in visited:
        visited.add(cur)
        chain.append(cur)
        # 找当前块里对 state 变量的赋值常量
        nxt = None
        ea = cur
        end = idc.get_func_attr(cur, idc.FUNCATTR_END)
        while ea < end and ea != idc.BADADDR:
            # 找 mov state, imm
            if idc.print_insn_mnem(ea) == 'mov':
                if idc.get_operand_type(ea, 1) == idc.o_imm:
                    val = idc.get_operand_value(ea, 1)
                    nxt = val
            ea = idc.next_head(ea)
        cur = nxt
    return chain

def dump_info(func_ea):
    f = ida_funcs.get_func(func_ea)
    print(f'function: {idc.get_func_name(func_ea)} @ {hex(func_ea)}')
    d, n = find_dispatcher(func_ea)
    print(f'dispatcher: {hex(d.start_ea)} with {n} successors')
    chain = trace_state_chain(d.start_ea)
    print(f'chain length: {len(chain)}')
    for i, b in enumerate(chain[:20]):
        print(f'  [{i}] {hex(b)}')

# 用：把光标放在目标函数上跑
ea = idc.get_screen_ea()
dump_info(ea)
```

### 通用去平坦化工具

| 工具 | 适用 | 说明 |
| --- | --- | --- |
| **D810**（IDA 插件） | 通用 | 交互式，效果好 |
| **ollvm-breaker** | IDA | 停更但思路清晰 |
| **deflat**（Ghidra） | Ghidra | 脚本化 |
| **SATURN** | 二进制 | 学术工具 |
| **Triton** | 符号执行 | 重型，能解复杂表达式 |

**D810 用法：**
```
1. 装插件到 IDA plugins 目录
2. Edit -> Plugins -> D810
3. 选目标函数，点 "Start"
4. 它会尝试还原，结果写回反编译视图
```

## 虚假控制流（BCF）

### 识别

```c
if ((x * x) >= 0) {    // 恒真
    真实代码;
} else {
    垃圾代码;
}
```

```c
if (((x | 1) != 0)) { ... }     // 恒真
if ((x & 0) == 0) { ... }       // 恒真
if ((x ^ x) == 0) { ... }       // 恒真
```

### 还原

```
1. 识别恒真/恒假条件（编译器不会生成这种代码）
2. patch 掉：jz/jnz -> jmp 或 nop
3. 或用 IDA 的 "Force jump" 功能
```

```python
# bcf_clean.py —— 找出恒真条件
import idautils, idc, idaapi
import re

PATTERNS = [
    r'\(.*\*.*\)\s*>=\s*0',
    r'\(\w+\s*\|\s*1\)\s*!=\s*0',
    r'\(\w+\s*&\s*0\)\s*==\s*0',
]

def scan_pseudo():
    """扫反编译伪代码里的恒真条件（需要 Hex-Rays）"""
    import ida_hexrays
    if not ida_hexrays.init_hexrays_plugin():
        print('Hex-Rays not available')
        return
    # 遍历所有函数
    for ea in idautils.Functions():
        try:
            cf = ida_hexrays.decompile(ea)
            if cf is None: continue
            src = str(cf)
            for pat in PATTERNS:
                if re.search(pat, src):
                    print(f'{idc.get_func_name(ea)} @ {hex(ea)} 命中 {pat}')
                    break
        except Exception:
            pass

scan_pseudo()
```

## 指令替换 / MBA

### 识别

```c
// 原本是 a + b，变成了：
a + b = (a ^ b) + 2 * (a & b)
a + b = (a | b) + (a & b)
```

### 常用恒等式（手工化简用）

```
x + y     = (x ^ y) + 2*(x & y)
x + y     = (x | y) + (x & y)
x - y     = (x ^ y) - 2*(~x & y)
-x        = ~x + 1
x ^ y     = (x | y) - (x & y)
!(x ^ y)  = (x == y)
(x & y) + (x | y) = x + y
```

### 自动化工具

| 工具 | 说明 |
| --- | --- |
| **MBA-Blast** | 学术工具，能化简复杂 MBA 表达式 |
| **SiMBA** | 同上，更快 |
| **Triton** | 符号执行 + 化简 |
| **Z3** | 通用 SMT，能验证等价 |

```python
# 用 z3 验证两个表达式是否等价
from z3 import *

x, y = BitVecs('x y', 32)
e1 = (x ^ y) + 2 * (x & y)
e2 = x + y
s = Solver()
s.add(e1 != e2)
print('equivalent' if s.check() == unsat else 'NOT equivalent')
```

## 字符串加密

### 识别

```c
// 特征
char buf[32];
for (i = 0; i < 32; i++)
    buf[i] = encrypted[i] ^ key[i % keylen];
// 然后 buf 被当字符串用
```

### 自动解密（IDAPython）

```python
# string_decrypt.py
import idc, ida_bytes, idautils

def try_xor(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def find_and_decrypt(ea, length, key):
    """在 ea 处读 length 字节，用 key 解，若是可打印就打印"""
    data = ida_bytes.get_bytes(ea, length)
    if not data: return
    dec = try_xor(data, key)
    if all(32 <= c < 127 or c in (9, 10, 13) for c in dec):
        print(f'{hex(ea)}: {dec.decode(errors="replace")}')

# 单字节暴力（最常用）
def brute_single_byte(ea, length):
    data = ida_bytes.get_bytes(ea, length)
    if not data: return
    for k in range(256):
        dec = bytes(b ^ k for b in data)
        if dec.count(b'http') or dec.count(b'.com') or dec.count(b'/api'):
            print(f'key=0x{k:02x} @ {hex(ea)}: {dec[:80]}')

# 用：选中一段数据后跑
ea = idc.read_selection_start()
end = idc.read_selection_end()
if ea != idc.BADADDR:
    brute_single_byte(ea, end - ea)
```

### 运行时 dump（最可靠）

```javascript
// 字符串解密必然在运行时发生，hook 解密函数或字符串构造点
// Android
Java.perform(function () {
    var S = Java.use('java.lang.String');
    S.$init.overload('[B').implementation = function (b) {
        var r = this.$init(b);
        console.log('[String] ' + r);
        return r;
    };
});

// Native
var strcmp = Module.findExportByName(null, 'strcmp');
Interceptor.attach(strcmp, {
    onEnter: function (args) {
        try {
            console.log('[strcmp] ' + args[0].readCString() + ' vs ' + args[1].readCString());
        } catch (e) {}
    }
});
```

## 间接跳转还原

### 特征

```asm
; 大量这种
ldr x8, [x0, x1, lsl #3]
br  x8
```

或：

```asm
jmp qword ptr [rax*8 + table]
```

### 还原思路

```
1. 找到跳转表基址（那个 table）
2. 确认索引范围（通常是 0..N）
3. 把表里每一项都 dump 出来，做成地址列表
4. 手工或脚本把每个目标建立交叉引用
5. IDA 里可以对 table 应用 "表识别"（Edit -> Other -> Specify switch）
```

```python
# dump_jumptable.py
import idc, ida_bytes, idaapi

def dump_table(base_ea, count, elem_size=8):
    print(f'table @ {hex(base_ea)}, {count} entries')
    for i in range(count):
        ea = base_ea + i * elem_size
        if elem_size == 8:
            target = ida_bytes.get_qword(ea)
        else:
            target = ida_bytes.get_dword(ea)
        print(f'  [{i}] {hex(target)}')
        # 加交叉引用
        idc.add_dref(base_ea + i * elem_size, target, idc.XREF_USER | idc.dr_R)

base = idc.read_selection_start()
if base != idc.BADADDR:
    dump_table(base, 64)
```

## Hikari / OLLVM 变种

Hikari 是 OLLVM 的增强版，特征是：

| 特征 | 说明 |
| --- | --- |
| 更强的 MBA | 表达式更难化简 |
| 函数包装（FCO + FLA 组合） | 每个函数外面套一层 |
| 运行时字符串解码 | 字符串解密函数被内联 |
| 高熵容器 | 关键数据段被压缩/加密 |
| 间接 BR/BLR dispatch | 大量间接跳转 |

**处理路径：**

```
1. 先跑 D810（能解一部分）
2. 剩下的手工：找 dispatcher -> 跟 state -> 重排
3. 字符串走运行时 hook dump
4. 间接跳转用表 dump + 手工建引用
5. 高熵段先找解密函数（在 .init_array 或 JNI_OnLoad 里）
```

**这是持久战。** 一个中等复杂度的 Hikari 函数可能要几小时。**如实报告进度，不要谎报"已还原"。**

## 验证还原正确

```
✅ 反编译后控制流是线性/简单的，不再有 dispatcher
✅ 字符串能正常显示（不是乱码）
✅ 常量是明确的值（不是一堆位运算）
✅ 关键函数的行为与动态调试观测一致
✅ 能写出等价的伪代码，且逻辑与原始功能吻合
```

## 输出规范

```
[反混淆] 样本=SHA256 混淆=OLLVM FCO + 字符串加密
原始状态: 目标函数 47 个块，dispatcher @ 0x1234，218 条 state 转移
方法: D810 自动 + 手工跟 state 链
结果:
  - 47 块重排为 12 个逻辑块
  - 字符串解密 key=0x5a（单字节 XOR），已解出 38 条
  - 3 处 MBA 表达式已化简为 a+b 形式
验证: 还原后的伪代码与动态 hook 观测的行为一致
残余: 2 个函数仍是间接跳转，未完全还原
证据: /path/deflat_result.c + /path/decrypt_strings.py
```

## 边界

- 只做反混淆。**不还原协议、不脱壳**。
- **还原不了就如实报告**：「还剩 N 个函数未还原」比"已完成"有价值。
- 虚拟化保护（VMProtect 类）**不在本技能范围**，转 rev-unpack-windows。
