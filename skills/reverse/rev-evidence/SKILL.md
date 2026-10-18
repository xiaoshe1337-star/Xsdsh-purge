---
name: rev-evidence
description: 逆向证据链与产物规范。规定证据目录结构、每个结论必须挂依据、统一交付物格式（report/algo/patch/verify）、支持一键复现与回滚。团队协作、长周期项目、需要回溯时必用。
enabled: true
---

# 逆向证据链与产物规范

## 核心原则

**没落库的结论 = 没发生。**

每条结论必须能回答三件事：
1. **怎么知道的**（命令 / 脚本 / 观测）
2. **产物在哪**（文件路径 + 哈希）
3. **怎么复现**（从零跑一遍）

## 目录结构

```
engagement/
├── 00-meta/
│   ├── engagement.json         # 目标、范围、时间、参与角色
│   └── timeline.md             # 时间线（谁在什么时候做了什么）
├── 01-samples/
│   ├── original/               # 原始样本（只读）
│   │   └── SAMPLE.apk          # sha256: abc123...
│   └── variants/               # 变体/解包产物
├── 02-static/
│   ├── baseline.json           # 哈希、大小、架构、熵值
│   ├── strings/                # 提取的字符串
│   ├── decompiled/             # 反编译输出
│   └── findings/               # 静态发现（每条一个文件）
├── 03-dynamic/
│   ├── hooks/                  # Hook 脚本
│   ├── logs/                   # 运行日志
│   └── findings/               # 动态发现
├── 04-unpack/
│   ├── method.md               # 用了什么方法
│   ├── artifacts/              # 脱壳产物
│   └── verify.log              # 验证日志
├── 05-protocol/
│   ├── captures/               # 抓包
│   ├── impl/                   # 算法实现
│   └── spec.md                 # 协议文档
├── 06-output/
│   ├── report.md               # 最终报告
│   ├── algo/                   # 可交付算法
│   ├── patch/                  # patch 文件
│   └── verify/                 # 验收脚本
└── 07-reproduce/
    ├── run.sh                  # 一键复现
    └── requirements.txt
```

## engagement.json

```json
{
  "id": "ENG-2026-1018-001",
  "created": "2026-10-18T03:30:00+08:00",
  "target": {
    "name": "com.example.app",
    "version": "1.2.3",
    "platform": "android"
  },
  "samples": [
    {
      "path": "01-samples/original/app.apk",
      "sha256": "abc123...",
      "size": 12345678,
      "added": "2026-10-18T03:30:00+08:00"
    }
  ],
  "scope": {
    "in": ["客户端结构", "通信协议", "加密算法"],
    "out": ["服务端", "用户数据"]
  },
  "roles": ["static", "dynamic", "unpack", "protocol", "protect"],
  "status": "in_progress"
}
```

## 发现记录格式（每条一个文件）

`02-static/findings/F-001.md`:

```markdown
# F-001: 使用 360 加固

- **类型**: 保护识别
- **样本**: sha256:abc123...
- **置信度**: 高
- **时间**: 2026-10-18T03:35:00+08:00
- **角色**: static

## 结论

样本使用 360 加固（libjiagu.so）。

## 证据

### 命令

```bash
find OUT/lib -name "*.so"
```

### 输出

```
OUT/lib/arm64-v8a/libjiagu.so
OUT/lib/arm64-v8a/libc++_shared.so
```

### 文件

- `02-static/strings/so_list.txt`（完整输出）
- `01-samples/original/app.apk` sha256=abc123...

## 影响

- 需要先脱壳才能做静态分析
- 转 rev-unpack-android

## 待验证

- [ ] BlackDex 是否能处理该版本 360 加固
```

## 结论必须挂证据

### 好的写法

```
[静态] 加密算法为 AES-128-CBC
证据:
  1. Hook 日志 03-dynamic/logs/cipher.log:12
     [Cipher alg] AES/CBC/PKCS5Padding
  2. 密钥 2b7e15... 来自 03-dynamic/logs/key.log:5
     [KEY] alg=AES key=2b7e151628aed2a6abf7158809cf4f3c
  3. 独立脚本 06-output/algo/aes_impl.py 能解开 5 个真实包
     verify 结果 06-output/verify/algo_result.log
```

### 差的写法

```
❌ 加密算法是 AES
   （没有证据，无法复现）
```

## 交付物格式

### 1. 报告（report.md）

```markdown
# 逆向分析报告：com.example.app v1.2.3

## 摘要
- 平台 / 保护 / 主要发现（3-5 条）

## 样本信息
- SHA256 / 大小 / 架构

## 分析过程
- 按阶段列，每阶段引用相关 findings

## 结论
- 每条挂 findings 编号

## 附录
- 证据索引
```

### 2. 算法实现（algo/）

```
algo/
├── aes_impl.py          # 独立可用，不依赖样本
├── aes_impl_test.py     # 验收脚本
└── README.md            # 用法 + 已知限制
```

**要求：独立可运行，不依赖原始样本。**

### 3. Patch（patch/）

```
patch/
├── 0001-bypass-check.patch    # 标准 diff 格式
├── apply.sh                   # 一键应用
└── README.md                  # 说明改了什么、为什么
```

### 4. 验收（verify/）

```bash
verify/
├── verify-all.sh         # 一键全跑
├── verify_algo.py
├── verify_unpack.py
└── expected/             # 期望输出（用于比对）
```

## 一键复现

`07-reproduce/run.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== 环境检查 ==="
command -v python3 || { echo "need python3"; exit 1; }
command -v jadx    || { echo "need jadx"; exit 1; }

echo "=== 样本校验 ==="
EXPECTED=$(python3 -c "import json;print(json.load(open('00-meta/engagement.json'))['samples'][0]['sha256'])")
ACTUAL=$(sha256sum 01-samples/original/app.apk | cut -d' ' -f1)
[ "$EXPECTED" = "$ACTUAL" ] || { echo "sample hash mismatch!"; exit 1; }
echo "sample OK"

echo "=== 静态分析 ==="
jadx -d 02-static/decompiled --show-bad-code 01-samples/original/app.apk

echo "=== 脱壳 ==="
bash 04-unpack/method.sh

echo "=== 验收 ==="
bash 06-output/verify/verify-all.sh

echo "=== 完成 ==="
```

## 回滚

**任何修改原始样本的动作都要可回滚。**

```bash
# 改之前先存副本
cp SAMPLE.apk 01-samples/variants/SAMPLE.patched.apk

# 记录改了什么
cat > 02-static/findings/patch-001.md <<'EOF'
# patch-001: 绕过签名校验
- 目标: com.example.Verify.check
- 原: 0x1234: 1A 00 00 34 (cbz w0, +0)
- 改: 0x1234: 1F 20 03 D5 (nop)
- 产物: 01-samples/variants/SAMPLE.patched.apk
EOF

# 原始文件永不修改
chmod 444 01-samples/original/*
```

## 时间线

`00-meta/timeline.md`:

```markdown
# 时间线

| 时间 | 角色 | 动作 | 产出 |
| --- | --- | --- | --- |
| 03:30 | - | 开始，登记样本 | engagement.json |
| 03:35 | static | 识别为 360 加固 | F-001 |
| 03:40 | unpack | BlackDex 脱壳 | 04-unpack/artifacts/ |
| 03:55 | static | 反编译真实代码 | 02-static/decompiled/ |
| 04:10 | dynamic | hook CryptoHelper | 03-dynamic/hooks/ |
| 04:25 | protocol | 还原 AES 算法 | 05-protocol/spec.md |
| 04:40 | - | 验收通过 | 06-output/verify/ |
```

## 跨角色交接

**子智能体回报必须包含：**

```
1. 做了什么（角色 / 命令）
2. 产出在哪（路径 + 哈希）
3. 结论（挂证据）
4. 未解决的问题
5. 建议下一步
```

**好的回报：**

```
[unpack 回报]
完成: BlackDex 脱壳
产物: 
  04-unpack/artifacts/classes.dex  sha256=def456...  8.2MB
  04-unpack/artifacts/classes2.dex sha256=ghi789...  5.1MB
验证:
  baksmali PASS
  jadx 反编译率 96%
结论: 360 加固已脱，可静态分析
未解决: assets/ 下还有 3 个 .dat 文件可能是运行时加载的 dex
建议: 先派 static 看主代码，再决定是否处理那 3 个文件
```

**差的回报：**

```
❌ 脱壳完成了，可以继续了
   （产物在哪？验证了吗？）
```

## 输出规范

```
[证据] engagement=ENG-2026-1018-001
新增:
  F-005: AES-128-CBC 算法还原 (置信度: 高)
    证据: 03-dynamic/logs/cipher.log:12, 06-output/algo/aes_impl.py
  产物:
    06-output/algo/aes_impl.py        sha256=...
    06-output/verify/algo_result.log  (5/5 PASS)
时间线已更新
```

## 边界

- **不要编造证据。** 没跑过的命令不要写进证据。
- 证据路径必须真实存在，哈希必须能验。
- 结论的置信度要诚实（推测就标"推测"）。
