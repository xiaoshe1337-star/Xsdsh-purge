"""
生成 dsh-purge 内置动态壁纸。

产物是两段可无缝循环的 MP4（lib/wallpapers/*.mp4），配色走 nachoneko 的
紫 / 白 / 粉调，但画面是纯程序化生成（渐变流动 + 光带 + 粒子），不含任何
第三方画作，可随插件自由分发。

循环技巧：所有运动量的周期都整除动画时长，保证首尾帧一致，<video loop>
播放时看不出接缝。

用法：python tools/gen_live_wallpapers.py
"""
from __future__ import annotations

import math
import subprocess
import sys
from pathlib import Path

import numpy as np

W, H = 1920, 1080          # 动态壁纸用 1080p 就够：整屏铺满后还要压在玻璃面板之下
FPS = 30
DUR = 8                    # 秒；下面所有周期的设置都要能整除它
OUT = Path(__file__).resolve().parent.parent / "lib" / "wallpapers"
FFMPEG = "ffmpeg"

# ── 配色（nachoneko 调：紫 / 粉 / 冷白） ─────────────────────────────────
PURPLE = np.array([124, 92, 200], dtype=np.float32)
PINK = np.array([214, 120, 178], dtype=np.float32)
MINT = np.array([132, 206, 214], dtype=np.float32)
DEEP = np.array([18, 14, 34], dtype=np.float32)


def smoothstep(edge0, edge1, x):
    t = np.clip((x - edge0) / max(edge1 - edge0, 1e-6), 0.0, 1.0)
    return t * t * (3.0 - 2.0 * t)


def blob(shape, cx, cy, rx, ry, power=2.0):
    """椭圆软斑，值域 0..1。"""
    h, w = shape
    yy, xx = np.mgrid[0:h, 0:w].astype(np.float32)
    d = np.sqrt(((xx - cx) / max(rx, 1e-6)) ** 2 + ((yy - cy) / max(ry, 1e-6)) ** 2)
    return np.clip(1.0 - d, 0.0, 1.0) ** power


# ── 壁纸 1：极光（neko-aurora）───────────────────────────────────────────
def frame_aurora(t):
    """t ∈ [0,1) 为一个循环内的相位。"""
    ph = 2 * math.pi * t
    h, w = H, W
    yy, xx = np.mgrid[0:h, 0:w].astype(np.float32)
    u = xx / w
    v = yy / h

    # 底色：上深下浅的紫，整体压暗，保证玻璃面板上的文字可读
    base = DEEP[None, None, :] * (1.0 - 0.35 * v[:, :, None])
    img = np.broadcast_to(base, (h, w, 3)).copy()

    # 三条极光带：正弦叠加，横向缓慢漂移（周期整除 DUR）
    for k, (col, f, amp, speed, ybase, thick) in enumerate([
        (PURPLE, 1.0, 0.10, 1, 0.42, 0.20),
        (PINK, 2.0, 0.07, 2, 0.56, 0.15),
        (MINT, 1.0, 0.05, -1, 0.66, 0.11),
    ]):
        wave = (
            np.sin(u * 2 * math.pi * f + ph * speed + k * 1.7) * amp
            + np.sin(u * 2 * math.pi * f * 2.0 - ph * speed * 2 + k * 0.9) * amp * 0.45
        )
        center = ybase + wave
        band = np.exp(-(((v - center) / thick) ** 2) * 2.2).astype(np.float32)
        # 横向亮度调制，避免整条一样亮
        ripple = (0.65 + 0.35 * np.sin(u * 2 * math.pi * (f + 1) + ph * 2 + k)).astype(np.float32)
        img += band[:, :, None] * ripple[:, :, None] * col[None, None, :] * 0.42

    # 两颗缓慢呼吸的柔光球
    for (bx, by, br, col, spd, phase) in [
        (0.26, 0.30, 0.30, PINK, 1, 0.0),
        (0.76, 0.22, 0.26, MINT, -1, 1.3),
    ]:
        pulse = 1.0 + 0.18 * math.sin(ph * spd + phase)
        g = blob((h, w), bx * w, by * h, br * w * pulse, br * w * pulse * 0.75, power=2.6)
        img += g[:, :, None] * col[None, None, :] * 0.30

    # 细密星点（固定不动，只做明暗闪烁）
    rng = np.random.default_rng(20261019)
    for _ in range(90):
        sx = int(rng.integers(0, w))
        sy = int(rng.integers(0, int(h * 0.7)))
        r = int(rng.integers(1, 3))
        a = 0.25 + 0.35 * (0.5 + 0.5 * math.sin(ph * int(rng.integers(1, 3)) + rng.random() * 6.28))
        x0, x1 = max(0, sx - r), min(w, sx + r + 1)
        y0, y1 = max(0, sy - r), min(h, sy + r + 1)
        img[y0:y1, x0:x1] += np.array([210, 205, 235], dtype=np.float32) * a * 0.5

    # 暗角
    vig = 1.0 - 0.55 * blob((h, w), w / 2, h / 2, w * 0.85, h * 0.95, power=1.35)
    img *= vig[:, :, None]
    return img


# ── 壁纸 2：涟漪（neko-ripple）───────────────────────────────────────────
def frame_ripple(t):
    """同心波纹从两个源点扩散；周期整除 DUR，首尾帧一致。"""
    ph = 2 * math.pi * t
    h, w = H, W
    yy, xx = np.mgrid[0:h, 0:w].astype(np.float32)

    img = np.broadcast_to(DEEP[None, None, :], (h, w, 3)).copy()

    # 底部大面积紫粉渐变
    v = yy / h
    img += (1.0 - v)[:, :, None] * (PURPLE * 0.16 + PINK * 0.10)[None, None, :]

    sources = [
        (0.30 * w, 0.44 * h, PURPLE, 1, 0.0, 118.0),
        (0.72 * w, 0.58 * h, PINK, 2, 1.9, 96.0),
    ]
    for (sx, sy, col, waves, phase, wavelength) in sources:
        d = np.sqrt((xx - sx) ** 2 + (yy - sy) ** 2)
        # 波数取整数，保证循环闭合；phase 只加常量偏移
        k = waves * 2 * math.pi / (wavelength * 4.0)
        ring = np.sin(d * k - ph * waves * 2 + phase)
        # 越远越弱
        fall = np.exp(-d / (w * 0.62)).astype(np.float32)
        img += (ring * fall)[:, :, None] * col[None, None, :] * 0.30

        # 源点本身的柔光
        g = blob((h, w), sx, sy, w * 0.16, w * 0.16, power=2.8)
        img += g[:, :, None] * col[None, None, :] * 0.34

    # 斜向光带扫过：位置按 cos 走，一个循环正好回到原点，首尾闭合。
    # （原先用 (t % 1) * 1.6 - 0.3 会从右侧跳回左侧，循环时看得见接缝）
    sweep = 0.5 + 0.5 * math.cos(ph)
    band = np.exp(-(((xx / w) - sweep) / 0.10) ** 2).astype(np.float32)
    img += band[:, :, None] * np.array([200, 180, 240], dtype=np.float32)[None, None, :] * 0.10

    vig = 1.0 - 0.55 * blob((h, w), w / 2, h / 2, w * 0.85, h * 0.95, power=1.35)
    img *= vig[:, :, None]
    return img


def render(name, frame_fn):
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"{name}.mp4"
    total = FPS * DUR
    cmd = [
        FFMPEG, "-y", "-loglevel", "error",
        "-f", "rawvideo", "-pix_fmt", "rgb24",
        "-s", f"{W}x{H}", "-r", str(FPS), "-i", "-",
        # yuv420p + faststart：浏览器 <video> 边下边播的前提
        "-c:v", "libx264", "-preset", "slow", "-crf", "24",
        "-pix_fmt", "yuv420p", "-g", str(FPS * 2),
        "-movflags", "+faststart",
        "-an",
        str(path),
    ]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    try:
        for i in range(total):
            img = frame_fn(i / total)
            img = np.clip(img, 0, 255)
            # 轻微抖动，压掉渐变色带
            img = img + np.random.default_rng(i).normal(0, 1.6, img.shape[:2])[:, :, None]
            proc.stdin.write(np.clip(img, 0, 255).astype(np.uint8).tobytes())
    finally:
        proc.stdin.close()
        proc.wait()
    if proc.returncode != 0:
        print(f"  {name}: ffmpeg 失败 rc={proc.returncode}")
        return None
    size = path.stat().st_size
    print(f"  {name:14s} {W}x{H} @{FPS}fps {DUR}s  {size/1024/1024:5.2f} MB  -> {path}")
    return size


def main():
    print("生成动态壁纸")
    total = 0
    for name, fn in [("neko-aurora", frame_aurora), ("neko-ripple", frame_ripple)]:
        s = render(name, fn)
        if s:
            total += s
    print(f"  合计 {total/1024/1024:.2f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
