"""
生成 dsh-purge 内置壁纸。

三张 2560x1440 的逆向 / 渗透主题背景，压成 JPEG（质量 82）后随包分发，
总体积控制在 1.2MB 以内。风格以「暗色 + 单色发光」为主：玻璃面板压在上面时
背景不能抢文字，所以明度全部压在 8%–28% 区间，只留少量高光做景深。

用法：python tools/gen_wallpapers.py
"""
from __future__ import annotations

import math
import random
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

W, H = 2560, 1440
OUT = Path(__file__).resolve().parent.parent / "lib" / "wallpapers"

# 字体：优先等宽字体，保证代码质感
MONO_CANDIDATES = [
    r"C:\Windows\Fonts\CascadiaCode.ttf",
    r"C:\Windows\Fonts\consola.ttf",
    r"C:\Windows\Fonts\lucon.ttf",
    r"C:\Windows\Fonts\arial.ttf",
]


def load_font(size: int) -> ImageFont.FreeTypeFont:
    for p in MONO_CANDIDATES:
        if Path(p).exists():
            try:
                return ImageFont.truetype(p, size)
            except OSError:
                continue
    return ImageFont.load_default()


def radial(shape, center, radius, falloff=2.0):
    """以 center 为中心的径向渐变遮罩，值域 0..1。"""
    h, w = shape
    yy, xx = np.mgrid[0:h, 0:w].astype(np.float32)
    cx, cy = center
    d = np.sqrt((xx - cx) ** 2 + (yy - cy) ** 2) / max(radius, 1e-6)
    return np.clip(1.0 - d, 0.0, 1.0) ** falloff


def lerp_gradient(shape, top, bottom):
    """垂直渐变。shape=(h, w)。

    注意 numpy 广播：(h,1,1) 与 (1,1,3) 相乘得 (h,1,3)，不会凭空多出 w 轴。
    先算 (h,1,3) 再沿宽度广播一次，才是 (h,w,3)。
    """
    h, w = shape
    t = np.linspace(0.0, 1.0, h, dtype=np.float32).reshape(h, 1, 1)
    top = np.array(top, dtype=np.float32).reshape(1, 1, 3)
    bottom = np.array(bottom, dtype=np.float32).reshape(1, 1, 3)
    strip = top * (1 - t) + bottom * t          # (h, 1, 3)
    return np.broadcast_to(strip, (h, w, 3)).copy()


def add_noise(arr, amount=3.0):
    """轻微胶片颗粒，避免大色块在 OLED 上出现色带。"""
    noise = np.random.normal(0, amount, arr.shape[:2]).astype(np.float32)
    arr = arr + noise[:, :, None]
    return np.clip(arr, 0, 255)


def draw_vignette(img: Image.Image, strength=0.55):
    arr = np.asarray(img).astype(np.float32)
    m = radial((H, W), (W / 2, H / 2), max(W, H) * 0.72, falloff=1.35)
    m = 1.0 - strength * (1.0 - m)
    arr = arr * m[:, :, None]
    return Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8))


# ── 壁纸 1：终端雨（绿色） ────────────────────────────────────────────────
def wallpaper_terminal_rain():
    base = lerp_gradient((H, W), (7, 16, 12), (3, 8, 6))
    img = Image.fromarray(np.clip(base, 0, 255).astype(np.uint8))

    # 中央偏右的绿色辉光
    arr = np.asarray(img).astype(np.float32)
    glow = radial((H, W), (W * 0.62, H * 0.42), W * 0.55, falloff=2.4)
    arr += glow[:, :, None] * np.array([12, 46, 28], dtype=np.float32)
    img = Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8))

    # 竖排代码雨
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    font = load_font(30)
    rng = random.Random(0x5A17)
    chars = "01{}[]()<>/\\|=+-*&^%$#@!~abcdefABCDEF"
    cols = list(range(0, W, 46))
    for x in cols:
        # 每列随机长度与亮度，右侧更密
        depth = 1.0 - abs(x / W - 0.62) * 1.3
        depth = max(0.15, min(1.0, depth))
        count = int(rng.randint(4, 16) * depth)
        y = rng.randint(-200, H)
        for k in range(count):
            ch = rng.choice(chars)
            a = int(rng.randint(10, 46) * depth)
            g = 90 + rng.randint(0, 80)
            d.text((x, y), ch, font=font, fill=(40, g, 70, a))
            y += rng.randint(30, 44)
    layer = layer.filter(ImageFilter.GaussianBlur(0.6))
    img = Image.alpha_composite(img.convert("RGBA"), layer).convert("RGB")

    # 顶部几条高光线
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    rng = random.Random(0x0C0DE)
    for _ in range(9):
        y = rng.randint(120, H - 120)
        x0 = rng.randint(0, W - 400)
        ln = rng.randint(120, 620)
        d.line([(x0, y), (x0 + ln, y)], fill=(60, 200, 130, rng.randint(8, 26)), width=1)
    img = Image.alpha_composite(img.convert("RGBA"), layer).convert("RGB")

    img = draw_vignette(img, 0.5)
    arr = add_noise(np.asarray(img).astype(np.float32), 3.2)
    return Image.fromarray(arr.astype(np.uint8))


# ── 壁纸 2：十六进制流（蓝紫） ────────────────────────────────────────────
def wallpaper_hexstream():
    base = lerp_gradient((H, W), (10, 10, 22), (4, 5, 12))
    img = Image.fromarray(np.clip(base, 0, 255).astype(np.uint8))

    arr = np.asarray(img).astype(np.float32)
    for (cx, cy, rad, col) in [
        (W * 0.28, H * 0.28, W * 0.46, (28, 22, 76)),
        (W * 0.78, H * 0.72, W * 0.42, (46, 18, 58)),
    ]:
        g = radial((H, W), (cx, cy), rad, falloff=2.6)
        arr += g[:, :, None] * np.array(col, dtype=np.float32)
    img = Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8))

    # hex dump 网格
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    font = load_font(22)
    rng = random.Random(0xB16B00B5)
    for row, y in enumerate(range(40, H, 30)):
        offset = rng.randint(0, 64)
        parts = []
        addr = (row * 16 + offset) & 0xFFFFFF
        parts.append(f"{addr:06x}  ")
        for _ in range(8):
            parts.append(f"{rng.randint(0, 255):02x} ")
        parts.append(" ")
        for _ in range(8):
            parts.append(chr(rng.randint(33, 126)))
        text = "".join(parts)
        a = rng.randint(12, 34)
        col = (140, 150, 255) if rng.random() < 0.7 else (190, 150, 255)
        d.text((36, y), text, font=font, fill=(*col, a))
    layer = layer.filter(ImageFilter.GaussianBlur(0.5))
    img = Image.alpha_composite(img.convert("RGBA"), layer).convert("RGB")

    img = draw_vignette(img, 0.52)
    arr = add_noise(np.asarray(img).astype(np.float32), 3.0)
    return Image.fromarray(arr.astype(np.uint8))


# ── 壁纸 3：拓扑网格（青灰，最中性） ──────────────────────────────────────
def wallpaper_topology():
    base = lerp_gradient((H, W), (12, 18, 22), (5, 8, 11))
    img = Image.fromarray(np.clip(base, 0, 255).astype(np.uint8))

    arr = np.asarray(img).astype(np.float32)
    g = radial((H, W), (W * 0.5, H * 0.18), W * 0.62, falloff=2.2)
    arr += g[:, :, None] * np.array([16, 40, 52], dtype=np.float32)
    img = Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8))

    # 网络节点 + 连线
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    rng = random.Random(0x7EC0)
    nodes = []
    for _ in range(64):
        x = rng.uniform(60, W - 60)
        y = rng.uniform(60, H - 60)
        nodes.append((x, y))

    for i, (x1, y1) in enumerate(nodes):
        for j in range(i + 1, len(nodes)):
            x2, y2 = nodes[j]
            dist = math.hypot(x2 - x1, y2 - y1)
            if dist < 300:
                a = int(34 * (1 - dist / 300))
                if a <= 0:
                    continue
                d.line([(x1, y1), (x2, y2)], fill=(90, 180, 200, a), width=1)

    for (x, y) in nodes:
        r = rng.randint(2, 4)
        a = rng.randint(60, 130)
        d.ellipse([x - r, y - r, x + r, y + r], fill=(120, 210, 230, a))
    layer = layer.filter(ImageFilter.GaussianBlur(0.7))
    img = Image.alpha_composite(img.convert("RGBA"), layer).convert("RGB")

    # 底部几条基线，像示波器
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    for k, y0 in enumerate([H * 0.78, H * 0.86]):
        pts = []
        for x in range(0, W, 8):
            y = y0 + math.sin(x / 190.0 + k * 1.7) * 16 + math.sin(x / 47.0) * 6
            pts.append((x, y))
        d.line(pts, fill=(80, 200, 220, 20 - k * 6), width=1)
    img = Image.alpha_composite(img.convert("RGBA"), layer).convert("RGB")

    img = draw_vignette(img, 0.48)
    arr = add_noise(np.asarray(img).astype(np.float32), 2.8)
    return Image.fromarray(arr.astype(np.uint8))


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    jobs = [
        ("terminal-rain", wallpaper_terminal_rain),
        ("hexstream", wallpaper_hexstream),
        ("topology", wallpaper_topology),
    ]
    total = 0
    for name, fn in jobs:
        img = fn()
        path = OUT / f"{name}.jpg"
        img.save(path, "JPEG", quality=82, optimize=True, progressive=True)
        size = path.stat().st_size
        total += size
        print(f"  {name:16s} {W}x{H}  {size/1024:7.1f} KB  -> {path}")
    print(f"  合计 {total/1024:.1f} KB")


if __name__ == "__main__":
    main()
